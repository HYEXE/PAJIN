"""Governed WEB assessment promotion, Graph admission, and local export helpers.

This module is deliberately downstream of execution.  It does not mint Campaign,
Capability, Approval, Permit, worker, or delivery authority.  Instead, it accepts
caller-pinned execution evidence, independently reloads both sealed WEB-003 Runs,
requires a trusted signature verifier to bind their execution attestations, and only
then projects corroborated observations into PAJIN Findings.  Promotion authority is
an in-memory, factory-only capability; serializing its artifact does not preserve it.

External delivery remains a separate boundary.  The helpers can describe a verified
local export, but neither accept delivery authority nor dispatch one.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import unicodedata
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal, Never, Self, SupportsIndex, TypeVar, cast, final

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator

from pajin.domain.models import CampaignMode, Finding, FindingSeverity, StrictModel, ToolRiskTier
from pajin.domain.replay import (
    CompiledReplaySpec,
    ModeReplayContract,
    ReplayArtifactSet,
    ReplayAttempt,
    ReplayAttemptStatus,
    ReplayBinding,
    ReplayExecutionStatus,
    ReplayOracleResult,
    ReplayOracleVerdict,
    ReplayOutcome,
    ReplaySessionPolicy,
    ValidationEvidenceExcerpt,
    ValidationPacket,
    replay_argument_digest,
)
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ReplayConfirmationLineage,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
)
from pajin.graph import (
    ActionApprovalAuthorization,
    CampaignFactPayload,
    CampaignFactProposal,
    GraphAction,
    GraphActionStatus,
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphAdmissionReason,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphLineageVerificationError,
    GraphNode,
    GraphNodeKind,
    GraphObservation,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSurface,
    HypothesisProposal,
    ObservationProposal,
    SQLiteGraphActionPermitStore,
    SQLiteGraphEventLog,
    SQLiteGraphStore,
    SurfaceProposal,
    graph_node_ref,
    parse_graph_proposal,
)
from pajin.graph.sqlite_store import (
    GovernedGraphDatabaseAuthority,
    _event_bytes,
    _events_from_connection,
    _node_bytes,
    _node_from_row,
    _require_exact_node_index,
    _validate_schema,
    _write_transaction,
    _writer_identity,
)
from pajin.reporting import escape_markdown_text, markdown_code_span
from pajin.reporting.sarif import (
    VerifiedSarifExport,
    load_verified_sarif_export,
)
from pajin.runtime.pinned_sqlite import PinnedSQLitePublication
from pajin.runtime.pinned_workspace import pinned_workspace_relative_path
from pajin.runtime.safe_files import load_bounded_strict_json, read_bounded_regular_bytes
from pajin.runtime.store import RunStore
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignResult,
    LocalWebAssessmentRunReference,
    local_web_assessment_run_reference,
)
from pajin.web_assessment.governed_gateway import (
    WebGatewayCompletedActionAuthority,
    WebGatewayCompletionReceipt,
    consume_web_gateway_completed_action_pair,
    verify_consumed_web_gateway_completed_action_pair,
)
from pajin.web_assessment.governed_models import (
    WebAssessmentCapabilityGrantConsumptionReceipt,
    WebAssessmentCapabilityGrantConsumptionStore,
)
from pajin.web_assessment.governed_worker import (
    HostLoopbackBrowserWorkerBackend,
    SignedWebWorkerActionEvidence,
    WebWorkerCompletedActionRecord,
    WebWorkerRole,
    WebWorkerTrustRegistry,
    verify_independent_web_worker_evidence,
)
from pajin.web_assessment.models import AssessmentIssue, IssueCheck, IssueStatus, local_origin
from pajin.web_assessment.verification import (
    load_verified_local_web_assessment_source_integrity,
)
from pajin.workflow.confirmation import decide_replay_confirmation
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    ValidationSnapshotSemantics,
    load_validation_snapshot,
    write_validation_artifacts,
)

GOVERNED_WEB_EXECUTION_EVIDENCE_API_VERSION: Final[
    Literal["pajin.dev/governed-web-execution-evidence/v1alpha1"]
] = "pajin.dev/governed-web-execution-evidence/v1alpha1"
GOVERNED_WEB_PROMOTION_API_VERSION: Final[Literal["pajin.dev/governed-web-promotion/v1alpha1"]] = (
    "pajin.dev/governed-web-promotion/v1alpha1"
)
GOVERNED_WEB_DELIVERY_MANIFEST_API_VERSION: Final[
    Literal["pajin.dev/governed-web-delivery-manifest/v1alpha1"]
] = "pajin.dev/governed-web-delivery-manifest/v1alpha1"
GOVERNED_WEB_POC_API_VERSION: Final[Literal["pajin.dev/governed-web-redacted-poc/v1alpha1"]] = (
    "pajin.dev/governed-web-redacted-poc/v1alpha1"
)
GOVERNED_WEB_EXECUTION_VERIFIER_ID: Final = "pajin.web.governed-worker-evidence-verifier"
GOVERNED_WEB_EXECUTION_VERIFIER_VERSION: Final = "1.0.0"
GOVERNED_WEB_GRAPH_PRODUCER_ID: Final = "pajin.web.governed-reporting"
GOVERNED_WEB_GRAPH_PRODUCER_VERSION: Final = "1.0.0"
GOVERNED_WEB_GRAPH_AGENT_ID: Final = "agent:web-governed-reporting"
GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID: Final = "pajin.graph.governed-web-admission-authority"
GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_VERSION: Final = "1.0.0"

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_PORTABLE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"
_ADAPTER_REF_PATTERN = r"^[a-z0-9][a-z0-9._/-]{2,199}$"
_MAX_CANONICAL_BYTES = 8 * 1024 * 1024
_MAX_DELIVERY_MANIFEST_BYTES = 64 * 1024
_MAX_POC_MANIFEST_BYTES = 128 * 1024
_ARTIFACT_REFERENCE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,399}$"

_CHECK_COMPONENT: Final[dict[IssueCheck, str]] = {
    "sql-login": "authentication boundary",
    "object-access": "authenticated object retrieval",
    "dom-xss": "search-route DOM rendering",
}
_CHECK_ROOT_CAUSE: Final[dict[IssueCheck, str]] = {
    "sql-login": "Login input reaches a query predicate without parameterization.",
    "object-access": "Object retrieval is not bound to authenticated ownership.",
    "dom-xss": "Search-route data reaches executable DOM interpretation.",
}
_CHECK_CANONICAL_CWE: Final[dict[IssueCheck, str]] = {
    "sql-login": "CWE-89",
    "object-access": "CWE-639",
    "dom-xss": "CWE-79",
}
_CHECK_CANONICAL_SEVERITY: Final[dict[IssueCheck, Literal["high", "medium"]]] = {
    "sql-login": "high",
    "object-access": "high",
    "dom-xss": "medium",
}
_CHECK_CANONICAL_POTENTIAL_IMPACT: Final[dict[IssueCheck, str]] = {
    "sql-login": (
        "An unauthenticated attacker could impersonate a privileged account and reach data "
        "or actions exposed to that account."
    ),
    "object-access": (
        "An attacker with any accepted session could enumerate basket identifiers and disclose "
        "other customers' cart contents."
    ),
    "dom-xss": (
        "A victim following a crafted URL could run attacker-controlled script with the "
        "application origin's browser privileges."
    ),
}
_CHECK_CANONICAL_REMEDIATION: Final[dict[IssueCheck, str]] = {
    "sql-login": (
        "Use parameterized queries for credential lookup, reject authentication input that "
        "changes query structure, and add true/false-condition regression tests."
    ),
    "object-access": (
        "Resolve basket ownership from the authenticated principal instead of a caller-supplied "
        "identifier, and deny every cross-owner object lookup."
    ),
    "dom-xss": (
        "Render search terms as text, remove unsafe HTML sinks, and enforce a restrictive "
        "Content Security Policy without unsafe inline execution."
    ),
}
_CHECK_HYPOTHESIS: Final[dict[IssueCheck, tuple[str, str, str]]] = {
    "sql-login": (
        "web.sql-login-boundary",
        "Controlled login input may bypass the authentication boundary.",
        "A true-condition trial establishes a session while its false control is rejected.",
    ),
    "object-access": (
        "web.object-ownership-boundary",
        "An authenticated session may retrieve another disposable account's object.",
        "The target object is returned while own-object and missing-object controls pass.",
    ),
    "dom-xss": (
        "web.same-origin-dom-execution",
        "A crafted search route may execute script in the application origin.",
        "Only the controlled probe sets its same-origin DOM marker.",
    ),
}


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


def _canonical_digest(domain: str, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > _MAX_CANONICAL_BYTES:
        raise ValueError("governed WEB canonical material exceeds its byte limit")
    return sha256(domain.encode("ascii") + b"\x00" + encoded).hexdigest()


GOVERNED_WEB_GRAPH_PRODUCER_DIGEST: Final = _canonical_digest(
    "pajin.web.governed-graph-producer/v1",
    {
        "producerId": GOVERNED_WEB_GRAPH_PRODUCER_ID,
        "producerVersion": GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
        "proposalKinds": (
            "CampaignFactProposal",
            "HypothesisProposal",
            "ObservationProposal",
            "SurfaceProposal",
        ),
    },
)
GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST: Final = _canonical_digest(
    "pajin.web.governed-graph-admission-authority/v1",
    {
        "authorityId": GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
        "authorityVersion": GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_VERSION,
        "producerDigest": GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
        "lineageAuthority": "durable-approved-action-permit-receipt",
    },
)


def governed_web_execution_verifier_digest(registry: WebWorkerTrustRegistry) -> str:
    """Bind the code-owned verifier implementation to one deployment trust registry."""

    if type(registry) is not WebWorkerTrustRegistry:
        raise TypeError("governed WEB verifier requires a WebWorkerTrustRegistry")
    return _canonical_digest(
        "pajin.web.governed-execution-verifier/v1",
        {
            "verifierId": GOVERNED_WEB_EXECUTION_VERIFIER_ID,
            "verifierVersion": GOVERNED_WEB_EXECUTION_VERIFIER_VERSION,
            "workerTrustRegistryDigest": registry.digest,
        },
    )


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires an explicit UTC offset")
    return value.astimezone(UTC)


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


_VERIFIER_BINDING_FACTORY_TOKEN = object()
_PROMOTION_AUTHORITY_FACTORY_TOKEN = object()
_GRAPH_AUTHORITY_FACTORY_TOKEN = object()
_GRAPH_ADMISSION_AUTHORITY_FACTORY_TOKEN = object()
_VALIDATION_AUTHORITY_FACTORY_TOKEN = object()


class _ImmutableAuthority:
    """Reject ordinary post-factory mutation of process-local authority handles."""

    __slots__ = ("__authority_frozen",)

    def __setattr__(self, name: str, value: object) -> None:
        try:
            frozen = object.__getattribute__(self, "_ImmutableAuthority__authority_frozen")
        except AttributeError:
            frozen = False
        if frozen:
            raise AttributeError("governed WEB authority handles are immutable")
        object.__setattr__(self, name, value)

    def _freeze_authority(self) -> None:
        object.__setattr__(self, "_ImmutableAuthority__authority_frozen", True)

    def __copy__(self) -> Never:
        raise TypeError("governed WEB authority handles cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> Never:
        raise TypeError("governed WEB authority handles cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("governed WEB authority handles cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("governed WEB authority handles cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("governed WEB authority handles cannot be serialized")


class GovernedWebExecutionEvidence(_FrozenStrictModel):
    """Exact authority and independent-execution pins consumed by promotion."""

    api_version: Literal["pajin.dev/governed-web-execution-evidence/v1alpha1"] = Field(
        default=GOVERNED_WEB_EXECUTION_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GovernedWebExecutionEvidence"] = "GovernedWebExecutionEvidence"
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    campaign_id: str = Field(
        alias="campaignId",
        pattern=r"^[a-z0-9][a-z0-9-]{2,79}$",
    )
    campaign_manifest_digest: str = Field(alias="campaignManifestDigest", pattern=_SHA256_PATTERN)
    source_capability_grant_id: str = Field(
        alias="sourceCapabilityGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_capability_grant_digest: str = Field(
        alias="sourceCapabilityGrantDigest",
        pattern=_SHA256_PATTERN,
    )
    source_capability_grant_consumption_receipt_id: str = Field(
        alias="sourceCapabilityGrantConsumptionReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_capability_grant_consumption_receipt_digest: str = Field(
        alias="sourceCapabilityGrantConsumptionReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_capability_grant_id: str = Field(
        alias="validationCapabilityGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_capability_grant_digest: str = Field(
        alias="validationCapabilityGrantDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_capability_grant_consumption_receipt_id: str = Field(
        alias="validationCapabilityGrantConsumptionReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_capability_grant_consumption_receipt_digest: str = Field(
        alias="validationCapabilityGrantConsumptionReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    capability_grant_authority_digest: str = Field(
        alias="capabilityGrantAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    capability_id: str = Field(alias="capabilityId", pattern=_IDENTIFIER_PATTERN)
    capability_version: str = Field(alias="capabilityVersion", pattern=_IDENTIFIER_PATTERN)
    capability_digest: str = Field(alias="capabilityDigest", pattern=_SHA256_PATTERN)
    adapter_ref: str = Field(alias="adapterRef", pattern=_ADAPTER_REF_PATTERN)
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    account_receipt_digest: str = Field(alias="accountReceiptDigest", pattern=_SHA256_PATTERN)
    worker_trust_registry_digest: str = Field(
        alias="workerTrustRegistryDigest",
        pattern=_SHA256_PATTERN,
    )
    execution_verifier_id: Literal["pajin.web.governed-worker-evidence-verifier"] = Field(
        default=GOVERNED_WEB_EXECUTION_VERIFIER_ID,
        alias="executionVerifierId",
    )
    execution_verifier_digest: str = Field(
        alias="executionVerifierDigest",
        pattern=_SHA256_PATTERN,
    )
    source_action_permit_id: str = Field(
        alias="sourceActionPermitId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_action_permit_digest: str = Field(
        alias="sourceActionPermitDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_action_permit_id: str = Field(
        alias="validationActionPermitId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_action_permit_digest: str = Field(
        alias="validationActionPermitDigest",
        pattern=_SHA256_PATTERN,
    )
    source_approval_id: str = Field(alias="sourceApprovalId", pattern=_IDENTIFIER_PATTERN)
    source_approval_digest: str = Field(
        alias="sourceApprovalDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_approval_id: str = Field(
        alias="validationApprovalId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_approval_digest: str = Field(
        alias="validationApprovalDigest",
        pattern=_SHA256_PATTERN,
    )
    source_approval_receipt_id: str = Field(
        alias="sourceApprovalReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_approval_receipt_digest: str = Field(
        alias="sourceApprovalReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_approval_receipt_id: str = Field(
        alias="validationApprovalReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_approval_receipt_digest: str = Field(
        alias="validationApprovalReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_request_id: str = Field(
        alias="sourceGatewayRequestId",
        pattern=_PORTABLE_IDENTIFIER_PATTERN,
    )
    source_gateway_request_digest: str = Field(
        alias="sourceGatewayRequestDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_request_id: str = Field(
        alias="validationGatewayRequestId",
        pattern=_PORTABLE_IDENTIFIER_PATTERN,
    )
    validation_gateway_request_digest: str = Field(
        alias="validationGatewayRequestDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_audit_run_id: str = Field(
        alias="sourceGatewayAuditRunId",
        pattern=_RUN_ID_PATTERN,
    )
    validation_gateway_audit_run_id: str = Field(
        alias="validationGatewayAuditRunId",
        pattern=_RUN_ID_PATTERN,
    )
    source_gateway_audit_pre_receipt_root_digest: str = Field(
        alias="sourceGatewayAuditPreReceiptRootDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_audit_pre_receipt_root_digest: str = Field(
        alias="validationGatewayAuditPreReceiptRootDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_audit_pre_receipt_event_head_digest: str = Field(
        alias="sourceGatewayAuditPreReceiptEventHeadDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_audit_pre_receipt_event_head_digest: str = Field(
        alias="validationGatewayAuditPreReceiptEventHeadDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_audit_final_root_digest: str = Field(
        alias="sourceGatewayAuditFinalRootDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_audit_final_root_digest: str = Field(
        alias="validationGatewayAuditFinalRootDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_audit_final_event_head_digest: str = Field(
        alias="sourceGatewayAuditFinalEventHeadDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_audit_final_event_head_digest: str = Field(
        alias="validationGatewayAuditFinalEventHeadDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_completion_receipt_id: str = Field(
        alias="sourceGatewayCompletionReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_gateway_completion_receipt_id: str = Field(
        alias="validationGatewayCompletionReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_gateway_completion_receipt_digest: str = Field(
        alias="sourceGatewayCompletionReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_completion_receipt_digest: str = Field(
        alias="validationGatewayCompletionReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_completion_receipt_reference: str = Field(
        alias="sourceGatewayCompletionReceiptReference",
        pattern=_ARTIFACT_REFERENCE_PATTERN,
    )
    validation_gateway_completion_receipt_reference: str = Field(
        alias="validationGatewayCompletionReceiptReference",
        pattern=_ARTIFACT_REFERENCE_PATTERN,
    )
    source_gateway_completion_authority_digest: str = Field(
        alias="sourceGatewayCompletionAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_completion_authority_digest: str = Field(
        alias="validationGatewayCompletionAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_launch_id: str = Field(
        alias="sourceGatewayLaunchId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_gateway_launch_id: str = Field(
        alias="validationGatewayLaunchId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_gateway_evidence_reference: str = Field(
        alias="sourceGatewayEvidenceReference",
        pattern=_ARTIFACT_REFERENCE_PATTERN,
    )
    validation_gateway_evidence_reference: str = Field(
        alias="validationGatewayEvidenceReference",
        pattern=_ARTIFACT_REFERENCE_PATTERN,
    )
    source_gateway_evidence_digest: str = Field(
        alias="sourceGatewayEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_evidence_digest: str = Field(
        alias="validationGatewayEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_request_reservation_reference: str = Field(
        alias="sourceGatewayRequestReservationReference",
        pattern=_ARTIFACT_REFERENCE_PATTERN,
    )
    validation_gateway_request_reservation_reference: str = Field(
        alias="validationGatewayRequestReservationReference",
        pattern=_ARTIFACT_REFERENCE_PATTERN,
    )
    source_gateway_request_reservation_digest: str = Field(
        alias="sourceGatewayRequestReservationDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_request_reservation_digest: str = Field(
        alias="validationGatewayRequestReservationDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_worker_result_digest: str = Field(
        alias="sourceGatewayWorkerResultDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_worker_result_digest: str = Field(
        alias="validationGatewayWorkerResultDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_tool_result_digest: str = Field(
        alias="sourceGatewayToolResultDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_tool_result_digest: str = Field(
        alias="validationGatewayToolResultDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_policy_decision_digest: str = Field(
        alias="sourceGatewayPolicyDecisionDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_policy_decision_digest: str = Field(
        alias="validationGatewayPolicyDecisionDigest",
        pattern=_SHA256_PATTERN,
    )
    source_gateway_outcome_digest: str = Field(
        alias="sourceGatewayOutcomeDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_gateway_outcome_digest: str = Field(
        alias="validationGatewayOutcomeDigest",
        pattern=_SHA256_PATTERN,
    )
    target_origin: str = Field(alias="targetOrigin")
    target_identity_digest: str = Field(alias="targetIdentityDigest", pattern=_SHA256_PATTERN)
    source_authorization_id: str = Field(
        alias="sourceAuthorizationId",
        min_length=1,
        max_length=200,
    )
    validation_authorization_id: str = Field(
        alias="validationAuthorizationId",
        min_length=1,
        max_length=200,
    )
    source_run_id: str = Field(alias="sourceRunId", pattern=_RUN_ID_PATTERN)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_SHA256_PATTERN)
    source_result_digest: str = Field(alias="sourceResultDigest", pattern=_SHA256_PATTERN)
    validation_run_id: str = Field(alias="validationRunId", pattern=_RUN_ID_PATTERN)
    validation_root_digest: str = Field(alias="validationRootDigest", pattern=_SHA256_PATTERN)
    validation_result_digest: str = Field(
        alias="validationResultDigest",
        pattern=_SHA256_PATTERN,
    )
    source_executor_process_id: int = Field(alias="sourceExecutorProcessId", ge=1, strict=True)
    validation_executor_process_id: int = Field(
        alias="validationExecutorProcessId",
        ge=1,
        strict=True,
    )
    source_observer_process_id: int = Field(alias="sourceObserverProcessId", ge=1, strict=True)
    validation_observer_process_id: int = Field(
        alias="validationObserverProcessId",
        ge=1,
        strict=True,
    )
    source_executor_key_id: str = Field(
        alias="sourceExecutorKeyId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_executor_key_id: str = Field(
        alias="validationExecutorKeyId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_executor_execution_id: str = Field(
        alias="sourceExecutorExecutionId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_executor_execution_id: str = Field(
        alias="validationExecutorExecutionId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_execution_attestation_digest: str = Field(
        alias="sourceExecutionAttestationDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_execution_attestation_digest: str = Field(
        alias="validationExecutionAttestationDigest",
        pattern=_SHA256_PATTERN,
    )
    source_executor_signature_verified: Literal[True] = Field(
        default=True,
        alias="sourceExecutorSignatureVerified",
    )
    validation_executor_signature_verified: Literal[True] = Field(
        default=True,
        alias="validationExecutorSignatureVerified",
    )
    source_observer_key_id: str = Field(alias="sourceObserverKeyId", pattern=_IDENTIFIER_PATTERN)
    validation_observer_key_id: str = Field(
        alias="validationObserverKeyId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_observer_execution_id: str = Field(
        alias="sourceObserverExecutionId",
        pattern=_IDENTIFIER_PATTERN,
    )
    validation_observer_execution_id: str = Field(
        alias="validationObserverExecutionId",
        pattern=_IDENTIFIER_PATTERN,
    )
    source_target_attestation_digest: str = Field(
        alias="sourceTargetAttestationDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_target_attestation_digest: str = Field(
        alias="validationTargetAttestationDigest",
        pattern=_SHA256_PATTERN,
    )
    source_worker_action_evidence_digest: str = Field(
        alias="sourceWorkerActionEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_worker_action_evidence_digest: str = Field(
        alias="validationWorkerActionEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    source_worker_completion_digest: str = Field(
        alias="sourceWorkerCompletionDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_worker_completion_digest: str = Field(
        alias="validationWorkerCompletionDigest",
        pattern=_SHA256_PATTERN,
    )
    source_target_signature_verified: Literal[True] = Field(
        default=True,
        alias="sourceTargetSignatureVerified",
    )
    validation_target_signature_verified: Literal[True] = Field(
        default=True,
        alias="validationTargetSignatureVerified",
    )
    source_completed_at: datetime = Field(alias="sourceCompletedAt")
    validation_completed_at: datetime = Field(alias="validationCompletedAt")
    source_gateway_completed_at: datetime = Field(alias="sourceGatewayCompletedAt")
    validation_gateway_completed_at: datetime = Field(alias="validationGatewayCompletedAt")
    completed_at: datetime = Field(alias="completedAt")

    @field_validator(
        "source_completed_at",
        "validation_completed_at",
        "source_gateway_completed_at",
        "validation_gateway_completed_at",
        "completed_at",
    )
    @classmethod
    def normalize_completed_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="governed WEB execution completion time")

    @field_validator("target_origin")
    @classmethod
    def require_loopback_target_origin(cls, value: str) -> str:
        return local_origin(value)

    @field_validator(
        "source_executor_signature_verified",
        "validation_executor_signature_verified",
        "source_target_signature_verified",
        "validation_target_signature_verified",
        mode="before",
    )
    @classmethod
    def require_verified_marker(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("governed WEB promotion requires every signature verification")
        return value

    @model_validator(mode="after")
    def bind_independent_execution(self) -> Self:
        distinct_pairs: tuple[tuple[object, object, str], ...] = (
            (self.source_authorization_id, self.validation_authorization_id, "authorizations"),
            (
                self.source_capability_grant_id,
                self.validation_capability_grant_id,
                "Capability Grants",
            ),
            (
                self.source_capability_grant_digest,
                self.validation_capability_grant_digest,
                "Capability Grant digests",
            ),
            (
                self.source_capability_grant_consumption_receipt_id,
                self.validation_capability_grant_consumption_receipt_id,
                "Capability Grant consumption receipts",
            ),
            (
                self.source_capability_grant_consumption_receipt_digest,
                self.validation_capability_grant_consumption_receipt_digest,
                "Capability Grant consumption receipt digests",
            ),
            (
                self.source_action_permit_id,
                self.validation_action_permit_id,
                "ActionPermits",
            ),
            (
                self.source_action_permit_digest,
                self.validation_action_permit_digest,
                "ActionPermit digests",
            ),
            (self.source_approval_id, self.validation_approval_id, "Approvals"),
            (
                self.source_approval_digest,
                self.validation_approval_digest,
                "Approval digests",
            ),
            (
                self.source_approval_receipt_id,
                self.validation_approval_receipt_id,
                "Approval receipts",
            ),
            (
                self.source_approval_receipt_digest,
                self.validation_approval_receipt_digest,
                "Approval receipt digests",
            ),
            (
                self.source_gateway_request_id,
                self.validation_gateway_request_id,
                "Gateway requests",
            ),
            (
                self.source_gateway_request_digest,
                self.validation_gateway_request_digest,
                "Gateway request digests",
            ),
            (
                self.source_gateway_audit_run_id,
                self.validation_gateway_audit_run_id,
                "Gateway audit Run IDs",
            ),
            (
                self.source_gateway_audit_pre_receipt_root_digest,
                self.validation_gateway_audit_pre_receipt_root_digest,
                "Gateway pre-receipt roots",
            ),
            (
                self.source_gateway_audit_pre_receipt_event_head_digest,
                self.validation_gateway_audit_pre_receipt_event_head_digest,
                "Gateway pre-receipt Event heads",
            ),
            (
                self.source_gateway_audit_final_root_digest,
                self.validation_gateway_audit_final_root_digest,
                "Gateway final roots",
            ),
            (
                self.source_gateway_audit_final_event_head_digest,
                self.validation_gateway_audit_final_event_head_digest,
                "Gateway final Event heads",
            ),
            (
                self.source_gateway_completion_receipt_id,
                self.validation_gateway_completion_receipt_id,
                "Gateway completion receipts",
            ),
            (
                self.source_gateway_completion_receipt_digest,
                self.validation_gateway_completion_receipt_digest,
                "Gateway completion receipt digests",
            ),
            (
                self.source_gateway_completion_authority_digest,
                self.validation_gateway_completion_authority_digest,
                "Gateway completion authorities",
            ),
            (
                self.source_gateway_launch_id,
                self.validation_gateway_launch_id,
                "Gateway launch IDs",
            ),
            (
                self.source_gateway_evidence_digest,
                self.validation_gateway_evidence_digest,
                "Gateway Evidence digests",
            ),
            (
                self.source_gateway_request_reservation_digest,
                self.validation_gateway_request_reservation_digest,
                "Gateway request reservation digests",
            ),
            (
                self.source_gateway_worker_result_digest,
                self.validation_gateway_worker_result_digest,
                "Gateway Worker-result digests",
            ),
            (
                self.source_gateway_tool_result_digest,
                self.validation_gateway_tool_result_digest,
                "Gateway Tool-result digests",
            ),
            (
                self.source_gateway_outcome_digest,
                self.validation_gateway_outcome_digest,
                "Gateway outcome digests",
            ),
            (self.source_run_id, self.validation_run_id, "Run IDs"),
            (self.source_root_digest, self.validation_root_digest, "Run roots"),
            (self.source_result_digest, self.validation_result_digest, "Result digests"),
            (
                self.source_executor_process_id,
                self.validation_executor_process_id,
                "executor process IDs",
            ),
            (self.source_executor_key_id, self.validation_executor_key_id, "executor keys"),
            (
                self.source_execution_attestation_digest,
                self.validation_execution_attestation_digest,
                "execution attestations",
            ),
            (
                self.source_target_attestation_digest,
                self.validation_target_attestation_digest,
                "target attestations",
            ),
            (
                self.source_worker_action_evidence_digest,
                self.validation_worker_action_evidence_digest,
                "Worker action evidence",
            ),
            (
                self.source_worker_completion_digest,
                self.validation_worker_completion_digest,
                "Worker completion authorities",
            ),
        )
        for source_value, validation_value, label in distinct_pairs:
            if source_value == validation_value:
                raise ValueError(f"governed WEB source and validation require distinct {label}")
        process_ids = {
            self.source_executor_process_id,
            self.validation_executor_process_id,
            self.source_observer_process_id,
            self.validation_observer_process_id,
        }
        key_ids = {
            self.source_executor_key_id,
            self.validation_executor_key_id,
            self.source_observer_key_id,
            self.validation_observer_key_id,
        }
        execution_ids = {
            self.source_executor_execution_id,
            self.validation_executor_execution_id,
            self.source_observer_execution_id,
            self.validation_observer_execution_id,
        }
        if len(process_ids) != 4 or len(key_ids) != 4 or len(execution_ids) != 4:
            raise ValueError(
                "governed WEB promotion requires four distinct process, key, and execution IDs"
            )
        if len(
            {
                self.source_run_id,
                self.validation_run_id,
                self.source_gateway_audit_run_id,
                self.validation_gateway_audit_run_id,
            }
        ) != 4:
            raise ValueError(
                "governed WEB promotion requires distinct browser and Gateway audit Runs"
            )
        if (
            self.source_gateway_completed_at < self.source_completed_at
            or self.validation_gateway_completed_at < self.validation_completed_at
            or self.completed_at
            != max(self.source_gateway_completed_at, self.validation_gateway_completed_at)
        ):
            raise ValueError("governed WEB aggregate completion differs from its Gateway receipts")
        expected_verifier_digest = _canonical_digest(
            "pajin.web.governed-execution-verifier/v1",
            {
                "verifierId": self.execution_verifier_id,
                "verifierVersion": GOVERNED_WEB_EXECUTION_VERIFIER_VERSION,
                "workerTrustRegistryDigest": self.worker_trust_registry_digest,
            },
        )
        if self.execution_verifier_digest != expected_verifier_digest:
            raise ValueError("governed WEB execution verifier binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_digest"},
        )
        expected = _canonical_digest("pajin.web.governed-execution-evidence/v1", material)
        if self.evidence_digest and self.evidence_digest != expected:
            raise ValueError("governed WEB execution Evidence Digest differs")
        object.__setattr__(self, "evidence_digest", expected)
        return self


class GovernedWebExecutionVerification(_FrozenStrictModel):
    """Trusted verifier output bound to one exact execution-evidence object."""

    verifier_id: str = Field(alias="verifierId", pattern=_IDENTIFIER_PATTERN)
    verifier_digest: str = Field(alias="verifierDigest", pattern=_SHA256_PATTERN)
    evidence_digest: str = Field(alias="evidenceDigest", pattern=_SHA256_PATTERN)
    source_execution_signature_valid: Literal[True] = Field(
        default=True,
        alias="sourceExecutionSignatureValid",
    )
    validation_execution_signature_valid: Literal[True] = Field(
        default=True,
        alias="validationExecutionSignatureValid",
    )
    source_target_signature_valid: Literal[True] = Field(
        default=True,
        alias="sourceTargetSignatureValid",
    )
    validation_target_signature_valid: Literal[True] = Field(
        default=True,
        alias="validationTargetSignatureValid",
    )
    verified_at: datetime = Field(alias="verifiedAt")

    @field_validator("verified_at")
    @classmethod
    def normalize_verified_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="governed WEB attestation verification time")

    @field_validator(
        "source_execution_signature_valid",
        "validation_execution_signature_valid",
        "source_target_signature_valid",
        "validation_target_signature_valid",
        mode="before",
    )
    @classmethod
    def require_valid_signature(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("governed WEB verifier rejected an attestation signature")
        return value


@final
class GovernedWebExecutionVerifierBinding(_ImmutableAuthority):
    """Factory-only verifier bound to the exact deployment Worker backend."""

    __slots__ = (
        "_grant_consumption_store",
        "_registry",
        "_source_action_evidence",
        "_source_completion",
        "_source_gateway_authority_digest",
        "_source_gateway_completion_authority",
        "_source_gateway_final_event_head",
        "_source_gateway_final_root_digest",
        "_source_gateway_receipt",
        "_source_gateway_receipt_reference",
        "_source_gateway_run_path",
        "_validation_action_evidence",
        "_validation_completion",
        "_validation_gateway_authority_digest",
        "_validation_gateway_completion_authority",
        "_validation_gateway_final_event_head",
        "_validation_gateway_final_root_digest",
        "_validation_gateway_receipt",
        "_validation_gateway_receipt_reference",
        "_validation_gateway_run_path",
        "_worker_backend",
    )

    def __init__(
        self,
        *,
        _factory_token: object,
        worker_backend: HostLoopbackBrowserWorkerBackend,
        grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore,
        source_gateway_completion: WebGatewayCompletedActionAuthority,
        validation_gateway_completion: WebGatewayCompletedActionAuthority,
    ) -> None:
        if _factory_token is not _VERIFIER_BINDING_FACTORY_TOKEN:
            raise TypeError(
                "governed WEB verifier binding can only be created by its code-owned factory"
            )
        if type(worker_backend) is not HostLoopbackBrowserWorkerBackend:
            raise TypeError(
                "governed WEB verifier requires the exact deployment Worker backend"
            )
        registry = worker_backend.trust_registry
        if type(grant_consumption_store) is not WebAssessmentCapabilityGrantConsumptionStore:
            raise TypeError("governed WEB verifier requires the exact durable Grant store")
        if type(registry) is not WebWorkerTrustRegistry:
            raise TypeError("governed WEB Worker backend has no canonical trust registry")
        if (
            type(source_gateway_completion) is not WebGatewayCompletedActionAuthority
            or type(validation_gateway_completion) is not WebGatewayCompletedActionAuthority
        ):
            raise TypeError("governed WEB verifier requires opaque Gateway completion authorities")
        source_completion = source_gateway_completion.backend_completion
        validation_completion = validation_gateway_completion.backend_completion
        source_record = source_completion.completion
        validation_record = validation_completion.completion
        source_action_evidence = source_completion.action_evidence
        validation_action_evidence = validation_completion.action_evidence
        self._worker_backend = worker_backend
        self._grant_consumption_store = grant_consumption_store
        self._registry = WebWorkerTrustRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        self._source_action_evidence = SignedWebWorkerActionEvidence.model_validate(
            source_action_evidence.model_dump(mode="json", by_alias=True)
        )
        self._source_completion = WebWorkerCompletedActionRecord.model_validate(
            source_record.model_dump(mode="json", by_alias=True)
        )
        self._source_gateway_receipt = WebGatewayCompletionReceipt.model_validate(
            source_gateway_completion.receipt.model_dump(mode="json", by_alias=True)
        )
        self._source_gateway_receipt_reference = source_gateway_completion.receipt_reference
        self._source_gateway_final_root_digest = source_gateway_completion.final_root_digest
        self._source_gateway_final_event_head = source_gateway_completion.final_event_head
        self._source_gateway_authority_digest = source_gateway_completion.authority_digest
        self._source_gateway_completion_authority = source_gateway_completion
        self._source_gateway_run_path = source_gateway_completion.run_path
        self._validation_action_evidence = SignedWebWorkerActionEvidence.model_validate(
            validation_action_evidence.model_dump(mode="json", by_alias=True)
        )
        self._validation_completion = WebWorkerCompletedActionRecord.model_validate(
            validation_record.model_dump(mode="json", by_alias=True)
        )
        self._validation_gateway_receipt = WebGatewayCompletionReceipt.model_validate(
            validation_gateway_completion.receipt.model_dump(mode="json", by_alias=True)
        )
        self._validation_gateway_receipt_reference = validation_gateway_completion.receipt_reference
        self._validation_gateway_final_root_digest = validation_gateway_completion.final_root_digest
        self._validation_gateway_final_event_head = validation_gateway_completion.final_event_head
        self._validation_gateway_authority_digest = validation_gateway_completion.authority_digest
        self._validation_gateway_completion_authority = validation_gateway_completion
        self._validation_gateway_run_path = validation_gateway_completion.run_path
        self._freeze_authority()

    @property
    def registry(self) -> WebWorkerTrustRegistry:
        return self._registry.model_copy(deep=True)

    @property
    def source_action_evidence(self) -> SignedWebWorkerActionEvidence:
        return self._source_action_evidence.model_copy(deep=True)

    @property
    def validation_action_evidence(self) -> SignedWebWorkerActionEvidence:
        return self._validation_action_evidence.model_copy(deep=True)

    @property
    def verifier_id(self) -> str:
        return GOVERNED_WEB_EXECUTION_VERIFIER_ID

    @property
    def verifier_digest(self) -> str:
        return governed_web_execution_verifier_digest(self._registry)

    def _validated_gateway_run_paths(self) -> tuple[Path, Path]:
        """Reload the exact consumed Gateway authorities and return their pinned Runs."""

        verify_consumed_web_gateway_completed_action_pair(
            expected_backend=self._worker_backend,
            source=self._source_gateway_completion_authority,
            validation=self._validation_gateway_completion_authority,
        )
        source_path = self._source_gateway_completion_authority.run_path
        validation_path = self._validation_gateway_completion_authority.run_path
        if (
            source_path != self._source_gateway_run_path
            or validation_path != self._validation_gateway_run_path
        ):
            raise ValueError("governed WEB Gateway Run path differs from its factory binding")
        return source_path, validation_path

    def verify(
        self,
        evidence: GovernedWebExecutionEvidence,
        *,
        source: LocalWebAssessmentRunReference,
        validation: LocalWebAssessmentRunReference,
    ) -> GovernedWebExecutionVerification:
        """Cryptographically verify and bind all four observer/executor statements."""

        if type(evidence) is not GovernedWebExecutionEvidence:
            raise TypeError("governed WEB verifier requires canonical execution Evidence")
        _require_unshadowed_methods(
            self._worker_backend,
            ("require_authoritative_completion_profile",),
            label="Worker completion backend",
        )
        HostLoopbackBrowserWorkerBackend.require_authoritative_completion_profile(
            self._worker_backend
        )
        self._validated_gateway_run_paths()
        if (
            evidence.execution_verifier_id != self.verifier_id
            or evidence.execution_verifier_digest != self.verifier_digest
            or evidence.worker_trust_registry_digest != self._registry.digest
            or self._worker_backend.trust_registry.digest != self._registry.digest
        ):
            raise ValueError("governed WEB verifier or trust-registry binding differs")
        trusted_now = _normalize_utc(
            _system_utc_now(),
            label="governed WEB verifier trusted clock",
        )
        _require_current_worker_registry(self._registry, trusted_now=trusted_now)
        verified = verify_independent_web_worker_evidence(
            source_target=self._source_action_evidence.target_identity,
            source=self._source_action_evidence.execution_attestation,
            validation_target=self._validation_action_evidence.target_identity,
            validation=self._validation_action_evidence.execution_attestation,
            registry=self._registry,
            verification_time=trusted_now,
        )
        _require_governed_web_worker_action_binding(
            evidence=evidence,
            source=source,
            validation=validation,
            source_action=self._source_action_evidence,
            validation_action=self._validation_action_evidence,
            verified_process_ids=verified.process_ids,
            verified_key_ids=verified.key_ids,
            verified_execution_ids=verified.execution_ids,
            verified_registry_digest=verified.trust_registry_digest,
        )
        _require_governed_web_worker_completion_binding(
            evidence=evidence,
            source=self._source_completion,
            validation=self._validation_completion,
            source_action=self._source_action_evidence,
            validation_action=self._validation_action_evidence,
        )
        _require_governed_web_gateway_completion_binding(
            evidence=evidence,
            source=self._source_gateway_receipt,
            validation=self._validation_gateway_receipt,
            source_receipt_reference=self._source_gateway_receipt_reference,
            validation_receipt_reference=self._validation_gateway_receipt_reference,
            source_final_root_digest=self._source_gateway_final_root_digest,
            validation_final_root_digest=self._validation_gateway_final_root_digest,
            source_final_event_head=self._source_gateway_final_event_head,
            validation_final_event_head=self._validation_gateway_final_event_head,
            source_authority_digest=self._source_gateway_authority_digest,
            validation_authority_digest=self._validation_gateway_authority_digest,
        )
        _require_governed_web_grant_consumption_bindings(
            evidence,
            self._grant_consumption_store,
        )
        latest_statement = max(
            self._source_action_evidence.target_identity.statement.issued_at,
            self._source_action_evidence.execution_attestation.statement.issued_at,
            self._validation_action_evidence.target_identity.statement.issued_at,
            self._validation_action_evidence.execution_attestation.statement.issued_at,
        )
        if trusted_now < latest_statement:
            raise ValueError("governed WEB verification predates a signed statement")
        return GovernedWebExecutionVerification(
            verifierId=self.verifier_id,
            verifierDigest=self.verifier_digest,
            evidenceDigest=evidence.evidence_digest,
            verifiedAt=trusted_now,
        )


def create_governed_web_execution_verifier_binding(
    *,
    worker_backend: HostLoopbackBrowserWorkerBackend,
    grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore,
    source_gateway_completion: WebGatewayCompletedActionAuthority,
    validation_gateway_completion: WebGatewayCompletedActionAuthority,
) -> GovernedWebExecutionVerifierBinding:
    """Consume two sealed Gateway completions and bind their signed Worker evidence."""

    if type(worker_backend) is not HostLoopbackBrowserWorkerBackend:
        raise TypeError("governed WEB verifier requires the exact deployment Worker backend")
    if type(grant_consumption_store) is not WebAssessmentCapabilityGrantConsumptionStore:
        raise TypeError("governed WEB verifier requires the exact durable Grant store")
    _require_unshadowed_methods(
        grant_consumption_store,
        ("receipt_for_grant", "_require_exact_runtime"),
        label="durable Grant consumption store",
    )
    WebAssessmentCapabilityGrantConsumptionStore._require_exact_runtime(
        grant_consumption_store
    )
    consumed_source, consumed_validation = consume_web_gateway_completed_action_pair(
        expected_backend=worker_backend,
        source=source_gateway_completion,
        validation=validation_gateway_completion,
    )

    return GovernedWebExecutionVerifierBinding(
        _factory_token=_VERIFIER_BINDING_FACTORY_TOKEN,
        worker_backend=worker_backend,
        grant_consumption_store=grant_consumption_store,
        source_gateway_completion=consumed_source,
        validation_gateway_completion=consumed_validation,
    )


def _require_current_worker_registry(
    registry: WebWorkerTrustRegistry,
    *,
    trusted_now: datetime,
) -> None:
    for role in WebWorkerRole:
        key = registry.active_key(role)
        not_before = _normalize_utc(key.not_before, label="Web Worker key not-before time")
        not_after = (
            _normalize_utc(key.not_after, label="Web Worker key not-after time")
            if key.not_after is not None
            else None
        )
        if trusted_now < not_before or (not_after is not None and trusted_now >= not_after):
            raise ValueError("governed WEB Worker registry key is not currently valid")


def _require_governed_web_worker_action_binding(
    *,
    evidence: GovernedWebExecutionEvidence,
    source: LocalWebAssessmentRunReference,
    validation: LocalWebAssessmentRunReference,
    source_action: SignedWebWorkerActionEvidence,
    validation_action: SignedWebWorkerActionEvidence,
    verified_process_ids: tuple[int, int, int, int],
    verified_key_ids: tuple[str, str, str, str],
    verified_execution_ids: tuple[str, str, str, str],
    verified_registry_digest: str,
) -> None:
    source_target = source_action.target_identity
    source_execution = source_action.execution_attestation
    validation_target = validation_action.target_identity
    validation_execution = validation_action.execution_attestation
    expected_process_ids = (
        evidence.source_observer_process_id,
        evidence.source_executor_process_id,
        evidence.validation_observer_process_id,
        evidence.validation_executor_process_id,
    )
    expected_key_ids = (
        evidence.source_observer_key_id,
        evidence.source_executor_key_id,
        evidence.validation_observer_key_id,
        evidence.validation_executor_key_id,
    )
    expected_execution_ids = (
        evidence.source_observer_execution_id,
        evidence.source_executor_execution_id,
        evidence.validation_observer_execution_id,
        evidence.validation_executor_execution_id,
    )
    if (
        verified_registry_digest != evidence.worker_trust_registry_digest
        or verified_process_ids != expected_process_ids
        or verified_key_ids != expected_key_ids
        or verified_execution_ids != expected_execution_ids
        or source_action.digest != evidence.source_worker_action_evidence_digest
        or validation_action.digest != evidence.validation_worker_action_evidence_digest
        or source_target.digest != evidence.source_target_attestation_digest
        or validation_target.digest != evidence.validation_target_attestation_digest
        or source_execution.digest != evidence.source_execution_attestation_digest
        or validation_execution.digest != evidence.validation_execution_attestation_digest
    ):
        raise ValueError("signed governed WEB Worker identity or attestation differs")
    source_authority = source_execution.statement.authority
    validation_authority = validation_execution.statement.authority
    if (
        source_authority.shared_scope != validation_authority.shared_scope
        or source_target.statement.authority != source_authority
        or validation_target.statement.authority != validation_authority
        or source_authority.campaign_id != evidence.campaign_id
        or source_authority.campaign_digest != evidence.campaign_manifest_digest
        or source_authority.capability_id != evidence.capability_id
        or source_authority.capability_version != evidence.capability_version
        or source_authority.capability_digest != evidence.capability_digest
        or source_authority.adapter_digest != evidence.adapter_digest
        or source_authority.account_receipt_digest != evidence.account_receipt_digest
        or source_authority.target_origin != evidence.target_origin
        or validation_authority.target_origin != evidence.target_origin
        or source_authority.target_origin != source.result.origin
        or source_authority.target_product != source.result.target_product
        or source_authority.target_version != source.result.target_version
        or source_authority.expected_target_fingerprint_digest
        != evidence.target_identity_digest
    ):
        raise ValueError("signed governed WEB Worker authority scope differs")
    if (
        source_authority.capability_grant_id,
        source_authority.capability_grant_digest,
        source_authority.capability_grant_consumption_receipt_id,
        source_authority.capability_grant_consumption_receipt_digest,
        source_authority.request_id,
        source_authority.request_digest,
        source_authority.action_permit_id,
        source_authority.action_permit_digest,
        source_authority.approval_id,
        source_authority.approval_digest,
        source_authority.approval_receipt_id,
        source_authority.approval_receipt_digest,
        source_authority.expected_run_id,
    ) != (
        evidence.source_capability_grant_id,
        evidence.source_capability_grant_digest,
        evidence.source_capability_grant_consumption_receipt_id,
        evidence.source_capability_grant_consumption_receipt_digest,
        evidence.source_gateway_request_id,
        evidence.source_gateway_request_digest,
        evidence.source_action_permit_id,
        evidence.source_action_permit_digest,
        evidence.source_approval_id,
        evidence.source_approval_digest,
        evidence.source_approval_receipt_id,
        evidence.source_approval_receipt_digest,
        evidence.source_run_id,
    ) or (
        validation_authority.capability_grant_id,
        validation_authority.capability_grant_digest,
        validation_authority.capability_grant_consumption_receipt_id,
        validation_authority.capability_grant_consumption_receipt_digest,
        validation_authority.request_id,
        validation_authority.request_digest,
        validation_authority.action_permit_id,
        validation_authority.action_permit_digest,
        validation_authority.approval_id,
        validation_authority.approval_digest,
        validation_authority.approval_receipt_id,
        validation_authority.approval_receipt_digest,
        validation_authority.expected_run_id,
    ) != (
        evidence.validation_capability_grant_id,
        evidence.validation_capability_grant_digest,
        evidence.validation_capability_grant_consumption_receipt_id,
        evidence.validation_capability_grant_consumption_receipt_digest,
        evidence.validation_gateway_request_id,
        evidence.validation_gateway_request_digest,
        evidence.validation_action_permit_id,
        evidence.validation_action_permit_digest,
        evidence.validation_approval_id,
        evidence.validation_approval_digest,
        evidence.validation_approval_receipt_id,
        evidence.validation_approval_receipt_digest,
        evidence.validation_run_id,
    ):
        raise ValueError(
            "signed governed WEB Worker Grant, request, Permit, Approval, or receipt differs"
        )
    if (
        (
            source_execution.statement.run_id,
            source_execution.statement.run_root_digest,
            source_execution.statement.result_digest,
            source_execution.statement.finished_at,
        )
        != (
            source.run_id,
            source.root_digest,
            source.result_digest,
            evidence.source_completed_at,
        )
        or (
            validation_execution.statement.run_id,
            validation_execution.statement.run_root_digest,
            validation_execution.statement.result_digest,
            validation_execution.statement.finished_at,
        )
        != (
            validation.run_id,
            validation.root_digest,
            validation.result_digest,
            evidence.validation_completed_at,
        )
        or source.result.finished_at != evidence.source_completed_at
        or validation.result.finished_at != evidence.validation_completed_at
        or source_target.statement.target_product != source.result.target_product
        or source_target.statement.target_version != source.result.target_version
        or validation_target.statement.target_product != validation.result.target_product
        or validation_target.statement.target_version != validation.result.target_version
    ):
        raise ValueError("signed governed WEB Worker Run, result, or target differs")


def _require_governed_web_worker_completion_binding(
    *,
    evidence: GovernedWebExecutionEvidence,
    source: WebWorkerCompletedActionRecord,
    validation: WebWorkerCompletedActionRecord,
    source_action: SignedWebWorkerActionEvidence,
    validation_action: SignedWebWorkerActionEvidence,
) -> None:
    source_target = source_action.target_identity
    source_execution = source_action.execution_attestation
    validation_target = validation_action.target_identity
    validation_execution = validation_action.execution_attestation
    if (
        source.role is not WebWorkerRole.SOURCE_EXECUTOR
        or validation.role is not WebWorkerRole.VALIDATION_EXECUTOR
        or source.worker_trust_registry_digest != evidence.worker_trust_registry_digest
        or validation.worker_trust_registry_digest != evidence.worker_trust_registry_digest
        or source.completion_digest != evidence.source_worker_completion_digest
        or validation.completion_digest != evidence.validation_worker_completion_digest
        or source.authority != source_execution.statement.authority
        or source.authority != source_target.statement.authority
        or validation.authority != validation_execution.statement.authority
        or validation.authority != validation_target.statement.authority
        or (
            source.gateway_execution_id,
            source.worker_execution_id,
            source.observer_execution_id,
            source.executor_process_id,
            source.observer_process_id,
            source.executor_key_id,
            source.observer_key_id,
        )
        != (
            evidence.source_executor_execution_id,
            evidence.source_executor_execution_id,
            evidence.source_observer_execution_id,
            evidence.source_executor_process_id,
            evidence.source_observer_process_id,
            evidence.source_executor_key_id,
            evidence.source_observer_key_id,
        )
        or (
            validation.gateway_execution_id,
            validation.worker_execution_id,
            validation.observer_execution_id,
            validation.executor_process_id,
            validation.observer_process_id,
            validation.executor_key_id,
            validation.observer_key_id,
        )
        != (
            evidence.validation_executor_execution_id,
            evidence.validation_executor_execution_id,
            evidence.validation_observer_execution_id,
            evidence.validation_executor_process_id,
            evidence.validation_observer_process_id,
            evidence.validation_executor_key_id,
            evidence.validation_observer_key_id,
        )
        or (
            source.target_identity_attestation_digest,
            source.execution_attestation_digest,
            source.worker_action_evidence_digest,
            source.target_identity_digest,
            source.run_id,
            source.run_root_digest,
            source.result_digest,
        )
        != (
            evidence.source_target_attestation_digest,
            evidence.source_execution_attestation_digest,
            evidence.source_worker_action_evidence_digest,
            evidence.target_identity_digest,
            evidence.source_run_id,
            evidence.source_root_digest,
            evidence.source_result_digest,
        )
        or (
            validation.target_identity_attestation_digest,
            validation.execution_attestation_digest,
            validation.worker_action_evidence_digest,
            validation.target_identity_digest,
            validation.run_id,
            validation.run_root_digest,
            validation.result_digest,
        )
        != (
            evidence.validation_target_attestation_digest,
            evidence.validation_execution_attestation_digest,
            evidence.validation_worker_action_evidence_digest,
            evidence.target_identity_digest,
            evidence.validation_run_id,
            evidence.validation_root_digest,
            evidence.validation_result_digest,
        )
        or source.completed_at < evidence.source_completed_at
        or validation.completed_at < evidence.validation_completed_at
    ):
        raise ValueError("governed WEB completed-action authority differs from execution Evidence")


def _require_governed_web_gateway_completion_binding(
    *,
    evidence: GovernedWebExecutionEvidence,
    source: WebGatewayCompletionReceipt,
    validation: WebGatewayCompletionReceipt,
    source_receipt_reference: str,
    validation_receipt_reference: str,
    source_final_root_digest: str,
    validation_final_root_digest: str,
    source_final_event_head: str,
    validation_final_event_head: str,
    source_authority_digest: str,
    validation_authority_digest: str,
) -> None:
    """Exact-bind both sealed ToolGateway audit Runs before any Promotion exists."""

    if (
        source.role != "source"
        or validation.role != "validation"
        or source.authority.request_id != evidence.source_gateway_request_id
        or validation.authority.request_id != evidence.validation_gateway_request_id
        or source.authority.expected_run_id != evidence.source_run_id
        or validation.authority.expected_run_id != evidence.validation_run_id
        or source.authority.capability_grant_id != evidence.source_capability_grant_id
        or validation.authority.capability_grant_id != evidence.validation_capability_grant_id
        or source.authority.action_permit_id != evidence.source_action_permit_id
        or validation.authority.action_permit_id != evidence.validation_action_permit_id
        or source.authority.approval_receipt_id != evidence.source_approval_receipt_id
        or validation.authority.approval_receipt_id != evidence.validation_approval_receipt_id
        or source.backend_completion_digest != evidence.source_worker_completion_digest
        or validation.backend_completion_digest != evidence.validation_worker_completion_digest
        or source.worker_execution_id != evidence.source_executor_execution_id
        or validation.worker_execution_id != evidence.validation_executor_execution_id
    ):
        raise ValueError("governed WEB Gateway authority differs from its signed execution scope")
    source_actual = (
        source.gateway_audit_run_id,
        source.gateway_audit_root_digest,
        source.gateway_event_head_digest,
        source_final_root_digest,
        source_final_event_head,
        source.receipt_id,
        source.receipt_digest,
        source_receipt_reference,
        source_authority_digest,
        source.gateway_launch_id,
        source.gateway_evidence_reference,
        source.gateway_evidence_digest,
        source.gateway_request_reservation_reference,
        source.gateway_request_reservation_digest,
        source.worker_result_digest,
        source.tool_result_digest,
        source.policy_decision_digest,
        source.gateway_outcome_digest,
        source.completed_at,
    )
    source_expected = (
        evidence.source_gateway_audit_run_id,
        evidence.source_gateway_audit_pre_receipt_root_digest,
        evidence.source_gateway_audit_pre_receipt_event_head_digest,
        evidence.source_gateway_audit_final_root_digest,
        evidence.source_gateway_audit_final_event_head_digest,
        evidence.source_gateway_completion_receipt_id,
        evidence.source_gateway_completion_receipt_digest,
        evidence.source_gateway_completion_receipt_reference,
        evidence.source_gateway_completion_authority_digest,
        evidence.source_gateway_launch_id,
        evidence.source_gateway_evidence_reference,
        evidence.source_gateway_evidence_digest,
        evidence.source_gateway_request_reservation_reference,
        evidence.source_gateway_request_reservation_digest,
        evidence.source_gateway_worker_result_digest,
        evidence.source_gateway_tool_result_digest,
        evidence.source_gateway_policy_decision_digest,
        evidence.source_gateway_outcome_digest,
        evidence.source_gateway_completed_at,
    )
    validation_actual = (
        validation.gateway_audit_run_id,
        validation.gateway_audit_root_digest,
        validation.gateway_event_head_digest,
        validation_final_root_digest,
        validation_final_event_head,
        validation.receipt_id,
        validation.receipt_digest,
        validation_receipt_reference,
        validation_authority_digest,
        validation.gateway_launch_id,
        validation.gateway_evidence_reference,
        validation.gateway_evidence_digest,
        validation.gateway_request_reservation_reference,
        validation.gateway_request_reservation_digest,
        validation.worker_result_digest,
        validation.tool_result_digest,
        validation.policy_decision_digest,
        validation.gateway_outcome_digest,
        validation.completed_at,
    )
    validation_expected = (
        evidence.validation_gateway_audit_run_id,
        evidence.validation_gateway_audit_pre_receipt_root_digest,
        evidence.validation_gateway_audit_pre_receipt_event_head_digest,
        evidence.validation_gateway_audit_final_root_digest,
        evidence.validation_gateway_audit_final_event_head_digest,
        evidence.validation_gateway_completion_receipt_id,
        evidence.validation_gateway_completion_receipt_digest,
        evidence.validation_gateway_completion_receipt_reference,
        evidence.validation_gateway_completion_authority_digest,
        evidence.validation_gateway_launch_id,
        evidence.validation_gateway_evidence_reference,
        evidence.validation_gateway_evidence_digest,
        evidence.validation_gateway_request_reservation_reference,
        evidence.validation_gateway_request_reservation_digest,
        evidence.validation_gateway_worker_result_digest,
        evidence.validation_gateway_tool_result_digest,
        evidence.validation_gateway_policy_decision_digest,
        evidence.validation_gateway_outcome_digest,
        evidence.validation_gateway_completed_at,
    )
    if (
        source_actual != source_expected
        or validation_actual != validation_expected
        or evidence.completed_at
        != max(source.completed_at, validation.completed_at)
    ):
        raise ValueError("governed WEB Gateway receipt or sealed audit lineage differs")


def _require_governed_web_grant_consumption_bindings(
    evidence: GovernedWebExecutionEvidence,
    store: WebAssessmentCapabilityGrantConsumptionStore,
) -> tuple[
    WebAssessmentCapabilityGrantConsumptionReceipt,
    WebAssessmentCapabilityGrantConsumptionReceipt,
]:
    if type(store) is not WebAssessmentCapabilityGrantConsumptionStore:
        raise TypeError("governed WEB execution requires the exact durable Grant store")
    try:
        WebAssessmentCapabilityGrantConsumptionStore._require_exact_runtime(store)
        source = WebAssessmentCapabilityGrantConsumptionStore.receipt_for_grant(
            store,
            evidence.source_capability_grant_id,
        )
        validation = WebAssessmentCapabilityGrantConsumptionStore.receipt_for_grant(
            store,
            evidence.validation_capability_grant_id,
        )
    except Exception as exc:
        raise ValueError("governed WEB durable Grant receipts could not be reloaded") from exc
    if source is None or validation is None:
        raise ValueError("governed WEB durable Grant consumption receipt is absent")
    source_expected = (
        evidence.campaign_id,
        evidence.capability_grant_authority_digest,
        evidence.source_capability_grant_id,
        evidence.source_capability_grant_digest,
        evidence.source_gateway_request_id,
        evidence.source_gateway_request_digest,
        evidence.source_action_permit_id,
        evidence.source_action_permit_digest,
        evidence.source_approval_receipt_id,
        evidence.source_approval_receipt_digest,
        evidence.source_capability_grant_consumption_receipt_id,
        evidence.source_capability_grant_consumption_receipt_digest,
    )
    validation_expected = (
        evidence.campaign_id,
        evidence.capability_grant_authority_digest,
        evidence.validation_capability_grant_id,
        evidence.validation_capability_grant_digest,
        evidence.validation_gateway_request_id,
        evidence.validation_gateway_request_digest,
        evidence.validation_action_permit_id,
        evidence.validation_action_permit_digest,
        evidence.validation_approval_receipt_id,
        evidence.validation_approval_receipt_digest,
        evidence.validation_capability_grant_consumption_receipt_id,
        evidence.validation_capability_grant_consumption_receipt_digest,
    )
    if (
        (
            source.campaign_id,
            source.grant_authority_digest,
            source.capability_grant_id,
            source.capability_grant_digest,
            source.request_id,
            source.request_digest,
            source.permit_id,
            source.permit_digest,
            source.approval_receipt_id,
            source.approval_receipt_digest,
            source.receipt_id,
            source.receipt_digest,
        )
        != source_expected
        or (
            validation.campaign_id,
            validation.grant_authority_digest,
            validation.capability_grant_id,
            validation.capability_grant_digest,
            validation.request_id,
            validation.request_digest,
            validation.permit_id,
            validation.permit_digest,
            validation.approval_receipt_id,
            validation.approval_receipt_digest,
            validation.receipt_id,
            validation.receipt_digest,
        )
        != validation_expected
        or source == validation
    ):
        raise ValueError("governed WEB durable Grant consumption receipt differs")
    return source, validation


class GovernedWebAttackPathConfirmation(_FrozenStrictModel):
    path_id: str = Field(alias="pathId", pattern=r"^finding-path-web_[a-f0-9]{24}$")
    title: str = Field(min_length=1, max_length=300)
    stage_ids: tuple[str, ...] = Field(alias="stageIds", min_length=2, max_length=8)
    finding_ids: tuple[str, ...] = Field(alias="findingIds", min_length=1, max_length=8)
    observed_impact: str = Field(alias="observedImpact", min_length=1, max_length=2_000)
    confirmation_semantics: Literal["verified-independent-replay"] = Field(
        default="verified-independent-replay",
        alias="confirmationSemantics",
    )


class GovernedWebClaimReconciliation(_FrozenStrictModel):
    check: IssueCheck
    source_status: Literal["locally-reproduced", "not-reproduced", "inconclusive"] = Field(
        alias="sourceStatus"
    )
    validation_status: Literal["locally-reproduced", "not-reproduced", "inconclusive"] = Field(
        alias="validationStatus"
    )
    outcome: Literal["local-corroborated", "mismatch", "inconclusive"]
    source_semantic_digest: str = Field(alias="sourceSemanticDigest", pattern=_SHA256_PATTERN)
    validation_semantic_digest: str = Field(
        alias="validationSemanticDigest",
        pattern=_SHA256_PATTERN,
    )


class GovernedWebPromotion(_FrozenStrictModel):
    """Deterministic PAJIN Finding projection after independent verification."""

    api_version: Literal["pajin.dev/governed-web-promotion/v1alpha1"] = Field(
        default=GOVERNED_WEB_PROMOTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GovernedWebPromotion"] = "GovernedWebPromotion"
    promotion_digest: str = Field(default="", alias="promotionDigest", max_length=64)
    reconciliation_result_digest: str = Field(
        alias="reconciliationResultDigest",
        pattern=_SHA256_PATTERN,
    )
    execution_evidence: GovernedWebExecutionEvidence = Field(alias="executionEvidence")
    execution_verification: GovernedWebExecutionVerification = Field(alias="executionVerification")
    claims: tuple[
        GovernedWebClaimReconciliation,
        GovernedWebClaimReconciliation,
        GovernedWebClaimReconciliation,
    ]
    findings: tuple[Finding, ...] = Field(max_length=3)
    attack_paths: tuple[GovernedWebAttackPathConfirmation, ...] = Field(
        alias="attackPaths",
        max_length=2,
    )
    finding_authority: Literal[True] = Field(default=True, alias="findingAuthority")
    confirmation_semantics: Literal["verified-independent-replay"] = Field(
        default="verified-independent-replay",
        alias="confirmationSemantics",
    )
    promoted_at: datetime = Field(alias="promotedAt")

    @field_validator("promoted_at")
    @classmethod
    def normalize_promoted_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="governed WEB promotion time")

    @field_validator("finding_authority", mode="before")
    @classmethod
    def require_finding_authority(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("governed WEB promotion must disclose Finding authority")
        return value

    @model_validator(mode="after")
    def bind_promotion(self) -> Self:
        if self.execution_verification.evidence_digest != self.execution_evidence.evidence_digest:
            raise ValueError("governed WEB verification belongs to another execution Evidence")
        if self.execution_verification.verified_at < self.execution_evidence.completed_at:
            raise ValueError("governed WEB verification predates completed execution Evidence")
        if self.promoted_at < max(
            self.execution_evidence.completed_at,
            self.execution_verification.verified_at,
        ):
            raise ValueError("governed WEB promotion predates execution verification")
        finding_ids = [finding.finding_id for finding in self.findings]
        if finding_ids != sorted(set(finding_ids)):
            raise ValueError("governed WEB Findings must be unique and sorted")
        if any(not finding.validated for finding in self.findings):
            raise ValueError("governed WEB promotion cannot contain an unvalidated Finding")
        if tuple(claim.check for claim in self.claims) != (
            "sql-login",
            "object-access",
            "dom-xss",
        ):
            raise ValueError("governed WEB promotion requires the three ordered claims")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"promotion_digest"},
        )
        expected = _canonical_digest("pajin.web.governed-promotion/v1", material)
        if self.promotion_digest and self.promotion_digest != expected:
            raise ValueError("governed WEB promotion Digest differs")
        object.__setattr__(self, "promotion_digest", expected)
        return self


@final
class GovernedWebPromotionAuthority(_ImmutableAuthority):
    """Non-serializable authority proving a Promotion was rebuilt from sealed inputs."""

    __slots__ = (
        "_factory_token",
        "_grant_consumption_store",
        "_promotion",
        "_reconciliation",
        "_source_gateway_run_path",
        "_source_run_path",
        "_validation_gateway_run_path",
        "_validation_run_path",
        "_verifier",
    )

    def __init__(
        self,
        *,
        _promotion: GovernedWebPromotion,
        _reconciliation: LocalWebAssessmentCampaignResult,
        _grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore,
        _source_run_path: Path,
        _validation_run_path: Path,
        _verifier: GovernedWebExecutionVerifierBinding,
        _factory_token: object,
    ) -> None:
        if _factory_token is not _PROMOTION_AUTHORITY_FACTORY_TOKEN:
            raise TypeError(
                "governed WEB Promotion authority can only be created by its code-owned gate"
            )
        if (
            type(_promotion) is not GovernedWebPromotion
            or type(_reconciliation) is not LocalWebAssessmentCampaignResult
            or type(_grant_consumption_store)
            is not WebAssessmentCapabilityGrantConsumptionStore
            or type(_verifier) is not GovernedWebExecutionVerifierBinding
        ):
            raise TypeError("governed WEB Promotion authority inputs are not canonical")
        promotion = GovernedWebPromotion.model_validate(
            _promotion.model_dump(mode="json", by_alias=True)
        )
        reconciliation = LocalWebAssessmentCampaignResult.model_validate(
            _reconciliation.model_dump(mode="json", by_alias=True)
        )
        if (
            _verifier._grant_consumption_store is not _grant_consumption_store
            or _verifier.verifier_digest != promotion.execution_verification.verifier_digest
            or _verifier.verifier_id != promotion.execution_verification.verifier_id
        ):
            raise ValueError("governed WEB Promotion verifier differs from its factory binding")
        source_gateway_run_path, validation_gateway_run_path = (
            _verifier._validated_gateway_run_paths()
        )
        expected_claims = _promotion_claims(reconciliation)
        expected_findings = _derive_findings(reconciliation, promotion.execution_evidence)
        expected_paths = _derive_attack_paths(reconciliation, expected_findings)
        _require_governed_web_grant_consumption_bindings(
            promotion.execution_evidence,
            _grant_consumption_store,
        )
        if (
            promotion.reconciliation_result_digest != reconciliation.result_digest
            or promotion.claims != expected_claims
            or promotion.findings != expected_findings
            or promotion.attack_paths != expected_paths
        ):
            raise ValueError(
                "governed WEB Promotion differs from its sealed reconciliation derivation"
            )
        self._promotion = promotion
        self._reconciliation = reconciliation
        self._grant_consumption_store = _grant_consumption_store
        self._source_run_path = Path(
            os.path.abspath(os.fspath(_source_run_path))
        )
        self._validation_run_path = Path(
            os.path.abspath(os.fspath(_validation_run_path))
        )
        self._source_gateway_run_path = source_gateway_run_path
        self._validation_gateway_run_path = validation_gateway_run_path
        self._verifier = _verifier
        self._factory_token = _factory_token
        self._freeze_authority()

    def _validated_gateway_run_paths(self) -> tuple[Path, Path]:
        source_path, validation_path = self._verifier._validated_gateway_run_paths()
        if (
            source_path != self._source_gateway_run_path
            or validation_path != self._validation_gateway_run_path
        ):
            raise ValueError("governed WEB Promotion Gateway roots differ from its factory")
        return source_path, validation_path

    @property
    def promotion(self) -> GovernedWebPromotion:
        """Return the serializable artifact without transferring gate authority."""

        return self._promotion.model_copy(deep=True)

    @property
    def promotion_digest(self) -> str:
        return self._promotion.promotion_digest

    @property
    def execution_evidence(self) -> GovernedWebExecutionEvidence:
        return self._promotion.execution_evidence.model_copy(deep=True)

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(item.model_copy(deep=True) for item in self._promotion.findings)

    @property
    def attack_paths(self) -> tuple[GovernedWebAttackPathConfirmation, ...]:
        return tuple(item.model_copy(deep=True) for item in self._promotion.attack_paths)

    @property
    def grant_consumption_store(self) -> WebAssessmentCapabilityGrantConsumptionStore:
        """Return the exact read-only receipt authority bound during promotion."""

        return self._grant_consumption_store


def _promotion_claims(
    reconciliation: LocalWebAssessmentCampaignResult,
) -> tuple[
    GovernedWebClaimReconciliation,
    GovernedWebClaimReconciliation,
    GovernedWebClaimReconciliation,
]:
    claim_items = [
        GovernedWebClaimReconciliation(
            check=item.check,
            sourceStatus=item.source_status,
            validationStatus=item.validation_status,
            outcome=item.outcome,
            sourceSemanticDigest=item.source_semantic_digest,
            validationSemanticDigest=item.validation_semantic_digest,
        )
        for item in reconciliation.claim_reconciliations
    ]
    if len(claim_items) != 3:  # pragma: no cover - guarded by the source model
        raise ValueError("governed WEB promotion requires exactly three claim comparisons")
    return (claim_items[0], claim_items[1], claim_items[2])


def _validated_promotion_authority(
    authority: GovernedWebPromotionAuthority,
) -> GovernedWebPromotion:
    if type(authority) is not GovernedWebPromotionAuthority:
        raise TypeError("governed WEB downstream gate requires Promotion authority")
    rebound = GovernedWebPromotionAuthority(
        _promotion=authority._promotion,
        _reconciliation=authority._reconciliation,
        _grant_consumption_store=authority._grant_consumption_store,
        _source_run_path=authority._source_run_path,
        _validation_run_path=authority._validation_run_path,
        _verifier=authority._verifier,
        _factory_token=_PROMOTION_AUTHORITY_FACTORY_TOKEN,
    )
    return rebound.promotion


def promote_governed_web_findings(
    *,
    reconciliation: LocalWebAssessmentCampaignResult,
    execution_evidence: GovernedWebExecutionEvidence,
    verifier: GovernedWebExecutionVerifierBinding,
    source_run_path: Path,
    validation_run_path: Path,
    promoted_at: datetime,
) -> GovernedWebPromotionAuthority:
    """Reload both Runs and promote only matching, independently verified outcomes."""

    canonical_reconciliation = LocalWebAssessmentCampaignResult.model_validate(
        reconciliation.model_dump(mode="json", by_alias=True)
    )
    canonical_evidence = GovernedWebExecutionEvidence.model_validate(
        execution_evidence.model_dump(mode="json", by_alias=True)
    )
    if type(verifier) is not GovernedWebExecutionVerifierBinding:
        raise TypeError("governed WEB promotion requires the code-owned execution verifier binding")
    promoted_at = _normalize_utc(promoted_at, label="governed WEB promotion time")
    if promoted_at < canonical_reconciliation.reconciled_at:
        raise ValueError("governed WEB promotion predates Run reconciliation")
    source_verified = load_verified_local_web_assessment_source_integrity(
        source_run_path,
        expected_run_id=canonical_evidence.source_run_id,
        expected_root_digest=canonical_evidence.source_root_digest,
    )
    validation_verified = load_verified_local_web_assessment_source_integrity(
        validation_run_path,
        expected_run_id=canonical_evidence.validation_run_id,
        expected_root_digest=canonical_evidence.validation_root_digest,
    )
    source = local_web_assessment_run_reference(
        role="source",
        verified_source=source_verified,
    )
    validation = local_web_assessment_run_reference(
        role="validation",
        verified_source=validation_verified,
    )
    if (
        source != canonical_reconciliation.source
        or validation != canonical_reconciliation.validation
    ):
        raise ValueError("governed WEB reconciliation differs from the reloaded sealed Runs")
    _require_execution_result_bindings(canonical_evidence, source, validation)
    raw_verification = verifier.verify(
        canonical_evidence,
        source=source,
        validation=validation,
    )
    verification = GovernedWebExecutionVerification.model_validate(
        raw_verification.model_dump(mode="json", by_alias=True)
    )
    if (
        verification.evidence_digest != canonical_evidence.evidence_digest
        or verification.verifier_id != GOVERNED_WEB_EXECUTION_VERIFIER_ID
        or verification.verifier_digest != canonical_evidence.execution_verifier_digest
    ):
        raise ValueError("governed WEB signature verifier returned foreign authority")
    promoted_at = max(promoted_at, verification.verified_at)
    findings = _derive_findings(canonical_reconciliation, canonical_evidence)
    paths = _derive_attack_paths(canonical_reconciliation, findings)
    promotion = GovernedWebPromotion(
        reconciliationResultDigest=canonical_reconciliation.result_digest,
        executionEvidence=canonical_evidence,
        executionVerification=verification,
        claims=_promotion_claims(canonical_reconciliation),
        findings=findings,
        attackPaths=paths,
        promotedAt=promoted_at,
    )
    return GovernedWebPromotionAuthority(
        _promotion=promotion,
        _reconciliation=canonical_reconciliation,
        _grant_consumption_store=verifier._grant_consumption_store,
        _source_run_path=source_verified.run_path,
        _validation_run_path=validation_verified.run_path,
        _verifier=verifier,
        _factory_token=_PROMOTION_AUTHORITY_FACTORY_TOKEN,
    )


def _require_execution_result_bindings(
    evidence: GovernedWebExecutionEvidence,
    source: LocalWebAssessmentRunReference,
    validation: LocalWebAssessmentRunReference,
) -> None:
    if (
        evidence.source_run_id != source.run_id
        or evidence.source_root_digest != source.root_digest
        or evidence.source_result_digest != source.result_digest
        or evidence.source_authorization_id != source.authorization_id
        or evidence.validation_run_id != validation.run_id
        or evidence.validation_root_digest != validation.root_digest
        or evidence.validation_result_digest != validation.result_digest
        or evidence.validation_authorization_id != validation.authorization_id
        or source.result.target_version != validation.result.target_version
        or source.result.origin != validation.result.origin
        or evidence.source_completed_at < source.result.finished_at
        or evidence.validation_completed_at < validation.result.finished_at
    ):
        raise ValueError("governed WEB execution Evidence differs from the sealed Results")


def _derive_findings(
    reconciliation: LocalWebAssessmentCampaignResult,
    evidence: GovernedWebExecutionEvidence,
) -> tuple[Finding, ...]:
    source_issues = {issue.check: issue for issue in reconciliation.source.result.issues}
    validation_issues = {issue.check: issue for issue in reconciliation.validation.result.issues}
    findings: list[Finding] = []
    for comparison in reconciliation.claim_reconciliations:
        if comparison.outcome != "local-corroborated":
            continue
        if not (comparison.source_status == comparison.validation_status == "locally-reproduced"):
            continue
        source_issue = source_issues[comparison.check]
        validation_issue = validation_issues[comparison.check]
        _require_exact_issue_match(source_issue, validation_issue)
        identity_material = {
            "check": comparison.check,
            "sourceSemanticDigest": comparison.source_semantic_digest,
            "validationSemanticDigest": comparison.validation_semantic_digest,
            "targetIdentityDigest": evidence.target_identity_digest,
            "executionEvidenceDigest": evidence.evidence_digest,
        }
        finding_id = (
            "finding_web_"
            + _canonical_digest(
                "pajin.web.governed-finding/v1",
                identity_material,
            )[:24]
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                title=source_issue.title,
                severity=FindingSeverity(source_issue.severity),
                threat_class=source_issue.cwe,
                target=reconciliation.plan.origin,
                summary=source_issue.observed_impact,
                impact=source_issue.potential_impact,
                affected_component=_CHECK_COMPONENT[source_issue.check],
                root_cause=_CHECK_ROOT_CAUSE[source_issue.check],
                reproduction=[
                    "Run the sealed source assessment through the exact governed browser "
                    "Capability and ActionPermit.",
                    "Replay the same code-owned diagnostic in a separately keyed executor process.",
                    "Compare the typed true/false controls; both executions reported "
                    "locally-reproduced.",
                ],
                evidence=[
                    f"web/source/{evidence.source_run_id}/result.json",
                ],
                remediation=[source_issue.remediation],
                confidence=0.99,
                validated=True,
            )
        )
    return tuple(sorted(findings, key=lambda finding: finding.finding_id))


def _require_exact_issue_match(source: AssessmentIssue, validation: AssessmentIssue) -> None:
    if (
        source.check != validation.check
        or source.cwe != validation.cwe
        or source.severity != validation.severity
        or source.status != validation.status
        or source.title != validation.title
        or source.observed_impact != validation.observed_impact
        or source.potential_impact != validation.potential_impact
        or source.remediation != validation.remediation
    ):
        raise ValueError("governed WEB source and validation issue narratives differ")
    if (
        source.cwe != _CHECK_CANONICAL_CWE[source.check]
        or source.severity != _CHECK_CANONICAL_SEVERITY[source.check]
        or source.potential_impact != _CHECK_CANONICAL_POTENTIAL_IMPACT[source.check]
        or source.remediation != _CHECK_CANONICAL_REMEDIATION[source.check]
    ):
        raise ValueError("governed WEB issue narrative differs from the code-owned diagnostic")


def _derive_attack_paths(
    reconciliation: LocalWebAssessmentCampaignResult,
    findings: tuple[Finding, ...],
) -> tuple[GovernedWebAttackPathConfirmation, ...]:
    finding_by_check = {
        comparison.check: next(
            (
                finding
                for finding in findings
                if finding.threat_class
                == next(
                    issue.cwe
                    for issue in reconciliation.source.result.issues
                    if issue.check == comparison.check
                )
            ),
            None,
        )
        for comparison in reconciliation.claim_reconciliations
    }
    source_issues = {
        issue.issue_id: issue for issue in reconciliation.source.result.issues
    }
    validation_issues = {
        issue.issue_id: issue for issue in reconciliation.validation.result.issues
    }
    confirmed: list[GovernedWebAttackPathConfirmation] = []
    for comparison, path, validation_path in zip(
        reconciliation.attack_path_reconciliations,
        reconciliation.source.result.attack_paths,
        reconciliation.validation.result.attack_paths,
        strict=True,
    ):
        if (
            comparison.outcome != "local-corroborated"
            or comparison.source_status != "locally-validated"
            or comparison.validation_status != "locally-validated"
        ):
            continue
        path_finding_items: list[Finding] = []
        stage_lineage_valid = True
        for stage, validation_stage in zip(path.stages, validation_path.stages, strict=True):
            if (
                stage.ordinal != validation_stage.ordinal
                or stage.stage_id != validation_stage.stage_id
                or stage.state != validation_stage.state
                or stage.summary != validation_stage.summary
                or len(stage.evidence_ids) != len(validation_stage.evidence_ids)
            ):
                stage_lineage_valid = False
                break
            if stage.state == "observed":
                if stage.issue_id is not None or validation_stage.issue_id is not None:
                    stage_lineage_valid = False
                    break
                continue
            if stage.issue_id is None or validation_stage.issue_id is None:
                stage_lineage_valid = False
                break
            source_issue = source_issues.get(stage.issue_id)
            validation_issue = validation_issues.get(validation_stage.issue_id)
            if (
                source_issue is None
                or validation_issue is None
                or source_issue.check != validation_issue.check
                or source_issue.status != "locally-reproduced"
                or validation_issue.status != "locally-reproduced"
                or stage.state != "locally-reproduced"
            ):
                stage_lineage_valid = False
                break
            finding = finding_by_check[source_issue.check]
            if finding is None:
                stage_lineage_valid = False
                break
            path_finding_items.append(finding)
        if not stage_lineage_valid:
            continue
        path_findings = tuple(path_finding_items)
        if not path_findings or len({item.finding_id for item in path_findings}) != len(
            path_findings
        ):
            continue
        digest = _canonical_digest(
            "pajin.web.governed-attack-path/v1",
            {
                "sourceSemanticDigest": comparison.source_semantic_digest,
                "validationSemanticDigest": comparison.validation_semantic_digest,
                "findingIds": [finding.finding_id for finding in path_findings],
            },
        )
        confirmed.append(
            GovernedWebAttackPathConfirmation(
                pathId=f"finding-path-web_{digest[:24]}",
                title=path.title,
                stageIds=tuple(stage.stage_id for stage in path.stages),
                findingIds=tuple(finding.finding_id for finding in path_findings),
                observedImpact=path.observed_impact,
            )
        )
    return tuple(sorted(confirmed, key=lambda item: item.path_id))


_AuthorityResultT = TypeVar("_AuthorityResultT")


@final
class GovernedWebValidationAuthority(_ImmutableAuthority):
    """Opaque, one-use export authority for one exact governed validation Run."""

    __slots__ = (
        "__candidate_source_root_digest",
        "__export_consumed",
        "__export_root",
        "__export_root_identity",
        "__final_root_digest",
        "__graph_admission_authority",
        "__lock",
        "__poc_consumed",
        "__poc_root",
        "__poc_root_identity",
        "__promotion_authority",
        "__run_id",
        "__run_path",
    )

    def __init__(
        self,
        *,
        _factory_token: object,
        run_path: Path,
        run_id: str,
        candidate_source_root_digest: str,
        final_root_digest: str,
        promotion_authority: GovernedWebPromotionAuthority,
        graph_admission_authority: GovernedWebGraphAdmissionAuthority,
    ) -> None:
        if _factory_token is not _VALIDATION_AUTHORITY_FACTORY_TOKEN:
            raise TypeError(
                "governed WEB validation authority can only be created by its code-owned writer"
            )
        if (
            type(promotion_authority) is not GovernedWebPromotionAuthority
            or type(graph_admission_authority) is not GovernedWebGraphAdmissionAuthority
        ):
            raise TypeError("governed WEB validation authority inputs are not canonical")
        pinned_run_path = pinned_workspace_relative_path(
            run_path,
            label="governed WEB validation Run path",
        )
        self.__run_path = (
            pinned_run_path
            if pinned_run_path is not None
            else run_path.resolve(strict=True)
        )
        self.__run_id = run_id
        self.__candidate_source_root_digest = candidate_source_root_digest
        self.__final_root_digest = final_root_digest
        self.__promotion_authority = promotion_authority
        self.__graph_admission_authority = graph_admission_authority
        self.__export_consumed = False
        self.__export_root: Path | None = None
        self.__export_root_identity: tuple[tuple[int, int], tuple[int, int]] | None = None
        self.__poc_consumed = False
        self.__poc_root: Path | None = None
        self.__poc_root_identity: tuple[tuple[int, int], tuple[int, int]] | None = None
        self.__lock = threading.Lock()
        self._require_exact_projection()
        self._freeze_authority()

    @property
    def run_path(self) -> Path:
        return self.__run_path

    @property
    def run_id(self) -> str:
        return self.__run_id

    @property
    def candidate_source_root_digest(self) -> str:
        return self.__candidate_source_root_digest

    @property
    def final_root_digest(self) -> str:
        return self.__final_root_digest

    @property
    def finding_count(self) -> int:
        return len(self.__promotion_authority.findings)

    @property
    def graph_admission_digest(self) -> str:
        return self.__graph_admission_authority.admission.admission_digest

    @property
    def graph_event_count(self) -> int:
        return len(self.__graph_admission_authority.events)

    def _protected_output_roots(self) -> tuple[Path, ...]:
        promotion = self.__promotion_authority
        graph_authority = self.__graph_admission_authority._graph_authority
        graph_authority._require_factory_binding()
        grant_store_path = promotion._grant_consumption_store._path
        source_gateway_run_path, validation_gateway_run_path = (
            promotion._validated_gateway_run_paths()
        )
        roots = [
            self.__run_path,
            promotion._source_run_path,
            promotion._validation_run_path,
            source_gateway_run_path,
            validation_gateway_run_path,
            graph_authority._graph_path.parent,
            grant_store_path.parent,
        ]
        published = (
            (self.__export_root, self.__export_root_identity),
            (self.__poc_root, self.__poc_root_identity),
        )
        for root, identity in published:
            if root is None:
                if identity is not None:  # pragma: no cover - internal invariant
                    raise ValueError("governed WEB published bundle identity is incomplete")
                continue
            if identity is None or _governed_bundle_root_identity(root) != identity:
                raise ValueError("governed WEB published bundle path identity changed")
            roots.append(root)
        return tuple(dict.fromkeys(roots))

    def _require_exact_projection(self) -> None:
        promotion = _validated_promotion_authority(self.__promotion_authority)
        graph_admission = _validated_graph_admission_authority(
            promotion,
            self.__graph_admission_authority,
        )
        stored_promotion = GovernedWebPromotion.model_validate(
            load_bounded_strict_json(
                self.__run_path / "governed-web-promotion.json",
                max_bytes=_MAX_CANONICAL_BYTES,
                label="sealed governed WEB Promotion",
                require_single_link=True,
            )
        )
        stored_graph_admission = GovernedWebGraphAdmission.model_validate(
            load_bounded_strict_json(
                self.__run_path / "governed-web-graph-admission.json",
                max_bytes=_MAX_CANONICAL_BYTES,
                label="sealed governed WEB Graph admission",
                require_single_link=True,
            )
        )
        loaded = load_validation_snapshot(
            self.__run_path,
            expected_run_id=self.__run_id,
            expected_root_digest=self.__final_root_digest,
        )
        if loaded.index is None:
            raise ValueError("governed WEB sealed validation projection lacks its exact index")
        projected_at = loaded.index.generated_at
        expected_candidates = [
            _candidate(finding, promotion, projected_at) for finding in promotion.findings
        ]
        expected_source_decisions = [
            _source_decision(candidate, projected_at) for candidate in expected_candidates
        ]
        expected_final_decisions = [
            _confirmed_decision(
                candidate=candidate,
                source_decision=source_decision,
                promotion=promotion,
                candidate_source_root_digest=self.__candidate_source_root_digest,
                decided_at=projected_at,
            )
            for candidate, source_decision in zip(
                expected_candidates,
                expected_source_decisions,
                strict=True,
            )
        ]
        dispositions = {
            disposition: [
                decision.candidate_id
                for decision in expected_final_decisions
                if decision.disposition is disposition
            ]
            for disposition in FindingDisposition
        }
        expected_index = VersionedValidationIndex(
            sourceRunId=self.__run_id,
            candidateSourceRootDigest=self.__candidate_source_root_digest,
            confirmationSemantics="verified-independent-replay",
            dispositions=dispositions,
            confirmedCandidateIds=[candidate.candidate_id for candidate in expected_candidates],
            generatedAt=projected_at,
        )
        expected_validation = FindingValidationSet(
            candidates=expected_candidates,
            decisions=expected_final_decisions,
            confirmed_findings=list(promotion.findings),
        )
        if (
            stored_promotion != promotion
            or stored_graph_admission != graph_admission
            or loaded.semantics is not ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY
            or loaded.index != expected_index
            or loaded.validation != expected_validation
        ):
            raise ValueError("governed WEB sealed validation projection differs from its authority")

    def _verified_export(self) -> VerifiedSarifExport:
        self._require_exact_projection()
        export = load_verified_sarif_export(
            self.__run_path,
            expected_run_id=self.__run_id,
            expected_root_digest=self.__final_root_digest,
        )
        if export.finding_count != self.finding_count:
            raise ValueError("governed WEB SARIF Finding count differs from its Promotion")
        return export

    def _perform_export_once(
        self,
        output_directory: Path,
        writer: Callable[[VerifiedSarifExport, _GovernedBundleDestination], _AuthorityResultT],
    ) -> _AuthorityResultT:
        with self.__lock:
            if self.__export_consumed:
                raise ValueError("governed WEB validation export authority is already consumed")
            destination = _require_safe_governed_bundle_destination(
                self,
                output_directory,
                label="governed WEB export",
            )
            with destination:
                result = writer(self._verified_export(), destination)
                identity = destination.published_identity()
                object.__setattr__(
                    self,
                    "_GovernedWebValidationAuthority__export_root",
                    destination.path,
                )
                object.__setattr__(
                    self,
                    "_GovernedWebValidationAuthority__export_root_identity",
                    identity,
                )
                object.__setattr__(
                    self,
                    "_GovernedWebValidationAuthority__export_consumed",
                    True,
                )
                return result

    def _perform_poc_once(
        self,
        output_directory: Path,
        writer: Callable[
            [
                GovernedWebPromotion,
                GovernedWebGraphAdmission,
                VerifiedSarifExport,
                _GovernedBundleDestination,
            ],
            _AuthorityResultT,
        ],
    ) -> _AuthorityResultT:
        with self.__lock:
            if self.__poc_consumed:
                raise ValueError("governed WEB PoC authority is already consumed")
            promotion = _validated_promotion_authority(self.__promotion_authority)
            graph_admission = _validated_graph_admission_authority(
                promotion,
                self.__graph_admission_authority,
            )
            destination = _require_safe_governed_bundle_destination(
                self,
                output_directory,
                label="governed WEB PoC",
            )
            with destination:
                result = writer(
                    promotion,
                    graph_admission,
                    self._verified_export(),
                    destination,
                )
                identity = destination.published_identity()
                object.__setattr__(
                    self,
                    "_GovernedWebValidationAuthority__poc_root",
                    destination.path,
                )
                object.__setattr__(
                    self,
                    "_GovernedWebValidationAuthority__poc_root_identity",
                    identity,
                )
                object.__setattr__(
                    self,
                    "_GovernedWebValidationAuthority__poc_consumed",
                    True,
                )
                return result


def write_governed_web_validation_projection(
    store: RunStore,
    promotion: GovernedWebPromotionAuthority,
    graph_admission: GovernedWebGraphAdmissionAuthority,
    *,
    decided_at: datetime,
) -> GovernedWebValidationAuthority:
    """Persist a two-seal restricted-gate projection for verified WEB replay.

    The generic replay runtime cannot ingest one multi-diagnostic browser Run directly.
    This adapter presents one typed logical ``ReplayArtifactSet`` per Candidate to the
    production ``decide_replay_confirmation`` reason matrix.  It then persists the
    resulting Decisions and uses the normal validation loader to re-verify the two-seal
    projection before returning.
    """

    canonical = _validated_promotion_authority(promotion)
    canonical_graph_admission = _validated_graph_admission_authority(
        canonical,
        graph_admission,
    )
    decided_at = _normalize_utc(decided_at, label="governed WEB confirmation decision time")
    if decided_at < canonical.promoted_at:
        raise ValueError("governed WEB confirmation decision predates promotion")
    candidates = [_candidate(finding, canonical, decided_at) for finding in canonical.findings]
    source_decisions = [_source_decision(candidate, decided_at) for candidate in candidates]
    source_validation = FindingValidationSet(
        candidates=candidates,
        decisions=source_decisions,
        confirmed_findings=[],
    )
    store.write_json(
        "governed-web-promotion.json",
        canonical.model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        "governed-web-graph-admission.json",
        canonical_graph_admission.model_dump(mode="json", by_alias=True),
    )
    write_validation_artifacts(store, source_validation)
    store.write_json("findings.json", [])
    store.append_event(
        "web-governed.validation-source-created",
        {
            "candidateCount": len(candidates),
            "promotionDigest": canonical.promotion_digest,
            "graphAdmissionDigest": canonical_graph_admission.admission_digest,
            "graphEventCount": len(canonical_graph_admission.events),
        },
        occurred_at=decided_at,
    )
    source_seal = store.seal()

    final_decisions = [
        _confirmed_decision(
            candidate=candidate,
            source_decision=source_decision,
            promotion=canonical,
            candidate_source_root_digest=source_seal.root_digest,
            decided_at=decided_at,
        )
        for candidate, source_decision in zip(candidates, source_decisions, strict=True)
    ]
    dispositions = {
        disposition: [
            decision.candidate_id
            for decision in final_decisions
            if decision.disposition is disposition
        ]
        for disposition in FindingDisposition
    }
    index = VersionedValidationIndex(
        sourceRunId=store.run_id,
        candidateSourceRootDigest=source_seal.root_digest,
        confirmationSemantics="verified-independent-replay",
        dispositions=dispositions,
        confirmedCandidateIds=[candidate.candidate_id for candidate in candidates],
        generatedAt=decided_at,
    )
    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VersionedValidationDecisionSet(
            sourceRunId=store.run_id,
            decisions=final_decisions,
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VersionedConfirmedFindingSet(
            sourceRunId=store.run_id,
            confirmationSemantics="verified-independent-replay",
            findings=list(canonical.findings),
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_INDEX_PATH,
        index.model_dump(mode="json", by_alias=True),
    )
    store.write_text(
        VERSIONED_VALIDATION_REPORT_PATH,
        _render_validation_report(canonical),
    )
    store.append_event(
        "web-governed.validation-confirmed",
        {
            "candidateSourceRootDigest": source_seal.root_digest,
            "confirmedCount": len(candidates),
            "confirmationSemantics": "verified-independent-replay",
        },
        occurred_at=decided_at,
    )
    final_seal = store.seal()
    loaded = load_validation_snapshot(
        store.path,
        expected_run_id=store.run_id,
        expected_root_digest=final_seal.root_digest,
    )
    if (
        loaded.semantics is not ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY
        or loaded.validation.confirmed_findings != list(canonical.findings)
    ):
        raise ValueError("governed WEB confirmation projection failed verified reload")
    return GovernedWebValidationAuthority(
        _factory_token=_VALIDATION_AUTHORITY_FACTORY_TOKEN,
        run_path=store.path,
        run_id=store.run_id,
        candidate_source_root_digest=source_seal.root_digest,
        final_root_digest=final_seal.root_digest,
        promotion_authority=promotion,
        graph_admission_authority=graph_admission,
    )


def _candidate(
    finding: Finding,
    promotion: GovernedWebPromotion,
    created_at: datetime,
) -> CandidateFinding:
    digest = _canonical_digest(
        "pajin.web.governed-candidate/v1",
        {
            "findingId": finding.finding_id,
            "promotionDigest": promotion.promotion_digest,
        },
    )
    return CandidateFinding(
        candidate_id=f"candidate_web_{digest[:24]}",
        claim=finding.model_copy(update={"validated": False}),
        source="trusted-core:governed-web-promotion",
        source_agent_id="trusted-core:governed-web-confirmation-adapter",
        source_request_ids=[promotion.execution_evidence.source_gateway_request_id],
        created_at=created_at,
    )


def _source_decision(
    candidate: CandidateFinding,
    decided_at: datetime,
) -> ValidationDecision:
    digest = _canonical_digest(
        "pajin.web.governed-source-decision/v1",
        {"candidateId": candidate.candidate_id},
    )
    return ValidationDecision(
        decision_id=f"decision_web_source_{digest[:24]}",
        candidate_id=candidate.candidate_id,
        validator_id="trusted-core:governed-web-source-gate",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING],
        decision_summary="The Candidate awaits the independently attested WEB validation run.",
        supporting_evidence=list(candidate.claim.evidence),
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[
            ValidationCheckResult(
                check_id="candidate-bound-validator-assessment",
                status=ValidationCheckStatus.PASS,
                reason_code=ValidationReasonCode.VALIDATOR_CONFIRMED,
                summary=("The governed source and validation semantic claims matched exactly."),
            ),
            ValidationCheckResult(
                check_id="independent-reproduction",
                status=ValidationCheckStatus.FAIL,
                reason_code=ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING,
                summary="Independent execution is applied only by the confirmation gate.",
            ),
        ],
        decided_at=decided_at,
    )


def _confirmed_decision(
    *,
    candidate: CandidateFinding,
    source_decision: ValidationDecision,
    promotion: GovernedWebPromotion,
    candidate_source_root_digest: str,
    decided_at: datetime,
) -> ValidationDecision:
    artifact_set, lineage = _governed_replay_gate_input(
        candidate=candidate,
        promotion=promotion,
        candidate_source_root_digest=candidate_source_root_digest,
        projected_at=decided_at,
    )
    decision = decide_replay_confirmation(
        candidate=candidate,
        source_decision=source_decision,
        artifact_set=artifact_set,
        lineage=lineage,
        decided_at=decided_at,
        independent_execution_attested=True,
    )
    if (
        decision.disposition is not FindingDisposition.CONFIRMED
        or decision.confirmation_basis is not ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
        or decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE
        or decision.validator_id != "trusted-core:confirmed-gate"
    ):
        raise ValueError("production confirmation gate did not confirm governed WEB evidence")
    return decision


def _governed_replay_gate_input(
    *,
    candidate: CandidateFinding,
    promotion: GovernedWebPromotion,
    candidate_source_root_digest: str,
    projected_at: datetime,
) -> tuple[ReplayArtifactSet, ReplayConfirmationLineage]:
    """Adapt verified browser Runs to the production gate's typed replay contract.

    The adapter describes the already verified validation Run as one logical, non-
    executable replay slice per Candidate.  It does not mint or dispatch replay
    authority.  Exact ActionPermit and attestation pins remain in ``lineage`` and the
    enclosing ``GovernedWebPromotion``.
    """

    evidence = promotion.execution_evidence
    finding = next(
        item for item in promotion.findings if item.finding_id == candidate.claim.finding_id
    )
    check = next(
        (
            issue_check
            for issue_check, component in _CHECK_COMPONENT.items()
            if component == finding.affected_component
        ),
        None,
    )
    if check is None:
        raise ValueError("governed WEB Finding has no registered diagnostic component")
    claim = next(item for item in promotion.claims if item.check == check)
    outcome_digest = _canonical_digest(
        "pajin.web.governed-replay-outcome/v1",
        {
            "candidateId": candidate.candidate_id,
            "validationRunId": evidence.validation_run_id,
            "validationRootDigest": evidence.validation_root_digest,
            "findingId": finding.finding_id,
        },
    )
    suffix = outcome_digest[:24]
    replay_run_slice = f"{evidence.validation_run_id}.{finding.threat_class.lower()}"
    source_reference = candidate.claim.evidence[0]
    validation_reference = f"web/validation/{evidence.validation_run_id}/result.json"
    binding = ReplayBinding(
        candidate_id=candidate.candidate_id,
        campaign=evidence.campaign_id,
        candidate_run_id=evidence.source_run_id,
        replay_run_id=replay_run_slice,
        original_request_id=evidence.source_gateway_request_id,
        mode=CampaignMode.BUG_BOUNTY,
        scenario_id=f"web.governed.{claim.check}",
        threat_class=finding.threat_class,
        tool_id=evidence.capability_id,
        tool_version=evidence.capability_version,
        target_id=f"target_web_{evidence.target_identity_digest[:24]}",
        target=finding.target,
    )
    contract = ModeReplayContract(
        contract_id=f"web-governed-contract:{claim.check}:v1",
        mode=binding.mode,
        scenario_id=binding.scenario_id,
        tool_id=binding.tool_id,
        tool_version=binding.tool_version,
        method="BROWSER",
        risk_tier=ToolRiskTier.T2,
        automatic=True,
        replay_safe=True,
        idempotent=True,
        session_policy=ReplaySessionPolicy.STATELESS,
        repetitions=1,
        required_successes=1,
        oracle_id="web.governed-semantic-match-oracle",
        oracle_version="1.0.0",
        observation_schema="pajin.web.governed-semantic-match/v1",
        semantic_support_required=True,
        allowed_argument_fields={"adapter_ref", "origin"},
    )
    packet = ValidationPacket(
        packet_id=f"validation-packet-web_{suffix}",
        candidate_run_id=binding.candidate_run_id,
        candidate=candidate,
        mode=binding.mode,
        scenario_id=binding.scenario_id,
        target_id=binding.target_id,
        target=binding.target,
        threat_class=binding.threat_class,
        original_request_ids=candidate.source_request_ids,
        evidence=[
            ValidationEvidenceExcerpt(
                reference=source_reference,
                sha256=evidence.source_result_digest,
                excerpt="Redacted source result bound to the governed WEB Candidate.",
            )
        ],
        semantic_support_required=True,
        replay_contract_id=contract.contract_id,
        created_at=projected_at,
    )
    arguments: dict[str, JsonValue] = {
        "adapter_ref": evidence.adapter_ref,
        "origin": finding.target,
    }
    spec = CompiledReplaySpec(
        spec_id=f"compiled-replay-web_{suffix}",
        contract_id=contract.contract_id,
        original_plan_step_id=f"step-web-{claim.check}",
        binding=binding,
        method=contract.method,
        arguments=arguments,
        argument_digest=replay_argument_digest(arguments),
        original_request_digest=evidence.source_gateway_request_digest,
        original_evidence_digest=evidence.source_result_digest,
        source_capability_digest=evidence.source_capability_grant_digest,
        risk_tier=contract.risk_tier,
        replay_safe=True,
        idempotent=True,
        session_policy=contract.session_policy,
        repetitions=1,
        required_successes=1,
        oracle_id=contract.oracle_id,
        oracle_version=contract.oracle_version,
        observation_schema=contract.observation_schema,
        semantic_support_required=True,
        grant_id=evidence.validation_capability_grant_id,
        max_calls=1,
        compiled_at=projected_at,
        expires_at=projected_at + timedelta(seconds=1),
    )
    attempt = ReplayAttempt(
        attempt_id=f"replay-attempt-web_{suffix}",
        spec_id=spec.spec_id,
        binding=binding,
        attempt_number=1,
        replay_request_id=evidence.validation_gateway_request_id,
        status=ReplayAttemptStatus.SUCCEEDED,
        observation_schema=spec.observation_schema,
        observation={
            "check": claim.check,
            "sourceSemanticDigest": claim.source_semantic_digest,
            "validationSemanticDigest": claim.validation_semantic_digest,
            "validationRunId": evidence.validation_run_id,
            "validationRootDigest": evidence.validation_root_digest,
        },
        evidence=[validation_reference],
        started_at=projected_at,
        finished_at=projected_at,
    )
    oracle = ReplayOracleResult(
        oracle_result_id=f"oracle-result-web_{suffix}",
        spec_id=spec.spec_id,
        binding=binding,
        oracle_id=spec.oracle_id,
        oracle_version=spec.oracle_version,
        observation_schema=spec.observation_schema,
        verdict=ReplayOracleVerdict.SUPPORTS,
        attempt_ids=[attempt.attempt_id],
        supporting_evidence=[validation_reference],
        support_count=1,
        required_support_count=1,
        summary="The typed WEB oracle matched the independently verified semantic claim.",
        evaluated_at=projected_at,
    )
    outcome = ReplayOutcome(
        outcome_id=f"replay-outcome-web_{suffix}",
        spec_id=spec.spec_id,
        binding=binding,
        execution_status=ReplayExecutionStatus.SUCCEEDED,
        attempts=[attempt],
        attempt_ids=[attempt.attempt_id],
        replay_request_ids=[attempt.replay_request_id],
        evidence=[validation_reference],
        oracle_result=oracle,
        completed_at=projected_at,
    )
    artifact_set = ReplayArtifactSet(
        validation_packet=packet,
        contract=contract,
        spec=spec,
        outcome=outcome,
    )
    lineage = ReplayConfirmationLineage(
        replay_run_id=replay_run_slice,
        replay_outcome_id=artifact_set.outcome.outcome_id,
        replay_request_ids=artifact_set.outcome.replay_request_ids,
        replay_evidence=artifact_set.outcome.evidence,
        oracle_result_id=oracle.oracle_result_id,
        ticket_id=evidence.validation_action_permit_id,
        candidate_source_root_digest=candidate_source_root_digest,
        artifact_set_digest=promotion.promotion_digest,
        artifact_seal_root_digest=evidence.validation_root_digest,
        receipt_seal_root_digest=evidence.validation_execution_attestation_digest,
        verified_at=promotion.execution_verification.verified_at,
    )
    return artifact_set, lineage


def _render_validation_report(promotion: GovernedWebPromotion) -> str:
    lines = [
        "# Governed web assessment confirmation",
        "",
        "- Confirmation semantics: `verified-independent-replay`",
        f"- Confirmed Findings: {len(promotion.findings)}",
        f"- Confirmed attack paths: {len(promotion.attack_paths)}",
        "- External delivery performed: `false`",
        "",
        "## Findings",
        "",
    ]
    for finding in promotion.findings:
        lines.extend(
            [
                f"### {escape_markdown_text(finding.title)}",
                "",
                f"- Finding ID: {markdown_code_span(finding.finding_id)}",
                f"- Severity: {markdown_code_span(finding.severity.value)}",
                f"- Threat class: {markdown_code_span(finding.threat_class)}",
                f"- Target: {markdown_code_span(finding.target)}",
                "- Affected component: "
                + (
                    markdown_code_span(finding.affected_component)
                    if finding.affected_component is not None
                    else "Not recorded"
                ),
                f"- Confidence: {markdown_code_span(format(finding.confidence, '.2f'))}",
                f"- Validated: {markdown_code_span(str(finding.validated).lower())}",
                f"- Summary: {escape_markdown_text(finding.summary)}",
                "- Impact assessment: "
                + escape_markdown_text(finding.impact or "Not recorded"),
                "- Root cause: "
                + escape_markdown_text(finding.root_cause or "Not recorded"),
                "",
                "#### Reproduction",
                "",
                *(
                    [
                        f"{index}. {escape_markdown_text(step)}"
                        for index, step in enumerate(finding.reproduction, start=1)
                    ]
                    or ["No reproduction steps recorded."]
                ),
                "",
                "#### Evidence",
                "",
                *(
                    [f"- {markdown_code_span(reference)}" for reference in finding.evidence]
                    or ["No evidence references recorded."]
                ),
                "",
                "#### Remediation",
                "",
                *(
                    [f"- {escape_markdown_text(item)}" for item in finding.remediation]
                    or ["No remediation recorded."]
                ),
                "",
            ]
        )
    if promotion.attack_paths:
        lines.extend(["## Attack paths", ""])
        for path in promotion.attack_paths:
            lines.extend(
                [
                    f"### {escape_markdown_text(path.title)}",
                    "",
                    f"- Path ID: {markdown_code_span(path.path_id)}",
                    f"- Stages: {markdown_code_span(' -> '.join(path.stage_ids))}",
                    f"- Impact: {escape_markdown_text(path.observed_impact)}",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


@final
@dataclass(frozen=True, slots=True)
class GovernedWebPermitLineageVerifier:
    """Reload exact approval, Permit, and consumption receipt for every proposal."""

    permit_store: SQLiteGraphActionPermitStore
    grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore
    execution_evidence: GovernedWebExecutionEvidence

    def __post_init__(self) -> None:
        if type(self.permit_store) is not SQLiteGraphActionPermitStore:
            raise TypeError(
                "governed WEB Graph lineage requires the durable SQLite approved-Permit store"
            )
        if (
            type(self.grant_consumption_store)
            is not WebAssessmentCapabilityGrantConsumptionStore
        ):
            raise TypeError(
                "governed WEB Graph lineage requires the durable Grant consumption store"
            )
        if type(self.execution_evidence) is not GovernedWebExecutionEvidence:
            raise TypeError("governed WEB Graph lineage requires canonical execution Evidence")
        object.__setattr__(
            self,
            "execution_evidence",
            GovernedWebExecutionEvidence.model_validate(
                self.execution_evidence.model_dump(mode="json", by_alias=True)
            ),
        )
        self._load_authorization("source")
        self._load_authorization("validation")
        _require_governed_web_grant_consumption_bindings(
            self.execution_evidence,
            self.grant_consumption_store,
        )

    @property
    def execution_evidence_digest(self) -> str:
        return self.execution_evidence.evidence_digest

    @property
    def tool_id(self) -> str:
        source = self._load_authorization("source").action.permit.capability
        validation = self._load_authorization("validation").action.permit.capability
        if source != validation:
            raise GraphLineageVerificationError(
                "governed WEB source and validation Permits use different Capabilities"
            )
        return source.tool_id

    def verify(
        self,
        lineage: GraphProposalLineage,
        *,
        proposal_digest: str | None = None,
        expected_event_log_head_digest: str | None = None,
    ) -> None:
        if proposal_digest is not None or expected_event_log_head_digest is not None:
            raise GraphLineageVerificationError(
                "governed WEB Permit lineage cannot use sealed-source trust arguments"
            )
        try:
            canonical = GraphProposalLineage.model_validate(
                lineage.model_dump(mode="json", by_alias=True)
            )
        except Exception as exc:
            raise GraphLineageVerificationError(
                "governed WEB Graph lineage is not canonical"
            ) from exc
        evidence = self.execution_evidence
        if canonical.action_permit_id == evidence.source_action_permit_id:
            role: Literal["source", "validation"] = "source"
        elif canonical.action_permit_id == evidence.validation_action_permit_id:
            role = "validation"
        else:
            raise GraphLineageVerificationError(
                "governed WEB Graph lineage names an unverified ActionPermit"
            )
        authorization = self._load_authorization(role)
        permit = authorization.action.permit
        run_id = evidence.source_run_id if role == "source" else evidence.validation_run_id
        root_digest = (
            evidence.source_root_digest if role == "source" else evidence.validation_root_digest
        )
        result_digest = (
            evidence.source_result_digest if role == "source" else evidence.validation_result_digest
        )
        expected_reference = f"evidence/web-{role}-result.json"
        grant_id = (
            evidence.source_capability_grant_id
            if role == "source"
            else evidence.validation_capability_grant_id
        )
        grant_digest = (
            evidence.source_capability_grant_digest
            if role == "source"
            else evidence.validation_capability_grant_digest
        )
        if (
            canonical.campaign_id != evidence.campaign_id
            or canonical.run_id != run_id
            or canonical.request_id != permit.request_id
            or canonical.request_digest != permit.request_digest
            or canonical.capability_grant_id != grant_id
            or canonical.capability_grant_digest != grant_digest
            or canonical.capability_id != permit.capability.capability_id
            or canonical.capability_version != permit.capability.capability_version
            or canonical.capability_digest != permit.capability.definition_digest
            or canonical.action_permit_id != permit.permit_id
            or canonical.action_permit_digest != permit.permit_digest
            or canonical.source_authority_id is not None
            or canonical.source_authority_digest is not None
            or canonical.source_root_digest != root_digest
            or canonical.evidence
            != [GraphEvidenceBinding(reference=expected_reference, sha256=result_digest)]
        ):
            raise GraphLineageVerificationError(
                "governed WEB Graph lineage differs from durable execution authority"
            )

    def _load_authorization(
        self,
        role: Literal["source", "validation"],
    ) -> ActionApprovalAuthorization:
        evidence = self.execution_evidence
        approval_id = (
            evidence.source_approval_id if role == "source" else evidence.validation_approval_id
        )
        approval_digest = (
            evidence.source_approval_digest
            if role == "source"
            else evidence.validation_approval_digest
        )
        receipt_id = (
            evidence.source_approval_receipt_id
            if role == "source"
            else evidence.validation_approval_receipt_id
        )
        receipt_digest = (
            evidence.source_approval_receipt_digest
            if role == "source"
            else evidence.validation_approval_receipt_digest
        )
        permit_id = (
            evidence.source_action_permit_id
            if role == "source"
            else evidence.validation_action_permit_id
        )
        permit_digest = (
            evidence.source_action_permit_digest
            if role == "source"
            else evidence.validation_action_permit_digest
        )
        request_id = (
            evidence.source_gateway_request_id
            if role == "source"
            else evidence.validation_gateway_request_id
        )
        request_digest = (
            evidence.source_gateway_request_digest
            if role == "source"
            else evidence.validation_gateway_request_digest
        )
        run_id = evidence.source_run_id if role == "source" else evidence.validation_run_id
        try:
            authorization = SQLiteGraphActionPermitStore.approved_authorization(
                self.permit_store,
                approval_id,
                permit_id,
            )
        except Exception as exc:
            raise GraphLineageVerificationError(
                "governed WEB durable approval authorization could not be reloaded"
            ) from exc
        if authorization is None:
            raise GraphLineageVerificationError(
                "governed WEB durable approval authorization is absent"
            )
        approval = authorization.approval
        permit = authorization.action.permit
        receipt = authorization.receipt
        if (
            authorization.action.newly_consumed is not False
            or approval.approval_id != approval_id
            or approval.approval_digest != approval_digest
            or approval.campaign_id != evidence.campaign_id
            or approval.campaign_digest != evidence.campaign_manifest_digest
            or approval.run_id != run_id
            or receipt.receipt_id != receipt_id
            or receipt.receipt_digest != receipt_digest
            or receipt.approval != approval
            or receipt.action_permit != permit
            or permit.permit_id != permit_id
            or permit.permit_digest != permit_digest
            or permit.campaign_id != evidence.campaign_id
            or permit.run_id != run_id
            or permit.request_id != request_id
            or permit.request_digest != request_digest
            or permit.target_digest != evidence.target_identity_digest
            or permit.capability.capability_id != evidence.capability_id
            or permit.capability.capability_version != evidence.capability_version
            or permit.capability.definition_digest != evidence.capability_digest
        ):
            raise GraphLineageVerificationError(
                "governed WEB durable Approval, Permit, or receipt differs"
            )
        return authorization


_GovernedGraphProposal = (
    SurfaceProposal | HypothesisProposal | ObservationProposal | CampaignFactProposal
)


class _GovernedWebBatchSnapshotLog:
    """Transaction-snapshot Event Log used only to preflight one atomic WEB batch."""

    def __init__(
        self,
        *,
        events: tuple[GraphAdmissionEvent, ...],
        nodes: dict[str, GraphNode],
    ) -> None:
        self._events = list(events)
        self._nodes = {key: value.model_copy(deep=True) for key, value in nodes.items()}
        self._attempts = {
            (event.proposal_id, event.proposal_digest): event.model_copy(deep=True)
            for event in events
        }
        self._first_digests: dict[str, str] = {}
        for event in events:
            self._first_digests.setdefault(event.proposal_id, event.proposal_digest)
        self._writer: object | None = None
        self._writer_identity: tuple[str, str] | None = None

    def claim_writer(self, authority_id: str, authority_digest: str) -> object:
        if self._writer is not None:
            raise ValueError("governed WEB batch snapshot writer is already claimed")
        if (authority_id, authority_digest) != (
            GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
            GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
        ):
            raise ValueError("governed WEB batch snapshot writer identity differs")
        self._writer = object()
        self._writer_identity = (authority_id, authority_digest)
        return self._writer

    def event_for_attempt(
        self,
        proposal_id: str,
        proposal_digest: str,
    ) -> GraphAdmissionEvent | None:
        event = self._attempts.get((proposal_id, proposal_digest))
        return event.model_copy(deep=True) if event is not None else None

    def first_proposal_digest(self, proposal_id: str) -> str | None:
        return self._first_digests.get(proposal_id)

    def next_position(self) -> tuple[int, str | None]:
        head = self._events[-1].event_digest if self._events else None
        return len(self._events) + 1, head

    def admitted_node(self, node_id: str) -> GraphNode | None:
        node = self._nodes.get(node_id)
        return node.model_copy(deep=True) if node is not None else None

    def append(self, event: GraphAdmissionEvent, *, writer: object) -> GraphAdmissionEvent:
        stored = GraphAdmissionEvent.model_validate(
            event.model_dump(mode="json", by_alias=True)
        )
        if writer is not self._writer or self._writer_identity != (
            stored.authority_id,
            stored.authority_digest,
        ):
            raise ValueError("governed WEB batch snapshot write authority differs")
        expected_sequence, expected_head = self.next_position()
        if (
            stored.sequence != expected_sequence
            or stored.previous_event_digest != expected_head
            or (stored.proposal_id, stored.proposal_digest) in self._attempts
            or stored.proposal_id in self._first_digests
        ):
            raise ValueError("governed WEB batch snapshot Event chain conflicts")
        proposed = {
            node.node_id: (node.campaign_id, GraphNodeKind(node.kind))
            for node in stored.admitted_nodes
        }
        for edge in stored.admitted_edges:
            for reference in (edge.source, edge.target):
                identity = proposed.get(reference.node_id)
                if identity is None:
                    existing = self._nodes.get(reference.node_id)
                    if existing is None:
                        raise ValueError("governed WEB batch contains a dangling Graph edge")
                    identity = (existing.campaign_id, GraphNodeKind(existing.kind))
                if identity != (reference.campaign_id, reference.kind):
                    raise ValueError("governed WEB batch Graph edge identity differs")
        for node in stored.admitted_nodes:
            existing = self._nodes.get(node.node_id)
            if existing is not None and existing != node:
                raise ValueError("governed WEB batch Graph node identity has equivocated")
        self._events.append(stored)
        self._attempts[(stored.proposal_id, stored.proposal_digest)] = stored
        self._first_digests[stored.proposal_id] = stored.proposal_digest
        for node in stored.admitted_nodes:
            self._nodes.setdefault(node.node_id, node.model_copy(deep=True))
        return stored.model_copy(deep=True)

    def events(self) -> tuple[GraphAdmissionEvent, ...]:
        return tuple(event.model_copy(deep=True) for event in self._events)


@final
class GovernedWebGraphAuthority(_ImmutableAuthority):
    """Factory-only authority for one all-or-none durable WEB Graph batch."""

    __slots__ = (
        "_campaign_id",
        "_event_log",
        "_event_writer",
        "_execution_evidence_digest",
        "_graph_database_authority",
        "_graph_file_identity",
        "_graph_path",
        "_graph_publication",
        "_graph_store",
        "_lock",
        "_permit_store",
        "_permit_verifier",
        "_promotion_digest",
    )

    def __init__(
        self,
        *,
        _factory_token: object,
        campaign_id: str,
        promotion_digest: str,
        execution_evidence_digest: str,
        graph_store: SQLiteGraphStore,
        graph_database_authority: GovernedGraphDatabaseAuthority | None,
        permit_verifier: GovernedWebPermitLineageVerifier,
        event_writer: object,
    ) -> None:
        if _factory_token is not _GRAPH_AUTHORITY_FACTORY_TOKEN:
            raise TypeError("governed WEB Graph authority requires its code-owned factory")
        self._campaign_id = campaign_id
        self._promotion_digest = promotion_digest
        self._execution_evidence_digest = execution_evidence_digest
        self._graph_store = graph_store
        self._graph_database_authority = graph_database_authority
        self._event_log = graph_store.event_log
        self._permit_store = graph_store.permit_store
        self._graph_path = graph_store.path
        self._graph_file_identity = (
            None
            if graph_database_authority is not None
            else _governed_graph_file_identity(self._graph_path)
        )
        self._graph_publication: PinnedSQLitePublication | None = None
        self._permit_verifier = permit_verifier
        self._event_writer = event_writer
        self._lock = threading.RLock()
        self._require_factory_binding()
        self._freeze_authority()

    @property
    def campaign_id(self) -> str:
        return self._campaign_id

    @property
    def promotion_digest(self) -> str:
        return self._promotion_digest

    @property
    def execution_evidence_digest(self) -> str:
        return self._execution_evidence_digest

    @property
    def graph_store(self) -> SQLiteGraphStore:
        return self._graph_store

    @property
    def permit_verifier(self) -> GovernedWebPermitLineageVerifier:
        return self._permit_verifier

    def freeze_and_bind_database(self) -> PinnedSQLitePublication:
        """Freeze one exact live pinned Graph DB and retain its final file identity."""

        with self._lock:
            self._require_factory_binding()
            authority = self._graph_database_authority
            if authority is None:
                raise TypeError("governed WEB Graph authority has no live database authority")
            publication = authority.freeze_and_publish()
            identity = _governed_graph_file_identity(self._graph_path)
            if (
                publication.reference != self._graph_path.as_posix()
                or publication.sha256
                != sha256(
                    read_bounded_regular_bytes(
                        self._graph_path,
                        max_bytes=64 * 1024 * 1024,
                        label="governed WEB frozen Graph database",
                        require_single_link=True,
                    )
                ).hexdigest()
            ):
                raise ValueError("governed WEB frozen Graph publication differs")
            object.__setattr__(self, "_graph_publication", publication)
            object.__setattr__(self, "_graph_file_identity", identity)
            self._require_factory_binding()
            return publication

    def _require_factory_binding(self) -> None:
        live_authority = self._graph_database_authority
        live_unfrozen = live_authority is not None and self._graph_publication is None
        if (
            type(self._graph_store) is not SQLiteGraphStore
            or self._graph_store.path != self._graph_path
            or self._graph_store.event_log is not self._event_log
            or self._graph_store.permit_store is not self._permit_store
            or type(self._permit_verifier) is not GovernedWebPermitLineageVerifier
            or self._execution_evidence_digest
            != self._permit_verifier.execution_evidence_digest
            or self._graph_store.campaign_id != self._campaign_id
            or getattr(self._event_log, "_campaign_id", None) != self._campaign_id
            or getattr(self._permit_store, "_campaign_id", None) != self._campaign_id
            or self._permit_verifier.permit_store is not self._permit_store
            or self._permit_verifier.grant_consumption_store.campaign_id
            != self._campaign_id
            or self._event_log.path != self._graph_path
            or self._permit_store.path != self._graph_path
            or getattr(self._event_log, "_writer", None) is not self._event_writer
            or getattr(self._event_log, "_writer_identity", None)
            != (
                GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
                GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
            )
        ):
            raise ValueError("governed WEB Graph authority binding differs from its factory")
        if live_authority is None:
            if (
                self._graph_publication is not None
                or self._graph_file_identity is None
                or _governed_graph_file_identity(self._graph_path)
                != self._graph_file_identity
            ):
                raise ValueError("governed WEB Graph authority binding differs from its factory")
        elif (
            type(live_authority) is not GovernedGraphDatabaseAuthority
            or live_authority.store is not self._graph_store
        ):
            raise ValueError("governed WEB live Graph authority differs from its factory")
        elif live_unfrozen:
            if self._graph_file_identity is not None or self._graph_path.exists():
                raise ValueError("governed WEB live Graph database was published out of band")
            try:
                live_authority.latest_checkpoint()
            except Exception as exc:
                raise ValueError("governed WEB live Graph database is unavailable") from exc
        else:
            publication = self._graph_publication
            if (
                publication is None
                or self._graph_file_identity is None
                or publication.reference != self._graph_path.as_posix()
                or _governed_graph_file_identity(self._graph_path)
                != self._graph_file_identity
            ):
                raise ValueError("governed WEB frozen Graph authority differs from its factory")
        _require_unshadowed_methods(
            self._event_log,
            (
                "claim_writer",
                "event_for_attempt",
                "events",
                "next_position",
            ),
            label="durable Graph Event Log",
        )
        _require_unshadowed_methods(
            self._permit_store,
            ("approved_authorization", "permit", "permits"),
            label="durable Graph Permit store",
        )
        _require_unshadowed_methods(
            self._permit_verifier.grant_consumption_store,
            ("receipt_for_grant", "_require_exact_runtime"),
            label="durable Grant consumption store",
        )
        _require_unshadowed_methods(
            self._permit_verifier,
            ("verify", "_load_authorization"),
            label="Permit lineage verifier",
        )

    def _require_durable_execution_lineage(self) -> None:
        self._require_factory_binding()
        GovernedWebPermitLineageVerifier._load_authorization(
            self._permit_verifier,
            "source",
        )
        GovernedWebPermitLineageVerifier._load_authorization(
            self._permit_verifier,
            "validation",
        )
        _require_governed_web_grant_consumption_bindings(
            self._permit_verifier.execution_evidence,
            self._permit_verifier.grant_consumption_store,
        )

    def _admit_atomic(
        self,
        proposals: tuple[_GovernedGraphProposal, ...],
    ) -> tuple[GraphAdmissionEvent, ...]:
        self._require_durable_execution_lineage()
        with self._lock:
            return _admit_governed_web_graph_batch(self, proposals)


def _governed_graph_file_identity(
    path: Path,
) -> tuple[tuple[int, int], tuple[int, int]]:
    parent = path.parent.lstat()
    opened = path.lstat()
    if (
        path.parent.is_symlink()
        or path.parent.is_junction()
        or path.is_symlink()
        or path.is_junction()
        or not stat.S_ISDIR(parent.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (
            os.name == "posix"
            and (
                parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) & 0o077
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            )
        )
    ):
        raise ValueError("governed WEB Graph database path identity is invalid")
    return (
        (parent.st_dev, parent.st_ino),
        (opened.st_dev, opened.st_ino),
    )


def _require_unshadowed_methods(
    instance: object,
    method_names: tuple[str, ...],
    *,
    label: str,
) -> None:
    instance_attributes = getattr(instance, "__dict__", None)
    if isinstance(instance_attributes, dict) and any(
        name in instance_attributes for name in method_names
    ):
        raise ValueError(f"governed WEB {label} contains an instance method override")
    for name in method_names:
        class_method = getattr(type(instance), name, None)
        bound_method = getattr(instance, name, None)
        if (
            class_method is None
            or bound_method is None
            or not callable(bound_method)
            or (
                bound_method is not class_method
                and getattr(bound_method, "__func__", None) is not class_method
            )
        ):
            raise TypeError(f"governed WEB {label} method binding is incomplete")


def governed_web_graph_producer_registration() -> GraphProducerRegistration:
    return GraphProducerRegistration(
        producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
        producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
        producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
        allowedProposalKinds=tuple(
            sorted(
                (
                    GraphProposalKind.CAMPAIGN_FACT,
                    GraphProposalKind.HYPOTHESIS,
                    GraphProposalKind.OBSERVATION,
                    GraphProposalKind.SURFACE,
                ),
                key=lambda item: item.value,
            )
        ),
    )


def create_governed_web_graph_authority(
    *,
    promotion: GovernedWebPromotionAuthority,
    graph_store: SQLiteGraphStore,
    grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore,
    graph_database_authority: GovernedGraphDatabaseAuthority | None = None,
) -> GovernedWebGraphAuthority:
    """Configure the fixed WEB-005 producer over a durable approved-Permit store."""

    if type(graph_store) is not SQLiteGraphStore:
        raise TypeError("governed WEB Graph authority requires one durable SQLite Graph store")
    canonical = _validated_promotion_authority(promotion)
    if (
        type(grant_consumption_store) is not WebAssessmentCapabilityGrantConsumptionStore
        or grant_consumption_store is not promotion._grant_consumption_store
    ):
        raise TypeError("governed WEB Graph authority requires the Promotion's durable Grant store")
    if graph_store.campaign_id != canonical.execution_evidence.campaign_id:
        raise ValueError("governed WEB Graph store belongs to another Campaign")
    if graph_database_authority is not None and (
        type(graph_database_authority) is not GovernedGraphDatabaseAuthority
        or graph_database_authority.store is not graph_store
    ):
        raise TypeError("governed WEB live Graph database authority differs")
    verifier = GovernedWebPermitLineageVerifier(
        permit_store=graph_store.permit_store,
        grant_consumption_store=grant_consumption_store,
        execution_evidence=canonical.execution_evidence,
    )
    _require_unshadowed_methods(
        graph_store.event_log,
        ("claim_writer", "event_for_attempt", "events", "next_position"),
        label="durable Graph Event Log",
    )
    event_writer = graph_store.event_log.claim_writer(
        GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
        GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
    )
    return GovernedWebGraphAuthority(
        _factory_token=_GRAPH_AUTHORITY_FACTORY_TOKEN,
        campaign_id=canonical.execution_evidence.campaign_id,
        promotion_digest=canonical.promotion_digest,
        execution_evidence_digest=canonical.execution_evidence.evidence_digest,
        graph_store=graph_store,
        graph_database_authority=graph_database_authority,
        permit_verifier=verifier,
        event_writer=event_writer,
    )


def _canonical_governed_web_graph_batch(
    proposals: tuple[_GovernedGraphProposal, ...],
) -> tuple[_GovernedGraphProposal, ...]:
    if not proposals:
        raise ValueError("governed WEB Graph batch cannot be empty")
    canonical = tuple(
        parse_graph_proposal(proposal.model_dump(mode="json", by_alias=True))
        for proposal in proposals
    )
    proposal_ids = [proposal.proposal_id for proposal in canonical]
    if len(proposal_ids) != len(set(proposal_ids)):
        raise ValueError("governed WEB Graph batch Proposal IDs are not unique")
    return canonical


def _load_exact_prior_governed_web_batch(
    connection: sqlite3.Connection,
    *,
    authority: GovernedWebGraphAuthority,
    canonical: tuple[_GovernedGraphProposal, ...],
    proposal_digests: tuple[str, ...],
) -> tuple[tuple[GraphAdmissionEvent, ...], tuple[GraphAdmissionEvent, ...] | None]:
    entry_events = _events_from_connection(
        connection,
        campaign_id=authority.campaign_id,
    )
    _require_exact_node_index(
        connection,
        campaign_id=authority.campaign_id,
        events=entry_events,
    )
    attempts = {(event.proposal_id, event.proposal_digest): event for event in entry_events}
    first_digests: dict[str, str] = {}
    for event in entry_events:
        first_digests.setdefault(event.proposal_id, event.proposal_digest)
    prior_events = tuple(
        attempts.get((proposal.proposal_id, digest))
        for proposal, digest in zip(canonical, proposal_digests, strict=True)
    )
    for proposal, digest in zip(canonical, proposal_digests, strict=True):
        first_digest = first_digests.get(proposal.proposal_id)
        if first_digest is not None and first_digest != digest:
            raise ValueError("governed WEB Graph batch Proposal ID has equivocated")
    if not any(event is not None for event in prior_events):
        return entry_events, None
    if not all(event is not None for event in prior_events):
        raise ValueError("governed WEB Graph batch was only partially recorded")
    exact_prior = tuple(cast(GraphAdmissionEvent, event) for event in prior_events)
    first_sequence = exact_prior[0].sequence
    expected_sequences = list(range(first_sequence, first_sequence + len(exact_prior)))
    authority_differs = any(
        event.decision is not GraphAdmissionDecision.ADMITTED
        or event.authority_id != GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID
        or event.authority_digest != GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST
        or event.producer_id != GOVERNED_WEB_GRAPH_PRODUCER_ID
        or event.producer_version != GOVERNED_WEB_GRAPH_PRODUCER_VERSION
        or event.producer_digest != GOVERNED_WEB_GRAPH_PRODUCER_DIGEST
        or event.proposal_id != proposal.proposal_id
        or event.proposal_digest != digest
        for event, proposal, digest in zip(
            exact_prior,
            canonical,
            proposal_digests,
            strict=True,
        )
    )
    if [event.sequence for event in exact_prior] != expected_sequences or authority_differs:
        raise ValueError("governed WEB prior Graph batch authority differs")
    return entry_events, exact_prior


def _stage_governed_web_graph_batch(
    *,
    authority: GovernedWebGraphAuthority,
    canonical: tuple[_GovernedGraphProposal, ...],
    proposal_digests: tuple[str, ...],
    entry_events: tuple[GraphAdmissionEvent, ...],
    admitted_at: datetime,
) -> tuple[GraphAdmissionEvent, ...]:
    existing_nodes: dict[str, GraphNode] = {}
    for event in entry_events:
        if event.decision is GraphAdmissionDecision.ADMITTED:
            for node in event.admitted_nodes:
                existing_nodes.setdefault(node.node_id, node.model_copy(deep=True))
    snapshot_log = _GovernedWebBatchSnapshotLog(
        events=entry_events,
        nodes=existing_nodes,
    )
    preflight = GraphAdmissionAuthority(
        campaign_id=authority.campaign_id,
        authority_id=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
        authority_digest=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
        producers=GraphProducerRegistry([governed_web_graph_producer_registration()]),
        lineage_verifier=authority.permit_verifier,
        event_log=snapshot_log,
        clock=lambda: admitted_at,
    )
    _require_unshadowed_methods(
        preflight,
        ("_rejection_reason", "_materialize", "_edges_resolve", "_new_event"),
        label="Graph batch preflight authority",
    )
    for proposal, proposal_digest in zip(canonical, proposal_digests, strict=True):
        reason = preflight._rejection_reason(
            proposal,
            proposal_digest=proposal_digest,
            expected_event_log_head_digest=None,
        )
        if reason is not None:
            raise ValueError(f"governed WEB Graph batch Proposal was rejected: {reason.value}")
        nodes, edges = preflight._materialize(proposal)
        if not preflight._edges_resolve(nodes, edges):
            raise ValueError(
                "governed WEB Graph batch Proposal was rejected: "
                f"{GraphAdmissionReason.DANGLING_EDGE.value}"
            )
        event = preflight._new_event(
            proposal,
            proposal_digest,
            decision=GraphAdmissionDecision.ADMITTED,
            reason=GraphAdmissionReason.ADMITTED,
            nodes=nodes,
            edges=edges,
        )
        snapshot_log.append(event, writer=preflight._event_writer)
    staged_events = snapshot_log.events()[len(entry_events) :]
    if len(staged_events) != len(canonical):
        raise ValueError("governed WEB Graph batch preflight count differs")
    return staged_events


def _persist_governed_web_graph_batch(
    connection: sqlite3.Connection,
    *,
    authority: GovernedWebGraphAuthority,
    entry_events: tuple[GraphAdmissionEvent, ...],
    staged_events: tuple[GraphAdmissionEvent, ...],
) -> None:
    for event in staged_events:
        connection.execute(
            """
            INSERT INTO graph_events (
                sequence, event_id, event_digest, previous_event_digest,
                proposal_id, proposal_digest, decision, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.sequence,
                event.event_id,
                event.event_digest,
                event.previous_event_digest,
                event.proposal_id,
                event.proposal_digest,
                event.decision.value,
                sqlite3.Binary(_event_bytes(event)),
            ),
        )
        for node in event.admitted_nodes:
            row = connection.execute(
                "SELECT * FROM graph_nodes WHERE node_id = ?",
                (node.node_id,),
            ).fetchone()
            if row is not None:
                if _node_from_row(row, campaign_id=authority.campaign_id) != node:
                    raise ValueError("governed WEB durable Graph node has equivocated")
                continue
            connection.execute(
                """
                INSERT INTO graph_nodes (
                    node_id, node_kind, admitted_sequence, node_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    node.node_id,
                    GraphNodeKind(node.kind).value,
                    event.sequence,
                    sqlite3.Binary(_node_bytes(node)),
                ),
            )
    persisted = _events_from_connection(
        connection,
        campaign_id=authority.campaign_id,
    )
    _require_exact_node_index(
        connection,
        campaign_id=authority.campaign_id,
        events=persisted,
    )
    if persisted[: len(entry_events)] != entry_events or persisted[len(entry_events) :] != (
        staged_events
    ):
        raise ValueError("governed WEB Graph batch durable reload differs")


def _admit_governed_web_graph_batch(
    authority: GovernedWebGraphAuthority,
    proposals: tuple[_GovernedGraphProposal, ...],
) -> tuple[GraphAdmissionEvent, ...]:
    canonical = _canonical_governed_web_graph_batch(proposals)
    produced_at = max(proposal.lineage.produced_at for proposal in canonical)
    admitted_at = _normalize_utc(
        _system_utc_now(),
        label="governed WEB Graph admission clock",
    )
    if admitted_at < produced_at:
        raise ValueError("governed WEB Graph admission clock predates its batch")

    with _write_transaction(authority.graph_store.path) as connection:
        _validate_schema(connection, campaign_id=authority.campaign_id)
        if _writer_identity(connection, "event") != (
            GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
            GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
        ):
            raise ValueError("governed WEB durable Graph writer authority differs")
        proposal_digests = tuple(proposal.digest() for proposal in canonical)
        entry_events, exact_prior = _load_exact_prior_governed_web_batch(
            connection,
            authority=authority,
            canonical=canonical,
            proposal_digests=proposal_digests,
        )
        if exact_prior is not None:
            return exact_prior
        staged_events = _stage_governed_web_graph_batch(
            authority=authority,
            canonical=canonical,
            proposal_digests=proposal_digests,
            entry_events=entry_events,
            admitted_at=admitted_at,
        )
        rechecked_events = _events_from_connection(
            connection,
            campaign_id=authority.campaign_id,
        )
        if rechecked_events != entry_events:
            raise ValueError("governed WEB Graph Event head changed during batch preflight")

        _persist_governed_web_graph_batch(
            connection,
            authority=authority,
            entry_events=entry_events,
            staged_events=staged_events,
        )
    reloaded = authority.graph_store.event_log.events()
    if reloaded[-len(staged_events) :] != staged_events:
        raise ValueError("governed WEB Graph batch changed after commit")
    return staged_events


class GovernedWebGraphEventReference(_FrozenStrictModel):
    sequence: int = Field(strict=True, ge=1)
    event_id: str = Field(alias="eventId", pattern=r"^graph-admission-event_[a-f0-9]{64}$")
    event_digest: str = Field(alias="eventDigest", pattern=_SHA256_PATTERN)
    proposal_id: str = Field(alias="proposalId", pattern=_IDENTIFIER_PATTERN)
    proposal_digest: str = Field(alias="proposalDigest", pattern=_SHA256_PATTERN)


class GovernedWebGraphAdmission(_FrozenStrictModel):
    api_version: Literal["pajin.dev/governed-web-graph-admission/v1alpha1"] = Field(
        default="pajin.dev/governed-web-graph-admission/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["GovernedWebGraphAdmission"] = "GovernedWebGraphAdmission"
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    promotion_digest: str = Field(alias="promotionDigest", pattern=_SHA256_PATTERN)
    execution_evidence_digest: str = Field(
        alias="executionEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    events: tuple[GovernedWebGraphEventReference, ...] = Field(min_length=1, max_length=20)
    surface_node_id: str = Field(alias="surfaceNodeId", pattern=_IDENTIFIER_PATTERN)
    hypothesis_node_ids: dict[IssueCheck, str] = Field(alias="hypothesisNodeIds")
    finding_fact_node_ids: dict[str, str] = Field(alias="findingFactNodeIds")

    @model_validator(mode="after")
    def bind_admission(self) -> Self:
        sequences = [event.sequence for event in self.events]
        if sequences != list(range(sequences[0], sequences[0] + len(sequences))):
            raise ValueError("governed WEB Graph admission Events are not contiguous")
        if len({event.event_id for event in self.events}) != len(self.events):
            raise ValueError("governed WEB Graph admission Event IDs are not unique")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_digest"},
        )
        expected = _canonical_digest("pajin.web.governed-graph-admission/v1", material)
        if self.admission_digest and self.admission_digest != expected:
            raise ValueError("governed WEB Graph admission Digest differs")
        object.__setattr__(self, "admission_digest", expected)
        return self


@final
class GovernedWebGraphAdmissionAuthority(_ImmutableAuthority):
    """Opaque proof that one exact WEB batch exists in the durable Event Log."""

    __slots__ = (
        "_admission",
        "_events",
        "_factory_token",
        "_graph_authority",
        "_proposals",
    )

    def __init__(
        self,
        *,
        _factory_token: object,
        admission: GovernedWebGraphAdmission,
        events: tuple[GraphAdmissionEvent, ...],
        graph_authority: GovernedWebGraphAuthority,
        proposals: tuple[_GovernedGraphProposal, ...],
    ) -> None:
        if _factory_token is not _GRAPH_ADMISSION_AUTHORITY_FACTORY_TOKEN:
            raise TypeError("governed WEB Graph admission requires its code-owned batch gate")
        if (
            type(admission) is not GovernedWebGraphAdmission
            or type(graph_authority) is not GovernedWebGraphAuthority
        ):
            raise TypeError("governed WEB Graph admission authority inputs are not canonical")
        self._factory_token = _factory_token
        self._admission = GovernedWebGraphAdmission.model_validate(
            admission.model_dump(mode="json", by_alias=True)
        )
        self._events = tuple(
            GraphAdmissionEvent.model_validate(event.model_dump(mode="json", by_alias=True))
            for event in events
        )
        self._graph_authority = graph_authority
        self._proposals = tuple(
            parse_graph_proposal(proposal.model_dump(mode="json", by_alias=True))
            for proposal in proposals
        )
        self._require_durable_reload()
        self._freeze_authority()

    @property
    def admission(self) -> GovernedWebGraphAdmission:
        return self._admission.model_copy(deep=True)

    @property
    def events(self) -> tuple[GraphAdmissionEvent, ...]:
        return tuple(event.model_copy(deep=True) for event in self._events)

    @property
    def proposals(self) -> tuple[_GovernedGraphProposal, ...]:
        return tuple(
            parse_graph_proposal(proposal.model_dump(mode="json", by_alias=True))
            for proposal in self._proposals
        )

    @property
    def surface_node_id(self) -> str:
        return self._admission.surface_node_id

    @property
    def hypothesis_node_ids(self) -> dict[IssueCheck, str]:
        return dict(self._admission.hypothesis_node_ids)

    @property
    def finding_fact_node_ids(self) -> dict[str, str]:
        return dict(self._admission.finding_fact_node_ids)

    def _require_durable_reload(self) -> None:
        self._graph_authority._require_durable_execution_lineage()
        if self._admission.promotion_digest != self._graph_authority.promotion_digest:
            raise ValueError("governed WEB Graph admission belongs to another Promotion")
        references = tuple(
            GovernedWebGraphEventReference(
                sequence=event.sequence,
                eventId=event.event_id,
                eventDigest=event.event_digest,
                proposalId=event.proposal_id,
                proposalDigest=event.proposal_digest,
            )
            for event in self._events
        )
        if (
            references != self._admission.events
            or len(self._proposals) != len(self._events)
            or any(
                proposal.proposal_id != event.proposal_id
                or proposal.digest() != event.proposal_digest
                for proposal, event in zip(self._proposals, self._events, strict=True)
            )
            or any(
            event.decision is not GraphAdmissionDecision.ADMITTED
            or event.authority_id != GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID
            or event.authority_digest != GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST
            or event.producer_id != GOVERNED_WEB_GRAPH_PRODUCER_ID
            or event.producer_version != GOVERNED_WEB_GRAPH_PRODUCER_VERSION
            or event.producer_digest != GOVERNED_WEB_GRAPH_PRODUCER_DIGEST
            for event in self._events
            )
        ):
            raise ValueError("governed WEB Graph admission Event authority differs")
        event_log = self._graph_authority.graph_store.event_log
        if type(event_log) is not SQLiteGraphEventLog:
            raise TypeError("governed WEB Graph admission requires the exact durable Event Log")
        durable_events = SQLiteGraphEventLog.events(event_log)
        by_id = {event.event_id: event for event in durable_events}
        if tuple(by_id.get(event.event_id) for event in self._events) != self._events:
            raise ValueError("governed WEB Graph admission is absent from the durable Event Log")


def _validated_graph_admission_authority(
    promotion: GovernedWebPromotion,
    authority: GovernedWebGraphAdmissionAuthority,
) -> GovernedWebGraphAdmission:
    if type(authority) is not GovernedWebGraphAdmissionAuthority:
        raise TypeError("governed WEB validation requires Graph admission authority")
    authority._require_durable_reload()
    admission = authority.admission
    if (
        admission.campaign_id != promotion.execution_evidence.campaign_id
        or admission.promotion_digest != promotion.promotion_digest
        or admission.execution_evidence_digest
        != promotion.execution_evidence.evidence_digest
    ):
        raise ValueError("governed WEB Graph admission belongs to another Promotion")
    return admission


def _graph_observation_proposal(
    *,
    role: Literal["source", "validation"],
    lineage: GraphProposalLineage,
    statuses: dict[IssueCheck, IssueStatus],
    hypotheses: dict[IssueCheck, GraphHypothesis],
    result_digest: str,
    executed_at: datetime,
    campaign_id: str,
    tool_id: str,
    target_digest: str,
) -> ObservationProposal:
    permit_id = lineage.action_permit_id
    permit_digest = lineage.action_permit_digest
    capability_id = lineage.capability_id
    capability_version = lineage.capability_version
    capability_digest = lineage.capability_digest
    if (
        permit_id is None
        or permit_digest is None
        or capability_id is None
        or capability_version is None
        or capability_digest is None
    ):  # pragma: no cover - guarded by GraphProposalLineage
        raise ValueError("governed WEB observation lineage lacks Permit authority")
    action = GraphAction(
        campaignId=campaign_id,
        requestId=lineage.request_id,
        requestDigest=lineage.request_digest,
        authorityKind=GraphAuthorityKind.ACTION_PERMIT,
        authorityId=permit_id,
        authorityDigest=permit_digest,
        capabilityId=capability_id,
        capabilityVersion=capability_version,
        capabilityDigest=capability_digest,
        toolId=tool_id,
        targetDigest=target_digest,
        status=GraphActionStatus.SUCCEEDED,
        executedAt=executed_at,
    )
    observation = GraphObservation(
        campaignId=campaign_id,
        observationType=f"web.{role}-execution",
        summary=(
            f"The {role} sealed browser execution completed under its exact ActionPermit "
            "and signed target observation."
        ),
        valueDigest=result_digest,
        producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
        producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
        producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
        origin=GraphContentOrigin.TARGET_DERIVED,
        confidence=1.0,
        observedAt=executed_at,
    )
    binding = lineage.evidence[0]
    evidence_node = GraphEvidence(
        campaignId=campaign_id,
        reference=binding.reference,
        sha256=binding.sha256,
        sourceRootDigest=lineage.source_root_digest,
        dataClassification="internal",
    )
    edges = [
        GraphEdge(
            campaignId=campaign_id,
            relation=GraphRelation.PRODUCES,
            source=graph_node_ref(action),
            target=graph_node_ref(observation),
            authorityId=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
            authorityDigest=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
        ),
        GraphEdge(
            campaignId=campaign_id,
            relation=GraphRelation.SUPPORTED_BY,
            source=graph_node_ref(observation),
            target=graph_node_ref(evidence_node),
            authorityId=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
            authorityDigest=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
        ),
    ]
    for check, hypothesis in hypotheses.items():
        status = statuses[check]
        if status == "inconclusive":
            continue
        edges.append(
            GraphEdge(
                campaignId=campaign_id,
                relation=(
                    GraphRelation.SUPPORTS
                    if status == "locally-reproduced"
                    else GraphRelation.CONTRADICTS
                ),
                source=graph_node_ref(observation),
                target=graph_node_ref(hypothesis),
                authorityId=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
                authorityDigest=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
            )
        )
    return ObservationProposal(
        proposalId=f"web-governed:{role}-observation:{observation.node_id[-24:]}",
        producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
        producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
        producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
        lineage=lineage,
        action=action,
        observation=observation,
        evidenceNodes=[evidence_node],
        edges=sorted(edges, key=lambda item: item.edge_id),
    )


def admit_governed_web_graph(
    *,
    promotion: GovernedWebPromotionAuthority,
    graph_authority: GovernedWebGraphAuthority,
) -> GovernedWebGraphAdmissionAuthority:
    """Admit the governed WEB chain through a preconfigured durable authority."""

    canonical = _validated_promotion_authority(promotion)
    if type(graph_authority) is not GovernedWebGraphAuthority:
        raise TypeError("governed WEB Graph admission requires its code-owned authority binding")
    graph_authority._require_factory_binding()
    evidence = canonical.execution_evidence
    if (
        graph_authority.campaign_id != evidence.campaign_id
        or graph_authority.promotion_digest != canonical.promotion_digest
        or graph_authority.execution_evidence_digest != evidence.evidence_digest
    ):
        raise ValueError("governed WEB Graph authority belongs to another Promotion")
    campaign_id = evidence.campaign_id
    produced_at = canonical.promoted_at
    agent_id = GOVERNED_WEB_GRAPH_AGENT_ID
    task_id = f"task:web-governed:{canonical.promotion_digest[:24]}"
    target_id = f"target:web:{evidence.target_identity_digest[:24]}"
    tool_id = graph_authority.permit_verifier.tool_id
    source_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=evidence.source_run_id,
        agentId=agent_id,
        taskId=task_id,
        requestId=evidence.source_gateway_request_id,
        requestDigest=evidence.source_gateway_request_digest,
        capabilityGrantId=evidence.source_capability_grant_id,
        capabilityGrantDigest=evidence.source_capability_grant_digest,
        capabilityId=evidence.capability_id,
        capabilityVersion=evidence.capability_version,
        capabilityDigest=evidence.capability_digest,
        actionPermitId=evidence.source_action_permit_id,
        actionPermitDigest=evidence.source_action_permit_digest,
        sourceRootDigest=evidence.source_root_digest,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/web-source-result.json",
                sha256=evidence.source_result_digest,
            )
        ],
        producedAt=produced_at,
    )
    validation_lineage = GraphProposalLineage(
        campaignId=campaign_id,
        runId=evidence.validation_run_id,
        agentId=agent_id,
        taskId=task_id,
        requestId=evidence.validation_gateway_request_id,
        requestDigest=evidence.validation_gateway_request_digest,
        capabilityGrantId=evidence.validation_capability_grant_id,
        capabilityGrantDigest=evidence.validation_capability_grant_digest,
        capabilityId=evidence.capability_id,
        capabilityVersion=evidence.capability_version,
        capabilityDigest=evidence.capability_digest,
        actionPermitId=evidence.validation_action_permit_id,
        actionPermitDigest=evidence.validation_action_permit_digest,
        sourceRootDigest=evidence.validation_root_digest,
        evidence=[
            GraphEvidenceBinding(
                reference="evidence/web-validation-result.json",
                sha256=evidence.validation_result_digest,
            )
        ],
        producedAt=produced_at,
    )
    surface = GraphSurface(
        campaignId=campaign_id,
        targetId=target_id,
        surfaceType="web.application",
        locatorSchema="pajin.web.exact-origin.v1",
        locatorDigest=evidence.target_identity_digest,
        origin=GraphContentOrigin.TRUSTED_CORE,
    )
    surface_proposal = SurfaceProposal(
        proposalId=f"web-governed:surface:{surface.node_id[-24:]}",
        producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
        producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
        producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
        lineage=source_lineage,
        surface=surface,
    )
    hypotheses: dict[IssueCheck, GraphHypothesis] = {}
    hypothesis_proposals: list[HypothesisProposal] = []
    source_status = {claim.check: claim.source_status for claim in canonical.claims}
    for check in ("sql-login", "object-access", "dom-xss"):
        hypothesis_type, statement, expected = _CHECK_HYPOTHESIS[check]
        hypothesis = GraphHypothesis(
            campaignId=campaign_id,
            hypothesisType=hypothesis_type,
            statement=statement,
            expectedObservable=expected,
            producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
            producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
            producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
            origin=GraphContentOrigin.TRUSTED_CORE,
            confidence=0.99 if source_status[check] == "locally-reproduced" else 0.5,
        )
        edge = GraphEdge(
            campaignId=campaign_id,
            relation=GraphRelation.MOTIVATES,
            source=graph_node_ref(surface),
            target=graph_node_ref(hypothesis),
            authorityId=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
            authorityDigest=GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
        )
        hypotheses[check] = hypothesis
        hypothesis_proposals.append(
            HypothesisProposal(
                proposalId=f"web-governed:hypothesis:{hypothesis.node_id[-24:]}",
                producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
                producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
                producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
                lineage=source_lineage,
                hypothesis=hypothesis,
                edges=[edge],
            )
        )

    source_observation_proposal = _graph_observation_proposal(
        role="source",
        lineage=source_lineage,
        statuses=source_status,
        hypotheses=hypotheses,
        result_digest=evidence.source_result_digest,
        executed_at=evidence.source_completed_at,
        campaign_id=campaign_id,
        tool_id=tool_id,
        target_digest=evidence.target_identity_digest,
    )
    validation_status = {claim.check: claim.validation_status for claim in canonical.claims}
    validation_observation_proposal = _graph_observation_proposal(
        role="validation",
        lineage=validation_lineage,
        statuses=validation_status,
        hypotheses=hypotheses,
        result_digest=evidence.validation_result_digest,
        executed_at=evidence.validation_completed_at,
        campaign_id=campaign_id,
        tool_id=tool_id,
        target_digest=evidence.target_identity_digest,
    )
    fact_proposals: list[CampaignFactProposal] = []
    for finding in canonical.findings:
        finding_digest = _canonical_digest(
            "pajin.web.governed-graph-finding/v1",
            finding.model_dump(mode="json"),
        )
        fact_proposals.append(
            CampaignFactProposal(
                proposalId=f"web-governed:finding:{finding_digest[:24]}",
                producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
                producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
                producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
                lineage=validation_lineage,
                fact=CampaignFactPayload(
                    factKey=f"finding.web.{finding_digest[:24]}",
                    statement=(
                        f"Validated Finding {finding.finding_id} is confirmed by independently "
                        "attested WEB executions."
                    ),
                    valueDigest=finding_digest,
                    producerId=GOVERNED_WEB_GRAPH_PRODUCER_ID,
                    producerVersion=GOVERNED_WEB_GRAPH_PRODUCER_VERSION,
                    producerDigest=GOVERNED_WEB_GRAPH_PRODUCER_DIGEST,
                    origin=GraphContentOrigin.TRUSTED_CORE,
                    recordedAt=produced_at,
                ),
            )
        )
    proposals: tuple[
        SurfaceProposal | HypothesisProposal | ObservationProposal | CampaignFactProposal,
        ...,
    ] = (
        surface_proposal,
        *hypothesis_proposals,
        source_observation_proposal,
        validation_observation_proposal,
        *fact_proposals,
    )
    events = graph_authority._admit_atomic(proposals)
    fact_events = events[-len(canonical.findings) :] if canonical.findings else ()
    finding_fact_node_ids = {
        finding.finding_id: event.admitted_nodes[0].node_id
        for finding, event in zip(canonical.findings, fact_events, strict=True)
    }
    admission = GovernedWebGraphAdmission(
        campaignId=evidence.campaign_id,
        promotionDigest=canonical.promotion_digest,
        executionEvidenceDigest=evidence.evidence_digest,
        events=tuple(
            GovernedWebGraphEventReference(
                sequence=event.sequence,
                eventId=event.event_id,
                eventDigest=event.event_digest,
                proposalId=event.proposal_id,
                proposalDigest=event.proposal_digest,
            )
            for event in events
        ),
        surfaceNodeId=surface.node_id,
        hypothesisNodeIds={check: node.node_id for check, node in hypotheses.items()},
        findingFactNodeIds=finding_fact_node_ids,
    )
    return GovernedWebGraphAdmissionAuthority(
        _factory_token=_GRAPH_ADMISSION_AUTHORITY_FACTORY_TOKEN,
        admission=admission,
        events=events,
        graph_authority=graph_authority,
        proposals=proposals,
    )


class RedactedGovernedWebPocManifest(_FrozenStrictModel):
    api_version: Literal["pajin.dev/governed-web-redacted-poc/v1alpha1"] = Field(
        default=GOVERNED_WEB_POC_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RedactedGovernedWebPocManifest"] = "RedactedGovernedWebPocManifest"
    manifest_digest: str = Field(default="", alias="manifestDigest", max_length=64)
    campaign_id: str = Field(
        alias="campaignId",
        pattern=r"^[a-z0-9][a-z0-9-]{2,79}$",
    )
    campaign_manifest_digest: str = Field(
        alias="campaignManifestDigest",
        pattern=_SHA256_PATTERN,
    )
    origin: str
    adapter_ref: str = Field(alias="adapterRef", pattern=_ADAPTER_REF_PATTERN)
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    target_identity_digest: str = Field(alias="targetIdentityDigest", pattern=_SHA256_PATTERN)
    source_assessment_run_id: str = Field(alias="sourceAssessmentRunId", pattern=_RUN_ID_PATTERN)
    source_assessment_root_digest: str = Field(
        alias="sourceAssessmentRootDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_assessment_run_id: str = Field(
        alias="validationAssessmentRunId",
        pattern=_RUN_ID_PATTERN,
    )
    validation_assessment_root_digest: str = Field(
        alias="validationAssessmentRootDigest",
        pattern=_SHA256_PATTERN,
    )
    promotion_digest: str = Field(alias="promotionDigest", pattern=_SHA256_PATTERN)
    graph_admission_digest: str = Field(alias="graphAdmissionDigest", pattern=_SHA256_PATTERN)
    validation_run_id: str = Field(alias="validationRunId", pattern=_RUN_ID_PATTERN)
    validation_root_digest: str = Field(alias="validationRootDigest", pattern=_SHA256_PATTERN)
    finding_set_digest: str = Field(alias="findingSetDigest", pattern=_SHA256_PATTERN)
    finding_count: int = Field(alias="findingCount", ge=0, le=3, strict=True)
    script_path: Literal["poc/reproduce.sh"] = Field(
        default="poc/reproduce.sh",
        alias="scriptPath",
    )
    script_sha256: str = Field(alias="scriptSha256", pattern=_SHA256_PATTERN)
    script_executable: Literal[True] = Field(default=True, alias="scriptExecutable")
    readme_path: Literal["poc/README.md"] = Field(
        default="poc/README.md",
        alias="readmePath",
    )
    readme_sha256: str = Field(alias="readmeSha256", pattern=_SHA256_PATTERN)
    credentials_embedded: Literal[False] = Field(default=False, alias="credentialsEmbedded")
    external_delivery_performed: Literal[False] = Field(
        default=False,
        alias="externalDeliveryPerformed",
    )

    @field_validator("origin")
    @classmethod
    def require_loopback_origin(cls, value: str) -> str:
        return local_origin(value)

    @model_validator(mode="after")
    def bind_manifest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"manifest_digest"},
        )
        expected = _canonical_digest("pajin.web.governed-redacted-poc/v1", material)
        if self.manifest_digest and self.manifest_digest != expected:
            raise ValueError("governed WEB redacted PoC Manifest Digest differs")
        object.__setattr__(self, "manifest_digest", expected)
        return self


def _render_redacted_governed_web_poc_script(*, origin: str, adapter_ref: str) -> str:
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        "OUTPUT_ROOT=${1:-./pajin-web-governed-output}\n"
        f"DEFAULT_ADAPTER_REF='{adapter_ref}'\n"
        'ADAPTER_REF=${ADAPTER_REF:-"$DEFAULT_ADAPTER_REF"}\n'
        "exec pajin web-campaign-run-governed-local "
        f'--origin {origin} --adapter-ref "$ADAPTER_REF" '
        '--authorized-local-lab --output "$OUTPUT_ROOT"\n'
    )


def _render_redacted_governed_web_poc_readme() -> str:
    return (
        "# Redacted governed web reproduction\n\n"
        "This bundle reruns the signed adapter against the exact approved loopback "
        "origin. Its manifest binds the independently sealed source and validation "
        "Runs, validated Finding set, and durable Graph admission. It contains no "
        "credentials, tokens, cookies, or external delivery destination. The operator "
        "must provide fresh local-lab authorization when the command runs.\n\n"
        "Run `./poc/reproduce.sh [output-directory]`. Set `ADAPTER_REF` only when the "
        "same signed adapter is installed under a deployment-specific reference.\n"
    )


def write_redacted_governed_web_poc(
    *,
    validation: GovernedWebValidationAuthority,
    output_directory: Path,
    origin: str,
    adapter_ref: str,
) -> RedactedGovernedWebPocManifest:
    """Atomically write one no-secret PoC bound to the full governed lineage."""

    if type(validation) is not GovernedWebValidationAuthority:
        raise TypeError("governed WEB PoC requires its opaque validation authority")
    origin = local_origin(origin)
    if re.fullmatch(_ADAPTER_REF_PATTERN, adapter_ref) is None:
        raise ValueError("governed WEB PoC adapter reference is invalid")
    def write_bundle(
        promotion: GovernedWebPromotion,
        graph_admission: GovernedWebGraphAdmission,
        export: VerifiedSarifExport,
        destination: _GovernedBundleDestination,
    ) -> RedactedGovernedWebPocManifest:
        evidence = promotion.execution_evidence
        if origin != evidence.target_origin or adapter_ref != evidence.adapter_ref:
            raise ValueError("governed WEB PoC target or signed adapter reference differs")
        script = _render_redacted_governed_web_poc_script(
            origin=origin,
            adapter_ref=adapter_ref,
        )
        readme = _render_redacted_governed_web_poc_readme()
        manifest = RedactedGovernedWebPocManifest(
            campaignId=evidence.campaign_id,
            campaignManifestDigest=evidence.campaign_manifest_digest,
            origin=origin,
            adapterRef=adapter_ref,
            adapterDigest=evidence.adapter_digest,
            targetIdentityDigest=evidence.target_identity_digest,
            sourceAssessmentRunId=evidence.source_run_id,
            sourceAssessmentRootDigest=evidence.source_root_digest,
            validationAssessmentRunId=evidence.validation_run_id,
            validationAssessmentRootDigest=evidence.validation_root_digest,
            promotionDigest=promotion.promotion_digest,
            graphAdmissionDigest=graph_admission.admission_digest,
            validationRunId=validation.run_id,
            validationRootDigest=validation.final_root_digest,
            findingSetDigest=export.finding_set_digest,
            findingCount=export.finding_count,
            scriptSha256=sha256(script.encode("utf-8")).hexdigest(),
            readmeSha256=sha256(readme.encode("utf-8")).hexdigest(),
        )
        staging_name, staging_fd, staging_identity = destination.create_staging()
        try:
            _mkdir_private_at(staging_fd, "poc", label="governed WEB PoC directory")
            poc_fd = _open_directory_at(
                staging_fd,
                "poc",
                label="governed WEB PoC directory",
            )
            try:
                manifest_bytes = _canonical_json_document(
                    manifest.model_dump(mode="json", by_alias=True),
                    label="governed WEB PoC manifest",
                )
                _write_bundle_file_at(
                    poc_fd,
                    "reproduce.sh",
                    script.encode("utf-8"),
                    mode=0o700,
                    label="governed WEB PoC script",
                )
                _write_bundle_file_at(
                    poc_fd,
                    "README.md",
                    readme.encode("utf-8"),
                    mode=0o600,
                    label="governed WEB PoC README",
                )
                _write_bundle_file_at(
                    poc_fd,
                    "manifest.json",
                    manifest_bytes,
                    mode=0o600,
                    label="governed WEB PoC manifest",
                )
                if (
                    _read_bundle_file_at(
                        poc_fd,
                        "reproduce.sh",
                        max_bytes=64 * 1024,
                        label="governed WEB PoC script",
                    )
                    != script.encode("utf-8")
                    or _read_bundle_file_at(
                        poc_fd,
                        "README.md",
                        max_bytes=64 * 1024,
                        label="governed WEB PoC README",
                    )
                    != readme.encode("utf-8")
                    or _read_bundle_file_at(
                        poc_fd,
                        "manifest.json",
                        max_bytes=_MAX_POC_MANIFEST_BYTES,
                        label="governed WEB PoC manifest",
                    )
                    != manifest_bytes
                    or set(os.listdir(poc_fd))
                    != {"reproduce.sh", "README.md", "manifest.json"}
                ):
                    raise ValueError("governed WEB PoC bundle differs after staging reload")
            finally:
                os.close(poc_fd)
            if set(os.listdir(staging_fd)) != {"poc"}:
                raise ValueError("governed WEB PoC staging inventory differs")
            destination.publish(
                staging_name,
                staging_fd,
                staging_identity,
                expected_files={
                    "poc/reproduce.sh": (script.encode("utf-8"), 0o700),
                    "poc/README.md": (readme.encode("utf-8"), 0o600),
                    "poc/manifest.json": (manifest_bytes, 0o600),
                },
            )
            return manifest
        finally:
            if staging_fd >= 0:
                os.close(staging_fd)
            destination.remove_if_present(
                staging_name,
                expected_identity=staging_identity,
            )

    return validation._perform_poc_once(output_directory, write_bundle)


def load_verified_redacted_governed_web_poc_manifest(
    path: Path,
    *,
    expected: RedactedGovernedWebPocManifest,
    bundle_root: Path,
) -> RedactedGovernedWebPocManifest:
    """Strictly reload a PoC manifest and its exact redacted file pair."""

    if type(expected) is not RedactedGovernedWebPocManifest:
        raise TypeError("governed WEB PoC reload requires its canonical expected manifest")
    raw = load_bounded_strict_json(
        path,
        max_bytes=_MAX_POC_MANIFEST_BYTES,
        label="governed WEB PoC manifest",
        require_single_link=True,
        max_depth=8,
        max_nodes=100,
    )
    manifest = RedactedGovernedWebPocManifest.model_validate(raw)
    root = bundle_root.resolve(strict=True)
    script_path = root / manifest.script_path
    readme_path = root / manifest.readme_path
    script = read_bounded_regular_bytes(
        script_path,
        max_bytes=64 * 1024,
        label="governed WEB PoC script",
        require_single_link=True,
    )
    readme = read_bounded_regular_bytes(
        readme_path,
        max_bytes=64 * 1024,
        label="governed WEB PoC README",
        require_single_link=True,
    )
    try:
        script_status = script_path.lstat()
        readme_status = readme_path.lstat()
        manifest_status = path.lstat()
    except OSError as exc:
        raise ValueError("governed WEB PoC bundle inventory is unavailable") from exc
    expected_script = _render_redacted_governed_web_poc_script(
        origin=manifest.origin,
        adapter_ref=manifest.adapter_ref,
    ).encode("utf-8")
    expected_readme = _render_redacted_governed_web_poc_readme().encode("utf-8")
    if (
        manifest != expected
        or script != expected_script
        or readme != expected_readme
        or sha256(script).hexdigest() != manifest.script_sha256
        or sha256(readme).hexdigest() != manifest.readme_sha256
        or not stat.S_ISREG(script_status.st_mode)
        or not stat.S_ISREG(readme_status.st_mode)
        or not stat.S_ISREG(manifest_status.st_mode)
        or stat.S_IMODE(script_status.st_mode) != 0o700
        or stat.S_IMODE(readme_status.st_mode) != 0o600
        or stat.S_IMODE(manifest_status.st_mode) != 0o600
        or set(path.relative_to(root).as_posix() for path in root.rglob("*"))
        != {"poc", manifest.script_path, manifest.readme_path, "poc/manifest.json"}
    ):
        raise ValueError("governed WEB PoC bundle differs from its validated lineage")
    return manifest


class GovernedWebDeliveryManifest(_FrozenStrictModel):
    api_version: Literal["pajin.dev/governed-web-delivery-manifest/v1alpha1"] = Field(
        default=GOVERNED_WEB_DELIVERY_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GovernedWebDeliveryManifest"] = "GovernedWebDeliveryManifest"
    manifest_digest: str = Field(default="", alias="manifestDigest", max_length=64)
    source_run_id: str = Field(alias="sourceRunId", pattern=_IDENTIFIER_PATTERN)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_SHA256_PATTERN)
    finding_set_digest: str = Field(alias="findingSetDigest", pattern=_SHA256_PATTERN)
    sarif_digest: str = Field(alias="sarifDigest", pattern=_SHA256_PATTERN)
    finding_count: int = Field(alias="findingCount", ge=0, le=1_000, strict=True)
    sarif_path: Literal["findings.sarif"] = Field(default="findings.sarif", alias="sarifPath")
    distinct_coordinator_record_supplied: Literal[False] = Field(
        default=False,
        alias="distinctCoordinatorRecordSupplied",
    )
    delivery_authorization_present: Literal[False] = Field(
        default=False,
        alias="deliveryAuthorizationPresent",
    )
    external_delivery_performed: Literal[False] = Field(
        default=False,
        alias="externalDeliveryPerformed",
    )
    delivery_receipt_authority: Literal[False] = Field(
        default=False,
        alias="deliveryReceiptAuthority",
    )
    delivery_record_state: None = Field(default=None, alias="deliveryRecordState")
    delivery_receipt_id: None = Field(default=None, alias="deliveryReceiptId")
    blocked_reason: str = Field(alias="blockedReason", min_length=1, max_length=500)
    prepared_at: datetime = Field(alias="preparedAt")

    @field_validator("prepared_at")
    @classmethod
    def normalize_prepared_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="governed WEB delivery manifest time")

    @field_validator(
        "distinct_coordinator_record_supplied",
        "delivery_authorization_present",
        "external_delivery_performed",
        "delivery_receipt_authority",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("governed WEB delivery markers must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_delivery_state(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"manifest_digest"},
        )
        expected = _canonical_digest("pajin.web.governed-delivery-readiness/v1", material)
        if self.manifest_digest and self.manifest_digest != expected:
            raise ValueError("governed WEB delivery Manifest Digest differs")
        object.__setattr__(self, "manifest_digest", expected)
        return self


@dataclass(frozen=True, slots=True)
class GovernedWebExportBundle:
    sarif: VerifiedSarifExport
    sarif_path: Path
    delivery_manifest: GovernedWebDeliveryManifest
    delivery_manifest_path: Path


def write_verified_governed_web_exports(
    *,
    validation: GovernedWebValidationAuthority,
    output_directory: Path,
    prepared_at: datetime,
) -> GovernedWebExportBundle:
    """Write verified SARIF outside the Run plus a non-dispatching delivery manifest."""

    if type(validation) is not GovernedWebValidationAuthority:
        raise TypeError("governed WEB export requires its opaque validation authority")
    prepared_at = _normalize_utc(prepared_at, label="governed WEB delivery manifest time")
    def write_pair(
        export: VerifiedSarifExport,
        destination: _GovernedBundleDestination,
    ) -> GovernedWebExportBundle:
        manifest = _delivery_manifest(export, prepared_at=prepared_at)
        sarif_bytes = export.content.encode("utf-8")
        manifest_bytes = _canonical_json_document(
            manifest.model_dump(mode="json", by_alias=True),
            label="governed WEB delivery-readiness manifest",
        )
        staging_name, staging_fd, staging_identity = destination.create_staging()
        try:
            if sha256(sarif_bytes).hexdigest() != export.sarif_digest:
                raise ValueError("governed WEB SARIF bytes differ from verified digest")
            _write_bundle_file_at(
                staging_fd,
                "findings.sarif",
                sarif_bytes,
                mode=0o600,
                label="governed WEB SARIF export",
            )
            _write_bundle_file_at(
                staging_fd,
                "delivery-readiness.json",
                manifest_bytes,
                mode=0o600,
                label="governed WEB delivery-readiness manifest",
            )
            if (
                _read_bundle_file_at(
                    staging_fd,
                    "findings.sarif",
                    max_bytes=_MAX_CANONICAL_BYTES,
                    label="governed WEB SARIF export",
                )
                != sarif_bytes
                or _read_bundle_file_at(
                    staging_fd,
                    "delivery-readiness.json",
                    max_bytes=_MAX_DELIVERY_MANIFEST_BYTES,
                    label="governed WEB delivery-readiness manifest",
                )
                != manifest_bytes
                or set(os.listdir(staging_fd))
                != {"findings.sarif", "delivery-readiness.json"}
            ):
                raise ValueError("governed WEB export pair differs after staging reload")
            bundle = GovernedWebExportBundle(
                sarif=export,
                sarif_path=destination.path / "findings.sarif",
                delivery_manifest=manifest,
                delivery_manifest_path=destination.path / "delivery-readiness.json",
            )
            destination.publish(
                staging_name,
                staging_fd,
                staging_identity,
                expected_files={
                    "findings.sarif": (sarif_bytes, 0o600),
                    "delivery-readiness.json": (manifest_bytes, 0o600),
                },
            )
            return bundle
        finally:
            if staging_fd >= 0:
                os.close(staging_fd)
            destination.remove_if_present(
                staging_name,
                expected_identity=staging_identity,
            )

    return validation._perform_export_once(output_directory, write_pair)


_DirectoryIdentity = tuple[int, int, int, int]


def _directory_identity(status: os.stat_result) -> _DirectoryIdentity:
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError("governed WEB bundle path component is not a directory")
    return status.st_dev, status.st_ino, status.st_mode, status.st_uid


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_directory_at(parent_fd: int, name: str, *, label: str) -> int:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ValueError(f"{label} has an invalid directory component")
    try:
        descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
        _directory_identity(os.fstat(descriptor))
        return descriptor
    except OSError as exc:
        raise ValueError(f"{label} is not an exact no-follow directory") from exc


def _mkdir_private_at(parent_fd: int, name: str, *, label: str) -> None:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ValueError(f"{label} has an invalid directory component")
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"{label} could not be created atomically") from exc
    if (
        not stat.S_ISDIR(status.st_mode)
        or (os.name == "posix" and status.st_uid != os.geteuid())
    ):
        raise ValueError(f"{label} is not a private owned directory")


def _open_bundle_parent(
    parent: Path,
    *,
    protected_identities: frozenset[tuple[int, int]],
    create: bool,
    label: str,
) -> tuple[int, _DirectoryIdentity]:
    if os.name != "posix" or not parent.is_absolute():
        raise ValueError(f"{label} requires an absolute POSIX destination")
    descriptor = os.open(parent.anchor, _directory_open_flags())
    try:
        current_identity = _directory_identity(os.fstat(descriptor))
        _reject_run_directory_ancestor(descriptor, label=label)
        components = parent.parts[1:]
        for component in components:
            if current_identity[:2] in protected_identities:
                raise ValueError(f"{label} destination overlaps a protected authority store")
            try:
                next_descriptor = os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise ValueError(f"{label} parent path changed") from None
                _mkdir_private_at(descriptor, component, label=f"{label} parent")
                next_descriptor = _open_directory_at(
                    descriptor,
                    component,
                    label=f"{label} parent",
                )
            except OSError as exc:
                raise ValueError(f"{label} parent contains an alias or changed") from exc
            os.close(descriptor)
            descriptor = next_descriptor
            current_identity = _directory_identity(os.fstat(descriptor))
            _reject_run_directory_ancestor(descriptor, label=label)
        if current_identity[:2] in protected_identities:
            raise ValueError(f"{label} destination overlaps a protected authority store")
        return descriptor, current_identity
    except BaseException:
        os.close(descriptor)
        raise


def _reject_run_directory_ancestor(descriptor: int, *, label: str) -> None:
    try:
        names = {unicodedata.normalize("NFC", name).casefold() for name in os.listdir(descriptor)}
    except OSError as exc:
        raise ValueError(f"{label} ancestor inventory is unavailable") from exc
    if {"events.jsonl", "run-integrity.jsonl"}.issubset(names):
        raise ValueError(f"{label} destination must not be inside any immutable Run")


def _opened_directory_ancestry(descriptor: int) -> tuple[tuple[int, int], ...]:
    current = os.dup(descriptor)
    identities: list[tuple[int, int]] = []
    try:
        while True:
            identity = _directory_identity(os.fstat(current))[:2]
            identities.append(identity)
            try:
                parent = os.open("..", _directory_open_flags(), dir_fd=current)
                _directory_identity(os.fstat(parent))
            except OSError as exc:
                raise ValueError(
                    "governed WEB output ancestry is not an exact no-follow directory"
                ) from exc
            parent_identity = _directory_identity(os.fstat(parent))[:2]
            if parent_identity == identity:
                os.close(parent)
                break
            os.close(current)
            current = parent
    finally:
        os.close(current)
    return tuple(identities)


def _protected_directory_identities(
    roots: tuple[Path, ...],
) -> frozenset[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    for root in roots:
        try:
            resolved = root.resolve(strict=True)
            status = resolved.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(status.st_mode):
            identities.add((status.st_dev, status.st_ino))
    return frozenset(identities)


def _write_bundle_file_at(
    directory_fd: int,
    name: str,
    content: bytes,
    *,
    mode: int,
    label: str,
) -> None:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ValueError(f"{label} has an invalid file name")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(name, flags, mode, dir_fd=directory_fd)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, mode)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - defensive OS contract
                raise OSError("governed WEB bundle write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or (os.name == "posix" and status.st_uid != os.geteuid())
            or stat.S_IMODE(status.st_mode) != mode
        ):
            raise ValueError(f"{label} is not an exact private regular file")
    except BaseException:
        with suppress(OSError):
            os.unlink(name, dir_fd=directory_fd)
        raise
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def _read_bundle_file_at(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or (os.name == "posix" and status.st_uid != os.geteuid())
        ):
            raise ValueError(f"{label} is not an exact private regular file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            raise ValueError(f"{label} exceeds its byte limit")
        return content
    finally:
        os.close(descriptor)


def _require_exact_bundle_inventory_at(
    directory_fd: int,
    *,
    expected_files: dict[str, tuple[bytes, int]],
    label: str,
) -> None:
    expected_directories: set[str] = set()
    for relative_path in expected_files:
        parts = Path(relative_path).parts
        if (
            not parts
            or Path(relative_path).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError(f"{label} expected inventory is invalid")
        for index in range(1, len(parts)):
            expected_directories.add("/".join(parts[:index]))

    observed_files: set[str] = set()
    observed_directories: set[str] = set()

    def walk(current_fd: int, prefix: str) -> None:
        for name in os.listdir(current_fd):
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise ValueError(f"{label} contains an invalid entry")
            relative = f"{prefix}/{name}" if prefix else name
            status = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISDIR(status.st_mode):
                if (
                    stat.S_IMODE(status.st_mode) != 0o700
                    or (os.name == "posix" and status.st_uid != os.geteuid())
                ):
                    raise ValueError(f"{label} contains a non-private directory")
                child_fd = _open_directory_at(current_fd, name, label=label)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
                        raise ValueError(f"{label} directory identity changed")
                    observed_directories.add(relative)
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
                continue
            expected = expected_files.get(relative)
            if expected is None or not stat.S_ISREG(status.st_mode):
                raise ValueError(f"{label} contains an unexpected entry")
            content, mode = expected
            if stat.S_IMODE(status.st_mode) != mode:
                raise ValueError(f"{label} file mode differs")
            observed = _read_bundle_file_at(
                current_fd,
                name,
                max_bytes=len(content),
                label=label,
            )
            if observed != content:
                raise ValueError(f"{label} file bytes differ")
            observed_files.add(relative)

    root = os.fstat(directory_fd)
    if (
        not stat.S_ISDIR(root.st_mode)
        or stat.S_IMODE(root.st_mode) != 0o700
        or (os.name == "posix" and root.st_uid != os.geteuid())
    ):
        raise ValueError(f"{label} root is not a private directory")
    walk(directory_fd, "")
    if observed_files != set(expected_files) or observed_directories != expected_directories:
        raise ValueError(f"{label} inventory differs")


def _remove_directory_tree_at(parent_fd: int, name: str) -> None:
    try:
        status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(status.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    descriptor = _open_directory_at(parent_fd, name, label="governed WEB staging cleanup")
    try:
        for child in os.listdir(descriptor):
            _remove_directory_tree_at(descriptor, child)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_fd)


def _rename_directory_no_replace_at(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source_name)
    encoded_destination = os.fsencode(destination_name)
    if os.uname().sysname == "Darwin":
        rename = library.renameatx_np
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(parent_fd, encoded_source, parent_fd, encoded_destination, 0x00000004)
    elif os.uname().sysname == "Linux":
        try:
            rename = library.renameat2
        except AttributeError as exc:  # pragma: no cover - old nonconforming libc
            raise OSError(errno.ENOTSUP, "atomic no-replace rename is unavailable") from exc
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(parent_fd, encoded_source, parent_fd, encoded_destination, 0x00000001)
    else:  # pragma: no cover - governed local browser runs target POSIX hosts
        raise OSError(errno.ENOTSUP, "atomic no-replace rename is unavailable")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError("governed WEB bundle destination already exists")
        raise OSError(error_number, os.strerror(error_number))


def _before_governed_bundle_publish(_destination: Path) -> None:
    """Test seam immediately before fd-relative publication."""


class _GovernedBundleDestination:
    __slots__ = (
        "_closed",
        "_expected_files",
        "_parent_fd",
        "_parent_identity",
        "_published",
        "_published_fd",
        "_published_identity",
        "label",
        "name",
        "path",
    )

    def __init__(
        self,
        *,
        path: Path,
        parent_fd: int,
        parent_identity: _DirectoryIdentity,
        label: str,
    ) -> None:
        self.path = path
        self.name = path.name
        self.label = label
        self._parent_fd = parent_fd
        self._parent_identity = parent_identity
        self._published = False
        self._published_fd = -1
        self._published_identity: _DirectoryIdentity | None = None
        self._expected_files: dict[str, tuple[bytes, int]] | None = None
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            if self._published_fd >= 0:
                os.close(self._published_fd)
                self._published_fd = -1
            os.close(self._parent_fd)
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError(f"{self.label} destination handle is closed")
        if _directory_identity(os.fstat(self._parent_fd)) != self._parent_identity:
            raise ValueError(f"{self.label} destination parent identity changed")

    def _require_current_path(self) -> None:
        self._require_open()
        descriptor, identity = _open_bundle_parent(
            self.path.parent,
            protected_identities=frozenset(),
            create=False,
            label=self.label,
        )
        os.close(descriptor)
        if identity != self._parent_identity:
            raise ValueError(f"{self.label} destination parent path changed")

    def create_staging(self) -> tuple[str, int, _DirectoryIdentity]:
        self._require_current_path()
        for _attempt in range(32):
            name = f".{self.name}.staging-{secrets.token_hex(12)}"
            try:
                _mkdir_private_at(self._parent_fd, name, label=f"{self.label} staging")
            except ValueError as exc:
                if isinstance(exc.__cause__, FileExistsError):
                    continue
                raise
            descriptor = _open_directory_at(
                self._parent_fd,
                name,
                label=f"{self.label} staging",
            )
            identity = _directory_identity(os.fstat(descriptor))
            named = _directory_identity(
                os.stat(name, dir_fd=self._parent_fd, follow_symlinks=False)
            )
            if identity != named:
                os.close(descriptor)
                raise ValueError(f"{self.label} staging identity changed")
            return name, descriptor, identity
        raise FileExistsError(f"{self.label} could not allocate unique staging")

    def remove_if_present(
        self,
        name: str,
        *,
        expected_identity: _DirectoryIdentity | None = None,
    ) -> None:
        self._require_open()
        if expected_identity is None:
            _remove_directory_tree_at(self._parent_fd, name)
            os.fsync(self._parent_fd)
            return
        try:
            named = _directory_identity(
                os.stat(name, dir_fd=self._parent_fd, follow_symlinks=False)
            )
        except (FileNotFoundError, ValueError):
            return
        if named != expected_identity:
            return
        descriptor = _open_directory_at(
            self._parent_fd,
            name,
            label=f"{self.label} cleanup",
        )
        try:
            if _directory_identity(os.fstat(descriptor)) != expected_identity:
                return
            for child in os.listdir(descriptor):
                _remove_directory_tree_at(descriptor, child)
        finally:
            os.close(descriptor)
        try:
            current = _directory_identity(
                os.stat(name, dir_fd=self._parent_fd, follow_symlinks=False)
            )
        except (FileNotFoundError, ValueError):
            return
        if current == expected_identity:
            os.rmdir(name, dir_fd=self._parent_fd)
        os.fsync(self._parent_fd)

    def publish(
        self,
        staging_name: str,
        staging_fd: int,
        staging_identity: _DirectoryIdentity,
        *,
        expected_files: dict[str, tuple[bytes, int]],
    ) -> None:
        self._require_open()
        if (
            _directory_identity(os.fstat(staging_fd)) != staging_identity
            or _directory_identity(
                os.stat(
                    staging_name,
                    dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
            )
            != staging_identity
        ):
            raise ValueError(f"{self.label} staging identity changed")
        _require_exact_bundle_inventory_at(
            staging_fd,
            expected_files=expected_files,
            label=f"{self.label} staging",
        )
        _before_governed_bundle_publish(self.path)
        self._require_current_path()
        if (
            _directory_identity(os.fstat(staging_fd)) != staging_identity
            or _directory_identity(
                os.stat(
                    staging_name,
                    dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
            )
            != staging_identity
        ):
            raise ValueError(f"{self.label} staging name changed before publication")
        try:
            os.stat(self.name, dir_fd=self._parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"{self.label} destination already exists")
        _rename_directory_no_replace_at(self._parent_fd, staging_name, self.name)
        self._published = True
        self._published_fd = os.dup(staging_fd)
        self._published_identity = staging_identity
        self._expected_files = dict(expected_files)
        os.fsync(self._parent_fd)
        try:
            self._require_current_path()
            self.published_identity()
        except BaseException:
            self.remove_if_present(self.name, expected_identity=staging_identity)
            self._published = False
            if self._published_fd >= 0:
                os.close(self._published_fd)
                self._published_fd = -1
            self._published_identity = None
            self._expected_files = None
            raise

    def published_identity(self) -> tuple[tuple[int, int], tuple[int, int]]:
        self._require_current_path()
        if not self._published:
            raise ValueError(f"{self.label} destination was not published")
        if (
            self._published_fd < 0
            or self._published_identity is None
            or self._expected_files is None
            or _directory_identity(os.fstat(self._published_fd))
            != self._published_identity
        ):
            raise ValueError(f"{self.label} published directory handle changed")
        status = os.stat(self.name, dir_fd=self._parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o700
            or (os.name == "posix" and status.st_uid != os.geteuid())
            or _directory_identity(status) != self._published_identity
        ):
            raise ValueError(f"{self.label} published directory identity is invalid")
        _require_exact_bundle_inventory_at(
            self._published_fd,
            expected_files=self._expected_files,
            label=f"{self.label} published bundle",
        )
        return self._parent_identity[:2], (status.st_dev, status.st_ino)


def _canonical_json_document(value: object, *, label: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > _MAX_CANONICAL_BYTES:
        raise ValueError(f"{label} exceeds its byte limit")
    return encoded


def _require_safe_governed_bundle_destination(
    validation: GovernedWebValidationAuthority,
    path: Path,
    *,
    label: str,
) -> _GovernedBundleDestination:
    requested = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    if not requested.name or requested.name in {".", ".."}:
        raise ValueError(f"{label} destination name is invalid")
    destination = _prospective_resolved_path(path, label=label)
    protected_roots = validation._protected_output_roots()
    for protected in protected_roots:
        protected_path = _prospective_resolved_path(
            protected,
            label="governed WEB protected authority root",
        )
        if (
            destination == protected_path
            or destination in protected_path.parents
            or protected_path in destination.parents
            or _paths_overlap_by_existing_identity(destination, protected_path)
        ):
            raise ValueError(f"{label} destination overlaps a protected authority store")
    protected_identities = _protected_directory_identities(protected_roots)
    parent_fd, parent_identity = _open_bundle_parent(
        requested.parent,
        protected_identities=protected_identities,
        create=True,
        label=label,
    )
    try:
        if protected_identities.intersection(_opened_directory_ancestry(parent_fd)):
            raise ValueError(f"{label} destination overlaps a protected authority store")
        try:
            os.stat(requested.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"{label} destination already exists")
        return _GovernedBundleDestination(
            path=requested,
            parent_fd=parent_fd,
            parent_identity=parent_identity,
            label=label,
        )
    except BaseException:
        os.close(parent_fd)
        raise


def _prospective_resolved_path(path: Path, *, label: str) -> Path:
    candidate = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    missing: list[str] = []
    cursor = candidate
    while not cursor.exists() and not cursor.is_symlink():
        if cursor.parent == cursor:
            raise ValueError(f"{label} has no existing filesystem ancestor")
        missing.append(cursor.name)
        cursor = cursor.parent
    try:
        resolved = cursor.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} contains an invalid filesystem alias") from exc
    for component in reversed(missing):
        resolved /= component
    return resolved


def _paths_overlap_by_existing_identity(candidate: Path, protected: Path) -> bool:
    candidate_exists, candidate_ancestry = _existing_path_ancestry(candidate)
    protected_exists, protected_ancestry = _existing_path_ancestry(protected)
    if not protected_exists:
        return False
    protected_identity = protected_ancestry[0]
    if protected_identity in candidate_ancestry:
        return True
    return candidate_exists and candidate_ancestry[0] in protected_ancestry


def _existing_path_ancestry(
    path: Path,
) -> tuple[bool, tuple[tuple[int, int], ...]]:
    requested_exists = path.exists()
    cursor = path
    while not cursor.exists():
        if cursor.parent == cursor:
            raise ValueError("governed WEB output path has no existing ancestor")
        cursor = cursor.parent
    resolved = cursor.resolve(strict=True)
    identities: list[tuple[int, int]] = []
    while True:
        status = resolved.lstat()
        identities.append((status.st_dev, status.st_ino))
        if resolved.parent == resolved:
            break
        resolved = resolved.parent
    return requested_exists, tuple(identities)


def _governed_bundle_root_identity(
    path: Path,
) -> tuple[tuple[int, int], tuple[int, int]]:
    parent = path.parent.lstat()
    opened = path.lstat()
    if (
        path.parent.is_symlink()
        or path.parent.is_junction()
        or path.is_symlink()
        or path.is_junction()
        or not stat.S_ISDIR(parent.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (
            os.name == "posix"
            and (
                parent.st_uid != os.geteuid()
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
            )
        )
    ):
        raise ValueError("governed WEB published bundle path identity is invalid")
    return (
        (parent.st_dev, parent.st_ino),
        (opened.st_dev, opened.st_ino),
    )


def _delivery_manifest(
    export: VerifiedSarifExport,
    *,
    prepared_at: datetime,
) -> GovernedWebDeliveryManifest:
    return GovernedWebDeliveryManifest(
        sourceRunId=export.source_run_id,
        sourceRootDigest=export.source_root_digest,
        findingSetDigest=export.finding_set_digest,
        sarifDigest=export.sarif_digest,
        findingCount=export.finding_count,
        blockedReason=(
            "WEB-005 does not accept external-delivery authority; a separate authorized "
            "coordinator must verify and deliver this export."
        ),
        preparedAt=prepared_at,
    )


def load_verified_governed_web_delivery_manifest(
    path: Path,
    *,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_finding_set_digest: str,
    expected_sarif_digest: str,
    expected_finding_count: int,
) -> GovernedWebDeliveryManifest:
    """Strictly reload one local-only, content-bound delivery-readiness manifest."""

    raw = load_bounded_strict_json(
        path,
        max_bytes=_MAX_DELIVERY_MANIFEST_BYTES,
        label="governed WEB delivery-readiness manifest",
        require_single_link=True,
        max_depth=8,
        max_nodes=100,
    )
    manifest = GovernedWebDeliveryManifest.model_validate(raw)
    if (
        manifest.source_run_id != expected_source_run_id
        or manifest.source_root_digest != expected_source_root_digest
        or manifest.finding_set_digest != expected_finding_set_digest
        or manifest.sarif_digest != expected_sarif_digest
        or manifest.finding_count != expected_finding_count
    ):
        raise ValueError("governed WEB delivery manifest belongs to another SARIF export")
    return manifest


__all__ = [
    "GOVERNED_WEB_EXECUTION_VERIFIER_ID",
    "GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST",
    "GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID",
    "GOVERNED_WEB_GRAPH_PRODUCER_DIGEST",
    "GOVERNED_WEB_GRAPH_PRODUCER_ID",
    "GOVERNED_WEB_GRAPH_PRODUCER_VERSION",
    "GovernedWebAttackPathConfirmation",
    "GovernedWebClaimReconciliation",
    "GovernedWebDeliveryManifest",
    "GovernedWebExecutionEvidence",
    "GovernedWebExecutionVerification",
    "GovernedWebExecutionVerifierBinding",
    "GovernedWebExportBundle",
    "GovernedWebGraphAdmission",
    "GovernedWebGraphAdmissionAuthority",
    "GovernedWebGraphAuthority",
    "GovernedWebGraphEventReference",
    "GovernedWebPermitLineageVerifier",
    "GovernedWebPromotion",
    "GovernedWebPromotionAuthority",
    "GovernedWebValidationAuthority",
    "RedactedGovernedWebPocManifest",
    "admit_governed_web_graph",
    "create_governed_web_execution_verifier_binding",
    "create_governed_web_graph_authority",
    "governed_web_execution_verifier_digest",
    "governed_web_graph_producer_registration",
    "load_verified_governed_web_delivery_manifest",
    "load_verified_redacted_governed_web_poc_manifest",
    "promote_governed_web_findings",
    "write_governed_web_validation_projection",
    "write_redacted_governed_web_poc",
    "write_verified_governed_web_exports",
]
