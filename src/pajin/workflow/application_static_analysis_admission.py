"""APP-001C sealed Application static-analysis knowledge admission."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from re import fullmatch
from typing import Annotated, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.application_static_analysis import (
    APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
    ApplicationStaticAnalysisCapabilityActivation,
    ApplicationStaticAnalysisOperation,
    ApplicationStaticAnalysisPreparation,
    ApplicationStaticAnalysisRequest,
    ApplicationStaticAnalysisSandboxBinding,
    ApplicationStaticAnalysisTool,
    ApplicationStaticParser,
    BoundedApplicationStaticAnalyzerAdapter,
    prepare_application_static_analysis,
    registered_application_static_analysis_binding,
)
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery.application_surfaces import (
    ApplicationArtifactRuntimeSurfaceRef,
    ApplicationSurfaceClass,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import CampaignManifest, StrictModel, campaign_manifest_digest
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphProducerRegistration,
    TrustedGraphLineageRegistry,
)
from pajin.graph.approval import (
    ActionApprovalConsumptionReceipt,
    build_action_approval_consumption_receipt,
)
from pajin.graph.authority import ActionPermit
from pajin.graph.domain_semantics import (
    MultiDomainGraphSemanticsError,
    SecurityDomainGraphTypeSetRef,
    resolve_registered_security_domain_graph_type_set,
)
from pajin.graph.models import (
    GraphAction,
    GraphActionStatus,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphNodeKind,
    GraphObservation,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    HypothesisProposal,
    ObservationProposal,
    graph_digest,
    graph_node_ref,
)
from pajin.graph.projection import GraphSnapshotRef, graph_snapshot_ref
from pajin.graph.sqlite_store import SQLiteGraphStore, load_verified_current_graph_snapshot
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_ID = (
    "pajin.workflow.application-static-analysis-knowledge-admission"
)
APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION = "1.0.0"
APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.application-static-analysis-knowledge-admission/v1"
).hexdigest()
APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION: Literal[
    "pajin.dev/application-static-analysis-knowledge-admission/v1alpha1"
] = "pajin.dev/application-static-analysis-knowledge-admission/v1alpha1"

_SIGNATURE_DOMAIN = b"pajin.workflow.application-static-analysis-execution-attestation/v1\0"
_MAX_ATTESTATION_BYTES = 2 * 1024 * 1024
_MAX_RECEIPT_BYTES = 512 * 1024
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_OBSERVATION_SUMMARY = (
    "A sealed read-only static-analysis execution produced a digest-bound neutral "
    "Application result receipt."
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_ArtifactPath = Annotated[
    str,
    Field(pattern=r"^evidence/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$"),
]

_FALSE_AUTHORITY_FIELDS = (
    "raw_artifact_embedded",
    "raw_analysis_output_embedded",
    "artifact_format_authority",
    "configuration_value_authority",
    "runtime_support_authority",
    "dependency_relationship_authority",
    "vulnerability_confirmation_authority",
    "hypothesis_confirmation_authority",
    "artifact_mutation_authorized",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "artifact_access_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class ApplicationStaticAnalysisKnowledgeAdmissionError(ValueError):
    """Raised when sealed Application knowledge cannot enter the Graph."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class ApplicationStaticAnalysisExecutionKeyState(StrEnum):
    """Lifecycle state for one deployment-owned execution attestation key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class ApplicationStaticAnalysisReviewSignal(StrEnum):
    """Fixed review-only signals allowed to motivate an open hypothesis."""

    BINARY_SECURITY_METADATA_REVIEW = "binary-security-metadata-review"
    CONFIGURATION_STRUCTURE_REVIEW = "configuration-structure-review"
    RUNTIME_METADATA_REVIEW = "runtime-metadata-review"
    LIBRARY_METADATA_REVIEW = "library-metadata-review"


_REVIEW_SIGNAL_BINDING = {
    ApplicationStaticAnalysisReviewSignal.BINARY_SECURITY_METADATA_REVIEW: (
        ApplicationStaticAnalysisOperation.BINARY_METADATA,
        ApplicationSurfaceClass.BINARY,
    ),
    ApplicationStaticAnalysisReviewSignal.CONFIGURATION_STRUCTURE_REVIEW: (
        ApplicationStaticAnalysisOperation.CONFIGURATION_STRUCTURE,
        ApplicationSurfaceClass.CONFIGURATION,
    ),
    ApplicationStaticAnalysisReviewSignal.RUNTIME_METADATA_REVIEW: (
        ApplicationStaticAnalysisOperation.RUNTIME_METADATA,
        ApplicationSurfaceClass.RUNTIME,
    ),
    ApplicationStaticAnalysisReviewSignal.LIBRARY_METADATA_REVIEW: (
        ApplicationStaticAnalysisOperation.LIBRARY_METADATA,
        ApplicationSurfaceClass.LIBRARY,
    ),
}


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


class ApplicationStaticAnalysisExecutionVerificationKey(_FrozenStrictModel):
    """One externally configured Ed25519 verifier and its lifecycle."""

    key_id: _Identifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: ApplicationStaticAnalysisExecutionKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Application static-analysis execution public key",
        )
        not_before = _aware_utc(self.not_before, label="Application execution key not-before")
        if self.not_after is not None:
            not_after = _aware_utc(
                self.not_after,
                label="Application execution key not-after",
            )
            if not_after <= not_before:
                raise ValueError("Application execution key validity window is empty")
        if (
            self.state is ApplicationStaticAnalysisExecutionKeyState.RETIRED
            and self.not_after is None
        ):
            raise ValueError("retired Application execution key requires not_after")
        if self.state is ApplicationStaticAnalysisExecutionKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Application execution key requires revoked_at")
            _aware_utc(self.revoked_at, label="Application execution key revocation")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked Application execution key cannot have revoked_at")
        return self


class ApplicationStaticAnalysisExecutionTrustAnchor(_FrozenStrictModel):
    """Deployment verifier that grants no artifact or sandbox execution authority."""

    api_version: Literal[
        "pajin.dev/application-static-analysis-execution-trust-anchor/v1alpha1"
    ] = Field(
        default="pajin.dev/application-static-analysis-execution-trust-anchor/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisExecutionTrustAnchor"] = (
        "ApplicationStaticAnalysisExecutionTrustAnchor"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    sandbox: ApplicationStaticAnalysisSandboxBinding
    capability: CodeBackedCapabilityRef
    capability_release: CapabilityReleaseRef = Field(alias="capabilityRelease")
    keys: tuple[ApplicationStaticAnalysisExecutionVerificationKey, ...] = Field(
        min_length=1,
        max_length=32,
    )
    deployment_owned: Literal[True] = Field(default=True, alias="deploymentOwned")
    verification_only: Literal[True] = Field(default=True, alias="verificationOnly")
    current_activation_bound: Literal[False] = Field(
        default=False,
        alias="currentActivationBound",
    )
    campaign_authority_bound: Literal[False] = Field(
        default=False,
        alias="campaignAuthorityBound",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_bound: Literal[False] = Field(default=False, alias="permitBound")
    artifact_access_authorized: Literal[False] = Field(
        default=False,
        alias="artifactAccessAuthorized",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("deployment_owned", "verification_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application execution trust-anchor markers must be true")
        return value

    @field_validator(
        "current_activation_bound",
        "campaign_authority_bound",
        "approval_satisfied",
        "permit_bound",
        "artifact_access_authorized",
        "sandbox_invocation_authorized",
        "graph_admission_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application execution trust anchor cannot grant authority")
        return value

    @model_validator(mode="after")
    def require_exact_sandbox_and_keyring(self) -> Self:
        if self.capability != registered_application_static_analysis_binding().capability:
            raise ValueError("Application execution trust-anchor Capability differs")
        keys = [(item.key_id, item.public_key_base64url) for item in self.keys]
        key_ids = [item.key_id for item in self.keys]
        public_keys = [item.public_key_base64url for item in self.keys]
        if (
            keys != sorted(keys)
            or len(key_ids) != len(set(key_ids))
            or len(public_keys) != len(set(public_keys))
        ):
            raise ValueError("Application execution trust-anchor keys must be unique and sorted")
        if (
            sum(
                item.state is ApplicationStaticAnalysisExecutionKeyState.ACTIVE
                for item in self.keys
            )
            != 1
        ):
            raise ValueError("Application execution trust anchor requires one active key")
        return self

    @property
    def digest(self) -> str:
        return graph_digest(
            "pajin.workflow.application-static-analysis-execution-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_CANONICAL_BYTES,
        )


class ApplicationSandboxRuntimeReceipt(_FrozenStrictModel):
    """Digest-only proof of one exact offline, read-only sandbox execution."""

    receipt_id: str = Field(default="", alias="receiptId", max_length=105)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    sandbox_binding_id: _Identifier = Field(alias="sandboxBindingId")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    operation: ApplicationStaticAnalysisOperation
    parser: ApplicationStaticParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=1, le=536_870_912)
    custody_binding_id: _Identifier = Field(alias="custodyBindingId")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    runtime_identity_digest: _Sha256 = Field(alias="runtimeIdentityDigest")
    confinement_digest: _Sha256 = Field(alias="confinementDigest")
    attested_at: datetime = Field(alias="attestedAt")
    custody_authorization_verified: Literal[True] = Field(
        default=True,
        alias="custodyAuthorizationVerified",
    )
    artifact_digest_verified: Literal[True] = Field(
        default=True,
        alias="artifactDigestVerified",
    )
    artifact_read_completed: Literal[True] = Field(
        default=True,
        alias="artifactReadCompleted",
    )
    parser_executable_verified: Literal[True] = Field(
        default=True,
        alias="parserExecutableVerified",
    )
    sandbox_image_verified: Literal[True] = Field(
        default=True,
        alias="sandboxImageVerified",
    )
    non_root_verified: Literal[True] = Field(default=True, alias="nonRootVerified")
    network_disabled_verified: Literal[True] = Field(
        default=True,
        alias="networkDisabledVerified",
    )
    read_only_root_verified: Literal[True] = Field(
        default=True,
        alias="readOnlyRootVerified",
    )
    read_only_artifact_mount_verified: Literal[True] = Field(
        default=True,
        alias="readOnlyArtifactMountVerified",
    )
    artifact_mount_noexec_verified: Literal[True] = Field(
        default=True,
        alias="artifactMountNoexecVerified",
    )
    no_new_privileges_verified: Literal[True] = Field(
        default=True,
        alias="noNewPrivilegesVerified",
    )
    resource_limits_verified: Literal[True] = Field(
        default=True,
        alias="resourceLimitsVerified",
    )
    raw_identity_metadata_embedded: Literal[False] = Field(
        default=False,
        alias="rawIdentityMetadataEmbedded",
    )
    raw_artifact_embedded: Literal[False] = Field(default=False, alias="rawArtifactEmbedded")
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("attested_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Application sandbox runtime attestation")

    @field_validator(
        "custody_authorization_verified",
        "artifact_digest_verified",
        "artifact_read_completed",
        "parser_executable_verified",
        "sandbox_image_verified",
        "non_root_verified",
        "network_disabled_verified",
        "read_only_root_verified",
        "read_only_artifact_mount_verified",
        "artifact_mount_noexec_verified",
        "no_new_privileges_verified",
        "resource_limits_verified",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application sandbox runtime verification markers must be true")
        return value

    @field_validator(
        "raw_identity_metadata_embedded",
        "raw_artifact_embedded",
        "network_access_authorized",
        "dynamic_target_execution_authorized",
        "debugger_attach_authorized",
        "artifact_mutation_authorized",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application sandbox runtime receipt cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.application-sandbox-runtime-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"application-sandbox-runtime_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Application sandbox runtime receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Application sandbox runtime receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class ApplicationStaticAnalysisResultReceipt(_FrozenStrictModel):
    """Neutral detached receipt with no raw artifact or parser output."""

    api_version: Literal["pajin.dev/application-static-analysis-result-receipt/v1alpha1"] = Field(
        default="pajin.dev/application-static-analysis-result-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisResultReceipt"] = (
        "ApplicationStaticAnalysisResultReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=105)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    execution_id: _Identifier = Field(alias="executionId")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    preparation_id: _Identifier = Field(alias="preparationId")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    operation: ApplicationStaticAnalysisOperation
    surface: ApplicationArtifactRuntimeSurfaceRef
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    output_schema: Literal["pajin.application.static-analysis-result.v1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    result_bytes: int = Field(alias="resultBytes", strict=True, ge=2, le=16_777_216)
    media_type: Literal["application/json"] = Field(default="application/json", alias="mediaType")
    review_signal: ApplicationStaticAnalysisReviewSignal | None = Field(
        default=None,
        alias="reviewSignal",
    )
    received_at: datetime = Field(alias="receivedAt")
    successful: Literal[True] = True
    digest_only: Literal[True] = Field(default=True, alias="digestOnly")
    raw_result_embedded: Literal[False] = Field(default=False, alias="rawResultEmbedded")
    raw_artifact_embedded: Literal[False] = Field(default=False, alias="rawArtifactEmbedded")
    artifact_path_embedded: Literal[False] = Field(default=False, alias="artifactPathEmbedded")
    configuration_value_embedded: Literal[False] = Field(
        default=False,
        alias="configurationValueEmbedded",
    )
    artifact_format_authority: Literal[False] = Field(
        default=False,
        alias="artifactFormatAuthority",
    )
    runtime_support_authority: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAuthority",
    )
    dependency_relationship_authority: Literal[False] = Field(
        default=False,
        alias="dependencyRelationshipAuthority",
    )
    vulnerability_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmationAuthority",
    )
    finding_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthority",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("received_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Application analysis receipt received-at")

    @field_validator("successful", "digest_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application result receipt success markers must be true")
        return value

    @field_validator(
        "raw_result_embedded",
        "raw_artifact_embedded",
        "artifact_path_embedded",
        "configuration_value_embedded",
        "artifact_format_authority",
        "runtime_support_authority",
        "dependency_relationship_authority",
        "vulnerability_confirmation_authority",
        "finding_confirmation_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application result receipt cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_review_signal_and_identity(self) -> Self:
        if self.review_signal is not None and _REVIEW_SIGNAL_BINDING[self.review_signal] != (
            self.operation,
            self.surface.surface_class,
        ):
            raise ValueError("Application review signal differs from exact Surface")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.application-static-analysis-result-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"application-analysis-result_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Application result receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Application result receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class ApplicationStaticAnalysisExecutionStatement(_FrozenStrictModel):
    """Signed assertion for one already-completed approved sandbox execution."""

    api_version: Literal["pajin.dev/application-static-analysis-execution-statement/v1alpha1"] = (
        Field(
            default="pajin.dev/application-static-analysis-execution-statement/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["ApplicationStaticAnalysisExecutionStatement"] = (
        "ApplicationStaticAnalysisExecutionStatement"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    sandbox_binding_id: _Identifier = Field(alias="sandboxBindingId")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    gateway_policy_decision: PolicyDecision = Field(alias="gatewayPolicyDecision")
    gateway_outcome_digest: _Sha256 = Field(alias="gatewayOutcomeDigest")
    execution_id: _Identifier = Field(alias="executionId")
    campaign_id: _Identifier = Field(alias="campaignId")
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    run_id: _Identifier = Field(alias="runId")
    preparation_id: _Identifier = Field(alias="preparationId")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    analysis_request: ApplicationStaticAnalysisRequest = Field(alias="analysisRequest")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    action_permit_id: _Identifier = Field(alias="actionPermitId")
    action_permit_digest: _Sha256 = Field(alias="actionPermitDigest")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    sandbox_runtime: ApplicationSandboxRuntimeReceipt = Field(alias="sandboxRuntime")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")
    result_receipt_id: _Identifier = Field(alias="resultReceiptId")
    result_receipt_digest: _Sha256 = Field(alias="resultReceiptDigest")
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    issued_at: datetime = Field(alias="issuedAt")
    status: Literal["succeeded"] = "succeeded"
    request_count: Literal[1] = Field(default=1, alias="requestCount")
    artifact_reads: Literal[1] = Field(default=1, alias="artifactReads")
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dynamic_target_executions: Literal[0] = Field(
        default=0,
        alias="dynamicTargetExecutions",
    )
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")
    artifact_write_operations: Literal[0] = Field(
        default=0,
        alias="artifactWriteOperations",
    )
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    gateway_policy_reentered: Literal[True] = Field(
        default=True,
        alias="gatewayPolicyReentered",
    )
    consumed_permit_verified: Literal[True] = Field(
        default=True,
        alias="consumedPermitVerified",
    )
    approval_receipt_verified: Literal[True] = Field(
        default=True,
        alias="approvalReceiptVerified",
    )
    exact_surface_bound: Literal[True] = Field(default=True, alias="exactSurfaceBound")
    exact_artifact_digest_verified: Literal[True] = Field(
        default=True,
        alias="exactArtifactDigestVerified",
    )
    custody_authorization_verified: Literal[True] = Field(
        default=True,
        alias="custodyAuthorizationVerified",
    )
    offline_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="offlineSandboxVerified",
    )
    result_sealed: Literal[True] = Field(default=True, alias="resultSealed")
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    new_artifact_access_authorized: Literal[False] = Field(
        default=False,
        alias="newArtifactAccessAuthorized",
    )
    new_sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="newSandboxInvocationAuthorized",
    )
    new_worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="newWorkerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    new_execution_authorized: Literal[False] = Field(
        default=False,
        alias="newExecutionAuthorized",
    )

    @field_validator("started_at", "finished_at", "issued_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Application static-analysis execution time")

    @field_validator(
        "request_count",
        "artifact_reads",
        "network_requests",
        "dynamic_target_executions",
        "debugger_attaches",
        "artifact_write_operations",
        "host_filesystem_reads",
        "credential_reads",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Application execution budget values must be integers")
        return value

    @field_validator(
        "gateway_policy_reentered",
        "consumed_permit_verified",
        "approval_receipt_verified",
        "exact_surface_bound",
        "exact_artifact_digest_verified",
        "custody_authorization_verified",
        "offline_sandbox_verified",
        "result_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application execution verification markers must be true")
        return value

    @field_validator(
        "raw_parser_output_embedded",
        "new_artifact_access_authorized",
        "new_sandbox_invocation_authorized",
        "new_worker_selection_authorized",
        "network_access_authorized",
        "dynamic_target_execution_authorized",
        "debugger_attach_authorized",
        "artifact_mutation_authorized",
        "replay_authorized",
        "graph_admission_authorized",
        "finding_confirmation_authorized",
        "new_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application execution statement cannot grant new authority")
        return value

    @model_validator(mode="after")
    def require_causal_execution(self) -> Self:
        if not (
            self.started_at
            <= self.sandbox_runtime.attested_at
            <= self.finished_at
            <= self.issued_at
        ):
            raise ValueError("Application execution statement timestamps are inconsistent")
        if self.analysis_request.method != "GET":
            raise ValueError("Application execution statement requires one exact GET request")
        if self.gateway_policy_decision.allowed is not True:
            raise ValueError("Application execution statement requires an allowed Gateway decision")
        return self

    @property
    def statement_key(self) -> str:
        return sha256(
            canonical_json_bytes(
                self.model_dump(mode="json", by_alias=True),
                label="Application static-analysis execution statement key",
                max_bytes=_MAX_CANONICAL_BYTES,
            )
        ).hexdigest()


class ApplicationStaticAnalysisExecutionBundle(_FrozenStrictModel):
    """Detached Ed25519 signature over one Application execution statement."""

    api_version: Literal["pajin.dev/application-static-analysis-execution-bundle/v1alpha1"] = Field(
        default="pajin.dev/application-static-analysis-execution-bundle/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisExecutionBundle"] = (
        "ApplicationStaticAnalysisExecutionBundle"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _Identifier = Field(alias="keyId")
    statement: ApplicationStaticAnalysisExecutionStatement
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_json_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Application static-analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("Application execution statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Application static-analysis execution signature",
        )
        return self


class ApplicationStaticAnalysisExecutionVerification(_FrozenStrictModel):
    """Result of verifying caller-supplied Application execution trust."""

    valid: Literal[True] = True
    key_id: _Identifier = Field(alias="keyId")
    key_state: ApplicationStaticAnalysisExecutionKeyState = Field(alias="keyState")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    issued_at: datetime = Field(alias="issuedAt")

    @field_validator("valid", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application static-analysis verification must be true")
        return value


@dataclass(frozen=True, slots=True)
class ApplicationStaticAnalysisExecutionAttestor:
    """Signing helper for a deployment runtime; it performs no analysis."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
    ) -> ApplicationStaticAnalysisExecutionAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 Application execution private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if (
            len(matching) != 1
            or matching[0].state is not ApplicationStaticAnalysisExecutionKeyState.ACTIVE
        ):
            raise ValueError("Application execution signer key is not active")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Application execution active public key",
        )
        if public_bytes != expected:
            raise ValueError("Application execution private key does not match its trust anchor")

    def attest(
        self,
        statement: ApplicationStaticAnalysisExecutionStatement,
    ) -> ApplicationStaticAnalysisExecutionBundle:
        canonical_statement = ApplicationStaticAnalysisExecutionStatement.model_validate(
            statement.model_dump(mode="json", by_alias=True)
        )
        sandbox = self.trust_anchor.sandbox
        if (
            canonical_statement.trust_domain != self.trust_anchor.trust_domain
            or canonical_statement.issuer != self.trust_anchor.issuer
            or canonical_statement.sandbox_binding_id != sandbox.sandbox_binding_id
            or canonical_statement.sandbox_binding_digest != sandbox.sandbox_binding_digest
            or canonical_statement.deployment_id != sandbox.deployment_id
        ):
            raise ValueError("Application execution statement differs from its trust anchor")
        key = next(item for item in self.trust_anchor.keys if item.key_id == self.active_key_id)
        issued_at = canonical_statement.issued_at
        if issued_at < key.not_before or (key.not_after is not None and issued_at >= key.not_after):
            raise ValueError("Application execution signing key is not valid at issue time")
        canonical = canonical_json_bytes(
            canonical_statement.model_dump(mode="json", by_alias=True),
            label="Application static-analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return ApplicationStaticAnalysisExecutionBundle(
            keyId=self.active_key_id,
            statement=canonical_statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


def application_static_analysis_execution_public_key(private_key: bytes) -> str:
    """Derive the base64url Ed25519 public key for deployment configuration."""

    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def application_static_analysis_execution_bundle_bytes(
    bundle: ApplicationStaticAnalysisExecutionBundle,
) -> bytes:
    """Serialize a readable bundle whose signature covers canonical statement bytes."""

    return (
        json.dumps(
            bundle.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def application_static_analysis_result_receipt_bytes(
    receipt: ApplicationStaticAnalysisResultReceipt,
) -> bytes:
    """Serialize one detached digest-only result receipt."""

    return (
        json.dumps(
            receipt.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def application_static_analysis_gateway_outcome_digest(
    *,
    policy_decision: PolicyDecision,
    request_digest: str,
    permit_digest: str,
    sandbox_runtime_receipt_digest: str,
    result_receipt_digest: str,
) -> str:
    """Bind one allowed Gateway result without embedding parser output."""

    canonical = PolicyDecision.model_validate(policy_decision.model_dump(mode="json"))
    if canonical.allowed is not True:
        raise ValueError("Application Gateway outcome requires an allowed policy decision")
    for label, value in (
        ("request", request_digest),
        ("Permit", permit_digest),
        ("sandbox runtime", sandbox_runtime_receipt_digest),
        ("result receipt", result_receipt_digest),
    ):
        if not isinstance(value, str) or fullmatch(r"^[a-f0-9]{64}$", value) is None:
            raise ValueError(f"Application Gateway {label} digest is invalid")
    return graph_digest(
        "pajin.workflow.application-static-analysis-gateway-outcome/v1",
        {
            "policyDecision": canonical.model_dump(mode="json"),
            "requestDigest": request_digest,
            "permitDigest": permit_digest,
            "sandboxRuntimeReceiptDigest": sandbox_runtime_receipt_digest,
            "resultReceiptDigest": result_receipt_digest,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def verify_application_static_analysis_execution_bundle(
    bundle: ApplicationStaticAnalysisExecutionBundle,
    *,
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
) -> ApplicationStaticAnalysisExecutionVerification:
    """Verify one detached deployment signature against the configured keyring."""

    try:
        canonical_bundle = ApplicationStaticAnalysisExecutionBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        canonical_anchor = ApplicationStaticAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
    except Exception as exc:
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "Application execution attestation is not canonical"
        ) from exc
    statement = canonical_bundle.statement
    sandbox = canonical_anchor.sandbox
    if (
        statement.trust_domain != canonical_anchor.trust_domain
        or statement.issuer != canonical_anchor.issuer
        or statement.sandbox_binding_id != sandbox.sandbox_binding_id
        or statement.sandbox_binding_digest != sandbox.sandbox_binding_digest
        or statement.deployment_id != sandbox.deployment_id
    ):
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "Application execution attestation is not trusted"
        )
    matching = [key for key in canonical_anchor.keys if key.key_id == canonical_bundle.key_id]
    if len(matching) != 1:
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "Application execution signing key is not trusted"
        )
    key = matching[0]
    if key.state is ApplicationStaticAnalysisExecutionKeyState.REVOKED:
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "Application execution signing key is revoked"
        )
    if statement.issued_at < key.not_before or (
        key.not_after is not None and statement.issued_at >= key.not_after
    ):
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "Application execution signing key is outside its validity window"
        )
    canonical_statement = canonical_json_bytes(
        statement.model_dump(mode="json", by_alias=True),
        label="Application static-analysis execution statement",
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    try:
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="Application execution public key",
            )
        ).verify(
            _base64url_decode(
                canonical_bundle.signature_base64url,
                expected_length=64,
                label="Application execution signature",
            ),
            _SIGNATURE_DOMAIN + canonical_statement,
        )
    except (InvalidSignature, ValueError) as exc:
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "Application execution signature is invalid"
        ) from exc
    return ApplicationStaticAnalysisExecutionVerification(
        keyId=key.key_id,
        keyState=key.state,
        trustAnchorDigest=canonical_anchor.digest,
        statementSha256=canonical_bundle.statement_sha256,
        issuedAt=statement.issued_at,
    )


@dataclass(frozen=True, slots=True)
class ApplicationStaticAnalysisObservationSourceInputs:
    """Current authority plus two deployment-produced detached evidence files."""

    source_root: Path
    attestation_reference: str
    expected_run_id: str
    activation: ApplicationStaticAnalysisCapabilityActivation
    campaign: CampaignManifest
    preparation: ApplicationStaticAnalysisPreparation
    job: CapabilityGraphCampaignJobInput


@dataclass(frozen=True, slots=True)
class VerifiedApplicationStaticAnalysisObservationSource:
    """One independently verified, already-completed sandbox analysis."""

    preparation: ApplicationStaticAnalysisPreparation
    job: CapabilityGraphCampaignJobInput
    permit: ActionPermit
    approval_receipt: ActionApprovalConsumptionReceipt
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor
    verification: ApplicationStaticAnalysisExecutionVerification
    bundle: ApplicationStaticAnalysisExecutionBundle
    result_receipt: ApplicationStaticAnalysisResultReceipt
    attestation_reference: str
    attestation_sha256: str
    result_receipt_reference: str
    result_receipt_sha256: str
    source_root_digest: str


class ApplicationStaticAnalysisKnowledgeAdmissionPolicy(_FrozenStrictModel):
    """Code-owned authority for a neutral Observation and optional open Hypothesis."""

    api_version: Literal[
        "pajin.dev/application-static-analysis-knowledge-admission-policy/v1alpha1"
    ] = Field(
        default="pajin.dev/application-static-analysis-knowledge-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ApplicationStaticAnalysisKnowledgeAdmissionPolicy"] = (
        "ApplicationStaticAnalysisKnowledgeAdmissionPolicy"
    )
    policy_id: str = Field(default="", alias="policyId", max_length=112)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.application-static-analysis-knowledge-admission"] = Field(
        default="pajin.workflow.application-static-analysis-knowledge-admission",
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(default="1.0.0", alias="producerVersion")
    producer_digest: _Sha256 = Field(
        default=APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["application.analysis-observation"] = Field(
        default="application.analysis-observation",
        alias="observationType",
    )
    hypothesis_type: Literal["application.vulnerability"] = Field(
        default="application.vulnerability",
        alias="hypothesisType",
    )
    review_signals: tuple[ApplicationStaticAnalysisReviewSignal, ...] = Field(
        default=tuple(ApplicationStaticAnalysisReviewSignal),
        alias="reviewSignals",
    )
    knowledge_only: Literal[True] = Field(default=True, alias="knowledgeOnly")
    bounded_hypothesis_enabled: Literal[True] = Field(
        default=True,
        alias="boundedHypothesisEnabled",
    )
    artifact_format_authority: Literal[False] = Field(
        default=False,
        alias="artifactFormatAuthority",
    )
    vulnerability_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmationAuthorized",
    )
    finding_production_authorized: Literal[False] = Field(
        default=False,
        alias="findingProductionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("knowledge_only", "bounded_hypothesis_enabled", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application knowledge policy markers must be true")
        return value

    @field_validator(
        "artifact_format_authority",
        "vulnerability_confirmation_authorized",
        "finding_production_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application knowledge policy cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        if (
            self.producer_digest != APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST
            or self.review_signals != tuple(ApplicationStaticAnalysisReviewSignal)
        ):
            raise ValueError("Application knowledge policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.application-static-analysis-knowledge-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"application-analysis-knowledge-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Application knowledge policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Application knowledge policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class ApplicationGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph Snapshot and its already-existing single writer."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError("Application knowledge admission requires a non-empty Graph Snapshot")
        return self


class ApplicationStaticAnalysisKnowledgeCandidate(_FrozenStrictModel):
    """Content-addressed neutral Observation and optional bounded Hypothesis."""

    api_version: Literal["pajin.dev/application-static-analysis-knowledge-candidate/v1alpha1"] = (
        Field(
            default="pajin.dev/application-static-analysis-knowledge-candidate/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["ApplicationStaticAnalysisKnowledgeCandidate"] = (
        "ApplicationStaticAnalysisKnowledgeCandidate"
    )
    candidate_id: str = Field(default="", alias="candidateId", max_length=112)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: ApplicationStaticAnalysisKnowledgeAdmissionPolicy
    graph: ApplicationGraphAdmissionBinding
    preparation: ApplicationStaticAnalysisPreparation
    surface: ApplicationArtifactRuntimeSurfaceRef
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    source_execution_snapshot: GraphSnapshotRef = Field(alias="sourceExecutionSnapshot")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    attestation_reference: _ArtifactPath = Field(alias="attestationReference")
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")
    result_receipt_digest: _Sha256 = Field(alias="resultReceiptDigest")
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    output_schema: Literal["pajin.application.static-analysis-result.v1"] = Field(
        default=APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    operation: ApplicationStaticAnalysisOperation
    review_signal: ApplicationStaticAnalysisReviewSignal | None = Field(
        default=None,
        alias="reviewSignal",
    )
    observation_proposal: ObservationProposal = Field(alias="observationProposal")
    hypothesis_proposal: HypothesisProposal | None = Field(
        default=None,
        alias="hypothesisProposal",
    )
    state: Literal["sealed-knowledge-not-admitted"] = "sealed-knowledge-not-admitted"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    consumed_permit_verified: Literal[True] = Field(
        default=True,
        alias="consumedPermitVerified",
    )
    artifact_digest_attestation_verified: Literal[True] = Field(
        default=True,
        alias="artifactDigestAttestationVerified",
    )
    sandbox_runtime_receipt_verified: Literal[True] = Field(
        default=True,
        alias="sandboxRuntimeReceiptVerified",
    )
    neutral_observation_produced: Literal[True] = Field(
        default=True,
        alias="neutralObservationProduced",
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    raw_artifact_embedded: Literal[False] = Field(default=False, alias="rawArtifactEmbedded")
    raw_analysis_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawAnalysisOutputEmbedded",
    )
    artifact_format_authority: Literal[False] = Field(
        default=False,
        alias="artifactFormatAuthority",
    )
    configuration_value_authority: Literal[False] = Field(
        default=False,
        alias="configurationValueAuthority",
    )
    runtime_support_authority: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAuthority",
    )
    dependency_relationship_authority: Literal[False] = Field(
        default=False,
        alias="dependencyRelationshipAuthority",
    )
    vulnerability_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmationAuthority",
    )
    hypothesis_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="hypothesisConfirmationAuthority",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
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
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "sealed_source_verified",
        "consumed_permit_verified",
        "artifact_digest_attestation_verified",
        "sandbox_runtime_receipt_verified",
        "neutral_observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application sealed knowledge markers must be true")
        return value

    @field_validator("graph_admitted", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application knowledge candidate authority flags must be false")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError(
                "Application Domain Graph semantics are not registered exactly"
            ) from exc
        observation = self.observation_proposal
        evidence = {(item.reference, item.sha256) for item in observation.evidence_nodes}
        expected_evidence = {
            (self.attestation_reference, self.attestation_sha256),
            (self.result_receipt_reference, self.result_receipt_sha256),
        }
        hypothesis = self.hypothesis_proposal
        expected_hypothesis = self.review_signal is not None
        if (
            self.surface != self.preparation.surface.reference()
            or self.preparation.surface.domain_graph_type_set != self.domain_graph_type_set
            or self.source_execution_snapshot != self.graph.snapshot
            or self.operation is not self.preparation.operation
            or self.artifact_sha256 != self.preparation.artifact_custody.artifact_sha256
            or self.output_schema != self.preparation.analysis_request.output_schema
            or semantics.domain_classification.domain is not SecurityDomain.APPLICATION
            or semantics.surface_type != "application.artifact-runtime"
            or semantics.locator_schema != "pajin.locator.application.artifact-runtime.v1"
            or semantics.observation_type != self.policy.observation_type
            or semantics.hypothesis_type != self.policy.hypothesis_type
            or observation.observation.observation_type != self.policy.observation_type
            or observation.observation.summary != _OBSERVATION_SUMMARY
            or observation.observation.origin is not GraphContentOrigin.TARGET_DERIVED
            or observation.observation.confidence != 1.0
            or observation.producer_id != self.policy.producer_id
            or observation.producer_version != self.policy.producer_version
            or observation.producer_digest != self.policy.producer_digest
            or observation.lineage.campaign_id != self.graph.snapshot.campaign_id
            or observation.lineage.run_id != self.source_run_id
            or observation.lineage.source_root_digest != self.source_root_digest
            or evidence != expected_evidence
            or len(observation.evidence_nodes) != 2
            or {edge.relation for edge in observation.edges}
            != {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
            or expected_hypothesis != (hypothesis is not None)
        ):
            raise ValueError("Application knowledge candidate differs from sealed semantics")
        if hypothesis is not None:
            if self.review_signal is None:
                raise ValueError("Application Hypothesis lacks a bounded review signal")
            statement, expected_observable = _hypothesis_text(self.review_signal)
            if (
                hypothesis.producer_id != self.policy.producer_id
                or hypothesis.producer_version != self.policy.producer_version
                or hypothesis.producer_digest != self.policy.producer_digest
                or hypothesis.lineage.campaign_id != observation.lineage.campaign_id
                or hypothesis.lineage.run_id != observation.lineage.run_id
                or hypothesis.lineage.source_root_digest != observation.lineage.source_root_digest
                or hypothesis.lineage.evidence != observation.lineage.evidence
                or hypothesis.hypothesis.hypothesis_type != self.policy.hypothesis_type
                or hypothesis.hypothesis.statement != statement
                or hypothesis.hypothesis.expected_observable != expected_observable
                or hypothesis.hypothesis.origin is not GraphContentOrigin.AGENT_DERIVED
                or hypothesis.hypothesis.confidence != 0.5
                or len(hypothesis.edges) != 1
                or hypothesis.edges[0].relation is not GraphRelation.ENABLES
                or hypothesis.edges[0].source != graph_node_ref(observation.observation)
                or hypothesis.edges[0].target != graph_node_ref(hypothesis.hypothesis)
            ):
                raise ValueError(
                    "Application bounded Hypothesis differs from the neutral Observation"
                )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.application-static-analysis-knowledge-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"application-analysis-knowledge_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Application knowledge candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Application knowledge candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class ApplicationStaticAnalysisKnowledgeAdmission(_FrozenStrictModel):
    """Proof that sealed Application knowledge entered only the existing writer."""

    api_version: Literal["pajin.dev/application-static-analysis-knowledge-admission/v1alpha1"] = (
        Field(
            default=APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["ApplicationStaticAnalysisKnowledgeAdmission"] = (
        "ApplicationStaticAnalysisKnowledgeAdmission"
    )
    admission_id: str = Field(default="", alias="admissionId", max_length=112)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: ApplicationStaticAnalysisKnowledgeCandidate
    observation_graph_event: GraphAdmissionEvent = Field(alias="observationGraphEvent")
    hypothesis_graph_event: GraphAdmissionEvent | None = Field(
        default=None,
        alias="hypothesisGraphEvent",
    )
    state: Literal["registered-not-authorized"] = "registered-not-authorized"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    neutral_observation_produced: Literal[True] = Field(
        default=True,
        alias="neutralObservationProduced",
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[True] = Field(default=True, alias="graphAdmitted")
    graph_single_writer_reused: Literal[True] = Field(
        default=True,
        alias="graphSingleWriterReused",
    )
    bounded_hypothesis_admitted: bool = Field(alias="boundedHypothesisAdmitted")
    raw_artifact_embedded: Literal[False] = Field(default=False, alias="rawArtifactEmbedded")
    raw_analysis_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawAnalysisOutputEmbedded",
    )
    artifact_format_authority: Literal[False] = Field(
        default=False,
        alias="artifactFormatAuthority",
    )
    configuration_value_authority: Literal[False] = Field(
        default=False,
        alias="configurationValueAuthority",
    )
    runtime_support_authority: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAuthority",
    )
    dependency_relationship_authority: Literal[False] = Field(
        default=False,
        alias="dependencyRelationshipAuthority",
    )
    vulnerability_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmationAuthority",
    )
    hypothesis_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="hypothesisConfirmationAuthority",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
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
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "sealed_source_verified",
        "neutral_observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "graph_single_writer_reused",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Application knowledge admission markers must be true")
        return value

    @field_validator("bounded_hypothesis_admitted", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Application bounded Hypothesis marker must be boolean")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Application knowledge admission cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_admission_identity(self) -> Self:
        observation = self.candidate.observation_proposal
        _require_admitted_event(
            event=self.observation_graph_event,
            proposal=observation,
            graph=self.candidate.graph,
            expected_kind=GraphProposalKind.OBSERVATION,
        )
        kinds = [node.kind for node in self.observation_graph_event.admitted_nodes]
        if (
            kinds.count(GraphNodeKind.ACTION.value) != 1
            or kinds.count(GraphNodeKind.OBSERVATION.value) != 1
            or kinds.count(GraphNodeKind.EVIDENCE.value) != 2
            or len(kinds) != 4
            or any(
                edge.relation not in {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
                for edge in self.observation_graph_event.admitted_edges
            )
        ):
            raise ValueError(
                "Application Observation admission exceeds neutral knowledge authority"
            )
        hypothesis = self.candidate.hypothesis_proposal
        expected_hypothesis = hypothesis is not None
        if (
            self.bounded_hypothesis_admitted is not expected_hypothesis
            or (self.hypothesis_graph_event is not None) is not expected_hypothesis
        ):
            raise ValueError("Application bounded Hypothesis admission marker differs")
        if hypothesis is not None and self.hypothesis_graph_event is not None:
            _require_admitted_event(
                event=self.hypothesis_graph_event,
                proposal=hypothesis,
                graph=self.candidate.graph,
                expected_kind=GraphProposalKind.HYPOTHESIS,
            )
            event = self.hypothesis_graph_event
            if (
                event.sequence != self.observation_graph_event.sequence + 1
                or event.previous_event_digest != self.observation_graph_event.event_digest
                or event.admitted_nodes != [hypothesis.hypothesis]
                or event.admitted_edges != hypothesis.edges
                or len(event.admitted_edges) != 1
                or event.admitted_edges[0].relation is not GraphRelation.ENABLES
            ):
                raise ValueError("Application bounded Hypothesis exceeds open knowledge authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.application-static-analysis-knowledge-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"application-analysis-knowledge-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Application knowledge admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Application knowledge admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def _hypothesis_text(
    signal: ApplicationStaticAnalysisReviewSignal,
) -> tuple[str, str]:
    text = {
        ApplicationStaticAnalysisReviewSignal.BINARY_SECURITY_METADATA_REVIEW: (
            "The exact binary security metadata warrants bounded independent review.",
            "Independent static re-analysis reproduces the same review signal for the exact "
            "artifact digest.",
        ),
        ApplicationStaticAnalysisReviewSignal.CONFIGURATION_STRUCTURE_REVIEW: (
            "The exact configuration structure warrants bounded independent review.",
            "Independent static re-analysis reproduces the same configuration-structure "
            "review signal for the exact artifact digest.",
        ),
        ApplicationStaticAnalysisReviewSignal.RUNTIME_METADATA_REVIEW: (
            "The declared runtime metadata warrants bounded independent review.",
            "Independent static re-analysis reproduces the same runtime-metadata review "
            "signal for the exact artifact digest.",
        ),
        ApplicationStaticAnalysisReviewSignal.LIBRARY_METADATA_REVIEW: (
            "The exact library metadata warrants bounded independent review.",
            "Independent static re-analysis reproduces the same library-metadata review "
            "signal for the exact artifact digest.",
        ),
    }
    return text[signal]


def application_static_analysis_knowledge_producer_registration() -> GraphProducerRegistration:
    """Return the exact code-owned Application Observation/Hypothesis producer."""

    return GraphProducerRegistration(
        producerId=APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_ID,
        producerVersion=APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION,
        producerDigest=APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        allowedProposalKinds=(
            GraphProposalKind.HYPOTHESIS,
            GraphProposalKind.OBSERVATION,
        ),
    )


class ApplicationStaticAnalysisKnowledgeAdmissionGate:
    """Reverify detached Application receipts and reuse the Graph single writer."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
        trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
    ) -> None:
        if type(graph_store) is not SQLiteGraphStore:
            raise TypeError("Application knowledge admission requires an exact SQLite Graph Store")
        if type(graph_admission) is not GraphAdmissionAuthority:
            raise TypeError(
                "Application knowledge admission requires the Graph Admission authority"
            )
        if type(trusted_lineages) is not TrustedGraphLineageRegistry:
            raise TypeError("Application knowledge admission requires the trusted lineage registry")
        if type(trust_anchor) is not ApplicationStaticAnalysisExecutionTrustAnchor:
            raise TypeError("Application knowledge admission requires a deployment trust anchor")
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("Application knowledge Graph authority wiring differs")
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages
        self._trust_anchor = ApplicationStaticAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )

    def prepare_candidate(
        self,
        inputs: ApplicationStaticAnalysisObservationSourceInputs,
        graph: ApplicationGraphAdmissionBinding,
    ) -> ApplicationStaticAnalysisKnowledgeCandidate:
        try:
            canonical_graph = ApplicationGraphAdmissionBinding.model_validate(
                graph.model_dump(mode="json", by_alias=True)
            )
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except ApplicationStaticAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application knowledge candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: ApplicationStaticAnalysisObservationSourceInputs,
        candidate: ApplicationStaticAnalysisKnowledgeCandidate,
    ) -> ApplicationStaticAnalysisKnowledgeAdmission:
        try:
            canonical = ApplicationStaticAnalysisKnowledgeCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                    "Application knowledge candidate differs from sealed source authority"
                )
            observation = canonical.observation_proposal
            observation_prior = self._graph_store.event_log.event_for_attempt(
                observation.proposal_id,
                observation.digest(),
            )
            if observation_prior is None:
                self._require_current_graph(canonical.graph)
                expected_head = canonical.graph.snapshot.event_log_head_digest
                if expected_head is None:
                    raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                        "Application knowledge admission requires a non-empty Graph head"
                    )
                self._trusted_lineages.register(observation.lineage)
                observation_result = self._graph_admission.submit_if_current(
                    observation,
                    expected_event_log_head_digest=expected_head,
                )
            else:
                observation_result = self._graph_admission.submit(observation)
            self._require_admitted_result(observation_result.event, canonical.graph)

            hypothesis_event: GraphAdmissionEvent | None = None
            hypothesis = canonical.hypothesis_proposal
            if hypothesis is not None:
                hypothesis_prior = self._graph_store.event_log.event_for_attempt(
                    hypothesis.proposal_id,
                    hypothesis.digest(),
                )
                if hypothesis_prior is None:
                    if self._graph_store.event_log.next_position()[1] != (
                        observation_result.event.event_digest
                    ):
                        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                            "Application bounded Hypothesis source is no longer the current "
                            "Graph head"
                        )
                    self._trusted_lineages.register(hypothesis.lineage)
                    hypothesis_result = self._graph_admission.submit_if_current(
                        hypothesis,
                        expected_event_log_head_digest=observation_result.event.event_digest,
                    )
                else:
                    hypothesis_result = self._graph_admission.submit(hypothesis)
                self._require_admitted_result(hypothesis_result.event, canonical.graph)
                hypothesis_event = hypothesis_result.event
            return ApplicationStaticAnalysisKnowledgeAdmission(
                candidate=canonical,
                observationGraphEvent=observation_result.event,
                hypothesisGraphEvent=hypothesis_event,
                boundedHypothesisAdmitted=hypothesis is not None,
            )
        except ApplicationStaticAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application knowledge admission failed closed"
            ) from exc

    def _require_admitted_result(
        self,
        event: GraphAdmissionEvent,
        graph: ApplicationGraphAdmissionBinding,
    ) -> None:
        if (
            event.decision is not GraphAdmissionDecision.ADMITTED
            or event.authority_id != graph.authority_id
            or event.authority_digest != graph.authority_digest
        ):
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Graph Admission authority rejected Application knowledge"
            )

    def _build_candidate(
        self,
        inputs: ApplicationStaticAnalysisObservationSourceInputs,
        graph: ApplicationGraphAdmissionBinding,
    ) -> ApplicationStaticAnalysisKnowledgeCandidate:
        source = load_verified_application_static_analysis_observation_source(
            inputs,
            graph_store=self._graph_store,
            trust_anchor=self._trust_anchor,
        )
        permit = source.permit
        statement = source.bundle.statement
        receipt = source.result_receipt
        runtime = statement.sandbox_runtime
        if graph.snapshot.campaign_id != permit.campaign_id:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application execution source and Graph admission Campaigns differ"
            )
        policy = ApplicationStaticAnalysisKnowledgeAdmissionPolicy()
        value_digest = graph_digest(
            "pajin.workflow.application-static-analysis-observation-value/v1",
            {
                "preparationDigest": source.preparation.preparation_digest,
                "surfaceReference": source.preparation.surface.reference().model_dump(
                    mode="json",
                    by_alias=True,
                ),
                "artifactSHA256": receipt.artifact_sha256,
                "operation": source.preparation.operation.value,
                "parser": source.preparation.analysis_request.parser.value,
                "outputSchema": receipt.output_schema,
                "requestDigest": permit.request_digest,
                "approvalReceiptDigest": source.approval_receipt.receipt_digest,
                "trustAnchorDigest": source.verification.trust_anchor_digest,
                "statementSha256": source.verification.statement_sha256,
                "gatewayOutcomeDigest": statement.gateway_outcome_digest,
                "sandboxRuntimeReceiptDigest": runtime.receipt_digest,
                "runtimeIdentityDigest": runtime.runtime_identity_digest,
                "confinementDigest": runtime.confinement_digest,
                "resultReceiptDigest": receipt.receipt_digest,
                "resultBodySha256": receipt.result_body_sha256,
                "resultBytes": receipt.result_bytes,
                "reviewSignal": (
                    receipt.review_signal.value if receipt.review_signal is not None else None
                ),
                "sourceRootDigest": source.source_root_digest,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        action = GraphAction(
            campaignId=permit.campaign_id,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            authorityKind=GraphAuthorityKind.ACTION_PERMIT,
            authorityId=permit.permit_id,
            authorityDigest=permit.permit_digest,
            capabilityId=permit.capability.capability_id,
            capabilityVersion=permit.capability.capability_version,
            capabilityDigest=permit.capability.definition_digest,
            toolId=source.job.request.tool_id,
            targetDigest=permit.target_digest,
            status=GraphActionStatus.SUCCEEDED,
            executedAt=statement.started_at,
        )
        observation = GraphObservation(
            campaignId=permit.campaign_id,
            observationType=policy.observation_type,
            summary=_OBSERVATION_SUMMARY,
            valueDigest=value_digest,
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            origin=GraphContentOrigin.TARGET_DERIVED,
            confidence=1.0,
            observedAt=receipt.received_at,
        )
        bindings = sorted(
            (
                GraphEvidenceBinding(
                    reference=source.attestation_reference,
                    sha256=source.attestation_sha256,
                ),
                GraphEvidenceBinding(
                    reference=source.result_receipt_reference,
                    sha256=source.result_receipt_sha256,
                ),
            ),
            key=lambda item: (item.reference, item.sha256),
        )
        evidence_nodes = sorted(
            (
                GraphEvidence(
                    campaignId=permit.campaign_id,
                    reference=item.reference,
                    sha256=item.sha256,
                    sourceRootDigest=source.source_root_digest,
                    dataClassification="restricted",
                )
                for item in bindings
            ),
            key=lambda item: item.node_id,
        )
        edges = [
            GraphEdge(
                campaignId=permit.campaign_id,
                relation=GraphRelation.PRODUCES,
                source=graph_node_ref(action),
                target=graph_node_ref(observation),
                authorityId=graph.authority_id,
                authorityDigest=graph.authority_digest,
            ),
            *(
                GraphEdge(
                    campaignId=permit.campaign_id,
                    relation=GraphRelation.SUPPORTED_BY,
                    source=graph_node_ref(observation),
                    target=graph_node_ref(item),
                    authorityId=graph.authority_id,
                    authorityDigest=graph.authority_digest,
                )
                for item in evidence_nodes
            ),
        ]
        observation_lineage = _source_lineage(
            source=source,
            bindings=bindings,
            agent_id="agent:application-static-analysis-observation-admission",
            task_id=f"task:application-analysis-observation:{statement.statement_key[:32]}",
        )
        proposal_key = graph_digest(
            "pajin.workflow.application-static-analysis-observation-proposal-id/v1",
            {
                "sourceRootDigest": source.source_root_digest,
                "statementSha256": source.verification.statement_sha256,
                "resultReceiptDigest": receipt.receipt_digest,
                "snapshotDigest": graph.snapshot.snapshot_digest,
                "observationNodeId": observation.node_id,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        observation_proposal = ObservationProposal(
            proposalId=f"proposal:application-observation:{proposal_key}",
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            lineage=observation_lineage,
            action=action,
            observation=observation,
            evidenceNodes=evidence_nodes,
            edges=sorted(edges, key=lambda item: item.edge_id),
        )
        hypothesis_proposal: HypothesisProposal | None = None
        if receipt.review_signal is not None:
            hypothesis_statement, expected_observable = _hypothesis_text(receipt.review_signal)
            hypothesis = GraphHypothesis(
                campaignId=permit.campaign_id,
                hypothesisType=policy.hypothesis_type,
                statement=hypothesis_statement,
                expectedObservable=expected_observable,
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                origin=GraphContentOrigin.AGENT_DERIVED,
                confidence=0.5,
            )
            hypothesis_edge = GraphEdge(
                campaignId=permit.campaign_id,
                relation=GraphRelation.ENABLES,
                source=graph_node_ref(observation),
                target=graph_node_ref(hypothesis),
                authorityId=graph.authority_id,
                authorityDigest=graph.authority_digest,
            )
            hypothesis_lineage = _source_lineage(
                source=source,
                bindings=bindings,
                agent_id="agent:application-static-analysis-hypothesis-admission",
                task_id=f"task:application-analysis-hypothesis:{statement.statement_key[:32]}",
            )
            hypothesis_key = graph_digest(
                "pajin.workflow.application-static-analysis-hypothesis-proposal-id/v1",
                {
                    "observationProposalDigest": observation_proposal.digest(),
                    "hypothesisNodeId": hypothesis.node_id,
                    "reviewSignal": receipt.review_signal.value,
                },
                max_bytes=_MAX_CANONICAL_BYTES,
            )
            hypothesis_proposal = HypothesisProposal(
                proposalId=f"proposal:application-hypothesis:{hypothesis_key}",
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                lineage=hypothesis_lineage,
                hypothesis=hypothesis,
                edges=[hypothesis_edge],
            )
        return ApplicationStaticAnalysisKnowledgeCandidate(
            policy=policy,
            graph=graph,
            preparation=source.preparation,
            surface=source.preparation.surface.reference(),
            domainGraphTypeSet=source.preparation.surface.domain_graph_type_set,
            sourceExecutionSnapshot=permit.snapshot,
            sourceRunId=permit.run_id,
            sourceRootDigest=source.source_root_digest,
            trustAnchorDigest=source.verification.trust_anchor_digest,
            statementSha256=source.verification.statement_sha256,
            approvalReceiptId=source.approval_receipt.receipt_id,
            approvalReceiptDigest=source.approval_receipt.receipt_digest,
            attestationReference=source.attestation_reference,
            attestationSha256=source.attestation_sha256,
            resultReceiptReference=source.result_receipt_reference,
            resultReceiptSha256=source.result_receipt_sha256,
            resultReceiptDigest=receipt.receipt_digest,
            resultBodySha256=receipt.result_body_sha256,
            artifactSHA256=receipt.artifact_sha256,
            outputSchema=receipt.output_schema,
            operation=source.preparation.operation,
            reviewSignal=receipt.review_signal,
            observationProposal=observation_proposal,
            hypothesisProposal=hypothesis_proposal,
        )

    def _require_current_graph(self, graph: ApplicationGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest != getattr(self._graph_admission, "_authority_digest", None)
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application knowledge Graph Admission authority differs"
            )
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application knowledge Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application knowledge Graph Snapshot is not the current canonical head"
            )


def _source_lineage(
    *,
    source: VerifiedApplicationStaticAnalysisObservationSource,
    bindings: list[GraphEvidenceBinding],
    agent_id: str,
    task_id: str,
) -> GraphProposalLineage:
    permit = source.permit
    return GraphProposalLineage(
        campaignId=permit.campaign_id,
        runId=permit.run_id,
        agentId=agent_id,
        taskId=task_id,
        requestId=permit.request_id,
        requestDigest=permit.request_digest,
        capabilityGrantId=source.job.grant.grant_id,
        capabilityGrantDigest=capability_grant_digest(source.job.grant),
        capabilityId=permit.capability.capability_id,
        capabilityVersion=permit.capability.capability_version,
        capabilityDigest=permit.capability.definition_digest,
        actionPermitId=permit.permit_id,
        actionPermitDigest=permit.permit_digest,
        sourceRootDigest=source.source_root_digest,
        evidence=bindings,
        producedAt=source.bundle.statement.issued_at,
    )


def load_verified_application_static_analysis_observation_source(
    inputs: ApplicationStaticAnalysisObservationSourceInputs,
    *,
    graph_store: SQLiteGraphStore,
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
) -> VerifiedApplicationStaticAnalysisObservationSource:
    """Verify current authority, consumed Permit, signature, and detached receipt."""

    if type(inputs) is not ApplicationStaticAnalysisObservationSourceInputs:
        raise TypeError("Application knowledge admission requires exact source inputs")
    if type(graph_store) is not SQLiteGraphStore:
        raise TypeError("Application source verification requires the exact SQLite Graph Store")
    if type(trust_anchor) is not ApplicationStaticAnalysisExecutionTrustAnchor:
        raise TypeError("Application source verification requires a deployment trust anchor")
    if type(inputs.activation) is not ApplicationStaticAnalysisCapabilityActivation:
        raise TypeError("Application source verification requires current Application activation")
    try:
        campaign = CampaignManifest.model_validate(
            inputs.campaign.model_dump(mode="json", by_alias=True)
        )
        preparation = ApplicationStaticAnalysisPreparation.model_validate(
            inputs.preparation.model_dump(mode="json", by_alias=True)
        )
        job = CapabilityGraphCampaignJobInput.model_validate(
            inputs.job.model_dump(mode="json", by_alias=True)
        )
        trust_anchor = ApplicationStaticAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        prepared = preparation.prepared_action
        rebuilt = prepare_application_static_analysis(
            activation=inputs.activation,
            release=preparation.release,
            campaign=campaign,
            surface=preparation.surface,
            operation=preparation.operation,
            analyzer=BoundedApplicationStaticAnalyzerAdapter(
                preparation.artifact_custody,
                preparation.sandbox,
            ),
            request_id=prepared.request.request_id,
            agent_id=prepared.request.agent_id,
        )
        if rebuilt != preparation:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application preparation differs from current signed and scoped authority"
            )
        if (
            trust_anchor.sandbox != preparation.sandbox
            or trust_anchor.capability != preparation.binding.capability
            or trust_anchor.capability_release != preparation.release
            or job.profile != "capability-graph-v1"
            or job.approval is None
            or job.release != preparation.release
            or job.request != prepared.request
            or job.proposal.capability != prepared.capability
            or job.proposal.request_id != prepared.request.request_id
            or job.proposal.request_digest != prepared.request_digest
            or job.proposal.normalized_parameters_digest != prepared.normalized_parameters_digest
            or job.proposal.snapshot != job.decision.snapshot
            or job.proposal.decision_id != job.decision.decision_id
            or job.proposal.decision_digest != job.decision.decision_digest
            or job.decision.decision_payload_digest != preparation.preparation_digest
            or job.proposal.campaign_id != campaign.metadata.name
            or job.proposal.campaign_id != job.grant.campaign
            or job.request.agent_id != job.grant.subject
            or job.request.tool_id not in job.grant.tools
            or job.request.target not in job.grant.targets
            or job.approval.source_intent_digest != preparation.preparation_digest
            or job.approval.activation_set_digest != prepared.activation_set_digest
        ):
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application preparation and approved execution inputs differ"
            )
        permits = tuple(
            permit
            for permit in graph_store.permit_store.permits()
            if permit.run_id == inputs.expected_run_id
            and permit.request_id == prepared.request.request_id
        )
        if len(permits) != 1:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application execution source lacks one exact consumed ActionPermit"
            )
        permit = permits[0]
        if (
            permit.campaign_id != job.proposal.campaign_id
            or permit.run_id != job.proposal.run_id
            or permit.proposal_id != job.proposal.proposal_id
            or permit.proposal_digest != job.proposal.proposal_digest
            or permit.envelope_id != job.proposal.envelope_id
            or permit.envelope_digest != job.proposal.envelope_digest
            or permit.decision_id != job.decision.decision_id
            or permit.decision_digest != job.decision.decision_digest
            or permit.snapshot != job.decision.snapshot
            or permit.capability != prepared.capability
            or permit.target_digest != job.proposal.target_digest
            or permit.target_digest != sha256(prepared.request.target.encode("utf-8")).hexdigest()
            or permit.request_id != prepared.request.request_id
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
            or permit.reservation != job.proposal.reservation
        ):
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application consumed ActionPermit differs from the prepared action"
            )
        receipts = tuple(
            receipt
            for receipt in graph_store.permit_store.approval_consumptions()
            if receipt.action_permit.permit_id == permit.permit_id
        )
        if len(receipts) != 1:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application execution source lacks one exact approval consumption receipt"
            )
        approval_receipt = receipts[0]
        if (
            approval_receipt.action_permit != permit
            or approval_receipt.approval != job.approval
            or approval_receipt != build_action_approval_consumption_receipt(job.approval, permit)
        ):
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application approval receipt differs from the consumed action"
            )
        attestation_reference = _artifact_reference(
            inputs.attestation_reference,
            label="Application execution attestation",
        )
        attestation_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, attestation_reference),
            max_bytes=_MAX_ATTESTATION_BYTES,
            label="Application execution attestation",
            require_single_link=True,
        )
        bundle = ApplicationStaticAnalysisExecutionBundle.model_validate(
            parse_strict_json_bytes(
                attestation_bytes,
                label="Application execution attestation",
                max_bytes=_MAX_ATTESTATION_BYTES,
                max_depth=32,
                max_nodes=20_000,
            )
        )
        verification = verify_application_static_analysis_execution_bundle(
            bundle,
            trust_anchor=trust_anchor,
        )
        statement = bundle.statement
        result_reference = _artifact_reference(
            statement.result_receipt_reference,
            label="Application static-analysis result receipt",
        )
        if result_reference == attestation_reference:
            raise ApplicationStaticAnalysisKnowledgeAdmissionError(
                "Application attestation and result receipt must be distinct evidence"
            )
        result_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, result_reference),
            max_bytes=_MAX_RECEIPT_BYTES,
            label="Application static-analysis result receipt",
            require_single_link=True,
        )
        result_receipt = ApplicationStaticAnalysisResultReceipt.model_validate(
            parse_strict_json_bytes(
                result_bytes,
                label="Application static-analysis result receipt",
                max_bytes=_MAX_RECEIPT_BYTES,
                max_depth=20,
                max_nodes=8_000,
            )
        )
        result_sha256 = sha256(result_bytes).hexdigest()
        _validate_application_execution_source(
            campaign=campaign,
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=approval_receipt,
            trust_anchor=trust_anchor,
            statement=statement,
            result_receipt=result_receipt,
            result_receipt_sha256=result_sha256,
        )
        attestation_sha256 = sha256(attestation_bytes).hexdigest()
        source_root_digest = application_static_analysis_source_root_digest(
            attestation_sha256=attestation_sha256,
            result_receipt_sha256=result_sha256,
            trust_anchor_digest=verification.trust_anchor_digest,
            statement_sha256=verification.statement_sha256,
        )
        return VerifiedApplicationStaticAnalysisObservationSource(
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=approval_receipt,
            trust_anchor=trust_anchor,
            verification=verification,
            bundle=bundle,
            result_receipt=result_receipt,
            attestation_reference=attestation_reference,
            attestation_sha256=attestation_sha256,
            result_receipt_reference=result_reference,
            result_receipt_sha256=result_sha256,
            source_root_digest=source_root_digest,
        )
    except ApplicationStaticAnalysisKnowledgeAdmissionError:
        raise
    except Exception as exc:
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "sealed Application static-analysis source authority is invalid"
        ) from exc


def _validate_application_execution_source(
    *,
    campaign: CampaignManifest,
    preparation: ApplicationStaticAnalysisPreparation,
    job: CapabilityGraphCampaignJobInput,
    permit: ActionPermit,
    approval_receipt: ActionApprovalConsumptionReceipt,
    trust_anchor: ApplicationStaticAnalysisExecutionTrustAnchor,
    statement: ApplicationStaticAnalysisExecutionStatement,
    result_receipt: ApplicationStaticAnalysisResultReceipt,
    result_receipt_sha256: str,
) -> None:
    prepared = preparation.prepared_action
    sandbox = trust_anchor.sandbox
    runtime = statement.sandbox_runtime
    custody = preparation.artifact_custody
    duration = (statement.finished_at - statement.started_at).total_seconds()
    expected_gateway_decision = PolicyEngine().evaluate_tool_request(
        campaign,
        job.grant,
        prepared.request,
        ApplicationStaticAnalysisTool.spec,
        used_calls=0,
        now=statement.started_at,
    )
    expected_gateway_digest = application_static_analysis_gateway_outcome_digest(
        policy_decision=expected_gateway_decision,
        request_digest=permit.request_digest,
        permit_digest=permit.permit_digest,
        sandbox_runtime_receipt_digest=runtime.receipt_digest,
        result_receipt_digest=result_receipt.receipt_digest,
    )
    if (
        sandbox != preparation.sandbox
        or trust_anchor.capability != preparation.binding.capability
        or trust_anchor.capability_release != preparation.release
        or statement.gateway_policy_decision != expected_gateway_decision
        or statement.gateway_outcome_digest != expected_gateway_digest
        or statement.sandbox_binding_id != sandbox.sandbox_binding_id
        or statement.sandbox_binding_digest != sandbox.sandbox_binding_digest
        or statement.deployment_id != sandbox.deployment_id
        or statement.campaign_id != campaign.metadata.name
        or statement.campaign_digest != campaign_manifest_digest(campaign)
        or statement.run_id != permit.run_id
        or statement.preparation_id != preparation.preparation_id
        or statement.preparation_digest != preparation.preparation_digest
        or statement.analysis_request != preparation.analysis_request
        or statement.request_id != permit.request_id
        or statement.request_digest != permit.request_digest
        or statement.normalized_parameters_digest != permit.normalized_parameters_digest
        or statement.action_permit_id != permit.permit_id
        or statement.action_permit_digest != permit.permit_digest
        or statement.approval_receipt_id != approval_receipt.receipt_id
        or statement.approval_receipt_digest != approval_receipt.receipt_digest
        or runtime.sandbox_binding_id != sandbox.sandbox_binding_id
        or runtime.sandbox_binding_digest != sandbox.sandbox_binding_digest
        or runtime.deployment_id != sandbox.deployment_id
        or runtime.operation is not sandbox.operation
        or runtime.parser is not sandbox.parser
        or runtime.parser_executable_sha256 != sandbox.parser_executable_sha256
        or runtime.sandbox_image_sha256 != sandbox.sandbox_image_sha256
        or runtime.run_as_identity != sandbox.run_as_identity
        or runtime.artifact_sha256 != custody.artifact_sha256
        or runtime.artifact_bytes != custody.artifact_bytes
        or runtime.custody_binding_id != custody.custody_binding_id
        or runtime.custody_binding_digest != custody.custody_binding_digest
        or runtime.authorization_digest != custody.authorization_digest
        or result_receipt.execution_id != statement.execution_id
        or result_receipt.request_id != prepared.request.request_id
        or result_receipt.request_digest != prepared.request_digest
        or result_receipt.preparation_id != preparation.preparation_id
        or result_receipt.preparation_digest != preparation.preparation_digest
        or result_receipt.operation is not preparation.operation
        or result_receipt.surface != preparation.surface.reference()
        or result_receipt.artifact_sha256 != custody.artifact_sha256
        or result_receipt.output_schema != preparation.analysis_request.output_schema
        or result_receipt.result_bytes > preparation.analysis_request.budget.max_output_bytes
        or result_receipt.receipt_id != statement.result_receipt_id
        or result_receipt.receipt_digest != statement.result_receipt_digest
        or result_receipt_sha256 != statement.result_receipt_sha256
        or result_receipt.received_at != statement.finished_at
        or duration <= 0
        or duration > preparation.analysis_request.budget.runtime_seconds
        or not (
            permit.consumed_at
            <= statement.started_at
            <= runtime.attested_at
            <= statement.finished_at
            <= statement.issued_at
            < permit.expires_at
        )
    ):
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            "sealed Application execution statement differs from current authority"
        )


def _artifact_reference(value: str, *, label: str) -> str:
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError) as exc:
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(
            f"{label} reference is invalid"
        ) from exc
    if (
        not isinstance(value, str)
        or fullmatch(r"^evidence/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$", value) is None
        or not value.startswith("evidence/")
        or path.is_absolute()
        or len(path.parts) != 2
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".json"
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in path.name
        )
        or len(path.name) > 204
    ):
        raise ApplicationStaticAnalysisKnowledgeAdmissionError(f"{label} reference is invalid")
    return path.as_posix()


def _artifact_path(root: Path, reference: str) -> Path:
    parts = PurePosixPath(reference).parts
    return Path(root).resolve().joinpath(*parts)


def application_static_analysis_source_root_digest(
    *,
    attestation_sha256: str,
    result_receipt_sha256: str,
    trust_anchor_digest: str,
    statement_sha256: str,
) -> str:
    return graph_digest(
        "pajin.workflow.application-static-analysis-observation-source-root/v1",
        {
            "attestationSha256": attestation_sha256,
            "resultReceiptSha256": result_receipt_sha256,
            "trustAnchorDigest": trust_anchor_digest,
            "statementSha256": statement_sha256,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def _require_admitted_event(
    *,
    event: GraphAdmissionEvent,
    proposal: ObservationProposal | HypothesisProposal,
    graph: ApplicationGraphAdmissionBinding,
    expected_kind: GraphProposalKind,
) -> None:
    lineage = proposal.lineage
    expected_nodes = (
        sorted(
            [proposal.action, proposal.observation, *proposal.evidence_nodes],
            key=lambda item: item.node_id,
        )
        if isinstance(proposal, ObservationProposal)
        else [proposal.hypothesis]
    )
    expected_edges = sorted(proposal.edges, key=lambda item: item.edge_id)
    expected_lineage_digest = graph_digest(
        "pajin.graph.proposal-lineage/v1",
        lineage.model_dump(mode="json", by_alias=True),
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    if (
        event.decision is not GraphAdmissionDecision.ADMITTED
        or event.proposal_id != proposal.proposal_id
        or event.proposal_digest != proposal.digest()
        or event.proposal_kind is not expected_kind
        or event.producer_id != proposal.producer_id
        or event.producer_version != proposal.producer_version
        or event.producer_digest != proposal.producer_digest
        or event.authority_id != graph.authority_id
        or event.authority_digest != graph.authority_digest
        or event.campaign_id != lineage.campaign_id
        or event.proposal_campaign_id != lineage.campaign_id
        or event.run_id != lineage.run_id
        or event.agent_id != lineage.agent_id
        or event.task_id != lineage.task_id
        or event.request_id != lineage.request_id
        or event.request_digest != lineage.request_digest
        or event.lineage_digest != expected_lineage_digest
        or event.capability_grant_id != lineage.capability_grant_id
        or event.capability_grant_digest != lineage.capability_grant_digest
        or event.capability_id != lineage.capability_id
        or event.capability_version != lineage.capability_version
        or event.capability_digest != lineage.capability_digest
        or event.action_permit_id != lineage.action_permit_id
        or event.action_permit_digest != lineage.action_permit_digest
        or event.source_root_digest != lineage.source_root_digest
        or event.evidence != lineage.evidence
        or event.produced_at != lineage.produced_at
        or event.admitted_nodes != expected_nodes
        or event.admitted_edges != expected_edges
    ):
        raise ValueError("Application Graph admission differs from its bounded Proposal")


__all__ = [
    "APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION",
    "APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST",
    "APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_ID",
    "APPLICATION_STATIC_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION",
    "ApplicationGraphAdmissionBinding",
    "ApplicationSandboxRuntimeReceipt",
    "ApplicationStaticAnalysisExecutionAttestor",
    "ApplicationStaticAnalysisExecutionBundle",
    "ApplicationStaticAnalysisExecutionKeyState",
    "ApplicationStaticAnalysisExecutionStatement",
    "ApplicationStaticAnalysisExecutionTrustAnchor",
    "ApplicationStaticAnalysisExecutionVerification",
    "ApplicationStaticAnalysisExecutionVerificationKey",
    "ApplicationStaticAnalysisKnowledgeAdmission",
    "ApplicationStaticAnalysisKnowledgeAdmissionError",
    "ApplicationStaticAnalysisKnowledgeAdmissionGate",
    "ApplicationStaticAnalysisKnowledgeAdmissionPolicy",
    "ApplicationStaticAnalysisKnowledgeCandidate",
    "ApplicationStaticAnalysisObservationSourceInputs",
    "ApplicationStaticAnalysisResultReceipt",
    "ApplicationStaticAnalysisReviewSignal",
    "VerifiedApplicationStaticAnalysisObservationSource",
    "application_static_analysis_execution_bundle_bytes",
    "application_static_analysis_execution_public_key",
    "application_static_analysis_gateway_outcome_digest",
    "application_static_analysis_knowledge_producer_registration",
    "application_static_analysis_result_receipt_bytes",
    "application_static_analysis_source_root_digest",
    "load_verified_application_static_analysis_observation_source",
    "verify_application_static_analysis_execution_bundle",
]
