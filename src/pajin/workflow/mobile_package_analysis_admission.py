"""MOBILE-001C sealed Mobile package-analysis knowledge admission."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
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
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.mobile_package_analysis import (
    MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
    BoundedMobilePackageAnalyzerAdapter,
    MobilePackageAnalysisCapabilityActivation,
    MobilePackageAnalysisOperation,
    MobilePackageAnalysisPreparation,
    MobilePackageAnalysisRequest,
    MobilePackageAnalysisSandboxBinding,
    MobilePackageAnalysisTool,
    MobilePackageParser,
    prepare_mobile_package_analysis,
    registered_mobile_package_analysis_binding,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.mobile_surfaces import (
    MobileApplicationRuntimeSurfaceRef,
    MobilePlatform,
    MobileSurfaceClass,
)
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

MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_ID = (
    "pajin.workflow.mobile-package-analysis-knowledge-admission"
)
MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION = "1.0.0"
MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.mobile-package-analysis-knowledge-admission/v1"
).hexdigest()
MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION: Literal[
    "pajin.dev/mobile-package-analysis-knowledge-admission/v1alpha1"
] = "pajin.dev/mobile-package-analysis-knowledge-admission/v1alpha1"

_SIGNATURE_DOMAIN = b"pajin.workflow.mobile-package-analysis-execution-attestation/v1\0"
_MAX_ATTESTATION_BYTES = 2 * 1024 * 1024
_MAX_RECEIPT_BYTES = 512 * 1024
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_OBSERVATION_SUMMARY = (
    "A sealed read-only package-analysis execution produced a digest-bound neutral "
    "Mobile result receipt."
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
    "raw_parser_output_embedded",
    "raw_package_embedded",
    "raw_manifest_embedded",
    "signing_material_embedded",
    "raw_security_configuration_embedded",
    "device_state_embedded",
    "credential_material_embedded",
    "package_path_embedded",
    "artifact_format_authority",
    "package_format_authority",
    "manifest_truth_authority",
    "application_declaration_truth_authority",
    "signing_identity_authority",
    "runtime_declaration_truth_authority",
    "storage_value_authority",
    "deeplink_reachability_authority",
    "tls_enforcement_authority",
    "authentication_safety_authority",
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
    "package_access_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "worker_selection_authorized",
    "worker_job_materialization_authorized",
    "domain_worker_profile_bound",
    "device_bound_runtime_profile_applied",
    "network_access_authorized",
    "dns_access_authorized",
    "emulator_or_device_access_authorized",
    "package_installation_authorized",
    "application_launch_authorized",
    "instrumentation_authorized",
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "storage_read_authorized",
    "tls_invocation_authorized",
    "authentication_invocation_authorized",
    "credential_access_authorized",
    "package_mutation_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class MobilePackageAnalysisKnowledgeAdmissionError(ValueError):
    """Raised when sealed Mobile package knowledge cannot enter the Graph."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    """Reject state that Pydantic ``model_copy(update=...)`` did not validate."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        unknown = set(value.__dict__) - set(type(value).model_fields)
        if unknown:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                f"{label} contains unmodeled instance state"
            )
        for field_name in type(value).model_fields:
            _require_known_instance_fields(
                getattr(value, field_name),
                label=label,
                _seen=seen,
            )
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)


class MobilePackageAnalysisExecutionKeyState(StrEnum):
    """Lifecycle state for one deployment-owned execution attestation key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class MobilePackageAnalysisReviewSignal(StrEnum):
    """Fixed review-only signals allowed to motivate an open hypothesis."""

    APK_PACKAGE_STRUCTURE_REVIEW = "apk-package-structure-review"
    IPA_PACKAGE_STRUCTURE_REVIEW = "ipa-package-structure-review"
    APPLICATION_DECLARATION_REVIEW = "application-declaration-review"
    RUNTIME_DECLARATION_REVIEW = "runtime-declaration-review"
    STORAGE_DECLARATION_REVIEW = "storage-declaration-review"
    DEEP_LINK_DECLARATION_REVIEW = "deep-link-declaration-review"
    TLS_POLICY_DECLARATION_REVIEW = "tls-policy-declaration-review"
    AUTHENTICATION_FLOW_DECLARATION_REVIEW = "authentication-flow-declaration-review"


_REVIEW_SIGNAL_BINDING = {
    MobilePackageAnalysisReviewSignal.APK_PACKAGE_STRUCTURE_REVIEW: (
        MobilePackageAnalysisOperation.APK_PACKAGE_STRUCTURE,
        MobileSurfaceClass.APK,
    ),
    MobilePackageAnalysisReviewSignal.IPA_PACKAGE_STRUCTURE_REVIEW: (
        MobilePackageAnalysisOperation.IPA_PACKAGE_STRUCTURE,
        MobileSurfaceClass.IPA,
    ),
    MobilePackageAnalysisReviewSignal.APPLICATION_DECLARATION_REVIEW: (
        MobilePackageAnalysisOperation.APPLICATION_DECLARATION,
        MobileSurfaceClass.APPLICATION,
    ),
    MobilePackageAnalysisReviewSignal.RUNTIME_DECLARATION_REVIEW: (
        MobilePackageAnalysisOperation.RUNTIME_DECLARATION,
        MobileSurfaceClass.RUNTIME,
    ),
    MobilePackageAnalysisReviewSignal.STORAGE_DECLARATION_REVIEW: (
        MobilePackageAnalysisOperation.STORAGE_DECLARATION,
        MobileSurfaceClass.STORAGE,
    ),
    MobilePackageAnalysisReviewSignal.DEEP_LINK_DECLARATION_REVIEW: (
        MobilePackageAnalysisOperation.DEEP_LINK_DECLARATION,
        MobileSurfaceClass.DEEPLINK,
    ),
    MobilePackageAnalysisReviewSignal.TLS_POLICY_DECLARATION_REVIEW: (
        MobilePackageAnalysisOperation.TLS_POLICY_DECLARATION,
        MobileSurfaceClass.TLS,
    ),
    MobilePackageAnalysisReviewSignal.AUTHENTICATION_FLOW_DECLARATION_REVIEW: (
        MobilePackageAnalysisOperation.AUTHENTICATION_FLOW_DECLARATION,
        MobileSurfaceClass.AUTH,
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


class MobilePackageAnalysisExecutionVerificationKey(_FrozenStrictModel):
    """One externally configured Ed25519 verifier and its lifecycle."""

    key_id: _Identifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: MobilePackageAnalysisExecutionKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Mobile package-analysis static-analysis execution public key",
        )
        not_before = _aware_utc(
            self.not_before, label="Mobile package-analysis execution key not-before"
        )
        if self.not_after is not None:
            not_after = _aware_utc(
                self.not_after,
                label="Mobile package-analysis execution key not-after",
            )
            if not_after <= not_before:
                raise ValueError("Mobile package-analysis execution key validity window is empty")
        if self.state is MobilePackageAnalysisExecutionKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired Mobile package-analysis execution key requires not_after")
        if self.state is MobilePackageAnalysisExecutionKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError(
                    "revoked Mobile package-analysis execution key requires revoked_at"
                )
            _aware_utc(self.revoked_at, label="Mobile package-analysis execution key revocation")
        elif self.revoked_at is not None:
            raise ValueError(
                "non-revoked Mobile package-analysis execution key cannot have revoked_at"
            )
        return self


class MobilePackageAnalysisExecutionTrustAnchor(_FrozenStrictModel):
    """Deployment verifier that grants no package, Worker, or execution authority."""

    api_version: Literal["pajin.dev/mobile-package-analysis-execution-trust-anchor/v1alpha1"] = (
        Field(
            default="pajin.dev/mobile-package-analysis-execution-trust-anchor/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["MobilePackageAnalysisExecutionTrustAnchor"] = (
        "MobilePackageAnalysisExecutionTrustAnchor"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    sandbox: MobilePackageAnalysisSandboxBinding
    capability: CodeBackedCapabilityRef
    capability_release: CapabilityReleaseRef = Field(alias="capabilityRelease")
    keys: tuple[MobilePackageAnalysisExecutionVerificationKey, ...] = Field(
        min_length=1,
        max_length=32,
    )
    deployment_owned: Literal[True] = Field(default=True, alias="deploymentOwned")
    verification_only: Literal[True] = Field(default=True, alias="verificationOnly")
    external_static_sandbox_only: Literal[True] = Field(
        default=True,
        alias="externalStaticSandboxOnly",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
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
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    package_access_authorized: Literal[False] = Field(
        default=False,
        alias="packageAccessAuthorized",
    )
    worker_job_materialization_authorized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "deployment_owned",
        "verification_only",
        "external_static_sandbox_only",
        "domain_worker_profile_binding_deferred",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile package-analysis execution trust-anchor markers must be true")
        return value

    @field_validator(
        "current_activation_bound",
        "campaign_authority_bound",
        "approval_satisfied",
        "permit_bound",
        "artifact_access_authorized",
        "sandbox_invocation_authorized",
        "domain_worker_profile_bound",
        "device_bound_runtime_profile_applied",
        "package_access_authorized",
        "worker_job_materialization_authorized",
        "graph_admission_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "Mobile package-analysis execution trust anchor cannot grant authority"
            )
        return value

    @model_validator(mode="after")
    def require_exact_sandbox_and_keyring(self) -> Self:
        if (
            self.capability != registered_mobile_package_analysis_binding().capability
            or self.sandbox.domain_worker_profile_bound is not False
            or self.sandbox.domain_worker_profile_binding_deferred is not True
            or self.sandbox.device_bound_runtime_profile_applied is not False
            or self.sandbox.worker_job_materialization_available is not False
        ):
            raise ValueError("Mobile package-analysis execution trust-anchor Capability differs")
        keys = [(item.key_id, item.public_key_base64url) for item in self.keys]
        key_ids = [item.key_id for item in self.keys]
        public_keys = [item.public_key_base64url for item in self.keys]
        if (
            keys != sorted(keys)
            or len(key_ids) != len(set(key_ids))
            or len(public_keys) != len(set(public_keys))
        ):
            raise ValueError(
                "Mobile package-analysis execution trust-anchor keys must be unique and sorted"
            )
        if (
            sum(item.state is MobilePackageAnalysisExecutionKeyState.ACTIVE for item in self.keys)
            != 1
        ):
            raise ValueError(
                "Mobile package-analysis execution trust anchor requires one active key"
            )
        return self

    @property
    def digest(self) -> str:
        return graph_digest(
            "pajin.workflow.mobile-package-analysis-execution-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_CANONICAL_BYTES,
        )


class MobilePackageSandboxRuntimeReceipt(_FrozenStrictModel):
    """Digest-only provenance for one external device-free static sandbox execution."""

    receipt_id: str = Field(default="", alias="receiptId", max_length=105)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    sandbox_binding_id: _Identifier = Field(alias="sandboxBindingId")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    surface: MobileApplicationRuntimeSurfaceRef
    package_surface: MobileApplicationRuntimeSurfaceRef = Field(alias="packageSurface")
    operation: MobilePackageAnalysisOperation
    platform: MobilePlatform
    parser: MobilePackageParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    artifact_mount_target: Literal["/pajin/input/package"] = Field(
        default="/pajin/input/package",
        alias="artifactMountTarget",
    )
    output_schema: Literal["pajin.mobile.package-analysis-result.v1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    output_transport: Literal["bounded-json-stdout"] = Field(
        default="bounded-json-stdout",
        alias="outputTransport",
    )
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=1, le=536_870_912)
    custody_binding_id: _Identifier = Field(alias="custodyBindingId")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    custody_authority_id: _Identifier = Field(alias="custodyAuthorityId")
    custody_object_id: _Identifier = Field(alias="custodyObjectId")
    authorization_id: _Identifier = Field(alias="authorizationId")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    max_artifact_bytes: int = Field(alias="maxArtifactBytes", strict=True, ge=1)
    max_output_bytes: int = Field(alias="maxOutputBytes", strict=True, ge=1_024)
    max_runtime_seconds: int = Field(alias="maxRuntimeSeconds", strict=True, ge=1)
    max_memory_mib: int = Field(alias="maxMemoryMiB", strict=True, ge=64)
    max_process_count: int = Field(alias="maxProcessCount", strict=True, ge=1)
    max_archive_entries: int = Field(alias="maxArchiveEntries", strict=True, ge=1)
    max_total_uncompressed_bytes: int = Field(
        alias="maxTotalUncompressedBytes",
        strict=True,
        ge=1,
    )
    max_single_uncompressed_bytes: int = Field(
        alias="maxSingleUncompressedBytes",
        strict=True,
        ge=1,
    )
    max_archive_path_bytes: int = Field(alias="maxArchivePathBytes", strict=True, ge=1)
    max_archive_nesting_depth: int = Field(
        alias="maxArchiveNestingDepth",
        strict=True,
        ge=1,
    )
    max_compression_ratio: int = Field(alias="maxCompressionRatio", strict=True, ge=1)
    observed_archive_entries: int = Field(
        alias="observedArchiveEntries",
        strict=True,
        ge=0,
    )
    observed_total_uncompressed_bytes: int = Field(
        alias="observedTotalUncompressedBytes",
        strict=True,
        ge=0,
    )
    observed_largest_uncompressed_bytes: int = Field(
        alias="observedLargestUncompressedBytes",
        strict=True,
        ge=0,
    )
    observed_max_archive_path_bytes: int = Field(
        alias="observedMaxArchivePathBytes",
        strict=True,
        ge=0,
    )
    observed_archive_nesting_depth: int = Field(
        alias="observedArchiveNestingDepth",
        strict=True,
        ge=0,
    )
    observed_max_compression_ratio: int = Field(
        alias="observedMaxCompressionRatio",
        strict=True,
        ge=0,
    )
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
    package_read_completed: Literal[True] = Field(
        default=True,
        alias="packageReadCompleted",
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
    dns_disabled_verified: Literal[True] = Field(default=True, alias="dnsDisabledVerified")
    read_only_root_verified: Literal[True] = Field(
        default=True,
        alias="readOnlyRootVerified",
    )
    read_only_package_mount_verified: Literal[True] = Field(
        default=True,
        alias="readOnlyPackageMountVerified",
    )
    package_mount_noexec_verified: Literal[True] = Field(
        default=True,
        alias="packageMountNoexecVerified",
    )
    no_new_privileges_verified: Literal[True] = Field(
        default=True,
        alias="noNewPrivilegesVerified",
    )
    resource_limits_verified: Literal[True] = Field(
        default=True,
        alias="resourceLimitsVerified",
    )
    archive_limits_verified: Literal[True] = Field(
        default=True,
        alias="archiveLimitsVerified",
    )
    archive_rejection_rules_verified: Literal[True] = Field(
        default=True,
        alias="archiveRejectionRulesVerified",
    )
    archive_path_traversal_rejected: Literal[True] = Field(
        default=True,
        alias="archivePathTraversalRejected",
    )
    archive_symlinks_rejected: Literal[True] = Field(
        default=True,
        alias="archiveSymlinksRejected",
    )
    archive_duplicate_names_rejected: Literal[True] = Field(
        default=True,
        alias="archiveDuplicateNamesRejected",
    )
    external_static_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="externalStaticSandboxVerified",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    raw_identity_metadata_embedded: Literal[False] = Field(
        default=False,
        alias="rawIdentityMetadataEmbedded",
    )
    raw_package_embedded: Literal[False] = Field(default=False, alias="rawPackageEmbedded")
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    custody_authorization_authority: Literal[False] = Field(
        default=False,
        alias="custodyAuthorizationAuthority",
    )
    package_access_authorized: Literal[False] = Field(
        default=False,
        alias="packageAccessAuthorized",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    emulator_or_device_access_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorOrDeviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    host_filesystem_access_authorized: Literal[False] = Field(
        default=False,
        alias="hostFilesystemAccessAuthorized",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("attested_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Mobile package sandbox runtime attestation")

    @field_validator(
        "custody_authorization_verified",
        "artifact_digest_verified",
        "package_read_completed",
        "parser_executable_verified",
        "sandbox_image_verified",
        "non_root_verified",
        "network_disabled_verified",
        "dns_disabled_verified",
        "read_only_root_verified",
        "read_only_package_mount_verified",
        "package_mount_noexec_verified",
        "no_new_privileges_verified",
        "resource_limits_verified",
        "archive_limits_verified",
        "archive_rejection_rules_verified",
        "archive_path_traversal_rejected",
        "archive_symlinks_rejected",
        "archive_duplicate_names_rejected",
        "external_static_sandbox_verified",
        "domain_worker_profile_binding_deferred",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile package sandbox verification markers must be true")
        return value

    @field_validator(
        "raw_identity_metadata_embedded",
        "raw_package_embedded",
        "raw_parser_output_embedded",
        "domain_worker_profile_bound",
        "device_bound_runtime_profile_applied",
        "worker_job_materialized",
        "scope_expansion_authorized",
        "approval_authority",
        "permit_issuance_authorized",
        "custody_authorization_authority",
        "package_access_authorized",
        "sandbox_invocation_authorized",
        "network_access_authorized",
        "dns_access_authorized",
        "emulator_or_device_access_authorized",
        "package_installation_authorized",
        "application_launch_authorized",
        "instrumentation_authorized",
        "dynamic_target_execution_authorized",
        "storage_read_authorized",
        "tls_invocation_authorized",
        "authentication_invocation_authorized",
        "credential_access_authorized",
        "package_mutation_authorized",
        "replay_authorized",
        "debugger_attach_authorized",
        "host_filesystem_access_authorized",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mobile package sandbox receipt cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if (
            self.package_surface.surface_class
            not in {MobileSurfaceClass.APK, MobileSurfaceClass.IPA}
            or self.platform
            is not (
                MobilePlatform.ANDROID
                if self.package_surface.surface_class is MobileSurfaceClass.APK
                else MobilePlatform.IOS
            )
            or self.max_single_uncompressed_bytes > self.max_total_uncompressed_bytes
            or self.observed_archive_entries > self.max_archive_entries
            or (self.observed_total_uncompressed_bytes > self.max_total_uncompressed_bytes)
            or (self.observed_largest_uncompressed_bytes > self.max_single_uncompressed_bytes)
            or (self.observed_largest_uncompressed_bytes > self.observed_total_uncompressed_bytes)
            or self.observed_max_archive_path_bytes > self.max_archive_path_bytes
            or self.observed_archive_nesting_depth > self.max_archive_nesting_depth
            or self.observed_max_compression_ratio > self.max_compression_ratio
        ):
            raise ValueError("Mobile package sandbox receipt lineage or archive limits differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.mobile-package-sandbox-runtime-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"mobile-package-sandbox-runtime_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Mobile package sandbox runtime receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Mobile package sandbox runtime receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class MobilePackageAnalysisResultReceipt(_FrozenStrictModel):
    """Neutral detached receipt with no raw package, manifest, or parser output."""

    api_version: Literal["pajin.dev/mobile-package-analysis-result-receipt/v1alpha1"] = Field(
        default="pajin.dev/mobile-package-analysis-result-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisResultReceipt"] = "MobilePackageAnalysisResultReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=105)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    execution_id: _Identifier = Field(alias="executionId")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    preparation_id: _Identifier = Field(alias="preparationId")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    operation: MobilePackageAnalysisOperation
    platform: MobilePlatform
    parser: MobilePackageParser
    surface: MobileApplicationRuntimeSurfaceRef
    package_surface: MobileApplicationRuntimeSurfaceRef = Field(alias="packageSurface")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    output_schema: Literal["pajin.mobile.package-analysis-result.v1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    result_bytes: int = Field(alias="resultBytes", strict=True, ge=2, le=16_777_216)
    media_type: Literal["application/json"] = Field(default="application/json", alias="mediaType")
    review_signal: MobilePackageAnalysisReviewSignal | None = Field(
        default=None,
        alias="reviewSignal",
    )
    received_at: datetime = Field(alias="receivedAt")
    successful: Literal[True] = True
    digest_only: Literal[True] = Field(default=True, alias="digestOnly")
    raw_result_embedded: Literal[False] = Field(default=False, alias="rawResultEmbedded")
    raw_package_embedded: Literal[False] = Field(default=False, alias="rawPackageEmbedded")
    raw_manifest_embedded: Literal[False] = Field(default=False, alias="rawManifestEmbedded")
    signing_material_embedded: Literal[False] = Field(
        default=False,
        alias="signingMaterialEmbedded",
    )
    raw_security_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawSecurityConfigurationEmbedded",
    )
    device_state_embedded: Literal[False] = Field(
        default=False,
        alias="deviceStateEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    package_path_embedded: Literal[False] = Field(
        default=False,
        alias="packagePathEmbedded",
    )
    package_format_authority: Literal[False] = Field(
        default=False,
        alias="packageFormatAuthority",
    )
    manifest_truth_authority: Literal[False] = Field(
        default=False,
        alias="manifestTruthAuthority",
    )
    signing_identity_authority: Literal[False] = Field(
        default=False,
        alias="signingIdentityAuthority",
    )
    application_declaration_truth_authority: Literal[False] = Field(
        default=False,
        alias="applicationDeclarationTruthAuthority",
    )
    runtime_declaration_truth_authority: Literal[False] = Field(
        default=False,
        alias="runtimeDeclarationTruthAuthority",
    )
    runtime_support_authority: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAuthority",
    )
    storage_value_authority: Literal[False] = Field(
        default=False,
        alias="storageValueAuthority",
    )
    deeplink_reachability_authority: Literal[False] = Field(
        default=False,
        alias="deeplinkReachabilityAuthority",
    )
    tls_enforcement_authority: Literal[False] = Field(
        default=False,
        alias="tlsEnforcementAuthority",
    )
    authentication_safety_authority: Literal[False] = Field(
        default=False,
        alias="authenticationSafetyAuthority",
    )
    vulnerability_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmationAuthority",
    )
    finding_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthority",
    )
    security_property_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="securityPropertyConfirmationAuthority",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    custody_authorization_authority: Literal[False] = Field(
        default=False,
        alias="custodyAuthorizationAuthority",
    )
    package_access_authorized: Literal[False] = Field(
        default=False,
        alias="packageAccessAuthorized",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    emulator_or_device_access_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorOrDeviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("received_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Mobile package-analysis receipt received-at")

    @field_validator(
        "successful",
        "digest_only",
        "domain_worker_profile_binding_deferred",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile result receipt success markers must be true")
        return value

    @field_validator(
        "raw_result_embedded",
        "raw_package_embedded",
        "raw_manifest_embedded",
        "signing_material_embedded",
        "raw_security_configuration_embedded",
        "device_state_embedded",
        "credential_material_embedded",
        "package_path_embedded",
        "package_format_authority",
        "manifest_truth_authority",
        "signing_identity_authority",
        "application_declaration_truth_authority",
        "runtime_declaration_truth_authority",
        "runtime_support_authority",
        "storage_value_authority",
        "deeplink_reachability_authority",
        "tls_enforcement_authority",
        "authentication_safety_authority",
        "vulnerability_confirmation_authority",
        "finding_confirmation_authority",
        "security_property_confirmation_authority",
        "domain_worker_profile_bound",
        "device_bound_runtime_profile_applied",
        "worker_job_materialized",
        "scope_expansion_authorized",
        "approval_authority",
        "permit_issuance_authorized",
        "custody_authorization_authority",
        "package_access_authorized",
        "sandbox_invocation_authorized",
        "network_access_authorized",
        "dns_access_authorized",
        "emulator_or_device_access_authorized",
        "package_installation_authorized",
        "application_launch_authorized",
        "instrumentation_authorized",
        "dynamic_target_execution_authorized",
        "storage_read_authorized",
        "tls_invocation_authorized",
        "authentication_invocation_authorized",
        "credential_access_authorized",
        "package_mutation_authorized",
        "replay_authorized",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mobile package-analysis result receipt cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_review_signal_and_identity(self) -> Self:
        if (
            self.package_surface.surface_class
            not in {MobileSurfaceClass.APK, MobileSurfaceClass.IPA}
            or self.parser
            is not (
                MobilePackageParser.ANDROID_APK_STRUCTURE
                if self.package_surface.surface_class is MobileSurfaceClass.APK
                else MobilePackageParser.IOS_IPA_STRUCTURE
            )
            or self.platform
            is not (
                MobilePlatform.ANDROID
                if self.package_surface.surface_class is MobileSurfaceClass.APK
                else MobilePlatform.IOS
            )
            or (
                self.review_signal is not None
                and _REVIEW_SIGNAL_BINDING[self.review_signal]
                != (self.operation, self.surface.surface_class)
            )
        ):
            raise ValueError("Mobile review signal or package reference differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.mobile-package-analysis-result-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"mobile-package-analysis-result_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Mobile package-analysis result receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Mobile package-analysis result receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class MobilePackageAnalysisExecutionStatement(_FrozenStrictModel):
    """Signed assertion for one already-completed approved sandbox execution."""

    api_version: Literal["pajin.dev/mobile-package-analysis-execution-statement/v1alpha1"] = Field(
        default="pajin.dev/mobile-package-analysis-execution-statement/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisExecutionStatement"] = (
        "MobilePackageAnalysisExecutionStatement"
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
    analysis_request: MobilePackageAnalysisRequest = Field(alias="analysisRequest")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    action_permit_id: _Identifier = Field(alias="actionPermitId")
    action_permit_digest: _Sha256 = Field(alias="actionPermitDigest")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    sandbox_runtime: MobilePackageSandboxRuntimeReceipt = Field(alias="sandboxRuntime")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")
    result_receipt_id: _Identifier = Field(alias="resultReceiptId")
    result_receipt_digest: _Sha256 = Field(alias="resultReceiptDigest")
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    issued_at: datetime = Field(alias="issuedAt")
    status: Literal["succeeded"] = "succeeded"
    request_count: Literal[1] = Field(default=1, alias="requestCount")
    package_reads: Literal[1] = Field(default=1, alias="packageReads")
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_requests: Literal[0] = Field(default=0, alias="dnsRequests")
    emulator_sessions: Literal[0] = Field(default=0, alias="emulatorSessions")
    device_sessions: Literal[0] = Field(default=0, alias="deviceSessions")
    package_installations: Literal[0] = Field(default=0, alias="packageInstallations")
    application_launches: Literal[0] = Field(default=0, alias="applicationLaunches")
    instrumentation_sessions: Literal[0] = Field(
        default=0,
        alias="instrumentationSessions",
    )
    dynamic_target_executions: Literal[0] = Field(
        default=0,
        alias="dynamicTargetExecutions",
    )
    debugger_attaches: Literal[0] = Field(default=0, alias="debuggerAttaches")
    storage_reads: Literal[0] = Field(default=0, alias="storageReads")
    tls_connections: Literal[0] = Field(default=0, alias="tlsConnections")
    authentication_invocations: Literal[0] = Field(
        default=0,
        alias="authenticationInvocations",
    )
    package_write_operations: Literal[0] = Field(
        default=0,
        alias="packageWriteOperations",
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
    exact_package_surface_bound: Literal[True] = Field(
        default=True,
        alias="exactPackageSurfaceBound",
    )
    exact_artifact_digest_verified: Literal[True] = Field(
        default=True,
        alias="exactArtifactDigestVerified",
    )
    custody_authorization_verified: Literal[True] = Field(
        default=True,
        alias="custodyAuthorizationVerified",
    )
    external_static_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="externalStaticSandboxVerified",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    result_sealed: Literal[True] = Field(default=True, alias="resultSealed")
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    new_package_access_authorized: Literal[False] = Field(
        default=False,
        alias="newPackageAccessAuthorized",
    )
    new_sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="newSandboxInvocationAuthorized",
    )
    new_worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="newWorkerSelectionAuthorized",
    )
    new_domain_worker_profile_binding_authorized: Literal[False] = Field(
        default=False,
        alias="newDomainWorkerProfileBindingAuthorized",
    )
    worker_job_materialization_authorized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAuthorized",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    emulator_or_device_access_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorOrDeviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicTargetExecutionAuthorized",
    )
    debugger_attach_authorized: Literal[False] = Field(
        default=False,
        alias="debuggerAttachAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
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
        return _aware_utc(value, label="Mobile package-analysis execution time")

    @field_validator(
        "request_count",
        "package_reads",
        "network_requests",
        "dns_requests",
        "emulator_sessions",
        "device_sessions",
        "package_installations",
        "application_launches",
        "instrumentation_sessions",
        "dynamic_target_executions",
        "debugger_attaches",
        "storage_reads",
        "tls_connections",
        "authentication_invocations",
        "package_write_operations",
        "host_filesystem_reads",
        "credential_reads",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Mobile package-analysis budget values must be integers")
        return value

    @field_validator(
        "gateway_policy_reentered",
        "consumed_permit_verified",
        "approval_receipt_verified",
        "exact_surface_bound",
        "exact_package_surface_bound",
        "exact_artifact_digest_verified",
        "custody_authorization_verified",
        "external_static_sandbox_verified",
        "domain_worker_profile_binding_deferred",
        "result_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile package-analysis verification markers must be true")
        return value

    @field_validator(
        "raw_parser_output_embedded",
        "new_package_access_authorized",
        "new_sandbox_invocation_authorized",
        "new_worker_selection_authorized",
        "new_domain_worker_profile_binding_authorized",
        "worker_job_materialization_authorized",
        "domain_worker_profile_bound",
        "device_bound_runtime_profile_applied",
        "network_access_authorized",
        "dns_access_authorized",
        "emulator_or_device_access_authorized",
        "package_installation_authorized",
        "application_launch_authorized",
        "instrumentation_authorized",
        "dynamic_target_execution_authorized",
        "debugger_attach_authorized",
        "storage_read_authorized",
        "tls_invocation_authorized",
        "authentication_invocation_authorized",
        "credential_access_authorized",
        "package_mutation_authorized",
        "replay_authorized",
        "graph_admission_authorized",
        "finding_confirmation_authorized",
        "new_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mobile package-analysis statement cannot grant new authority")
        return value

    @model_validator(mode="after")
    def require_causal_execution(self) -> Self:
        if not (
            self.started_at
            <= self.sandbox_runtime.attested_at
            <= self.finished_at
            <= self.issued_at
        ):
            raise ValueError("Mobile package-analysis timestamps are inconsistent")
        if self.analysis_request.method != "GET":
            raise ValueError("Mobile package-analysis requires one exact GET request")
        if self.gateway_policy_decision.allowed is not True:
            raise ValueError("Mobile package-analysis requires an allowed Gateway decision")
        return self

    @property
    def statement_key(self) -> str:
        return sha256(
            canonical_json_bytes(
                self.model_dump(mode="json", by_alias=True),
                label="Mobile package-analysis execution statement key",
                max_bytes=_MAX_CANONICAL_BYTES,
            )
        ).hexdigest()


class MobilePackageAnalysisExecutionBundle(_FrozenStrictModel):
    """Detached Ed25519 signature over one Mobile package-analysis execution statement."""

    api_version: Literal["pajin.dev/mobile-package-analysis-execution-bundle/v1alpha1"] = Field(
        default="pajin.dev/mobile-package-analysis-execution-bundle/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisExecutionBundle"] = "MobilePackageAnalysisExecutionBundle"
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _Identifier = Field(alias="keyId")
    statement: MobilePackageAnalysisExecutionStatement
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_json_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Mobile package-analysis static-analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("Mobile package-analysis execution statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Mobile package-analysis static-analysis execution signature",
        )
        return self


class MobilePackageAnalysisExecutionVerification(_FrozenStrictModel):
    """Result of verifying caller-supplied Mobile package-analysis execution trust."""

    valid: Literal[True] = True
    key_id: _Identifier = Field(alias="keyId")
    key_state: MobilePackageAnalysisExecutionKeyState = Field(alias="keyState")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    issued_at: datetime = Field(alias="issuedAt")

    @field_validator("valid", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile package-analysis verification must be true")
        return value


@dataclass(frozen=True, slots=True)
class MobilePackageAnalysisExecutionAttestor:
    """Signing helper for a deployment runtime; it performs no analysis."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
    ) -> MobilePackageAnalysisExecutionAttestor:
        if len(private_key) != 32:
            raise ValueError(
                "Ed25519 Mobile package-analysis execution private key must contain 32 bytes"
            )
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        _require_known_instance_fields(
            self.trust_anchor,
            label="Mobile package-analysis trust anchor",
        )
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if (
            len(matching) != 1
            or matching[0].state is not MobilePackageAnalysisExecutionKeyState.ACTIVE
        ):
            raise ValueError("Mobile package-analysis execution signer key is not active")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Mobile package-analysis execution active public key",
        )
        if public_bytes != expected:
            raise ValueError(
                "Mobile package-analysis execution private key does not match its trust anchor"
            )

    def attest(
        self,
        statement: MobilePackageAnalysisExecutionStatement,
    ) -> MobilePackageAnalysisExecutionBundle:
        _require_known_instance_fields(
            statement,
            label="Mobile package-analysis execution statement",
        )
        canonical_statement = MobilePackageAnalysisExecutionStatement.model_validate(
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
            raise ValueError(
                "Mobile package-analysis execution statement differs from its trust anchor"
            )
        key = next(item for item in self.trust_anchor.keys if item.key_id == self.active_key_id)
        issued_at = canonical_statement.issued_at
        if issued_at < key.not_before or (key.not_after is not None and issued_at >= key.not_after):
            raise ValueError(
                "Mobile package-analysis execution signing key is not valid at issue time"
            )
        canonical = canonical_json_bytes(
            canonical_statement.model_dump(mode="json", by_alias=True),
            label="Mobile package-analysis static-analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return MobilePackageAnalysisExecutionBundle(
            keyId=self.active_key_id,
            statement=canonical_statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


def mobile_package_analysis_execution_public_key(private_key: bytes) -> str:
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


def mobile_package_analysis_execution_bundle_bytes(
    bundle: MobilePackageAnalysisExecutionBundle,
) -> bytes:
    """Serialize a readable bundle whose signature covers canonical statement bytes."""

    _require_known_instance_fields(bundle, label="Mobile package-analysis execution bundle")
    return (
        json.dumps(
            bundle.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def mobile_package_analysis_result_receipt_bytes(
    receipt: MobilePackageAnalysisResultReceipt,
) -> bytes:
    """Serialize one detached digest-only result receipt."""

    _require_known_instance_fields(receipt, label="Mobile package-analysis result receipt")
    return (
        json.dumps(
            receipt.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def mobile_package_analysis_gateway_outcome_digest(
    *,
    policy_decision: PolicyDecision,
    request_digest: str,
    permit_digest: str,
    sandbox_runtime_receipt_digest: str,
    result_receipt_digest: str,
) -> str:
    """Bind one allowed Gateway result without embedding parser output."""

    _require_known_instance_fields(
        policy_decision,
        label="Mobile package-analysis Gateway policy decision",
    )
    canonical = PolicyDecision.model_validate(policy_decision.model_dump(mode="json"))
    if canonical.allowed is not True:
        raise ValueError(
            "Mobile package-analysis Gateway outcome requires an allowed policy decision"
        )
    for label, value in (
        ("request", request_digest),
        ("Permit", permit_digest),
        ("sandbox runtime", sandbox_runtime_receipt_digest),
        ("result receipt", result_receipt_digest),
    ):
        if not isinstance(value, str) or fullmatch(r"^[a-f0-9]{64}$", value) is None:
            raise ValueError(f"Mobile package-analysis Gateway {label} digest is invalid")
    return graph_digest(
        "pajin.workflow.mobile-package-analysis-gateway-outcome/v1",
        {
            "policyDecision": canonical.model_dump(mode="json"),
            "requestDigest": request_digest,
            "permitDigest": permit_digest,
            "sandboxRuntimeReceiptDigest": sandbox_runtime_receipt_digest,
            "resultReceiptDigest": result_receipt_digest,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def verify_mobile_package_analysis_execution_bundle(
    bundle: MobilePackageAnalysisExecutionBundle,
    *,
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
) -> MobilePackageAnalysisExecutionVerification:
    """Verify one detached deployment signature against the configured keyring."""

    try:
        _require_known_instance_fields(bundle, label="Mobile package-analysis execution bundle")
        _require_known_instance_fields(
            trust_anchor,
            label="Mobile package-analysis trust anchor",
        )
        canonical_bundle = MobilePackageAnalysisExecutionBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        canonical_anchor = MobilePackageAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
    except Exception as exc:
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "Mobile package-analysis execution attestation is not canonical"
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
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "Mobile package-analysis execution attestation is not trusted"
        )
    matching = [key for key in canonical_anchor.keys if key.key_id == canonical_bundle.key_id]
    if len(matching) != 1:
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "Mobile package-analysis execution signing key is not trusted"
        )
    key = matching[0]
    if key.state is MobilePackageAnalysisExecutionKeyState.REVOKED:
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "Mobile package-analysis execution signing key is revoked"
        )
    if statement.issued_at < key.not_before or (
        key.not_after is not None and statement.issued_at >= key.not_after
    ):
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "Mobile package-analysis execution signing key is outside its validity window"
        )
    canonical_statement = canonical_json_bytes(
        statement.model_dump(mode="json", by_alias=True),
        label="Mobile package-analysis static-analysis execution statement",
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    try:
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="Mobile package-analysis execution public key",
            )
        ).verify(
            _base64url_decode(
                canonical_bundle.signature_base64url,
                expected_length=64,
                label="Mobile package-analysis execution signature",
            ),
            _SIGNATURE_DOMAIN + canonical_statement,
        )
    except (InvalidSignature, ValueError) as exc:
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "Mobile package-analysis execution signature is invalid"
        ) from exc
    return MobilePackageAnalysisExecutionVerification(
        keyId=key.key_id,
        keyState=key.state,
        trustAnchorDigest=canonical_anchor.digest,
        statementSha256=canonical_bundle.statement_sha256,
        issuedAt=statement.issued_at,
    )


@dataclass(frozen=True, slots=True)
class MobilePackageAnalysisObservationSourceInputs:
    """Current authority plus two deployment-produced detached evidence files."""

    source_root: Path
    attestation_reference: str
    expected_run_id: str
    activation: MobilePackageAnalysisCapabilityActivation
    campaign: CampaignManifest
    preparation: MobilePackageAnalysisPreparation
    job: CapabilityGraphCampaignJobInput


@dataclass(frozen=True, slots=True)
class VerifiedMobilePackageAnalysisObservationSource:
    """One independently verified, already-completed sandbox analysis."""

    preparation: MobilePackageAnalysisPreparation
    job: CapabilityGraphCampaignJobInput
    permit: ActionPermit
    approval_receipt: ActionApprovalConsumptionReceipt
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor
    verification: MobilePackageAnalysisExecutionVerification
    bundle: MobilePackageAnalysisExecutionBundle
    result_receipt: MobilePackageAnalysisResultReceipt
    attestation_reference: str
    attestation_sha256: str
    result_receipt_reference: str
    result_receipt_sha256: str
    source_root_digest: str


class MobilePackageAnalysisKnowledgeAdmissionPolicy(_FrozenStrictModel):
    """Code-owned authority for a neutral Observation and optional open Hypothesis."""

    api_version: Literal[
        "pajin.dev/mobile-package-analysis-knowledge-admission-policy/v1alpha1"
    ] = Field(
        default="pajin.dev/mobile-package-analysis-knowledge-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisKnowledgeAdmissionPolicy"] = (
        "MobilePackageAnalysisKnowledgeAdmissionPolicy"
    )
    policy_id: str = Field(default="", alias="policyId", max_length=112)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.mobile-package-analysis-knowledge-admission"] = Field(
        default="pajin.workflow.mobile-package-analysis-knowledge-admission",
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(default="1.0.0", alias="producerVersion")
    producer_digest: _Sha256 = Field(
        default=MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["mobile.analysis-observation"] = Field(
        default="mobile.analysis-observation",
        alias="observationType",
    )
    hypothesis_type: Literal["mobile.security-property"] = Field(
        default="mobile.security-property",
        alias="hypothesisType",
    )
    review_signals: tuple[MobilePackageAnalysisReviewSignal, ...] = Field(
        default=tuple(MobilePackageAnalysisReviewSignal),
        alias="reviewSignals",
    )
    knowledge_only: Literal[True] = Field(default=True, alias="knowledgeOnly")
    bounded_hypothesis_enabled: Literal[True] = Field(
        default=True,
        alias="boundedHypothesisEnabled",
    )
    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
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
    worker_job_authority: Literal[False] = Field(
        default=False,
        alias="workerJobAuthority",
    )
    package_or_device_runtime_authority: Literal[False] = Field(
        default=False,
        alias="packageOrDeviceRuntimeAuthority",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "knowledge_only",
        "bounded_hypothesis_enabled",
        "domain_worker_profile_binding_deferred",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile package-analysis knowledge policy markers must be true")
        return value

    @field_validator(
        "artifact_format_authority",
        "vulnerability_confirmation_authorized",
        "finding_production_authorized",
        "worker_job_authority",
        "package_or_device_runtime_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mobile package-analysis knowledge policy cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        if (
            self.producer_digest != MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST
            or self.review_signals != tuple(MobilePackageAnalysisReviewSignal)
        ):
            raise ValueError("Mobile package-analysis knowledge policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.mobile-package-analysis-knowledge-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"mobile-package-analysis-knowledge-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Mobile package-analysis knowledge policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Mobile package-analysis knowledge policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class MobileGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph Snapshot and its already-existing single writer."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError(
                "Mobile package-analysis knowledge admission requires a non-empty Graph Snapshot"
            )
        return self


class _MobileKnowledgeAuthorityBoundary(_FrozenStrictModel):
    """Mobile-specific negative authority carried through candidate and admission."""

    domain_worker_profile_binding_deferred: Literal[True] = Field(
        default=True,
        alias="domainWorkerProfileBindingDeferred",
    )
    exact_surface_and_package_bound: Literal[True] = Field(
        default=True,
        alias="exactSurfaceAndPackageBound",
    )
    external_static_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="externalStaticSandboxVerified",
    )
    raw_package_embedded: Literal[False] = Field(default=False, alias="rawPackageEmbedded")
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    raw_manifest_embedded: Literal[False] = Field(default=False, alias="rawManifestEmbedded")
    signing_material_embedded: Literal[False] = Field(
        default=False,
        alias="signingMaterialEmbedded",
    )
    raw_security_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawSecurityConfigurationEmbedded",
    )
    device_state_embedded: Literal[False] = Field(default=False, alias="deviceStateEmbedded")
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    package_path_embedded: Literal[False] = Field(
        default=False,
        alias="packagePathEmbedded",
    )
    package_format_authority: Literal[False] = Field(
        default=False,
        alias="packageFormatAuthority",
    )
    manifest_truth_authority: Literal[False] = Field(
        default=False,
        alias="manifestTruthAuthority",
    )
    application_declaration_truth_authority: Literal[False] = Field(
        default=False,
        alias="applicationDeclarationTruthAuthority",
    )
    signing_identity_authority: Literal[False] = Field(
        default=False,
        alias="signingIdentityAuthority",
    )
    runtime_declaration_truth_authority: Literal[False] = Field(
        default=False,
        alias="runtimeDeclarationTruthAuthority",
    )
    storage_value_authority: Literal[False] = Field(
        default=False,
        alias="storageValueAuthority",
    )
    deeplink_reachability_authority: Literal[False] = Field(
        default=False,
        alias="deeplinkReachabilityAuthority",
    )
    tls_enforcement_authority: Literal[False] = Field(
        default=False,
        alias="tlsEnforcementAuthority",
    )
    authentication_safety_authority: Literal[False] = Field(
        default=False,
        alias="authenticationSafetyAuthority",
    )
    worker_job_materialization_authorized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAuthorized",
    )
    domain_worker_profile_bound: Literal[False] = Field(
        default=False,
        alias="domainWorkerProfileBound",
    )
    device_bound_runtime_profile_applied: Literal[False] = Field(
        default=False,
        alias="deviceBoundRuntimeProfileApplied",
    )
    package_access_authorized: Literal[False] = Field(
        default=False,
        alias="packageAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(default=False, alias="dnsAccessAuthorized")
    emulator_or_device_access_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorOrDeviceAccessAuthorized",
    )
    package_installation_authorized: Literal[False] = Field(
        default=False,
        alias="packageInstallationAuthorized",
    )
    application_launch_authorized: Literal[False] = Field(
        default=False,
        alias="applicationLaunchAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tls_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsInvocationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
    )


class MobilePackageAnalysisKnowledgeCandidate(_MobileKnowledgeAuthorityBoundary):
    """Content-addressed neutral Observation and optional bounded Hypothesis."""

    api_version: Literal["pajin.dev/mobile-package-analysis-knowledge-candidate/v1alpha1"] = Field(
        default="pajin.dev/mobile-package-analysis-knowledge-candidate/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisKnowledgeCandidate"] = (
        "MobilePackageAnalysisKnowledgeCandidate"
    )
    candidate_id: str = Field(default="", alias="candidateId", max_length=112)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: MobilePackageAnalysisKnowledgeAdmissionPolicy
    graph: MobileGraphAdmissionBinding
    preparation: MobilePackageAnalysisPreparation
    surface: MobileApplicationRuntimeSurfaceRef
    package_surface: MobileApplicationRuntimeSurfaceRef = Field(alias="packageSurface")
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
    output_schema: Literal["pajin.mobile.package-analysis-result.v1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    operation: MobilePackageAnalysisOperation
    platform: MobilePlatform
    parser: MobilePackageParser
    review_signal: MobilePackageAnalysisReviewSignal | None = Field(
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
        "domain_worker_profile_binding_deferred",
        "exact_surface_and_package_bound",
        "external_static_sandbox_verified",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile package-analysis sealed knowledge markers must be true")
        return value

    @field_validator("graph_admitted", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "Mobile package-analysis knowledge candidate authority flags must be false"
            )
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError(
                "Mobile package-analysis Domain Graph semantics are not registered exactly"
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
            or self.package_surface != self.preparation.package_surface.reference()
            or self.preparation.surface.domain_graph_type_set != self.domain_graph_type_set
            or self.source_execution_snapshot != self.graph.snapshot
            or self.operation is not self.preparation.operation
            or self.platform
            is not (
                MobilePlatform.ANDROID
                if self.package_surface.surface_class is MobileSurfaceClass.APK
                else MobilePlatform.IOS
            )
            or self.parser is not self.preparation.sandbox.parser
            or self.parser is not self.preparation.analysis_request.parser
            or self.artifact_sha256 != self.preparation.package_custody.artifact_sha256
            or self.output_schema != self.preparation.analysis_request.output_schema
            or self.preparation.sandbox.domain_worker_profile_bound is not False
            or self.preparation.sandbox.domain_worker_profile_binding_deferred is not True
            or self.preparation.sandbox.device_bound_runtime_profile_applied is not False
            or self.preparation.sandbox.worker_job_materialization_available is not False
            or semantics.domain_classification.domain is not SecurityDomain.MOBILE
            or semantics.surface_type != "mobile.application-runtime"
            or semantics.locator_schema != "pajin.locator.mobile.application-runtime.v1"
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
            or len(observation.edges) != 3
            or sum(edge.relation is GraphRelation.PRODUCES for edge in observation.edges) != 1
            or sum(edge.relation is GraphRelation.SUPPORTED_BY for edge in observation.edges) != 2
            or {edge.relation for edge in observation.edges}
            != {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
            or expected_hypothesis != (hypothesis is not None)
            or (
                self.review_signal is not None
                and _REVIEW_SIGNAL_BINDING[self.review_signal]
                != (self.operation, self.surface.surface_class)
            )
        ):
            raise ValueError("Mobile package knowledge differs from sealed semantics")
        if hypothesis is not None:
            if self.review_signal is None:
                raise ValueError("Mobile Hypothesis lacks a bounded review signal")
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
                raise ValueError("Mobile bounded Hypothesis differs from the neutral Observation")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.mobile-package-analysis-knowledge-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"mobile-package-analysis-knowledge_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Mobile package-analysis knowledge candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Mobile package-analysis knowledge candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class MobilePackageAnalysisKnowledgeAdmission(_MobileKnowledgeAuthorityBoundary):
    """Proof that sealed Mobile package-analysis knowledge entered only the existing writer."""

    api_version: Literal["pajin.dev/mobile-package-analysis-knowledge-admission/v1alpha1"] = Field(
        default=MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobilePackageAnalysisKnowledgeAdmission"] = (
        "MobilePackageAnalysisKnowledgeAdmission"
    )
    admission_id: str = Field(default="", alias="admissionId", max_length=112)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: MobilePackageAnalysisKnowledgeCandidate
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
        "domain_worker_profile_binding_deferred",
        "exact_surface_and_package_bound",
        "external_static_sandbox_verified",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mobile package-analysis knowledge admission markers must be true")
        return value

    @field_validator("bounded_hypothesis_admitted", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Mobile package-analysis bounded Hypothesis marker must be boolean")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mobile package-analysis knowledge admission cannot grant authority")
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
                "Mobile package-analysis Observation admission exceeds neutral knowledge authority"
            )
        hypothesis = self.candidate.hypothesis_proposal
        expected_hypothesis = hypothesis is not None
        if (
            self.bounded_hypothesis_admitted is not expected_hypothesis
            or (self.hypothesis_graph_event is not None) is not expected_hypothesis
        ):
            raise ValueError("Mobile package-analysis bounded Hypothesis admission marker differs")
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
                raise ValueError(
                    "Mobile package-analysis bounded Hypothesis exceeds open knowledge authority"
                )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.mobile-package-analysis-knowledge-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"mobile-package-analysis-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Mobile package-analysis knowledge admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Mobile package-analysis knowledge admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def _hypothesis_text(
    signal: MobilePackageAnalysisReviewSignal,
) -> tuple[str, str]:
    text = {
        MobilePackageAnalysisReviewSignal.APK_PACKAGE_STRUCTURE_REVIEW: (
            "The exact APK package structure warrants bounded independent review.",
            "Independent static re-analysis reproduces the same APK package-structure "
            "review signal for the exact selected Surface and root package digest.",
        ),
        MobilePackageAnalysisReviewSignal.IPA_PACKAGE_STRUCTURE_REVIEW: (
            "The exact IPA package structure warrants bounded independent review.",
            "Independent static re-analysis reproduces the same IPA package-structure "
            "review signal for the exact selected Surface and root package digest.",
        ),
        MobilePackageAnalysisReviewSignal.APPLICATION_DECLARATION_REVIEW: (
            "The exact application declaration warrants bounded independent review.",
            "Independent static re-analysis reproduces the same application-declaration "
            "review signal for the exact selected Surface and root package digest.",
        ),
        MobilePackageAnalysisReviewSignal.RUNTIME_DECLARATION_REVIEW: (
            "The exact runtime declaration warrants bounded independent review.",
            "Independent static re-analysis reproduces the same runtime-declaration review "
            "signal for the exact selected Surface and root package digest.",
        ),
        MobilePackageAnalysisReviewSignal.STORAGE_DECLARATION_REVIEW: (
            "The exact storage declaration warrants bounded independent review.",
            "Independent static re-analysis reproduces the same storage-declaration review "
            "signal for the exact selected Surface and root package digest.",
        ),
        MobilePackageAnalysisReviewSignal.DEEP_LINK_DECLARATION_REVIEW: (
            "The exact deep-link declaration warrants bounded independent review.",
            "Independent static re-analysis reproduces the same deep-link-declaration review "
            "signal for the exact selected Surface and root package digest.",
        ),
        MobilePackageAnalysisReviewSignal.TLS_POLICY_DECLARATION_REVIEW: (
            "The exact TLS-policy declaration warrants bounded independent review.",
            "Independent static re-analysis reproduces the same TLS-policy review signal "
            "for the exact selected Surface and root package digest.",
        ),
        MobilePackageAnalysisReviewSignal.AUTHENTICATION_FLOW_DECLARATION_REVIEW: (
            "The exact authentication-flow declaration warrants bounded independent review.",
            "Independent static re-analysis reproduces the same authentication-flow review "
            "signal for the exact selected Surface and root package digest.",
        ),
    }
    return text[signal]


def mobile_package_analysis_knowledge_producer_registration() -> GraphProducerRegistration:
    """Return the exact code-owned Mobile package-analysis Observation/Hypothesis producer."""

    return GraphProducerRegistration(
        producerId=MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_ID,
        producerVersion=MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION,
        producerDigest=MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        allowedProposalKinds=(
            GraphProposalKind.HYPOTHESIS,
            GraphProposalKind.OBSERVATION,
        ),
    )


class MobilePackageAnalysisKnowledgeAdmissionGate:
    """Reverify detached Mobile package-analysis receipts and reuse the Graph single writer."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
        trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
    ) -> None:
        if type(graph_store) is not SQLiteGraphStore:
            raise TypeError(
                "Mobile package-analysis knowledge admission requires an exact SQLite Graph Store"
            )
        if type(graph_admission) is not GraphAdmissionAuthority:
            raise TypeError(
                "Mobile package-analysis knowledge admission requires the Graph Admission authority"
            )
        if type(trusted_lineages) is not TrustedGraphLineageRegistry:
            raise TypeError(
                "Mobile package-analysis knowledge admission requires the trusted lineage registry"
            )
        if type(trust_anchor) is not MobilePackageAnalysisExecutionTrustAnchor:
            raise TypeError(
                "Mobile package-analysis knowledge admission requires a deployment trust anchor"
            )
        _require_known_instance_fields(
            trust_anchor,
            label="Mobile package-analysis trust anchor",
        )
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("Mobile package-analysis knowledge Graph authority wiring differs")
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages
        self._trust_anchor = MobilePackageAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )

    def prepare_candidate(
        self,
        inputs: MobilePackageAnalysisObservationSourceInputs,
        graph: MobileGraphAdmissionBinding,
    ) -> MobilePackageAnalysisKnowledgeCandidate:
        try:
            _require_known_instance_fields(
                graph,
                label="Mobile package-analysis Graph binding",
            )
            _require_source_input_instance_fields(inputs)
            canonical_graph = MobileGraphAdmissionBinding.model_validate(
                graph.model_dump(mode="json", by_alias=True)
            )
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except MobilePackageAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis knowledge candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: MobilePackageAnalysisObservationSourceInputs,
        candidate: MobilePackageAnalysisKnowledgeCandidate,
    ) -> MobilePackageAnalysisKnowledgeAdmission:
        try:
            _require_source_input_instance_fields(inputs)
            _require_known_instance_fields(
                candidate,
                label="Mobile package-analysis knowledge candidate",
            )
            canonical = MobilePackageAnalysisKnowledgeCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise MobilePackageAnalysisKnowledgeAdmissionError(
                    "Mobile package-analysis knowledge candidate differs from sealed "
                    "source authority"
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
                    raise MobilePackageAnalysisKnowledgeAdmissionError(
                        "Mobile package-analysis knowledge admission requires a non-empty "
                        "Graph head"
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
                        raise MobilePackageAnalysisKnowledgeAdmissionError(
                            "Mobile package-analysis bounded Hypothesis source is no longer "
                            "the current "
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
            return MobilePackageAnalysisKnowledgeAdmission(
                candidate=canonical,
                observationGraphEvent=observation_result.event,
                hypothesisGraphEvent=hypothesis_event,
                boundedHypothesisAdmitted=hypothesis is not None,
            )
        except MobilePackageAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis knowledge admission failed closed"
            ) from exc

    def _require_admitted_result(
        self,
        event: GraphAdmissionEvent,
        graph: MobileGraphAdmissionBinding,
    ) -> None:
        if (
            event.decision is not GraphAdmissionDecision.ADMITTED
            or event.authority_id != graph.authority_id
            or event.authority_digest != graph.authority_digest
        ):
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Graph Admission authority rejected Mobile package-analysis knowledge"
            )

    def _build_candidate(
        self,
        inputs: MobilePackageAnalysisObservationSourceInputs,
        graph: MobileGraphAdmissionBinding,
    ) -> MobilePackageAnalysisKnowledgeCandidate:
        source = load_verified_mobile_package_analysis_observation_source(
            inputs,
            graph_store=self._graph_store,
            trust_anchor=self._trust_anchor,
        )
        permit = source.permit
        statement = source.bundle.statement
        receipt = source.result_receipt
        runtime = statement.sandbox_runtime
        if graph.snapshot.campaign_id != permit.campaign_id:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis execution source and Graph admission Campaigns differ"
            )
        policy = MobilePackageAnalysisKnowledgeAdmissionPolicy()
        value_digest = graph_digest(
            "pajin.workflow.mobile-package-analysis-observation-value/v1",
            {
                "preparationDigest": source.preparation.preparation_digest,
                "surfaceReference": source.preparation.surface.reference().model_dump(
                    mode="json",
                    by_alias=True,
                ),
                "packageSurfaceReference": (
                    source.preparation.package_surface.reference().model_dump(
                        mode="json",
                        by_alias=True,
                    )
                ),
                "artifactSHA256": receipt.artifact_sha256,
                "operation": source.preparation.operation.value,
                "platform": runtime.platform.value,
                "parser": runtime.parser.value,
                "artifactMountTarget": runtime.artifact_mount_target,
                "outputSchema": receipt.output_schema,
                "outputTransport": runtime.output_transport,
                "maxArtifactBytes": runtime.max_artifact_bytes,
                "maxOutputBytes": runtime.max_output_bytes,
                "maxRuntimeSeconds": runtime.max_runtime_seconds,
                "maxMemoryMiB": runtime.max_memory_mib,
                "maxProcessCount": runtime.max_process_count,
                "maxArchiveEntries": runtime.max_archive_entries,
                "maxTotalUncompressedBytes": runtime.max_total_uncompressed_bytes,
                "maxSingleUncompressedBytes": runtime.max_single_uncompressed_bytes,
                "maxArchivePathBytes": runtime.max_archive_path_bytes,
                "maxArchiveNestingDepth": runtime.max_archive_nesting_depth,
                "maxCompressionRatio": runtime.max_compression_ratio,
                "observedArchiveEntries": runtime.observed_archive_entries,
                "observedTotalUncompressedBytes": (runtime.observed_total_uncompressed_bytes),
                "observedLargestUncompressedBytes": (runtime.observed_largest_uncompressed_bytes),
                "observedMaxArchivePathBytes": runtime.observed_max_archive_path_bytes,
                "observedArchiveNestingDepth": (runtime.observed_archive_nesting_depth),
                "observedMaxCompressionRatio": runtime.observed_max_compression_ratio,
                "domainWorkerProfileBound": runtime.domain_worker_profile_bound,
                "domainWorkerProfileBindingDeferred": (
                    runtime.domain_worker_profile_binding_deferred
                ),
                "deviceBoundRuntimeProfileApplied": (runtime.device_bound_runtime_profile_applied),
                "workerJobMaterialized": runtime.worker_job_materialized,
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
            agent_id="agent:mobile-package-analysis-observation-admission",
            task_id=f"task:mobile-package-analysis-observation:{statement.statement_key[:32]}",
        )
        proposal_key = graph_digest(
            "pajin.workflow.mobile-package-analysis-observation-proposal-id/v1",
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
            proposalId=f"proposal:mobile-package-observation:{proposal_key}",
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
                agent_id="agent:mobile-package-analysis-hypothesis-admission",
                task_id=f"task:mobile-package-analysis-hypothesis:{statement.statement_key[:32]}",
            )
            hypothesis_key = graph_digest(
                "pajin.workflow.mobile-package-analysis-hypothesis-proposal-id/v1",
                {
                    "observationProposalDigest": observation_proposal.digest(),
                    "hypothesisNodeId": hypothesis.node_id,
                    "reviewSignal": receipt.review_signal.value,
                },
                max_bytes=_MAX_CANONICAL_BYTES,
            )
            hypothesis_proposal = HypothesisProposal(
                proposalId=f"proposal:mobile-package-hypothesis:{hypothesis_key}",
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                lineage=hypothesis_lineage,
                hypothesis=hypothesis,
                edges=[hypothesis_edge],
            )
        return MobilePackageAnalysisKnowledgeCandidate(
            policy=policy,
            graph=graph,
            preparation=source.preparation,
            surface=source.preparation.surface.reference(),
            packageSurface=source.preparation.package_surface.reference(),
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
            platform=runtime.platform,
            parser=runtime.parser,
            reviewSignal=receipt.review_signal,
            observationProposal=observation_proposal,
            hypothesisProposal=hypothesis_proposal,
        )

    def _require_current_graph(self, graph: MobileGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest != getattr(self._graph_admission, "_authority_digest", None)
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis knowledge Graph Admission authority differs"
            )
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis knowledge Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis knowledge Graph Snapshot is not the current canonical head"
            )


def _source_lineage(
    *,
    source: VerifiedMobilePackageAnalysisObservationSource,
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


def _require_source_input_instance_fields(
    inputs: MobilePackageAnalysisObservationSourceInputs,
) -> None:
    if type(inputs) is not MobilePackageAnalysisObservationSourceInputs:
        raise TypeError("Mobile package-analysis admission requires exact source inputs")
    for label, value in (
        ("Mobile activation set", inputs.activation.activation_set),
        ("Mobile Campaign", inputs.campaign),
        ("Mobile package-analysis preparation", inputs.preparation),
        ("Mobile package-analysis job", inputs.job),
    ):
        _require_known_instance_fields(value, label=label)


def load_verified_mobile_package_analysis_observation_source(
    inputs: MobilePackageAnalysisObservationSourceInputs,
    *,
    graph_store: SQLiteGraphStore,
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
) -> VerifiedMobilePackageAnalysisObservationSource:
    """Verify current authority, consumed Permit, signature, and detached receipt."""

    if type(inputs) is not MobilePackageAnalysisObservationSourceInputs:
        raise TypeError("Mobile package-analysis knowledge admission requires exact source inputs")
    if type(graph_store) is not SQLiteGraphStore:
        raise TypeError(
            "Mobile package-analysis source verification requires the exact SQLite Graph Store"
        )
    if type(trust_anchor) is not MobilePackageAnalysisExecutionTrustAnchor:
        raise TypeError(
            "Mobile package-analysis source verification requires a deployment trust anchor"
        )
    if type(inputs.activation) is not MobilePackageAnalysisCapabilityActivation:
        raise TypeError(
            "Mobile package-analysis source verification requires the current Mobile activation"
        )
    try:
        _require_source_input_instance_fields(inputs)
        _require_known_instance_fields(
            trust_anchor,
            label="Mobile package-analysis trust anchor",
        )
        campaign = CampaignManifest.model_validate(
            inputs.campaign.model_dump(mode="json", by_alias=True)
        )
        preparation = MobilePackageAnalysisPreparation.model_validate(
            inputs.preparation.model_dump(mode="json", by_alias=True)
        )
        job = CapabilityGraphCampaignJobInput.model_validate(
            inputs.job.model_dump(mode="json", by_alias=True)
        )
        trust_anchor = MobilePackageAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        prepared = preparation.prepared_action
        rebuilt = prepare_mobile_package_analysis(
            activation=inputs.activation,
            release=preparation.release,
            campaign=campaign,
            surface=preparation.surface,
            operation=preparation.operation,
            analyzer=BoundedMobilePackageAnalyzerAdapter(
                preparation.package_custody,
                preparation.sandbox,
            ),
            request_id=prepared.request.request_id,
            agent_id=prepared.request.agent_id,
        )
        if rebuilt != preparation:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis preparation differs from current signed and "
                "scoped authority"
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
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis preparation and approved execution inputs differ"
            )
        permits = tuple(
            permit
            for permit in graph_store.permit_store.permits()
            if permit.run_id == inputs.expected_run_id
            and permit.request_id == prepared.request.request_id
        )
        if len(permits) != 1:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis execution source lacks one exact consumed ActionPermit"
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
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis consumed ActionPermit differs from the prepared action"
            )
        receipts = tuple(
            receipt
            for receipt in graph_store.permit_store.approval_consumptions()
            if receipt.action_permit.permit_id == permit.permit_id
        )
        if len(receipts) != 1:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis execution source lacks one exact approval "
                "consumption receipt"
            )
        approval_receipt = receipts[0]
        if (
            approval_receipt.action_permit != permit
            or approval_receipt.approval != job.approval
            or approval_receipt != build_action_approval_consumption_receipt(job.approval, permit)
        ):
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis approval receipt differs from the consumed action"
            )
        attestation_reference = _artifact_reference(
            inputs.attestation_reference,
            label="Mobile package-analysis execution attestation",
        )
        attestation_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, attestation_reference),
            max_bytes=_MAX_ATTESTATION_BYTES,
            label="Mobile package-analysis execution attestation",
            require_single_link=True,
        )
        bundle = MobilePackageAnalysisExecutionBundle.model_validate(
            parse_strict_json_bytes(
                attestation_bytes,
                label="Mobile package-analysis execution attestation",
                max_bytes=_MAX_ATTESTATION_BYTES,
                max_depth=32,
                max_nodes=20_000,
            )
        )
        verification = verify_mobile_package_analysis_execution_bundle(
            bundle,
            trust_anchor=trust_anchor,
        )
        statement = bundle.statement
        result_reference = _artifact_reference(
            statement.result_receipt_reference,
            label="Mobile package-analysis static-analysis result receipt",
        )
        if result_reference == attestation_reference:
            raise MobilePackageAnalysisKnowledgeAdmissionError(
                "Mobile package-analysis attestation and result receipt must be distinct evidence"
            )
        result_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, result_reference),
            max_bytes=_MAX_RECEIPT_BYTES,
            label="Mobile package-analysis static-analysis result receipt",
            require_single_link=True,
        )
        result_receipt = MobilePackageAnalysisResultReceipt.model_validate(
            parse_strict_json_bytes(
                result_bytes,
                label="Mobile package-analysis static-analysis result receipt",
                max_bytes=_MAX_RECEIPT_BYTES,
                max_depth=20,
                max_nodes=8_000,
            )
        )
        result_sha256 = sha256(result_bytes).hexdigest()
        _validate_mobile_package_analysis_execution_source(
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
        source_root_digest = mobile_package_analysis_source_root_digest(
            attestation_sha256=attestation_sha256,
            result_receipt_sha256=result_sha256,
            trust_anchor_digest=verification.trust_anchor_digest,
            statement_sha256=verification.statement_sha256,
        )
        return VerifiedMobilePackageAnalysisObservationSource(
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
    except MobilePackageAnalysisKnowledgeAdmissionError:
        raise
    except Exception as exc:
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "sealed Mobile package-analysis static-analysis source authority is invalid"
        ) from exc


def _validate_mobile_package_analysis_execution_source(
    *,
    campaign: CampaignManifest,
    preparation: MobilePackageAnalysisPreparation,
    job: CapabilityGraphCampaignJobInput,
    permit: ActionPermit,
    approval_receipt: ActionApprovalConsumptionReceipt,
    trust_anchor: MobilePackageAnalysisExecutionTrustAnchor,
    statement: MobilePackageAnalysisExecutionStatement,
    result_receipt: MobilePackageAnalysisResultReceipt,
    result_receipt_sha256: str,
) -> None:
    prepared = preparation.prepared_action
    sandbox = trust_anchor.sandbox
    runtime = statement.sandbox_runtime
    custody = preparation.package_custody
    duration = (statement.finished_at - statement.started_at).total_seconds()
    expected_gateway_decision = PolicyEngine().evaluate_tool_request(
        campaign,
        job.grant,
        prepared.request,
        MobilePackageAnalysisTool.spec,
        used_calls=0,
        now=statement.started_at,
    )
    expected_gateway_digest = mobile_package_analysis_gateway_outcome_digest(
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
        or runtime.surface != preparation.surface.reference()
        or runtime.package_surface != preparation.package_surface.reference()
        or runtime.operation is not sandbox.operation
        or runtime.platform
        is not (
            MobilePlatform.ANDROID
            if preparation.package_surface.surface_class is MobileSurfaceClass.APK
            else MobilePlatform.IOS
        )
        or runtime.parser is not sandbox.parser
        or runtime.parser_executable_sha256 != sandbox.parser_executable_sha256
        or runtime.sandbox_image_sha256 != sandbox.sandbox_image_sha256
        or runtime.run_as_identity != sandbox.run_as_identity
        or runtime.artifact_mount_target != sandbox.artifact_mount_target
        or runtime.output_schema != sandbox.output_schema
        or runtime.output_transport != sandbox.output_transport
        or runtime.artifact_sha256 != custody.artifact_sha256
        or runtime.artifact_bytes != custody.artifact_bytes
        or runtime.custody_binding_id != custody.custody_binding_id
        or runtime.custody_binding_digest != custody.custody_binding_digest
        or runtime.custody_authority_id != custody.custody_authority_id
        or runtime.custody_object_id != custody.custody_object_id
        or runtime.authorization_id != custody.authorization_id
        or runtime.authorization_digest != custody.authorization_digest
        or runtime.max_artifact_bytes != sandbox.max_artifact_bytes
        or runtime.max_output_bytes != sandbox.max_output_bytes
        or runtime.max_runtime_seconds != sandbox.max_runtime_seconds
        or runtime.max_memory_mib != sandbox.max_memory_mib
        or runtime.max_process_count != sandbox.max_process_count
        or runtime.max_archive_entries != sandbox.max_archive_entries
        or runtime.max_total_uncompressed_bytes != sandbox.max_total_uncompressed_bytes
        or runtime.max_single_uncompressed_bytes != sandbox.max_single_uncompressed_bytes
        or runtime.max_archive_path_bytes != sandbox.max_archive_path_bytes
        or runtime.max_archive_nesting_depth != sandbox.max_archive_nesting_depth
        or runtime.max_compression_ratio != sandbox.max_compression_ratio
        or runtime.archive_path_traversal_rejected is not sandbox.archive_path_traversal_rejected
        or runtime.archive_symlinks_rejected is not sandbox.archive_symlinks_rejected
        or runtime.archive_duplicate_names_rejected is not sandbox.archive_duplicate_names_rejected
        or runtime.domain_worker_profile_bound is not False
        or runtime.domain_worker_profile_binding_deferred is not True
        or runtime.device_bound_runtime_profile_applied is not False
        or runtime.worker_job_materialized is not False
        or sandbox.domain_worker_profile_bound is not False
        or sandbox.domain_worker_profile_binding_deferred is not True
        or sandbox.device_bound_runtime_profile_applied is not False
        or sandbox.worker_job_materialization_available is not False
        or result_receipt.execution_id != statement.execution_id
        or result_receipt.request_id != prepared.request.request_id
        or result_receipt.request_digest != prepared.request_digest
        or result_receipt.preparation_id != preparation.preparation_id
        or result_receipt.preparation_digest != preparation.preparation_digest
        or result_receipt.operation is not preparation.operation
        or result_receipt.platform is not runtime.platform
        or result_receipt.parser is not sandbox.parser
        or result_receipt.surface != preparation.surface.reference()
        or result_receipt.package_surface != preparation.package_surface.reference()
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
        raise MobilePackageAnalysisKnowledgeAdmissionError(
            "sealed Mobile package-analysis execution statement differs from current authority"
        )


def _artifact_reference(value: str, *, label: str) -> str:
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError) as exc:
        raise MobilePackageAnalysisKnowledgeAdmissionError(f"{label} reference is invalid") from exc
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
        raise MobilePackageAnalysisKnowledgeAdmissionError(f"{label} reference is invalid")
    return path.as_posix()


def _artifact_path(root: Path, reference: str) -> Path:
    parts = PurePosixPath(reference).parts
    return Path(root).resolve().joinpath(*parts)


def mobile_package_analysis_source_root_digest(
    *,
    attestation_sha256: str,
    result_receipt_sha256: str,
    trust_anchor_digest: str,
    statement_sha256: str,
) -> str:
    return graph_digest(
        "pajin.workflow.mobile-package-analysis-observation-source-root/v1",
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
    graph: MobileGraphAdmissionBinding,
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
        raise ValueError(
            "Mobile package-analysis Graph admission differs from its bounded Proposal"
        )


__all__ = [
    "MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION",
    "MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST",
    "MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_ID",
    "MOBILE_PACKAGE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION",
    "MobileGraphAdmissionBinding",
    "MobilePackageAnalysisExecutionAttestor",
    "MobilePackageAnalysisExecutionBundle",
    "MobilePackageAnalysisExecutionKeyState",
    "MobilePackageAnalysisExecutionStatement",
    "MobilePackageAnalysisExecutionTrustAnchor",
    "MobilePackageAnalysisExecutionVerification",
    "MobilePackageAnalysisExecutionVerificationKey",
    "MobilePackageAnalysisKnowledgeAdmission",
    "MobilePackageAnalysisKnowledgeAdmissionError",
    "MobilePackageAnalysisKnowledgeAdmissionGate",
    "MobilePackageAnalysisKnowledgeAdmissionPolicy",
    "MobilePackageAnalysisKnowledgeCandidate",
    "MobilePackageAnalysisObservationSourceInputs",
    "MobilePackageAnalysisResultReceipt",
    "MobilePackageAnalysisReviewSignal",
    "MobilePackageSandboxRuntimeReceipt",
    "VerifiedMobilePackageAnalysisObservationSource",
    "load_verified_mobile_package_analysis_observation_source",
    "mobile_package_analysis_execution_bundle_bytes",
    "mobile_package_analysis_execution_public_key",
    "mobile_package_analysis_gateway_outcome_digest",
    "mobile_package_analysis_knowledge_producer_registration",
    "mobile_package_analysis_result_receipt_bytes",
    "mobile_package_analysis_source_root_digest",
    "verify_mobile_package_analysis_execution_bundle",
]
