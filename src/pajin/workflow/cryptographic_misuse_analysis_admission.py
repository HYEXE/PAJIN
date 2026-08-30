"""CRYPTO-001C sealed Cryptographic misuse-analysis knowledge admission."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from functools import cache
from hashlib import sha256
from pathlib import Path, PurePosixPath
from re import fullmatch
from types import MappingProxyType
from typing import Annotated, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.capabilities.activation import capability_grant_digest
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.cryptographic_misuse_analysis import (
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
    BoundedCryptographicMisuseAnalyzerAdapter,
    CryptographicAnalysisInputKind,
    CryptographicMisuseAnalysisCapabilityActivation,
    CryptographicMisuseAnalysisOperation,
    CryptographicMisuseAnalysisPreparation,
    CryptographicMisuseAnalysisRequest,
    CryptographicMisuseAnalysisSandboxBinding,
    CryptographicMisuseAnalysisTool,
    CryptographicMisuseAnalyzer,
    CryptographicMisuseRuleSetRef,
    CryptographicMisuseSignalKind,
    CryptographicSurfaceAnalysisMapping,
    prepare_cryptographic_misuse_analysis,
    registered_cryptographic_misuse_analysis_binding,
    registered_cryptographic_misuse_rule_set,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.cryptography_surfaces import (
    CryptographyProtocolKeyArtifactSurfaceRef,
    CryptographySurfaceClass,
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

CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_ID = (
    "pajin.workflow.cryptographic-misuse-analysis-knowledge-admission"
)
CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION = "1.0.0"
CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.cryptographic-misuse-analysis-knowledge-admission/v1"
).hexdigest()
CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION: Literal[
    "pajin.dev/cryptographic-misuse-analysis-knowledge-admission/v1alpha1"
] = "pajin.dev/cryptographic-misuse-analysis-knowledge-admission/v1alpha1"

_SIGNATURE_DOMAIN = b"pajin.workflow.cryptographic-misuse-analysis-execution-attestation/v1\0"
_MAX_ATTESTATION_BYTES = 2 * 1024 * 1024
_MAX_RECEIPT_BYTES = 512 * 1024
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_OBSERVATION_SUMMARY = (
    "A separately authorized sealed offline analysis produced structurally consistent, "
    "digest-bound neutral Cryptographic result metadata."
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
    "raw_key_material_embedded",
    "key_reference_embedded",
    "raw_ciphertext_embedded",
    "raw_plaintext_embedded",
    "raw_configuration_embedded",
    "artifact_format_authority",
    "configuration_value_authority",
    "runtime_support_authority",
    "dependency_relationship_authority",
    "vulnerability_confirmation_authority",
    "semantic_misuse_truth_authority",
    "negative_security_claim_authorized",
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
    "dns_access_authorized",
    "key_material_access_authorized",
    "credential_use_authorized",
    "cryptographic_operation_authorized",
    "key_search_authorized",
    "protocol_negotiation_authorized",
    "new_oracle_invocation_authorized",
    "plaintext_output_authorized",
    "key_material_output_authorized",
    "dynamic_target_execution_authorized",
    "debugger_attach_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class CryptographicMisuseAnalysisKnowledgeAdmissionError(ValueError):
    """Raised when sealed Cryptographic knowledge cannot enter the Graph."""


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
    """Reject unchecked model_copy(update=...) state at every trust boundary."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        unknown = set(value.__dict__) - set(type(value).model_fields)
        if unknown:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
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


def _canonical_model[ModelT: BaseModel](
    model_type: type[ModelT],
    value: object,
    *,
    label: str,
    by_alias: bool = True,
) -> ModelT:
    _require_known_instance_fields(value, label=label)
    try:
        if type(value) is not model_type:
            raise TypeError
        canonical = model_type.model_validate(value.model_dump(mode="json", by_alias=by_alias))
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        if isinstance(exc, CryptographicMisuseAnalysisKnowledgeAdmissionError):
            raise
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            f"{label} is not canonical"
        ) from exc
    _require_known_instance_fields(canonical, label=label)
    if canonical != value:
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(f"{label} drifted")
    return canonical


class CryptographicMisuseAnalysisExecutionKeyState(StrEnum):
    """Lifecycle state for one deployment-owned execution attestation key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class CryptographicMisuseOracleDisposition(StrEnum):
    """Structural result state; neither member confirms security truth."""

    STRUCTURALLY_CONSISTENT_REVIEW = "structurally-consistent-review"
    INCONCLUSIVE_NO_SIGNAL = "inconclusive-no-signal"


class CryptographicMisuseAnalysisResultDisposition(StrEnum):
    """Deployment-declared neutral routing result, never a security verdict."""

    REVIEW = "review"
    NO_SIGNAL = "no-signal"


_REVIEW_SIGNAL_BY_SURFACE_CLASS: Mapping[
    CryptographySurfaceClass,
    CryptographicMisuseSignalKind,
] = MappingProxyType(
    {
        CryptographySurfaceClass.PROTOCOL: CryptographicMisuseSignalKind.PROTOCOL_POLICY,
        CryptographySurfaceClass.KEY_USAGE: CryptographicMisuseSignalKind.KEY_USAGE_POLICY,
        CryptographySurfaceClass.CIPHERTEXT: CryptographicMisuseSignalKind.CIPHERTEXT_STRUCTURE,
        CryptographySurfaceClass.CONFIGURATION: CryptographicMisuseSignalKind.CONFIGURATION_POLICY,
    }
)


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


def _require_consistent_digest_byte_counts(
    *coordinates: tuple[str, str, int],
) -> None:
    """Reject contradictory byte counts for any repeated content digest."""

    seen: dict[str, tuple[str, int]] = {}
    for label, digest, byte_count in coordinates:
        if type(digest) is not str or fullmatch(r"^[a-f0-9]{64}$", digest) is None:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                f"Cryptographic {label} digest is invalid"
            )
        if type(byte_count) is not int or byte_count < 1:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                f"Cryptographic {label} byte count is invalid"
            )
        previous = seen.get(digest)
        if previous is not None and previous[1] != byte_count:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                f"Cryptographic {label} byte count conflicts with {previous[0]}"
            )
        seen[digest] = (label, byte_count)


class CryptographicMisuseAnalysisExecutionVerificationKey(_FrozenStrictModel):
    """One externally configured Ed25519 verifier and its lifecycle."""

    key_id: _Identifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: CryptographicMisuseAnalysisExecutionKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Cryptographic misuse-analysis execution public key",
        )
        not_before = _aware_utc(
            self.not_before, label="Cryptographic analysis execution key not-before"
        )
        if self.not_after is not None:
            not_after = _aware_utc(
                self.not_after,
                label="Cryptographic analysis execution key not-after",
            )
            if not_after <= not_before:
                raise ValueError("Cryptographic analysis execution key validity window is empty")
        if (
            self.state is CryptographicMisuseAnalysisExecutionKeyState.RETIRED
            and self.not_after is None
        ):
            raise ValueError("retired Cryptographic analysis execution key requires not_after")
        if self.state is CryptographicMisuseAnalysisExecutionKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Cryptographic analysis execution key requires revoked_at")
            _aware_utc(self.revoked_at, label="Cryptographic analysis execution key revocation")
        elif self.revoked_at is not None:
            raise ValueError(
                "non-revoked Cryptographic analysis execution key cannot have revoked_at"
            )
        return self


class CryptographicMisuseAnalysisExecutionTrustAnchor(_FrozenStrictModel):
    """Deployment verifier that grants no artifact or sandbox execution authority."""

    api_version: Literal[
        "pajin.dev/cryptographic-misuse-analysis-execution-trust-anchor/v1alpha1"
    ] = Field(
        default="pajin.dev/cryptographic-misuse-analysis-execution-trust-anchor/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisExecutionTrustAnchor"] = (
        "CryptographicMisuseAnalysisExecutionTrustAnchor"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    sandbox: CryptographicMisuseAnalysisSandboxBinding
    capability: CodeBackedCapabilityRef
    capability_release: CapabilityReleaseRef = Field(alias="capabilityRelease")
    keys: tuple[CryptographicMisuseAnalysisExecutionVerificationKey, ...] = Field(
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
            raise ValueError("Cryptographic analysis execution trust-anchor markers must be true")
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
            raise ValueError("Cryptographic analysis execution trust anchor cannot grant authority")
        return value

    @model_validator(mode="after")
    def require_exact_sandbox_and_keyring(self) -> Self:
        if self.capability != registered_cryptographic_misuse_analysis_binding().capability:
            raise ValueError("Cryptographic analysis execution trust-anchor Capability differs")
        keys = [(item.key_id, item.public_key_base64url) for item in self.keys]
        key_ids = [item.key_id for item in self.keys]
        public_keys = [item.public_key_base64url for item in self.keys]
        if (
            keys != sorted(keys)
            or len(key_ids) != len(set(key_ids))
            or len(public_keys) != len(set(public_keys))
        ):
            raise ValueError(
                "Cryptographic analysis execution trust-anchor keys must be unique and sorted"
            )
        if (
            sum(
                item.state is CryptographicMisuseAnalysisExecutionKeyState.ACTIVE
                for item in self.keys
            )
            != 1
        ):
            raise ValueError(
                "Cryptographic analysis execution trust anchor requires one active key"
            )
        return self

    @property
    def digest(self) -> str:
        return graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-execution-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_CANONICAL_BYTES,
        )


class CryptographicMisuseAnalysisSandboxRuntimeReceipt(_FrozenStrictModel):
    """Digest-only proof of one exact offline, read-only sandbox execution."""

    receipt_id: str = Field(default="", alias="receiptId", max_length=105)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    sandbox_binding_id: _Identifier = Field(alias="sandboxBindingId")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    surface: CryptographyProtocolKeyArtifactSurfaceRef
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer
    analyzer_executable_sha256: _Sha256 = Field(alias="analyzerExecutableSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    max_artifact_bytes: int = Field(
        alias="maxArtifactBytes",
        strict=True,
        ge=1,
        le=536_870_912,
    )
    max_output_bytes: int = Field(
        alias="maxOutputBytes",
        strict=True,
        ge=1_024,
        le=16_777_216,
    )
    max_runtime_seconds: int = Field(
        alias="maxRuntimeSeconds",
        strict=True,
        ge=1,
        le=300,
    )
    max_memory_mib: int = Field(alias="maxMemoryMiB", strict=True, ge=64, le=4_096)
    max_process_count: int = Field(alias="maxProcessCount", strict=True, ge=1, le=64)
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
    analyzer_executable_verified: Literal[True] = Field(
        default=True,
        alias="analyzerExecutableVerified",
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
    dns_disabled_verified: Literal[True] = Field(
        default=True,
        alias="dnsDisabledVerified",
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
    core_dump_disabled_verified: Literal[True] = Field(
        default=True,
        alias="coreDumpDisabledVerified",
    )
    raw_identity_metadata_embedded: Literal[False] = Field(
        default=False,
        alias="rawIdentityMetadataEmbedded",
    )
    raw_artifact_embedded: Literal[False] = Field(default=False, alias="rawArtifactEmbedded")
    raw_key_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawKeyMaterialEmbedded",
    )
    raw_plaintext_embedded: Literal[False] = Field(
        default=False,
        alias="rawPlaintextEmbedded",
    )
    raw_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawConfigurationEmbedded",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    key_search_authorized: Literal[False] = Field(
        default=False,
        alias="keySearchAuthorized",
    )
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="oracleInvocationAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("attested_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Cryptographic analysis sandbox runtime attestation")

    @field_validator(
        "custody_authorization_verified",
        "artifact_digest_verified",
        "artifact_read_completed",
        "analyzer_executable_verified",
        "sandbox_image_verified",
        "non_root_verified",
        "network_disabled_verified",
        "dns_disabled_verified",
        "read_only_root_verified",
        "read_only_artifact_mount_verified",
        "artifact_mount_noexec_verified",
        "no_new_privileges_verified",
        "resource_limits_verified",
        "core_dump_disabled_verified",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError(
                "Cryptographic analysis sandbox runtime verification markers must be true"
            )
        return value

    @field_validator(
        "raw_identity_metadata_embedded",
        "raw_artifact_embedded",
        "raw_key_material_embedded",
        "raw_plaintext_embedded",
        "raw_configuration_embedded",
        "network_access_authorized",
        "dns_access_authorized",
        "key_material_access_authorized",
        "credential_use_authorized",
        "cryptographic_operation_authorized",
        "key_search_authorized",
        "protocol_negotiation_authorized",
        "oracle_invocation_authorized",
        "artifact_mutation_authorized",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "Cryptographic analysis sandbox runtime receipt cannot grant authority"
            )
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cryptographic-analysis-sandbox-runtime-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"cryptographic-analysis-sandbox-runtime_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Cryptographic analysis sandbox runtime receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Cryptographic analysis sandbox runtime receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class CryptographicMisuseAnalysisResultReceipt(_FrozenStrictModel):
    """Neutral detached manifest with no raw artifact or analyzer output."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-result-receipt/v1alpha1"] = Field(
        default="pajin.dev/cryptographic-misuse-analysis-result-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisResultReceipt"] = (
        "CryptographicMisuseAnalysisResultReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=105)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    execution_id: _Identifier = Field(alias="executionId")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    preparation_id: _Identifier = Field(alias="preparationId")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    surface: CryptographyProtocolKeyArtifactSurfaceRef
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=1, le=536_870_912)
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    result_bytes: int = Field(alias="resultBytes", strict=True, ge=2, le=16_777_216)
    media_type: Literal["application/json"] = Field(default="application/json", alias="mediaType")
    result_disposition: CryptographicMisuseAnalysisResultDisposition = Field(
        alias="resultDisposition"
    )
    received_at: datetime = Field(alias="receivedAt")
    execution_completed: Literal[True] = Field(default=True, alias="executionCompleted")
    digest_only: Literal[True] = Field(default=True, alias="digestOnly")
    raw_result_embedded: Literal[False] = Field(default=False, alias="rawResultEmbedded")
    raw_artifact_embedded: Literal[False] = Field(default=False, alias="rawArtifactEmbedded")
    artifact_path_embedded: Literal[False] = Field(default=False, alias="artifactPathEmbedded")
    raw_key_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawKeyMaterialEmbedded",
    )
    key_reference_embedded: Literal[False] = Field(
        default=False,
        alias="keyReferenceEmbedded",
    )
    raw_ciphertext_embedded: Literal[False] = Field(
        default=False,
        alias="rawCiphertextEmbedded",
    )
    raw_plaintext_embedded: Literal[False] = Field(
        default=False,
        alias="rawPlaintextEmbedded",
    )
    raw_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawConfigurationEmbedded",
    )
    raw_parameter_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawParameterMaterialEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    caller_rule_or_plugin_embedded: Literal[False] = Field(
        default=False,
        alias="callerRuleOrPluginEmbedded",
    )
    result_body_read: Literal[False] = Field(default=False, alias="resultBodyRead")
    semantic_result_verified: Literal[False] = Field(
        default=False,
        alias="semanticResultVerified",
    )
    misuse_confirmed: Literal[False] = Field(default=False, alias="misuseConfirmed")
    negative_security_claim: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaim",
    )
    finding_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthority",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("received_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Cryptographic analysis receipt received-at")

    @field_validator("execution_completed", "digest_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cryptographic analysis result receipt success markers must be true")
        return value

    @field_validator(
        "raw_result_embedded",
        "raw_artifact_embedded",
        "artifact_path_embedded",
        "raw_key_material_embedded",
        "key_reference_embedded",
        "raw_ciphertext_embedded",
        "raw_plaintext_embedded",
        "raw_configuration_embedded",
        "raw_parameter_material_embedded",
        "credential_material_embedded",
        "caller_rule_or_plugin_embedded",
        "result_body_read",
        "semantic_result_verified",
        "misuse_confirmed",
        "negative_security_claim",
        "finding_confirmation_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cryptographic analysis result receipt cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-result-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"cryptographic-analysis-result_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Cryptographic analysis result receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Cryptographic analysis result receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class CryptographicMisuseOracleSignalMapping(_FrozenStrictModel):
    """One immutable Surface-class routing row owned by the admission Oracle."""

    surface_class: CryptographySurfaceClass = Field(alias="surfaceClass")
    review_signal: CryptographicMisuseSignalKind = Field(alias="reviewSignal")


_ORACLE_SIGNAL_MAPPING = tuple(
    CryptographicMisuseOracleSignalMapping(
        surfaceClass=surface_class,
        reviewSignal=_REVIEW_SIGNAL_BY_SURFACE_CLASS[surface_class],
    )
    for surface_class in sorted(CryptographySurfaceClass, key=lambda item: item.value)
)


class CryptographicMisuseAnalysisOraclePolicy(_FrozenStrictModel):
    """Code-owned structural verifier policy with no analyzer or artifact authority."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-oracle-policy/v1alpha1"] = Field(
        default="pajin.dev/cryptographic-misuse-analysis-oracle-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisOraclePolicy"] = (
        "CryptographicMisuseAnalysisOraclePolicy"
    )
    oracle_id: Literal["pajin.workflow.cryptographic-misuse-result-admission-oracle"] = Field(
        default="pajin.workflow.cryptographic-misuse-result-admission-oracle",
        alias="oracleId",
    )
    oracle_version: Literal["1.0.0"] = Field(default="1.0.0", alias="oracleVersion")
    oracle_digest: str = Field(default="", alias="oracleDigest", max_length=64)
    rule_set: CryptographicMisuseRuleSetRef = Field(
        default_factory=lambda: registered_cryptographic_misuse_rule_set().reference(),
        alias="ruleSet",
    )
    surface_signal_mapping: tuple[CryptographicMisuseOracleSignalMapping, ...] = Field(
        default_factory=lambda: tuple(
            item.model_copy(deep=True) for item in _ORACLE_SIGNAL_MAPPING
        ),
        alias="surfaceSignalMapping",
        min_length=4,
        max_length=4,
    )
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    structural_only: Literal[True] = Field(default=True, alias="structuralOnly")
    caller_decision_allowed: Literal[False] = Field(
        default=False,
        alias="callerDecisionAllowed",
    )
    artifact_read_allowed: Literal[False] = Field(default=False, alias="artifactReadAllowed")
    result_body_read_allowed: Literal[False] = Field(
        default=False,
        alias="resultBodyReadAllowed",
    )
    key_material_access_allowed: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAllowed",
    )
    cryptographic_operation_allowed: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAllowed",
    )
    semantic_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticTruthAuthority",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("structural_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cryptographic admission Oracle structural marker must be true")
        return value

    @field_validator(
        "caller_decision_allowed",
        "artifact_read_allowed",
        "result_body_read_allowed",
        "key_material_access_allowed",
        "cryptographic_operation_allowed",
        "semantic_truth_authority",
        "finding_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cryptographic admission Oracle cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        rule_set = registered_cryptographic_misuse_rule_set().reference()
        if (
            self.rule_set != rule_set
            or self.surface_signal_mapping != _ORACLE_SIGNAL_MAPPING
            or self.output_schema != CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA
        ):
            raise ValueError("Cryptographic admission Oracle policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"oracle_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-oracle-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.oracle_digest and self.oracle_digest != digest:
            raise ValueError("Cryptographic admission Oracle policy digest differs")
        object.__setattr__(self, "oracle_digest", digest)
        return self


@cache
def _registered_cryptographic_misuse_analysis_oracle_policy() -> (
    CryptographicMisuseAnalysisOraclePolicy
):
    return CryptographicMisuseAnalysisOraclePolicy()


def registered_cryptographic_misuse_analysis_oracle_policy() -> (
    CryptographicMisuseAnalysisOraclePolicy
):
    """Return an isolated structural Oracle policy without execution authority."""

    return _registered_cryptographic_misuse_analysis_oracle_policy().model_copy(deep=True)


class CryptographicMisuseAnalysisOracleVerdict(_FrozenStrictModel):
    """Recomputed structural consistency result; never cryptographic semantic truth."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-oracle-verdict/v1alpha1"] = Field(
        default="pajin.dev/cryptographic-misuse-analysis-oracle-verdict/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisOracleVerdict"] = (
        "CryptographicMisuseAnalysisOracleVerdict"
    )
    verdict_id: str = Field(default="", alias="verdictId", max_length=108)
    verdict_digest: str = Field(default="", alias="verdictDigest", max_length=64)
    oracle_policy: CryptographicMisuseAnalysisOraclePolicy = Field(alias="oraclePolicy")
    disposition: CryptographicMisuseOracleDisposition
    result_disposition: CryptographicMisuseAnalysisResultDisposition = Field(
        alias="resultDisposition"
    )
    review_signal: CryptographicMisuseSignalKind | None = Field(
        default=None,
        alias="reviewSignal",
    )
    surface: CryptographyProtocolKeyArtifactSurfaceRef
    surface_mapping: CryptographicSurfaceAnalysisMapping = Field(alias="surfaceMapping")
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    custody_binding_id: _Identifier = Field(alias="custodyBindingId")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=1, le=536_870_912)
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    result_receipt_id: _Identifier = Field(alias="resultReceiptId")
    result_receipt_digest: _Sha256 = Field(alias="resultReceiptDigest")
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    result_bytes: int = Field(alias="resultBytes", strict=True, ge=2, le=16_777_216)
    structurally_consistent: Literal[True] = Field(
        default=True,
        alias="structurallyConsistent",
    )
    result_body_digest_declared_only: Literal[True] = Field(
        default=True,
        alias="resultBodyDigestDeclaredOnly",
    )
    artifact_read_performed: Literal[False] = Field(
        default=False,
        alias="artifactReadPerformed",
    )
    result_body_read_performed: Literal[False] = Field(
        default=False,
        alias="resultBodyReadPerformed",
    )
    key_material_accessed: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessed",
    )
    cryptographic_operation_performed: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationPerformed",
    )
    semantic_truth_established: Literal[False] = Field(
        default=False,
        alias="semanticTruthEstablished",
    )
    misuse_confirmed: Literal[False] = Field(default=False, alias="misuseConfirmed")
    negative_security_claim: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaim",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("structurally_consistent", "result_body_digest_declared_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cryptographic admission Oracle verification markers must be true")
        return value

    @field_validator(
        "artifact_read_performed",
        "result_body_read_performed",
        "key_material_accessed",
        "cryptographic_operation_performed",
        "semantic_truth_established",
        "misuse_confirmed",
        "negative_security_claim",
        "finding_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cryptographic admission Oracle verdict cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_verdict_identity(self) -> Self:
        policy = registered_cryptographic_misuse_analysis_oracle_policy()
        expected_signal = (
            _REVIEW_SIGNAL_BY_SURFACE_CLASS[self.surface.surface_class]
            if self.result_disposition is CryptographicMisuseAnalysisResultDisposition.REVIEW
            else None
        )
        expected_disposition = (
            CryptographicMisuseOracleDisposition.STRUCTURALLY_CONSISTENT_REVIEW
            if expected_signal is not None
            else CryptographicMisuseOracleDisposition.INCONCLUSIVE_NO_SIGNAL
        )
        mapping = next(
            item
            for item in policy.rule_set.surface_analysis_mapping
            if item.surface_class is self.surface.surface_class
        )
        if (
            self.oracle_policy != policy
            or self.rule_set != policy.rule_set
            or self.surface_mapping != mapping
            or self.input_kind is not mapping.input_kind
            or self.review_signal is not expected_signal
            or self.disposition is not expected_disposition
        ):
            raise ValueError("Cryptographic admission Oracle verdict differs from exact policy")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verdict_id", "verdict_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-oracle-verdict/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        verdict_id = f"cryptographic-analysis-oracle_{digest}"
        if self.verdict_digest and self.verdict_digest != digest:
            raise ValueError("Cryptographic admission Oracle verdict digest differs")
        if self.verdict_id and self.verdict_id != verdict_id:
            raise ValueError("Cryptographic admission Oracle verdict ID differs")
        object.__setattr__(self, "verdict_digest", digest)
        object.__setattr__(self, "verdict_id", verdict_id)
        return self


def recompute_cryptographic_misuse_analysis_oracle_verdict(
    *,
    preparation: CryptographicMisuseAnalysisPreparation,
    result_receipt: CryptographicMisuseAnalysisResultReceipt,
) -> CryptographicMisuseAnalysisOracleVerdict:
    """Purely recompute strict metadata consistency without reading analysis inputs."""

    canonical_preparation = _canonical_model(
        CryptographicMisuseAnalysisPreparation,
        preparation,
        label="Cryptographic misuse-analysis preparation",
    )
    canonical_receipt = _canonical_model(
        CryptographicMisuseAnalysisResultReceipt,
        result_receipt,
        label="Cryptographic misuse-analysis result receipt",
    )
    request = canonical_preparation.analysis_request
    custody = canonical_preparation.artifact_custody
    surface = canonical_preparation.surface.reference()
    policy = registered_cryptographic_misuse_analysis_oracle_policy()
    mapping = next(
        item
        for item in policy.rule_set.surface_analysis_mapping
        if item.surface_class is surface.surface_class
    )
    if (
        canonical_receipt.preparation_id != canonical_preparation.preparation_id
        or canonical_receipt.preparation_digest != canonical_preparation.preparation_digest
        or canonical_receipt.surface != surface
        or canonical_receipt.input_kind is not canonical_preparation.input_kind
        or canonical_receipt.input_kind is not mapping.input_kind
        or canonical_receipt.operation is not canonical_preparation.operation
        or canonical_receipt.operation is not mapping.operation
        or canonical_receipt.analyzer is not request.analyzer
        or canonical_receipt.analyzer is not mapping.analyzer
        or canonical_receipt.rule_set != request.rule_set
        or canonical_receipt.rule_set != policy.rule_set
        or canonical_receipt.artifact_sha256 != custody.artifact_sha256
        or canonical_receipt.artifact_bytes != custody.artifact_bytes
        or canonical_receipt.output_schema != request.output_schema
        or canonical_receipt.output_schema != policy.output_schema
        or canonical_receipt.result_bytes > request.budget.max_output_bytes
    ):
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "Cryptographic result manifest differs from the exact structural Oracle inputs"
        )
    _require_consistent_digest_byte_counts(
        ("artifact", custody.artifact_sha256, custody.artifact_bytes),
        (
            "declared result body",
            canonical_receipt.result_body_sha256,
            canonical_receipt.result_bytes,
        ),
    )
    signal = (
        _REVIEW_SIGNAL_BY_SURFACE_CLASS[surface.surface_class]
        if canonical_receipt.result_disposition
        is CryptographicMisuseAnalysisResultDisposition.REVIEW
        else None
    )
    disposition = (
        CryptographicMisuseOracleDisposition.STRUCTURALLY_CONSISTENT_REVIEW
        if signal is not None
        else CryptographicMisuseOracleDisposition.INCONCLUSIVE_NO_SIGNAL
    )
    return CryptographicMisuseAnalysisOracleVerdict(
        oraclePolicy=policy,
        disposition=disposition,
        resultDisposition=canonical_receipt.result_disposition,
        reviewSignal=signal,
        surface=surface,
        surfaceMapping=mapping,
        ruleSet=policy.rule_set,
        inputKind=canonical_preparation.input_kind,
        custodyBindingId=custody.custody_binding_id,
        custodyBindingDigest=custody.custody_binding_digest,
        authorizationDigest=custody.authorization_digest,
        artifactSHA256=custody.artifact_sha256,
        artifactBytes=custody.artifact_bytes,
        outputSchema=request.output_schema,
        resultReceiptId=canonical_receipt.receipt_id,
        resultReceiptDigest=canonical_receipt.receipt_digest,
        resultBodySha256=canonical_receipt.result_body_sha256,
        resultBytes=canonical_receipt.result_bytes,
    )


class CryptographicMisuseAnalysisExecutionStatement(_FrozenStrictModel):
    """Signed assertion for one already-completed approved sandbox execution."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-execution-statement/v1alpha1"] = (
        Field(
            default="pajin.dev/cryptographic-misuse-analysis-execution-statement/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["CryptographicMisuseAnalysisExecutionStatement"] = (
        "CryptographicMisuseAnalysisExecutionStatement"
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
    analysis_request: CryptographicMisuseAnalysisRequest = Field(alias="analysisRequest")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    action_permit_id: _Identifier = Field(alias="actionPermitId")
    action_permit_digest: _Sha256 = Field(alias="actionPermitDigest")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    sandbox_runtime: CryptographicMisuseAnalysisSandboxRuntimeReceipt = Field(
        alias="sandboxRuntime"
    )
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
    dns_queries: Literal[0] = Field(default=0, alias="dnsQueries")
    artifact_write_operations: Literal[0] = Field(
        default=0,
        alias="artifactWriteOperations",
    )
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    key_material_reads: Literal[0] = Field(default=0, alias="keyMaterialReads")
    key_store_sessions: Literal[0] = Field(default=0, alias="keyStoreSessions")
    cryptographic_operations: Literal[0] = Field(default=0, alias="cryptographicOperations")
    key_search_attempts: Literal[0] = Field(default=0, alias="keySearchAttempts")
    protocol_negotiations: Literal[0] = Field(default=0, alias="protocolNegotiations")
    oracle_invocations: Literal[0] = Field(default=0, alias="oracleInvocations")
    plaintext_outputs: Literal[0] = Field(default=0, alias="plaintextOutputs")
    key_material_outputs: Literal[0] = Field(default=0, alias="keyMaterialOutputs")
    target_process_executions: Literal[0] = Field(
        default=0,
        alias="targetProcessExecutions",
    )
    shell_commands: Literal[0] = Field(default=0, alias="shellCommands")
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
    exact_rule_set_bound: Literal[True] = Field(default=True, alias="exactRuleSetBound")
    offline_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="offlineSandboxVerified",
    )
    result_sealed: Literal[True] = Field(default=True, alias="resultSealed")
    raw_analyzer_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawAnalyzerOutputEmbedded",
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
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    key_search_authorized: Literal[False] = Field(
        default=False,
        alias="keySearchAuthorized",
    )
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="oracleInvocationAuthorized",
    )
    plaintext_output_authorized: Literal[False] = Field(
        default=False,
        alias="plaintextOutputAuthorized",
    )
    key_material_output_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialOutputAuthorized",
    )
    target_process_execution_authorized: Literal[False] = Field(
        default=False,
        alias="targetProcessExecutionAuthorized",
    )
    shell_command_authorized: Literal[False] = Field(
        default=False,
        alias="shellCommandAuthorized",
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
        return _aware_utc(value, label="Cryptographic misuse-analysis execution time")

    @field_validator(
        "request_count",
        "artifact_reads",
        "network_requests",
        "dns_queries",
        "artifact_write_operations",
        "host_filesystem_reads",
        "credential_reads",
        "key_material_reads",
        "key_store_sessions",
        "cryptographic_operations",
        "key_search_attempts",
        "protocol_negotiations",
        "oracle_invocations",
        "plaintext_outputs",
        "key_material_outputs",
        "target_process_executions",
        "shell_commands",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Cryptographic analysis execution budget values must be integers")
        return value

    @field_validator(
        "gateway_policy_reentered",
        "consumed_permit_verified",
        "approval_receipt_verified",
        "exact_surface_bound",
        "exact_artifact_digest_verified",
        "custody_authorization_verified",
        "exact_rule_set_bound",
        "offline_sandbox_verified",
        "result_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cryptographic analysis execution verification markers must be true")
        return value

    @field_validator(
        "raw_analyzer_output_embedded",
        "new_artifact_access_authorized",
        "new_sandbox_invocation_authorized",
        "new_worker_selection_authorized",
        "network_access_authorized",
        "dns_access_authorized",
        "key_material_access_authorized",
        "credential_use_authorized",
        "cryptographic_operation_authorized",
        "key_search_authorized",
        "protocol_negotiation_authorized",
        "oracle_invocation_authorized",
        "plaintext_output_authorized",
        "key_material_output_authorized",
        "target_process_execution_authorized",
        "shell_command_authorized",
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
            raise ValueError(
                "Cryptographic analysis execution statement cannot grant new authority"
            )
        return value

    @model_validator(mode="after")
    def require_causal_execution(self) -> Self:
        if not (
            self.started_at
            <= self.sandbox_runtime.attested_at
            <= self.finished_at
            <= self.issued_at
        ):
            raise ValueError(
                "Cryptographic analysis execution statement timestamps are inconsistent"
            )
        if self.analysis_request.method != "GET":
            raise ValueError(
                "Cryptographic analysis execution statement requires one exact GET request"
            )
        if self.gateway_policy_decision.allowed is not True:
            raise ValueError(
                "Cryptographic analysis execution statement requires an allowed Gateway decision"
            )
        return self

    @property
    def statement_key(self) -> str:
        return sha256(
            canonical_json_bytes(
                self.model_dump(mode="json", by_alias=True),
                label="Cryptographic misuse-analysis execution statement key",
                max_bytes=_MAX_CANONICAL_BYTES,
            )
        ).hexdigest()


class CryptographicMisuseAnalysisExecutionBundle(_FrozenStrictModel):
    """Detached Ed25519 signature over one Cryptographic analysis execution statement."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-execution-bundle/v1alpha1"] = (
        Field(
            default="pajin.dev/cryptographic-misuse-analysis-execution-bundle/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["CryptographicMisuseAnalysisExecutionBundle"] = (
        "CryptographicMisuseAnalysisExecutionBundle"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _Identifier = Field(alias="keyId")
    statement: CryptographicMisuseAnalysisExecutionStatement
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_json_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Cryptographic misuse-analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("Cryptographic analysis execution statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Cryptographic misuse-analysis execution signature",
        )
        return self


class CryptographicMisuseAnalysisExecutionVerification(_FrozenStrictModel):
    """Result of verifying caller-supplied Cryptographic analysis execution trust."""

    valid: Literal[True] = True
    key_id: _Identifier = Field(alias="keyId")
    key_state: CryptographicMisuseAnalysisExecutionKeyState = Field(alias="keyState")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    issued_at: datetime = Field(alias="issuedAt")

    @field_validator("valid", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cryptographic misuse-analysis verification must be true")
        return value


@dataclass(frozen=True, slots=True)
class CryptographicMisuseAnalysisExecutionAttestor:
    """Signing helper for a deployment runtime; it performs no analysis."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
    ) -> CryptographicMisuseAnalysisExecutionAttestor:
        if len(private_key) != 32:
            raise ValueError(
                "Ed25519 Cryptographic analysis execution private key must contain 32 bytes"
            )
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        if type(self.active_key_id) is not str or not self.active_key_id:
            raise TypeError("Cryptographic analysis execution signer key ID must be exact")
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise TypeError("Cryptographic analysis execution signer requires Ed25519")
        anchor = _canonical_model(
            CryptographicMisuseAnalysisExecutionTrustAnchor,
            self.trust_anchor,
            label="Cryptographic misuse-analysis execution trust anchor",
        )
        matching = [key for key in anchor.keys if key.key_id == self.active_key_id]
        if (
            len(matching) != 1
            or matching[0].state is not CryptographicMisuseAnalysisExecutionKeyState.ACTIVE
        ):
            raise ValueError("Cryptographic analysis execution signer key is not active")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Cryptographic analysis execution active public key",
        )
        if public_bytes != expected:
            raise ValueError(
                "Cryptographic analysis execution private key does not match its trust anchor"
            )

    def attest(
        self,
        statement: CryptographicMisuseAnalysisExecutionStatement,
    ) -> CryptographicMisuseAnalysisExecutionBundle:
        canonical_statement = _canonical_model(
            CryptographicMisuseAnalysisExecutionStatement,
            statement,
            label="Cryptographic misuse-analysis execution statement",
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
                "Cryptographic analysis execution statement differs from its trust anchor"
            )
        key = next(item for item in self.trust_anchor.keys if item.key_id == self.active_key_id)
        issued_at = canonical_statement.issued_at
        if issued_at < key.not_before or (key.not_after is not None and issued_at >= key.not_after):
            raise ValueError(
                "Cryptographic analysis execution signing key is not valid at issue time"
            )
        canonical = canonical_json_bytes(
            canonical_statement.model_dump(mode="json", by_alias=True),
            label="Cryptographic misuse-analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return CryptographicMisuseAnalysisExecutionBundle(
            keyId=self.active_key_id,
            statement=canonical_statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


def cryptographic_misuse_analysis_execution_public_key(private_key: bytes) -> str:
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


def cryptographic_misuse_analysis_execution_bundle_bytes(
    bundle: CryptographicMisuseAnalysisExecutionBundle,
) -> bytes:
    """Serialize a readable bundle whose signature covers canonical statement bytes."""

    canonical = _canonical_model(
        CryptographicMisuseAnalysisExecutionBundle,
        bundle,
        label="Cryptographic misuse-analysis execution bundle",
    )
    return (
        json.dumps(
            canonical.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def cryptographic_misuse_analysis_result_receipt_bytes(
    receipt: CryptographicMisuseAnalysisResultReceipt,
) -> bytes:
    """Serialize one detached digest-only result receipt."""

    canonical = _canonical_model(
        CryptographicMisuseAnalysisResultReceipt,
        receipt,
        label="Cryptographic misuse-analysis result receipt",
    )
    return (
        json.dumps(
            canonical.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def cryptographic_misuse_analysis_gateway_outcome_digest(
    *,
    policy_decision: PolicyDecision,
    request_digest: str,
    permit_digest: str,
    sandbox_runtime_receipt_digest: str,
    result_receipt_digest: str,
) -> str:
    """Bind one allowed Gateway result without embedding analyzer output."""

    canonical = _canonical_model(
        PolicyDecision,
        policy_decision,
        label="Cryptographic Gateway policy decision",
        by_alias=False,
    )
    if canonical.allowed is not True:
        raise ValueError("Cryptographic Gateway outcome requires an allowed policy decision")
    for label, value in (
        ("request", request_digest),
        ("Permit", permit_digest),
        ("sandbox runtime", sandbox_runtime_receipt_digest),
        ("result receipt", result_receipt_digest),
    ):
        if not isinstance(value, str) or fullmatch(r"^[a-f0-9]{64}$", value) is None:
            raise ValueError(f"Cryptographic Gateway {label} digest is invalid")
    return graph_digest(
        "pajin.workflow.cryptographic-misuse-analysis-gateway-outcome/v1",
        {
            "policyDecision": canonical.model_dump(mode="json"),
            "requestDigest": request_digest,
            "permitDigest": permit_digest,
            "sandboxRuntimeReceiptDigest": sandbox_runtime_receipt_digest,
            "resultReceiptDigest": result_receipt_digest,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def verify_cryptographic_misuse_analysis_execution_bundle(
    bundle: CryptographicMisuseAnalysisExecutionBundle,
    *,
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
) -> CryptographicMisuseAnalysisExecutionVerification:
    """Verify one detached deployment signature against the configured keyring."""

    try:
        canonical_bundle = _canonical_model(
            CryptographicMisuseAnalysisExecutionBundle,
            bundle,
            label="Cryptographic misuse-analysis execution bundle",
        )
        canonical_anchor = _canonical_model(
            CryptographicMisuseAnalysisExecutionTrustAnchor,
            trust_anchor,
            label="Cryptographic misuse-analysis execution trust anchor",
        )
    except Exception as exc:
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "Cryptographic analysis execution attestation is not canonical"
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
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "Cryptographic analysis execution attestation is not trusted"
        )
    matching = [key for key in canonical_anchor.keys if key.key_id == canonical_bundle.key_id]
    if len(matching) != 1:
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "Cryptographic analysis execution signing key is not trusted"
        )
    key = matching[0]
    if key.state is CryptographicMisuseAnalysisExecutionKeyState.REVOKED:
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "Cryptographic analysis execution signing key is revoked"
        )
    if statement.issued_at < key.not_before or (
        key.not_after is not None and statement.issued_at >= key.not_after
    ):
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "Cryptographic analysis execution signing key is outside its validity window"
        )
    canonical_statement = canonical_json_bytes(
        statement.model_dump(mode="json", by_alias=True),
        label="Cryptographic misuse-analysis execution statement",
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    try:
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="Cryptographic analysis execution public key",
            )
        ).verify(
            _base64url_decode(
                canonical_bundle.signature_base64url,
                expected_length=64,
                label="Cryptographic analysis execution signature",
            ),
            _SIGNATURE_DOMAIN + canonical_statement,
        )
    except (InvalidSignature, ValueError) as exc:
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "Cryptographic analysis execution signature is invalid"
        ) from exc
    return CryptographicMisuseAnalysisExecutionVerification(
        keyId=key.key_id,
        keyState=key.state,
        trustAnchorDigest=canonical_anchor.digest,
        statementSha256=canonical_bundle.statement_sha256,
        issuedAt=statement.issued_at,
    )


@dataclass(frozen=True, slots=True)
class CryptographicMisuseAnalysisObservationSourceInputs:
    """Current authority plus two deployment-produced detached evidence files."""

    source_root: Path
    attestation_reference: str
    expected_run_id: str
    activation: CryptographicMisuseAnalysisCapabilityActivation
    campaign: CampaignManifest
    preparation: CryptographicMisuseAnalysisPreparation
    job: CapabilityGraphCampaignJobInput


@dataclass(frozen=True, slots=True)
class VerifiedCryptographicMisuseAnalysisObservationSource:
    """One cryptographically authenticated sealed execution source."""

    preparation: CryptographicMisuseAnalysisPreparation
    job: CapabilityGraphCampaignJobInput
    permit: ActionPermit
    approval_receipt: ActionApprovalConsumptionReceipt
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor
    verification: CryptographicMisuseAnalysisExecutionVerification
    bundle: CryptographicMisuseAnalysisExecutionBundle
    result_receipt: CryptographicMisuseAnalysisResultReceipt
    oracle_verdict: CryptographicMisuseAnalysisOracleVerdict
    attestation_reference: str
    attestation_sha256: str
    result_receipt_reference: str
    result_receipt_sha256: str
    source_root_digest: str


class CryptographicMisuseAnalysisKnowledgeAdmissionPolicy(_FrozenStrictModel):
    """Code-owned authority for a neutral Observation and optional open Hypothesis."""

    api_version: Literal[
        "pajin.dev/cryptographic-misuse-analysis-knowledge-admission-policy/v1alpha1"
    ] = Field(
        default="pajin.dev/cryptographic-misuse-analysis-knowledge-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CryptographicMisuseAnalysisKnowledgeAdmissionPolicy"] = (
        "CryptographicMisuseAnalysisKnowledgeAdmissionPolicy"
    )
    policy_id: str = Field(default="", alias="policyId", max_length=112)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.cryptographic-misuse-analysis-knowledge-admission"] = (
        Field(
            default="pajin.workflow.cryptographic-misuse-analysis-knowledge-admission",
            alias="producerId",
        )
    )
    producer_version: Literal["1.0.0"] = Field(default="1.0.0", alias="producerVersion")
    producer_digest: _Sha256 = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["cryptography.analysis-observation"] = Field(
        default="cryptography.analysis-observation",
        alias="observationType",
    )
    hypothesis_type: Literal["cryptography.misuse-weakness"] = Field(
        default="cryptography.misuse-weakness",
        alias="hypothesisType",
    )
    oracle_policy: CryptographicMisuseAnalysisOraclePolicy = Field(
        default_factory=registered_cryptographic_misuse_analysis_oracle_policy,
        alias="oraclePolicy",
    )
    review_signals: tuple[CryptographicMisuseSignalKind, ...] = Field(
        default_factory=lambda: registered_cryptographic_misuse_rule_set().signal_vocabulary,
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
    semantic_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticTruthAuthority",
    )
    negative_security_claim_authorized: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaimAuthorized",
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
            raise ValueError("Cryptographic analysis knowledge policy markers must be true")
        return value

    @field_validator(
        "artifact_format_authority",
        "semantic_truth_authority",
        "negative_security_claim_authorized",
        "vulnerability_confirmation_authorized",
        "finding_production_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cryptographic analysis knowledge policy cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        if (
            self.producer_digest != CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST
            or self.oracle_policy != registered_cryptographic_misuse_analysis_oracle_policy()
            or self.review_signals != registered_cryptographic_misuse_rule_set().signal_vocabulary
        ):
            raise ValueError("Cryptographic analysis knowledge policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-knowledge-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"cryptographic-analysis-knowledge-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Cryptographic analysis knowledge policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Cryptographic analysis knowledge policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class CryptographicGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph Snapshot and its already-existing single writer."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError(
                "Cryptographic analysis knowledge admission requires a non-empty Graph Snapshot"
            )
        return self


class CryptographicMisuseAnalysisKnowledgeCandidate(_FrozenStrictModel):
    """Content-addressed neutral Observation and optional bounded Hypothesis."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-knowledge-candidate/v1alpha1"] = (
        Field(
            default="pajin.dev/cryptographic-misuse-analysis-knowledge-candidate/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["CryptographicMisuseAnalysisKnowledgeCandidate"] = (
        "CryptographicMisuseAnalysisKnowledgeCandidate"
    )
    candidate_id: str = Field(default="", alias="candidateId", max_length=112)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: CryptographicMisuseAnalysisKnowledgeAdmissionPolicy
    graph: CryptographicGraphAdmissionBinding
    preparation: CryptographicMisuseAnalysisPreparation
    surface: CryptographyProtocolKeyArtifactSurfaceRef
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
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=1, le=536_870_912)
    output_schema: Literal["pajin.cryptography.offline-misuse-analysis-result.v1"] = Field(
        default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    operation: CryptographicMisuseAnalysisOperation
    analyzer: CryptographicMisuseAnalyzer
    input_kind: CryptographicAnalysisInputKind = Field(alias="inputKind")
    rule_set: CryptographicMisuseRuleSetRef = Field(alias="ruleSet")
    oracle_verdict: CryptographicMisuseAnalysisOracleVerdict = Field(alias="oracleVerdict")
    oracle_policy_digest: _Sha256 = Field(alias="oraclePolicyDigest")
    oracle_verdict_digest: _Sha256 = Field(alias="oracleVerdictDigest")
    result_disposition: CryptographicMisuseAnalysisResultDisposition = Field(
        alias="resultDisposition"
    )
    review_signal: CryptographicMisuseSignalKind | None = Field(
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
    structural_oracle_recomputed: Literal[True] = Field(
        default=True,
        alias="structuralOracleRecomputed",
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
    raw_key_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawKeyMaterialEmbedded",
    )
    key_reference_embedded: Literal[False] = Field(
        default=False,
        alias="keyReferenceEmbedded",
    )
    raw_ciphertext_embedded: Literal[False] = Field(
        default=False,
        alias="rawCiphertextEmbedded",
    )
    raw_plaintext_embedded: Literal[False] = Field(
        default=False,
        alias="rawPlaintextEmbedded",
    )
    raw_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawConfigurationEmbedded",
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
    semantic_misuse_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticMisuseTruthAuthority",
    )
    negative_security_claim_authorized: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaimAuthorized",
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
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    key_search_authorized: Literal[False] = Field(
        default=False,
        alias="keySearchAuthorized",
    )
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    new_oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="newOracleInvocationAuthorized",
    )
    plaintext_output_authorized: Literal[False] = Field(
        default=False,
        alias="plaintextOutputAuthorized",
    )
    key_material_output_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialOutputAuthorized",
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
        "structural_oracle_recomputed",
        "neutral_observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cryptographic sealed knowledge markers must be true")
        return value

    @field_validator("graph_admitted", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "Cryptographic analysis knowledge candidate authority flags must be false"
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
                "Cryptography Domain Graph semantics are not registered exactly"
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
            or self.input_kind is not self.preparation.input_kind
            or self.analyzer is not self.preparation.analysis_request.analyzer
            or self.rule_set != self.preparation.analysis_request.rule_set
            or self.artifact_sha256 != self.preparation.artifact_custody.artifact_sha256
            or self.artifact_bytes != self.preparation.artifact_custody.artifact_bytes
            or self.output_schema != self.preparation.analysis_request.output_schema
            or self.oracle_verdict.oracle_policy != self.policy.oracle_policy
            or self.oracle_policy_digest != self.policy.oracle_policy.oracle_digest
            or self.oracle_verdict_digest != self.oracle_verdict.verdict_digest
            or self.oracle_verdict.surface != self.surface
            or self.oracle_verdict.rule_set != self.rule_set
            or self.oracle_verdict.input_kind is not self.input_kind
            or self.oracle_verdict.artifact_sha256 != self.artifact_sha256
            or self.oracle_verdict.artifact_bytes != self.artifact_bytes
            or self.oracle_verdict.output_schema != self.output_schema
            or self.oracle_verdict.result_body_sha256 != self.result_body_sha256
            or self.oracle_verdict.result_receipt_digest != self.result_receipt_digest
            or self.result_disposition is not self.oracle_verdict.result_disposition
            or self.review_signal is not self.oracle_verdict.review_signal
            or semantics.domain_classification.domain is not SecurityDomain.CRYPTOGRAPHY
            or semantics.surface_type != "cryptography.protocol-key-artifact"
            or semantics.locator_schema != "pajin.locator.cryptography.protocol-key-artifact.v1"
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
            raise ValueError(
                "Cryptographic analysis knowledge candidate differs from sealed semantics"
            )
        if hypothesis is not None:
            if self.review_signal is None:
                raise ValueError("Cryptographic Hypothesis lacks a bounded review signal")
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
                    "Cryptographic bounded Hypothesis differs from the neutral Observation"
                )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-knowledge-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"cryptographic-analysis-knowledge_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Cryptographic analysis knowledge candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Cryptographic analysis knowledge candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class CryptographicMisuseAnalysisKnowledgeAdmission(_FrozenStrictModel):
    """Proof that sealed Cryptographic knowledge entered only the existing writer."""

    api_version: Literal["pajin.dev/cryptographic-misuse-analysis-knowledge-admission/v1alpha1"] = (
        Field(
            default=CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["CryptographicMisuseAnalysisKnowledgeAdmission"] = (
        "CryptographicMisuseAnalysisKnowledgeAdmission"
    )
    admission_id: str = Field(default="", alias="admissionId", max_length=112)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: CryptographicMisuseAnalysisKnowledgeCandidate
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
    raw_key_material_embedded: Literal[False] = Field(
        default=False,
        alias="rawKeyMaterialEmbedded",
    )
    key_reference_embedded: Literal[False] = Field(
        default=False,
        alias="keyReferenceEmbedded",
    )
    raw_ciphertext_embedded: Literal[False] = Field(
        default=False,
        alias="rawCiphertextEmbedded",
    )
    raw_plaintext_embedded: Literal[False] = Field(
        default=False,
        alias="rawPlaintextEmbedded",
    )
    raw_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawConfigurationEmbedded",
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
    semantic_misuse_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticMisuseTruthAuthority",
    )
    negative_security_claim_authorized: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaimAuthorized",
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
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    cryptographic_operation_authorized: Literal[False] = Field(
        default=False,
        alias="cryptographicOperationAuthorized",
    )
    key_search_authorized: Literal[False] = Field(
        default=False,
        alias="keySearchAuthorized",
    )
    protocol_negotiation_authorized: Literal[False] = Field(
        default=False,
        alias="protocolNegotiationAuthorized",
    )
    new_oracle_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="newOracleInvocationAuthorized",
    )
    plaintext_output_authorized: Literal[False] = Field(
        default=False,
        alias="plaintextOutputAuthorized",
    )
    key_material_output_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialOutputAuthorized",
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
            raise ValueError("Cryptographic analysis knowledge admission markers must be true")
        return value

    @field_validator("bounded_hypothesis_admitted", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cryptographic bounded Hypothesis marker must be boolean")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cryptographic analysis knowledge admission cannot grant authority")
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
                "Cryptographic Observation admission exceeds neutral knowledge authority"
            )
        hypothesis = self.candidate.hypothesis_proposal
        expected_hypothesis = hypothesis is not None
        if (
            self.bounded_hypothesis_admitted is not expected_hypothesis
            or (self.hypothesis_graph_event is not None) is not expected_hypothesis
        ):
            raise ValueError("Cryptographic bounded Hypothesis admission marker differs")
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
                    "Cryptographic bounded Hypothesis exceeds open knowledge authority"
                )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-knowledge-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"cryptographic-analysis-knowledge-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Cryptographic analysis knowledge admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Cryptographic analysis knowledge admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def _hypothesis_text(
    signal: CryptographicMisuseSignalKind,
) -> tuple[str, str]:
    text = {
        CryptographicMisuseSignalKind.PROTOCOL_POLICY: (
            "The structurally consistent protocol result metadata carries a bounded "
            "protocol-policy review signal.",
            "A separately authorized future re-analysis is required to evaluate the same "
            "protocol-policy signal for the exact Surface and artifact digest.",
        ),
        CryptographicMisuseSignalKind.KEY_USAGE_POLICY: (
            "The structurally consistent key-usage result metadata carries a bounded "
            "key-usage-policy review signal.",
            "A separately authorized future re-analysis is required to evaluate the same "
            "key-usage-policy signal for the exact Surface and artifact digest.",
        ),
        CryptographicMisuseSignalKind.CIPHERTEXT_STRUCTURE: (
            "The structurally consistent ciphertext result metadata carries a bounded "
            "ciphertext-structure review signal.",
            "A separately authorized future re-analysis is required to evaluate the same "
            "ciphertext-structure signal for the exact Surface and artifact digest.",
        ),
        CryptographicMisuseSignalKind.CONFIGURATION_POLICY: (
            "The structurally consistent configuration result metadata carries a bounded "
            "configuration-policy review signal.",
            "A separately authorized future re-analysis is required to evaluate the same "
            "configuration-policy signal for the exact Surface and artifact digest.",
        ),
    }
    return text[signal]


def cryptographic_misuse_analysis_knowledge_producer_registration() -> GraphProducerRegistration:
    """Return the exact code-owned Cryptography Observation/Hypothesis producer."""

    return GraphProducerRegistration(
        producerId=CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_ID,
        producerVersion=CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION,
        producerDigest=CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        allowedProposalKinds=(
            GraphProposalKind.HYPOTHESIS,
            GraphProposalKind.OBSERVATION,
        ),
    )


class CryptographicMisuseAnalysisKnowledgeAdmissionGate:
    """Reverify detached Cryptographic receipts and reuse the Graph single writer."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
        trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
    ) -> None:
        if type(graph_store) is not SQLiteGraphStore:
            raise TypeError(
                "Cryptographic analysis knowledge admission requires an exact SQLite Graph Store"
            )
        if type(graph_admission) is not GraphAdmissionAuthority:
            raise TypeError(
                "Cryptographic analysis knowledge admission requires the Graph Admission authority"
            )
        if type(trusted_lineages) is not TrustedGraphLineageRegistry:
            raise TypeError(
                "Cryptographic analysis knowledge admission requires the trusted lineage registry"
            )
        if type(trust_anchor) is not CryptographicMisuseAnalysisExecutionTrustAnchor:
            raise TypeError(
                "Cryptographic analysis knowledge admission requires a deployment trust anchor"
            )
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("Cryptographic analysis knowledge Graph authority wiring differs")
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages
        self._trust_anchor = _canonical_model(
            CryptographicMisuseAnalysisExecutionTrustAnchor,
            trust_anchor,
            label="Cryptographic misuse-analysis execution trust anchor",
        )

    def prepare_candidate(
        self,
        inputs: CryptographicMisuseAnalysisObservationSourceInputs,
        graph: CryptographicGraphAdmissionBinding,
    ) -> CryptographicMisuseAnalysisKnowledgeCandidate:
        try:
            canonical_graph = _canonical_model(
                CryptographicGraphAdmissionBinding,
                graph,
                label="Cryptographic Graph admission binding",
            )
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except CryptographicMisuseAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis knowledge candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: CryptographicMisuseAnalysisObservationSourceInputs,
        candidate: CryptographicMisuseAnalysisKnowledgeCandidate,
    ) -> CryptographicMisuseAnalysisKnowledgeAdmission:
        try:
            canonical = _canonical_model(
                CryptographicMisuseAnalysisKnowledgeCandidate,
                candidate,
                label="Cryptographic misuse-analysis knowledge candidate",
            )
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                    "Cryptographic analysis knowledge candidate differs from sealed "
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
                    raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                        "Cryptographic analysis knowledge admission requires a non-empty Graph head"
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
                        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                            "Cryptographic bounded Hypothesis source is no longer the current "
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
            return CryptographicMisuseAnalysisKnowledgeAdmission(
                candidate=canonical,
                observationGraphEvent=observation_result.event,
                hypothesisGraphEvent=hypothesis_event,
                boundedHypothesisAdmitted=hypothesis is not None,
            )
        except CryptographicMisuseAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis knowledge admission failed closed"
            ) from exc

    def _require_admitted_result(
        self,
        event: GraphAdmissionEvent,
        graph: CryptographicGraphAdmissionBinding,
    ) -> None:
        if (
            event.decision is not GraphAdmissionDecision.ADMITTED
            or event.authority_id != graph.authority_id
            or event.authority_digest != graph.authority_digest
        ):
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Graph Admission authority rejected Cryptographic analysis knowledge"
            )

    def _build_candidate(
        self,
        inputs: CryptographicMisuseAnalysisObservationSourceInputs,
        graph: CryptographicGraphAdmissionBinding,
    ) -> CryptographicMisuseAnalysisKnowledgeCandidate:
        source = load_verified_cryptographic_misuse_analysis_observation_source(
            inputs,
            graph_store=self._graph_store,
            trust_anchor=self._trust_anchor,
        )
        permit = source.permit
        statement = source.bundle.statement
        receipt = source.result_receipt
        oracle_verdict = source.oracle_verdict
        runtime = statement.sandbox_runtime
        if graph.snapshot.campaign_id != permit.campaign_id:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis execution source and Graph admission Campaigns differ"
            )
        policy = CryptographicMisuseAnalysisKnowledgeAdmissionPolicy()
        value_digest = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-observation-value/v1",
            {
                "preparationDigest": source.preparation.preparation_digest,
                "surfaceReference": source.preparation.surface.reference().model_dump(
                    mode="json",
                    by_alias=True,
                ),
                "artifactSHA256": receipt.artifact_sha256,
                "operation": source.preparation.operation.value,
                "inputKind": source.preparation.input_kind.value,
                "analyzer": source.preparation.analysis_request.analyzer.value,
                "ruleSet": source.preparation.analysis_request.rule_set.model_dump(
                    mode="json",
                    by_alias=True,
                ),
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
                "oraclePolicyDigest": oracle_verdict.oracle_policy.oracle_digest,
                "oracleVerdictDigest": oracle_verdict.verdict_digest,
                "oracleDisposition": oracle_verdict.disposition.value,
                "resultDisposition": oracle_verdict.result_disposition.value,
                "reviewSignal": (
                    oracle_verdict.review_signal.value
                    if oracle_verdict.review_signal is not None
                    else None
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
            agent_id="agent:cryptographic-misuse-analysis-observation-admission",
            task_id=f"task:cryptographic-analysis-observation:{statement.statement_key[:32]}",
        )
        proposal_key = graph_digest(
            "pajin.workflow.cryptographic-misuse-analysis-observation-proposal-id/v1",
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
            proposalId=f"proposal:cryptographic-observation:{proposal_key}",
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
        if oracle_verdict.review_signal is not None:
            hypothesis_statement, expected_observable = _hypothesis_text(
                oracle_verdict.review_signal
            )
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
                agent_id="agent:cryptographic-misuse-analysis-hypothesis-admission",
                task_id=f"task:cryptographic-analysis-hypothesis:{statement.statement_key[:32]}",
            )
            hypothesis_key = graph_digest(
                "pajin.workflow.cryptographic-misuse-analysis-hypothesis-proposal-id/v1",
                {
                    "observationProposalDigest": observation_proposal.digest(),
                    "hypothesisNodeId": hypothesis.node_id,
                    "reviewSignal": oracle_verdict.review_signal.value,
                },
                max_bytes=_MAX_CANONICAL_BYTES,
            )
            hypothesis_proposal = HypothesisProposal(
                proposalId=f"proposal:cryptographic-hypothesis:{hypothesis_key}",
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                lineage=hypothesis_lineage,
                hypothesis=hypothesis,
                edges=[hypothesis_edge],
            )
        return CryptographicMisuseAnalysisKnowledgeCandidate(
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
            artifactBytes=receipt.artifact_bytes,
            outputSchema=receipt.output_schema,
            operation=source.preparation.operation,
            analyzer=source.preparation.analysis_request.analyzer,
            inputKind=source.preparation.input_kind,
            ruleSet=source.preparation.analysis_request.rule_set,
            oracleVerdict=oracle_verdict,
            oraclePolicyDigest=oracle_verdict.oracle_policy.oracle_digest,
            oracleVerdictDigest=oracle_verdict.verdict_digest,
            resultDisposition=oracle_verdict.result_disposition,
            reviewSignal=oracle_verdict.review_signal,
            observationProposal=observation_proposal,
            hypothesisProposal=hypothesis_proposal,
        )

    def _require_current_graph(self, graph: CryptographicGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest != getattr(self._graph_admission, "_authority_digest", None)
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis knowledge Graph Admission authority differs"
            )
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis knowledge Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis knowledge Graph Snapshot is not the current canonical head"
            )


def _source_lineage(
    *,
    source: VerifiedCryptographicMisuseAnalysisObservationSource,
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


def load_verified_cryptographic_misuse_analysis_observation_source(
    inputs: CryptographicMisuseAnalysisObservationSourceInputs,
    *,
    graph_store: SQLiteGraphStore,
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
) -> VerifiedCryptographicMisuseAnalysisObservationSource:
    """Verify current authority, consumed Permit, signature, and detached receipt."""

    if type(inputs) is not CryptographicMisuseAnalysisObservationSourceInputs:
        raise TypeError("Cryptographic analysis knowledge admission requires exact source inputs")
    if type(graph_store) is not SQLiteGraphStore:
        raise TypeError("Cryptographic source verification requires the exact SQLite Graph Store")
    if type(trust_anchor) is not CryptographicMisuseAnalysisExecutionTrustAnchor:
        raise TypeError("Cryptographic source verification requires a deployment trust anchor")
    if type(inputs.activation) is not CryptographicMisuseAnalysisCapabilityActivation:
        raise TypeError("Cryptographic source verification requires current activation")
    try:
        campaign = _canonical_model(
            CampaignManifest,
            inputs.campaign,
            label="Cryptographic Campaign",
        )
        preparation = _canonical_model(
            CryptographicMisuseAnalysisPreparation,
            inputs.preparation,
            label="Cryptographic misuse-analysis preparation",
        )
        job = _canonical_model(
            CapabilityGraphCampaignJobInput,
            inputs.job,
            label="Cryptographic approved execution job",
        )
        trust_anchor = _canonical_model(
            CryptographicMisuseAnalysisExecutionTrustAnchor,
            trust_anchor,
            label="Cryptographic misuse-analysis execution trust anchor",
        )
        prepared = preparation.prepared_action
        rebuilt = prepare_cryptographic_misuse_analysis(
            activation=inputs.activation,
            release=preparation.release,
            campaign=campaign,
            surface=preparation.surface,
            operation=preparation.operation,
            analyzer=BoundedCryptographicMisuseAnalyzerAdapter(
                preparation.artifact_custody,
                preparation.sandbox,
            ),
            request_id=prepared.request.request_id,
            agent_id=prepared.request.agent_id,
        )
        if rebuilt != preparation:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic preparation differs from current signed and scoped authority"
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
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic preparation and approved execution inputs differ"
            )
        permits = tuple(
            permit
            for permit in graph_store.permit_store.permits()
            if permit.run_id == inputs.expected_run_id
            and permit.request_id == prepared.request.request_id
        )
        if len(permits) != 1:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis execution source lacks one exact consumed ActionPermit"
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
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic consumed ActionPermit differs from the prepared action"
            )
        receipts = tuple(
            receipt
            for receipt in graph_store.permit_store.approval_consumptions()
            if receipt.action_permit.permit_id == permit.permit_id
        )
        if len(receipts) != 1:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic analysis execution source lacks one exact approval "
                "consumption receipt"
            )
        approval_receipt = receipts[0]
        if (
            approval_receipt.action_permit != permit
            or approval_receipt.approval != job.approval
            or approval_receipt != build_action_approval_consumption_receipt(job.approval, permit)
        ):
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic approval receipt differs from the consumed action"
            )
        attestation_reference = _artifact_reference(
            inputs.attestation_reference,
            label="Cryptographic analysis execution attestation",
        )
        attestation_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, attestation_reference),
            max_bytes=_MAX_ATTESTATION_BYTES,
            label="Cryptographic analysis execution attestation",
            require_single_link=True,
        )
        bundle = CryptographicMisuseAnalysisExecutionBundle.model_validate(
            parse_strict_json_bytes(
                attestation_bytes,
                label="Cryptographic analysis execution attestation",
                max_bytes=_MAX_ATTESTATION_BYTES,
                max_depth=32,
                max_nodes=20_000,
            )
        )
        verification = verify_cryptographic_misuse_analysis_execution_bundle(
            bundle,
            trust_anchor=trust_anchor,
        )
        statement = bundle.statement
        result_reference = _artifact_reference(
            statement.result_receipt_reference,
            label="Cryptographic misuse-analysis result receipt",
        )
        if result_reference == attestation_reference:
            raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
                "Cryptographic attestation and result receipt must be distinct evidence"
            )
        result_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, result_reference),
            max_bytes=_MAX_RECEIPT_BYTES,
            label="Cryptographic misuse-analysis result receipt",
            require_single_link=True,
        )
        result_receipt = CryptographicMisuseAnalysisResultReceipt.model_validate(
            parse_strict_json_bytes(
                result_bytes,
                label="Cryptographic misuse-analysis result receipt",
                max_bytes=_MAX_RECEIPT_BYTES,
                max_depth=20,
                max_nodes=8_000,
            )
        )
        result_sha256 = sha256(result_bytes).hexdigest()
        attestation_sha256 = sha256(attestation_bytes).hexdigest()
        _require_consistent_digest_byte_counts(
            (
                "execution attestation file",
                attestation_sha256,
                len(attestation_bytes),
            ),
            ("result receipt file", result_sha256, len(result_bytes)),
            (
                "artifact",
                preparation.artifact_custody.artifact_sha256,
                preparation.artifact_custody.artifact_bytes,
            ),
            (
                "declared result body",
                result_receipt.result_body_sha256,
                result_receipt.result_bytes,
            ),
        )
        _validate_cryptographic_misuse_analysis_execution_source(
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
        oracle_verdict = recompute_cryptographic_misuse_analysis_oracle_verdict(
            preparation=preparation,
            result_receipt=result_receipt,
        )
        source_root_digest = cryptographic_misuse_analysis_source_root_digest(
            attestation_reference=attestation_reference,
            attestation_sha256=attestation_sha256,
            result_receipt_reference=result_reference,
            result_receipt_sha256=result_sha256,
            trust_anchor_digest=verification.trust_anchor_digest,
            statement_sha256=verification.statement_sha256,
            oracle_policy_digest=oracle_verdict.oracle_policy.oracle_digest,
            oracle_verdict_digest=oracle_verdict.verdict_digest,
        )
        return VerifiedCryptographicMisuseAnalysisObservationSource(
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=approval_receipt,
            trust_anchor=trust_anchor,
            verification=verification,
            bundle=bundle,
            result_receipt=result_receipt,
            oracle_verdict=oracle_verdict,
            attestation_reference=attestation_reference,
            attestation_sha256=attestation_sha256,
            result_receipt_reference=result_reference,
            result_receipt_sha256=result_sha256,
            source_root_digest=source_root_digest,
        )
    except CryptographicMisuseAnalysisKnowledgeAdmissionError:
        raise
    except Exception as exc:
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "sealed Cryptographic misuse-analysis source authority is invalid"
        ) from exc


def _validate_cryptographic_misuse_analysis_execution_source(
    *,
    campaign: CampaignManifest,
    preparation: CryptographicMisuseAnalysisPreparation,
    job: CapabilityGraphCampaignJobInput,
    permit: ActionPermit,
    approval_receipt: ActionApprovalConsumptionReceipt,
    trust_anchor: CryptographicMisuseAnalysisExecutionTrustAnchor,
    statement: CryptographicMisuseAnalysisExecutionStatement,
    result_receipt: CryptographicMisuseAnalysisResultReceipt,
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
        CryptographicMisuseAnalysisTool.spec,
        used_calls=0,
        now=statement.started_at,
    )
    expected_gateway_digest = cryptographic_misuse_analysis_gateway_outcome_digest(
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
        or runtime.input_kind is not preparation.input_kind
        or runtime.rule_set != sandbox.rule_set
        or runtime.operation is not sandbox.operation
        or runtime.analyzer is not sandbox.analyzer
        or runtime.analyzer_executable_sha256 != sandbox.analyzer_executable_sha256
        or runtime.sandbox_image_sha256 != sandbox.sandbox_image_sha256
        or runtime.run_as_identity != sandbox.run_as_identity
        or runtime.max_artifact_bytes != sandbox.max_artifact_bytes
        or runtime.max_output_bytes != sandbox.max_output_bytes
        or runtime.max_runtime_seconds != sandbox.max_runtime_seconds
        or runtime.max_memory_mib != sandbox.max_memory_mib
        or runtime.max_process_count != sandbox.max_process_count
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
        or result_receipt.input_kind is not preparation.input_kind
        or result_receipt.operation is not preparation.operation
        or result_receipt.analyzer is not preparation.analysis_request.analyzer
        or result_receipt.rule_set != preparation.analysis_request.rule_set
        or result_receipt.surface != preparation.surface.reference()
        or result_receipt.artifact_sha256 != custody.artifact_sha256
        or result_receipt.artifact_bytes != custody.artifact_bytes
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
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
            "sealed Cryptographic execution statement differs from current authority"
        )


def _artifact_reference(value: str, *, label: str) -> str:
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError) as exc:
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(
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
        raise CryptographicMisuseAnalysisKnowledgeAdmissionError(f"{label} reference is invalid")
    return path.as_posix()


def _artifact_path(root: Path, reference: str) -> Path:
    parts = PurePosixPath(reference).parts
    return Path(root).resolve().joinpath(*parts)


def cryptographic_misuse_analysis_source_root_digest(
    *,
    attestation_reference: str,
    attestation_sha256: str,
    result_receipt_reference: str,
    result_receipt_sha256: str,
    trust_anchor_digest: str,
    statement_sha256: str,
    oracle_policy_digest: str,
    oracle_verdict_digest: str,
) -> str:
    canonical_attestation_reference = _artifact_reference(
        attestation_reference,
        label="Cryptographic analysis execution attestation",
    )
    canonical_result_reference = _artifact_reference(
        result_receipt_reference,
        label="Cryptographic misuse-analysis result receipt",
    )
    if canonical_attestation_reference == canonical_result_reference:
        raise ValueError("Cryptographic source-root evidence references must be distinct")
    for label, value in (
        ("attestation", attestation_sha256),
        ("result receipt", result_receipt_sha256),
        ("trust anchor", trust_anchor_digest),
        ("statement", statement_sha256),
        ("Oracle policy", oracle_policy_digest),
        ("Oracle verdict", oracle_verdict_digest),
    ):
        if type(value) is not str or fullmatch(r"^[a-f0-9]{64}$", value) is None:
            raise ValueError(f"Cryptographic source-root {label} digest is invalid")
    return graph_digest(
        "pajin.workflow.cryptographic-misuse-analysis-observation-source-root/v1",
        {
            "attestationReference": canonical_attestation_reference,
            "attestationSha256": attestation_sha256,
            "resultReceiptReference": canonical_result_reference,
            "resultReceiptSha256": result_receipt_sha256,
            "trustAnchorDigest": trust_anchor_digest,
            "statementSha256": statement_sha256,
            "oraclePolicyDigest": oracle_policy_digest,
            "oracleVerdictDigest": oracle_verdict_digest,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def _require_admitted_event(
    *,
    event: GraphAdmissionEvent,
    proposal: ObservationProposal | HypothesisProposal,
    graph: CryptographicGraphAdmissionBinding,
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
        raise ValueError("Cryptographic Graph admission differs from its bounded Proposal")


__all__ = [
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_ID",
    "CRYPTOGRAPHIC_MISUSE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION",
    "CryptographicGraphAdmissionBinding",
    "CryptographicMisuseAnalysisExecutionAttestor",
    "CryptographicMisuseAnalysisExecutionBundle",
    "CryptographicMisuseAnalysisExecutionKeyState",
    "CryptographicMisuseAnalysisExecutionStatement",
    "CryptographicMisuseAnalysisExecutionTrustAnchor",
    "CryptographicMisuseAnalysisExecutionVerification",
    "CryptographicMisuseAnalysisExecutionVerificationKey",
    "CryptographicMisuseAnalysisKnowledgeAdmission",
    "CryptographicMisuseAnalysisKnowledgeAdmissionError",
    "CryptographicMisuseAnalysisKnowledgeAdmissionGate",
    "CryptographicMisuseAnalysisKnowledgeAdmissionPolicy",
    "CryptographicMisuseAnalysisKnowledgeCandidate",
    "CryptographicMisuseAnalysisObservationSourceInputs",
    "CryptographicMisuseAnalysisOraclePolicy",
    "CryptographicMisuseAnalysisOracleVerdict",
    "CryptographicMisuseAnalysisResultDisposition",
    "CryptographicMisuseAnalysisResultReceipt",
    "CryptographicMisuseAnalysisSandboxRuntimeReceipt",
    "CryptographicMisuseOracleDisposition",
    "CryptographicMisuseOracleSignalMapping",
    "VerifiedCryptographicMisuseAnalysisObservationSource",
    "cryptographic_misuse_analysis_execution_bundle_bytes",
    "cryptographic_misuse_analysis_execution_public_key",
    "cryptographic_misuse_analysis_gateway_outcome_digest",
    "cryptographic_misuse_analysis_knowledge_producer_registration",
    "cryptographic_misuse_analysis_result_receipt_bytes",
    "cryptographic_misuse_analysis_source_root_digest",
    "load_verified_cryptographic_misuse_analysis_observation_source",
    "recompute_cryptographic_misuse_analysis_oracle_verdict",
    "registered_cryptographic_misuse_analysis_oracle_policy",
    "verify_cryptographic_misuse_analysis_execution_bundle",
]
