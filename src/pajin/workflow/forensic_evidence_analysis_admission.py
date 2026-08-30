"""FORENSICS-001C sealed forensic-evidence knowledge admission.

The module verifies two independent deployment assertions before admitting neutral
knowledge: source/custody membership and parser execution.  Neither signature is
source truth by itself and neither trust anchor grants source access, execution,
Permit, approval, mutation, or Graph authority.
"""

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
from pajin.capabilities.forensic_evidence_analysis import (
    FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
    BoundedForensicEvidenceParserAdapter,
    ForensicEvidenceAnalysisCapabilityActivation,
    ForensicEvidenceAnalysisOperation,
    ForensicEvidenceAnalysisPreparation,
    ForensicEvidenceAnalysisRequest,
    ForensicEvidenceAnalysisSandboxBinding,
    ForensicEvidenceAnalysisTool,
    ForensicEvidenceCustodyBinding,
    ForensicEvidenceInputKind,
    ForensicEvidenceParser,
    ForensicEvidenceRuleSetRef,
    ForensicEvidenceSignalKind,
    prepare_forensic_evidence_analysis,
    registered_forensic_evidence_analysis_binding,
    registered_forensic_evidence_rule_set,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.control_plane.domain_worker_boundaries import DomainWorkerBoundaryProfileRef
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery import (
    ForensicImmutableArtifactSurface,
    ForensicImmutableArtifactSurfaceRef,
    ForensicSourceRootKind,
    ForensicSurfaceClass,
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

FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_ID: Literal[
    "pajin.workflow.forensic-evidence-analysis-knowledge-admission"
] = "pajin.workflow.forensic-evidence-analysis-knowledge-admission"
FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION: Literal["1.0.0"] = "1.0.0"
FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.forensic-evidence-analysis-knowledge-admission/v1"
).hexdigest()
FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION: Literal[
    "pajin.dev/forensic-evidence-analysis-knowledge-admission/v1alpha1"
] = "pajin.dev/forensic-evidence-analysis-knowledge-admission/v1alpha1"

_SOURCE_SIGNATURE_DOMAIN = b"pajin.workflow.forensic-evidence-source-membership-attestation/v1\0"
_EXECUTION_SIGNATURE_DOMAIN = (
    b"pajin.workflow.forensic-evidence-analysis-execution-attestation/v1\0"
)
_MAX_ATTESTATION_BYTES = 3 * 1024 * 1024
_MAX_RECEIPT_BYTES = 512 * 1024
_MAX_CANONICAL_BYTES = 6 * 1024 * 1024
_OBSERVATION_SUMMARY = (
    "A sealed read-only forensic parser execution produced a digest-bound neutral "
    "forensic analysis receipt."
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}"),
]
_ArtifactPath = Annotated[
    str,
    Field(pattern=r"^evidence/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$"),
]

_FALSE_AUTHORITY_FIELDS = (
    "raw_source_embedded",
    "raw_result_embedded",
    "raw_provenance_embedded",
    "source_path_embedded",
    "identity_material_embedded",
    "secret_material_embedded",
    "credential_material_embedded",
    "source_truth_authority",
    "provenance_truth_authority",
    "custody_truth_authority",
    "semantic_truth_authority",
    "evidence_class_verified",
    "source_format_verified",
    "parser_correctness_established",
    "negative_security_claim",
    "finding_production_authorized",
    "hypothesis_confirmation_authority",
    "source_mutation_authorized",
    "artifact_mutation_authorized",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "source_access_authorized",
    "source_mount_authorized",
    "source_copy_authorized",
    "custody_authorization_authority",
    "sandbox_invocation_authorized",
    "parser_invocation_authorized",
    "worker_selection_authorized",
    "worker_job_materialization_authorized",
    "network_access_authorized",
    "dns_access_authorized",
    "credential_use_authorized",
    "secret_material_access_authorized",
    "lateral_movement_authorized",
    "target_execution_authorized",
    "device_access_authorized",
    "plugin_loading_authorized",
    "shell_command_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "graph_admission_authorized",
    "execution_authorized",
    "independent_source_truth_established",
)


class ForensicEvidenceAnalysisKnowledgeAdmissionError(ValueError):
    """Raised when sealed forensic evidence cannot enter the Graph."""


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
    """Reject state smuggled through unvalidated ``model_copy(update=...)`` calls."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        unknown = set(value.__dict__) - set(type(value).model_fields)
        if unknown:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
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


class ForensicEvidenceSourceMembershipKeyState(StrEnum):
    """Lifecycle state for a deployment-owned source/custody membership key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class ForensicEvidenceAnalysisExecutionKeyState(StrEnum):
    """Lifecycle state for a deployment-owned parser execution key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class ForensicEvidenceAnalysisResultDisposition(StrEnum):
    """Only the neutral result classes accepted from a parser deployment."""

    REVIEW = "review"
    NO_SIGNAL = "no-signal"


class ForensicEvidenceAnalysisOracleDisposition(StrEnum):
    """Code-owned structural Oracle outcomes."""

    REVIEW = "review"
    NO_SIGNAL = "no-signal"


class ForensicEvidenceSourceMembershipVerificationKey(_FrozenStrictModel):
    key_id: _Identifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: ForensicEvidenceSourceMembershipKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _validate_key_lifecycle(self, label="Forensic source membership key")
        return self


class ForensicEvidenceAnalysisExecutionVerificationKey(_FrozenStrictModel):
    key_id: _Identifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: ForensicEvidenceAnalysisExecutionKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _validate_key_lifecycle(self, label="Forensic parser execution key")
        return self


def _validate_key_lifecycle(
    key: ForensicEvidenceSourceMembershipVerificationKey
    | ForensicEvidenceAnalysisExecutionVerificationKey,
    *,
    label: str,
) -> (
    ForensicEvidenceSourceMembershipVerificationKey
    | ForensicEvidenceAnalysisExecutionVerificationKey
):
    _base64url_decode(
        key.public_key_base64url,
        expected_length=32,
        label=f"{label} public key",
    )
    not_before = _aware_utc(key.not_before, label=f"{label} not-before")
    if key.not_after is not None:
        not_after = _aware_utc(key.not_after, label=f"{label} not-after")
        if not_after <= not_before:
            raise ValueError(f"{label} validity window is empty")
    if key.state.value == "retired" and key.not_after is None:
        raise ValueError(f"retired {label} requires not_after")
    if key.state.value == "revoked":
        if key.revoked_at is None:
            raise ValueError(f"revoked {label} requires revoked_at")
        _aware_utc(key.revoked_at, label=f"{label} revocation")
    elif key.revoked_at is not None:
        raise ValueError(f"non-revoked {label} cannot have revoked_at")
    return key


class ForensicEvidenceSourceState(_FrozenStrictModel):
    """Digest-only coordinates for one immutable source/custody state."""

    source_root_kind: ForensicSourceRootKind = Field(alias="sourceRootKind")
    source_root_sha256: _Sha256 = Field(alias="sourceRootSHA256")
    source_artifact_record_sha256: _Sha256 = Field(alias="sourceArtifactRecordSHA256")
    provenance_record_sha256: _Sha256 = Field(alias="provenanceRecordSHA256")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=0, le=536_870_912)
    custody_binding_id: _Identifier = Field(alias="custodyBindingId")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    custody_authority_id: _Identifier = Field(alias="custodyAuthorityId")
    custody_object_id: _Identifier = Field(alias="custodyObjectId")
    authorization_id: _Identifier = Field(alias="authorizationId")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    immutable_object_version: _Identifier = Field(alias="immutableObjectVersion")
    purpose: Literal["forensic-evidence-analysis-source-membership"] = (
        "forensic-evidence-analysis-source-membership"
    )

    @property
    def digest(self) -> str:
        return graph_digest(
            "pajin.workflow.forensic-evidence-source-state/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_CANONICAL_BYTES,
        )


class ForensicEvidenceSourceMembershipTrustAnchor(_FrozenStrictModel):
    """Preconfigured verifier for one exact immutable source/custody membership."""

    api_version: Literal["pajin.dev/forensic-evidence-source-membership-trust-anchor/v1alpha1"] = (
        Field(
            default="pajin.dev/forensic-evidence-source-membership-trust-anchor/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["ForensicEvidenceSourceMembershipTrustAnchor"] = (
        "ForensicEvidenceSourceMembershipTrustAnchor"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    surface: ForensicImmutableArtifactSurface
    source_root_kind: ForensicSourceRootKind = Field(alias="sourceRootKind")
    source_root_sha256: _Sha256 = Field(alias="sourceRootSHA256")
    source_artifact_record_sha256: _Sha256 = Field(alias="sourceArtifactRecordSHA256")
    provenance_record_sha256: _Sha256 = Field(alias="provenanceRecordSHA256")
    artifact_custody: ForensicEvidenceCustodyBinding = Field(alias="artifactCustody")
    immutable_object_version: _Identifier = Field(alias="immutableObjectVersion")
    purpose: Literal["forensic-evidence-analysis-source-membership"] = (
        "forensic-evidence-analysis-source-membership"
    )
    provider_contract: Literal[
        "pajin.forensics.immutable-evidence-source-custody-attestation@1.0.0"
    ] = Field(
        default="pajin.forensics.immutable-evidence-source-custody-attestation@1.0.0",
        alias="providerContract",
    )
    keys: tuple[ForensicEvidenceSourceMembershipVerificationKey, ...] = Field(
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
    source_access_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAccessAuthorized",
    )
    source_mount_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMountAuthorized",
    )
    source_copy_authorized: Literal[False] = Field(
        default=False,
        alias="sourceCopyAuthorized",
    )
    custody_authorization_authority: Literal[False] = Field(
        default=False,
        alias="custodyAuthorizationAuthority",
    )
    mutation_authorized: Literal[False] = Field(default=False, alias="mutationAuthorized")
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("deployment_owned", "verification_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic source membership trust markers must be true")
        return value

    @field_validator(
        "current_activation_bound",
        "campaign_authority_bound",
        "source_access_authorized",
        "source_mount_authorized",
        "source_copy_authorized",
        "custody_authorization_authority",
        "mutation_authorized",
        "graph_admission_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic source membership trust anchor cannot grant authority")
        return value

    @model_validator(mode="after")
    def require_exact_keyring(self) -> Self:
        provenance = self.surface.locator.provenance
        custody = self.artifact_custody
        keys = [(item.key_id, item.public_key_base64url) for item in self.keys]
        key_ids = [item.key_id for item in self.keys]
        public_keys = [item.public_key_base64url for item in self.keys]
        if (
            keys != sorted(keys)
            or len(key_ids) != len(set(key_ids))
            or len(public_keys) != len(set(public_keys))
            or sum(
                item.state is ForensicEvidenceSourceMembershipKeyState.ACTIVE for item in self.keys
            )
            != 1
            or self.source_root_kind is not provenance.source_root_kind
            or self.source_root_sha256 != provenance.source_root_sha256
            or self.source_artifact_record_sha256 != provenance.source_artifact_record_sha256
            or self.provenance_record_sha256 != provenance.provenance_record_sha256
            or custody.surface != self.surface
            or custody.artifact_sha256 != provenance.artifact_sha256
            or custody.artifact_bytes != provenance.artifact_bytes
        ):
            raise ValueError(
                "Forensic source membership anchor keyring or provenance coordinates differ"
            )
        return self

    @property
    def digest(self) -> str:
        return graph_digest(
            "pajin.workflow.forensic-evidence-source-membership-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_CANONICAL_BYTES,
        )


class ForensicEvidenceSourceMembershipAttestation(_FrozenStrictModel):
    """Deployment assertion that exact custody coordinates remained immutable.

    Verification proves signature origin and integrity relative to configured trust.
    It does not make the asserted coordinates caller-independent forensic facts.
    """

    api_version: Literal["pajin.dev/forensic-evidence-source-membership-attestation/v1alpha1"] = (
        Field(
            default="pajin.dev/forensic-evidence-source-membership-attestation/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["ForensicEvidenceSourceMembershipAttestation"] = (
        "ForensicEvidenceSourceMembershipAttestation"
    )
    attestation_id: str = Field(default="", alias="attestationId", max_length=112)
    attestation_digest: str = Field(default="", alias="attestationDigest", max_length=64)
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    surface: ForensicImmutableArtifactSurface
    source_root_kind: ForensicSourceRootKind = Field(alias="sourceRootKind")
    source_root_sha256: _Sha256 = Field(alias="sourceRootSHA256")
    source_artifact_record_sha256: _Sha256 = Field(alias="sourceArtifactRecordSHA256")
    provenance_record_sha256: _Sha256 = Field(alias="provenanceRecordSHA256")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=0, le=536_870_912)
    custody_binding_id: _Identifier = Field(alias="custodyBindingId")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    custody_authority_id: _Identifier = Field(alias="custodyAuthorityId")
    custody_object_id: _Identifier = Field(alias="custodyObjectId")
    authorization_id: _Identifier = Field(alias="authorizationId")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    immutable_object_version: _Identifier = Field(alias="immutableObjectVersion")
    purpose: Literal["forensic-evidence-analysis-source-membership"] = (
        "forensic-evidence-analysis-source-membership"
    )
    provider_contract: Literal[
        "pajin.forensics.immutable-evidence-source-custody-attestation@1.0.0"
    ] = Field(
        default="pajin.forensics.immutable-evidence-source-custody-attestation@1.0.0",
        alias="providerContract",
    )
    pre_state: ForensicEvidenceSourceState = Field(alias="preState")
    post_state: ForensicEvidenceSourceState = Field(alias="postState")
    valid_from: datetime = Field(alias="validFrom")
    valid_until: datetime = Field(alias="validUntil")
    attested_at: datetime = Field(alias="attestedAt")
    membership_attested: Literal[True] = Field(default=True, alias="membershipAttested")
    source_root_attested: Literal[True] = Field(default=True, alias="sourceRootAttested")
    artifact_record_attested: Literal[True] = Field(
        default=True,
        alias="artifactRecordAttested",
    )
    provenance_record_attested: Literal[True] = Field(
        default=True,
        alias="provenanceRecordAttested",
    )
    custody_coordinates_attested: Literal[True] = Field(
        default=True,
        alias="custodyCoordinatesAttested",
    )
    artifact_digest_and_size_attested: Literal[True] = Field(
        default=True,
        alias="artifactDigestAndSizeAttested",
    )
    provenance_preserved_attested: Literal[True] = Field(
        default=True,
        alias="provenancePreservedAttested",
    )
    no_mutation_attested: Literal[True] = Field(default=True, alias="noMutationAttested")
    source_truth_authority: Literal[False] = Field(
        default=False,
        alias="sourceTruthAuthority",
    )
    provenance_truth_authority: Literal[False] = Field(
        default=False,
        alias="provenanceTruthAuthority",
    )
    custody_truth_authority: Literal[False] = Field(
        default=False,
        alias="custodyTruthAuthority",
    )
    source_access_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAccessAuthorized",
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("valid_from", "valid_until", "attested_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Forensic source membership time")

    @field_validator(
        "membership_attested",
        "source_root_attested",
        "artifact_record_attested",
        "provenance_record_attested",
        "custody_coordinates_attested",
        "artifact_digest_and_size_attested",
        "provenance_preserved_attested",
        "no_mutation_attested",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic source membership assertions must be true")
        return value

    @field_validator(
        "source_truth_authority",
        "provenance_truth_authority",
        "custody_truth_authority",
        "source_access_authorized",
        "source_mutation_authorized",
        "graph_admission_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic source membership cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_immutable_state_and_identity(self) -> Self:
        expected = ForensicEvidenceSourceState(
            sourceRootKind=self.source_root_kind,
            sourceRootSHA256=self.source_root_sha256,
            sourceArtifactRecordSHA256=self.source_artifact_record_sha256,
            provenanceRecordSHA256=self.provenance_record_sha256,
            artifactSHA256=self.artifact_sha256,
            artifactBytes=self.artifact_bytes,
            custodyBindingId=self.custody_binding_id,
            custodyBindingDigest=self.custody_binding_digest,
            custodyAuthorityId=self.custody_authority_id,
            custodyObjectId=self.custody_object_id,
            authorizationId=self.authorization_id,
            authorizationDigest=self.authorization_digest,
            immutableObjectVersion=self.immutable_object_version,
            purpose=self.purpose,
        )
        if (
            self.pre_state != expected
            or self.post_state != expected
            or not (self.valid_from <= self.attested_at < self.valid_until)
        ):
            raise ValueError("Forensic source membership immutable state or validity differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attestation_id", "attestation_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-source-membership-attestation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        attestation_id = f"forensic-source-membership_{digest}"
        if self.attestation_digest and self.attestation_digest != digest:
            raise ValueError("Forensic source membership attestation digest differs")
        if self.attestation_id and self.attestation_id != attestation_id:
            raise ValueError("Forensic source membership attestation ID differs")
        object.__setattr__(self, "attestation_digest", digest)
        object.__setattr__(self, "attestation_id", attestation_id)
        return self


class ForensicEvidenceSourceMembershipBundle(_FrozenStrictModel):
    """Detached source/custody signature nested in the execution statement."""

    api_version: Literal["pajin.dev/forensic-evidence-source-membership-bundle/v1alpha1"] = Field(
        default="pajin.dev/forensic-evidence-source-membership-bundle/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceSourceMembershipBundle"] = (
        "ForensicEvidenceSourceMembershipBundle"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _Identifier = Field(alias="keyId")
    attestation: ForensicEvidenceSourceMembershipAttestation
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_json_bytes(
            self.attestation.model_dump(mode="json", by_alias=True),
            label="Forensic source membership attestation",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if sha256(canonical).hexdigest() != self.attestation_sha256:
            raise ValueError("Forensic source membership attestation digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Forensic source membership signature",
        )
        return self


class ForensicEvidenceSourceMembershipVerification(_FrozenStrictModel):
    """Integrity/origin result relative to the configured source trust anchor."""

    verification_id: str = Field(default="", alias="verificationId", max_length=112)
    verification_digest: str = Field(default="", alias="verificationDigest", max_length=64)
    valid: Literal[True] = True
    key_id: _Identifier = Field(alias="keyId")
    key_state: ForensicEvidenceSourceMembershipKeyState = Field(alias="keyState")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    attested_at: datetime = Field(alias="attestedAt")
    deployment_assertion_only: Literal[True] = Field(
        default=True,
        alias="deploymentAssertionOnly",
    )
    independent_source_truth_established: Literal[False] = Field(
        default=False,
        alias="independentSourceTruthEstablished",
    )

    @field_validator("valid", "deployment_assertion_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic source membership verification markers must be true")
        return value

    @field_validator("independent_source_truth_established", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic source membership signature is not independent truth")
        return value

    @field_validator("attested_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Forensic source membership verification time")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verification_id", "verification_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-source-membership-verification/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        verification_id = f"forensic-source-membership-verification_{digest}"
        if self.verification_digest and self.verification_digest != digest:
            raise ValueError("Forensic source membership verification digest differs")
        if self.verification_id and self.verification_id != verification_id:
            raise ValueError("Forensic source membership verification ID differs")
        object.__setattr__(self, "verification_digest", digest)
        object.__setattr__(self, "verification_id", verification_id)
        return self


@dataclass(frozen=True, slots=True)
class ForensicEvidenceSourceMembershipAttestor:
    """Deployment signing helper; it grants no source or custody authority."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    ) -> ForensicEvidenceSourceMembershipAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 forensic source private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if (
            len(matching) != 1
            or matching[0].state is not ForensicEvidenceSourceMembershipKeyState.ACTIVE
        ):
            raise ValueError("Forensic source membership signer key is not active")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Forensic source membership active public key",
        )
        if public_bytes != expected:
            raise ValueError("Forensic source private key does not match its trust anchor")

    def attest(
        self,
        attestation: ForensicEvidenceSourceMembershipAttestation,
    ) -> ForensicEvidenceSourceMembershipBundle:
        canonical_attestation = ForensicEvidenceSourceMembershipAttestation.model_validate(
            attestation.model_dump(mode="json", by_alias=True)
        )
        _require_source_attestation_matches_anchor(
            canonical_attestation,
            self.trust_anchor,
        )
        key = next(item for item in self.trust_anchor.keys if item.key_id == self.active_key_id)
        if canonical_attestation.attested_at < key.not_before or (
            key.not_after is not None and canonical_attestation.attested_at >= key.not_after
        ):
            raise ValueError("Forensic source membership key is not valid at attestation time")
        canonical = canonical_json_bytes(
            canonical_attestation.model_dump(mode="json", by_alias=True),
            label="Forensic source membership attestation",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return ForensicEvidenceSourceMembershipBundle(
            keyId=self.active_key_id,
            attestation=canonical_attestation,
            attestationSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SOURCE_SIGNATURE_DOMAIN + canonical)
            ),
        )


def forensic_evidence_source_membership_public_key(private_key: bytes) -> str:
    """Derive a source-membership Ed25519 public key for deployment configuration."""

    return _ed25519_public_key(private_key)


def forensic_evidence_source_membership_bundle_bytes(
    bundle: ForensicEvidenceSourceMembershipBundle,
) -> bytes:
    return _pretty_json_bytes(bundle)


def verify_forensic_evidence_source_membership_bundle(
    bundle: ForensicEvidenceSourceMembershipBundle,
    *,
    trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
) -> ForensicEvidenceSourceMembershipVerification:
    """Verify source assertion integrity against one preconfigured exact anchor."""

    try:
        canonical_bundle = ForensicEvidenceSourceMembershipBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        canonical_anchor = ForensicEvidenceSourceMembershipTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        attestation = canonical_bundle.attestation
        _require_source_attestation_matches_anchor(attestation, canonical_anchor)
        matching = [key for key in canonical_anchor.keys if key.key_id == canonical_bundle.key_id]
        if len(matching) != 1:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic source membership signing key is not trusted"
            )
        key = matching[0]
        if key.state is ForensicEvidenceSourceMembershipKeyState.REVOKED:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic source membership signing key is revoked"
            )
        if attestation.attested_at < key.not_before or (
            key.not_after is not None and attestation.attested_at >= key.not_after
        ):
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic source membership key is outside its validity window"
            )
        canonical = canonical_json_bytes(
            attestation.model_dump(mode="json", by_alias=True),
            label="Forensic source membership attestation",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="Forensic source membership public key",
            )
        ).verify(
            _base64url_decode(
                canonical_bundle.signature_base64url,
                expected_length=64,
                label="Forensic source membership signature",
            ),
            _SOURCE_SIGNATURE_DOMAIN + canonical,
        )
        return ForensicEvidenceSourceMembershipVerification(
            keyId=key.key_id,
            keyState=key.state,
            trustAnchorDigest=canonical_anchor.digest,
            attestationSha256=canonical_bundle.attestation_sha256,
            attestedAt=attestation.attested_at,
        )
    except ForensicEvidenceAnalysisKnowledgeAdmissionError:
        raise
    except (InvalidSignature, ValueError) as exc:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic source membership signature is invalid"
        ) from exc
    except Exception as exc:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic source membership assertion is not canonical"
        ) from exc


def _require_source_attestation_matches_anchor(
    attestation: ForensicEvidenceSourceMembershipAttestation,
    anchor: ForensicEvidenceSourceMembershipTrustAnchor,
) -> None:
    custody = anchor.artifact_custody
    if (
        attestation.trust_domain != anchor.trust_domain
        or attestation.issuer != anchor.issuer
        or attestation.surface != anchor.surface
        or attestation.source_root_kind is not anchor.source_root_kind
        or attestation.source_root_sha256 != anchor.source_root_sha256
        or attestation.source_artifact_record_sha256 != anchor.source_artifact_record_sha256
        or attestation.provenance_record_sha256 != anchor.provenance_record_sha256
        or attestation.artifact_sha256 != custody.artifact_sha256
        or attestation.artifact_bytes != custody.artifact_bytes
        or attestation.custody_binding_id != custody.custody_binding_id
        or attestation.custody_binding_digest != custody.custody_binding_digest
        or attestation.custody_authority_id != custody.custody_authority_id
        or attestation.custody_object_id != custody.custody_object_id
        or attestation.authorization_id != custody.authorization_id
        or attestation.authorization_digest != custody.authorization_digest
        or attestation.immutable_object_version != anchor.immutable_object_version
        or attestation.purpose != anchor.purpose
        or attestation.provider_contract != anchor.provider_contract
    ):
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic source membership assertion differs from its configured anchor"
        )


def _ed25519_public_key(private_key: bytes) -> str:
    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _pretty_json_bytes(value: BaseModel) -> bytes:
    return (
        json.dumps(
            value.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


class ForensicEvidenceAnalysisExecutionTrustAnchor(_FrozenStrictModel):
    """Preconfigured parser verifier, deliberately separate from source trust."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-execution-trust-anchor/v1alpha1"] = (
        Field(
            default="pajin.dev/forensic-evidence-analysis-execution-trust-anchor/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["ForensicEvidenceAnalysisExecutionTrustAnchor"] = (
        "ForensicEvidenceAnalysisExecutionTrustAnchor"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    sandbox: ForensicEvidenceAnalysisSandboxBinding
    capability: CodeBackedCapabilityRef
    capability_release: CapabilityReleaseRef = Field(alias="capabilityRelease")
    keys: tuple[ForensicEvidenceAnalysisExecutionVerificationKey, ...] = Field(
        min_length=1,
        max_length=32,
    )
    deployment_owned: Literal[True] = Field(default=True, alias="deploymentOwned")
    verification_only: Literal[True] = Field(default=True, alias="verificationOnly")
    source_membership_authority: Literal[False] = Field(
        default=False,
        alias="sourceMembershipAuthority",
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
    source_access_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAccessAuthorized",
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
            raise ValueError("Forensic parser execution trust markers must be true")
        return value

    @field_validator(
        "source_membership_authority",
        "current_activation_bound",
        "campaign_authority_bound",
        "approval_satisfied",
        "permit_bound",
        "source_access_authorized",
        "sandbox_invocation_authorized",
        "graph_admission_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic parser execution trust anchor cannot grant authority")
        return value

    @model_validator(mode="after")
    def require_exact_sandbox_and_keyring(self) -> Self:
        if self.capability != registered_forensic_evidence_analysis_binding().capability:
            raise ValueError("Forensic parser execution trust-anchor Capability differs")
        keys = [(item.key_id, item.public_key_base64url) for item in self.keys]
        key_ids = [item.key_id for item in self.keys]
        public_keys = [item.public_key_base64url for item in self.keys]
        if (
            keys != sorted(keys)
            or len(key_ids) != len(set(key_ids))
            or len(public_keys) != len(set(public_keys))
            or sum(
                item.state is ForensicEvidenceAnalysisExecutionKeyState.ACTIVE for item in self.keys
            )
            != 1
        ):
            raise ValueError("Forensic parser keys must be unique, sorted, and have one active key")
        return self

    @property
    def digest(self) -> str:
        return graph_digest(
            "pajin.workflow.forensic-evidence-analysis-execution-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_CANONICAL_BYTES,
        )


class ForensicEvidenceAnalysisSandboxRuntimeReceipt(_FrozenStrictModel):
    """Signed digest-only deployment assertion for one bounded parser run."""

    receipt_id: str = Field(default="", alias="receiptId", max_length=112)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    sandbox_binding_id: _Identifier = Field(alias="sandboxBindingId")
    sandbox_binding_digest: _Sha256 = Field(alias="sandboxBindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    surface: ForensicImmutableArtifactSurfaceRef
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser
    parser_executable_sha256: _Sha256 = Field(alias="parserExecutableSHA256")
    parser_configuration_sha256: _Sha256 = Field(alias="parserConfigurationSHA256")
    sandbox_image_sha256: _Sha256 = Field(alias="sandboxImageSHA256")
    run_as_identity: _Identifier = Field(alias="runAsIdentity")
    evidence_mount_target: str = Field(
        alias="evidenceMountTarget",
        pattern=r"^/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$",
    )
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    output_transport: Literal["bounded-json-stdout"] = Field(
        default="bounded-json-stdout",
        alias="outputTransport",
    )
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=0, le=536_870_912)
    custody_binding_id: _Identifier = Field(alias="custodyBindingId")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    custody_authority_id: _Identifier = Field(alias="custodyAuthorityId")
    custody_object_id: _Identifier = Field(alias="custodyObjectId")
    authorization_id: _Identifier = Field(alias="authorizationId")
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    max_artifact_bytes: int = Field(alias="maxArtifactBytes", strict=True, ge=1)
    max_output_bytes: int = Field(alias="maxOutputBytes", strict=True, ge=1)
    max_runtime_seconds: int = Field(alias="maxRuntimeSeconds", strict=True, ge=1)
    max_memory_mib: int = Field(alias="maxMemoryMiB", strict=True, ge=1)
    max_process_count: int = Field(alias="maxProcessCount", strict=True, ge=1)
    parser_work_unit: Literal["one-source-or-expanded-byte-processed"] = Field(
        default="one-source-or-expanded-byte-processed",
        alias="parserWorkUnit",
    )
    max_parser_work_units: int = Field(alias="maxParserWorkUnits", strict=True, ge=1)
    max_recursion_depth: int = Field(alias="maxRecursionDepth", strict=True, ge=1)
    max_decompression_ratio: int = Field(alias="maxDecompressionRatio", strict=True, ge=1)
    max_decompressed_bytes: int = Field(alias="maxDecompressedBytes", strict=True, ge=1)
    observed_artifact_bytes: int = Field(alias="observedArtifactBytes", strict=True, ge=0)
    observed_output_bytes: int = Field(alias="observedOutputBytes", strict=True, ge=0)
    observed_runtime_seconds: int = Field(alias="observedRuntimeSeconds", strict=True, ge=0)
    observed_peak_memory_mib: int = Field(alias="observedPeakMemoryMiB", strict=True, ge=0)
    observed_peak_process_count: int = Field(
        alias="observedPeakProcessCount",
        strict=True,
        ge=0,
    )
    observed_parser_work_units: int = Field(
        alias="observedParserWorkUnits",
        strict=True,
        ge=1,
    )
    observed_recursion_depth: int = Field(alias="observedRecursionDepth", strict=True, ge=0)
    observed_decompression_ratio: int = Field(
        alias="observedDecompressionRatio",
        strict=True,
        ge=0,
    )
    observed_decompressed_bytes: int = Field(
        alias="observedDecompressedBytes",
        strict=True,
        ge=0,
    )
    pre_state: ForensicEvidenceSourceState = Field(alias="preState")
    post_state: ForensicEvidenceSourceState = Field(alias="postState")
    runtime_identity_digest: _Sha256 = Field(alias="runtimeIdentityDigest")
    confinement_digest: _Sha256 = Field(alias="confinementDigest")
    attested_at: datetime = Field(alias="attestedAt")
    source_membership_checked: Literal[True] = Field(
        default=True,
        alias="sourceMembershipChecked",
    )
    custody_coordinates_checked: Literal[True] = Field(
        default=True,
        alias="custodyCoordinatesChecked",
    )
    parser_executable_checked: Literal[True] = Field(
        default=True,
        alias="parserExecutableChecked",
    )
    parser_configuration_checked: Literal[True] = Field(
        default=True,
        alias="parserConfigurationChecked",
    )
    sandbox_image_checked: Literal[True] = Field(
        default=True,
        alias="sandboxImageChecked",
    )
    exact_worker_profile_checked: Literal[True] = Field(
        default=True,
        alias="exactWorkerProfileChecked",
    )
    exact_surface_checked: Literal[True] = Field(default=True, alias="exactSurfaceChecked")
    exact_rule_set_checked: Literal[True] = Field(default=True, alias="exactRuleSetChecked")
    exact_parser_checked: Literal[True] = Field(default=True, alias="exactParserChecked")
    exact_mount_checked: Literal[True] = Field(default=True, alias="exactMountChecked")
    non_root_checked: Literal[True] = Field(default=True, alias="nonRootChecked")
    network_disabled_checked: Literal[True] = Field(
        default=True,
        alias="networkDisabledChecked",
    )
    dns_disabled_checked: Literal[True] = Field(default=True, alias="dnsDisabledChecked")
    core_dump_disabled_checked: Literal[True] = Field(
        default=True,
        alias="coreDumpDisabledChecked",
    )
    read_only_root_checked: Literal[True] = Field(
        default=True,
        alias="readOnlyRootChecked",
    )
    read_only_evidence_mount_checked: Literal[True] = Field(
        default=True,
        alias="readOnlyEvidenceMountChecked",
    )
    evidence_mount_noexec_checked: Literal[True] = Field(
        default=True,
        alias="evidenceMountNoexecChecked",
    )
    no_new_privileges_checked: Literal[True] = Field(
        default=True,
        alias="noNewPrivilegesChecked",
    )
    confinement_checked: Literal[True] = Field(default=True, alias="confinementChecked")
    resource_limits_checked: Literal[True] = Field(
        default=True,
        alias="resourceLimitsChecked",
    )
    provenance_preserved_attested: Literal[True] = Field(
        default=True,
        alias="provenancePreservedAttested",
    )
    no_mutation_attested: Literal[True] = Field(default=True, alias="noMutationAttested")
    artifact_read_operations: Literal[1] = Field(default=1, alias="artifactReadOperations")
    source_write_operations: Literal[0] = Field(default=0, alias="sourceWriteOperations")
    source_copy_operations: Literal[0] = Field(default=0, alias="sourceCopyOperations")
    evidence_mutation_operations: Literal[0] = Field(
        default=0,
        alias="evidenceMutationOperations",
    )
    source_root_write_operations: Literal[0] = Field(
        default=0,
        alias="sourceRootWriteOperations",
    )
    artifact_write_operations: Literal[0] = Field(
        default=0,
        alias="artifactWriteOperations",
    )
    artifact_copy_operations: Literal[0] = Field(
        default=0,
        alias="artifactCopyOperations",
    )
    custody_record_write_operations: Literal[0] = Field(
        default=0,
        alias="custodyRecordWriteOperations",
    )
    provenance_record_write_operations: Literal[0] = Field(
        default=0,
        alias="provenanceRecordWriteOperations",
    )
    network_requests: Literal[0] = Field(default=0, alias="networkRequests")
    dns_queries: Literal[0] = Field(default=0, alias="dnsQueries")
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    credential_uses: Literal[0] = Field(default=0, alias="credentialUses")
    secret_material_reads: Literal[0] = Field(default=0, alias="secretMaterialReads")
    device_sessions: Literal[0] = Field(default=0, alias="deviceSessions")
    plugin_loads: Literal[0] = Field(default=0, alias="pluginLoads")
    lateral_movement_attempts: Literal[0] = Field(
        default=0,
        alias="lateralMovementAttempts",
    )
    target_process_executions: Literal[0] = Field(
        default=0,
        alias="targetProcessExecutions",
    )
    shell_commands: Literal[0] = Field(default=0, alias="shellCommands")
    raw_source_embedded: Literal[False] = Field(default=False, alias="rawSourceEmbedded")
    raw_parser_output_embedded: Literal[False] = Field(
        default=False,
        alias="rawParserOutputEmbedded",
    )
    source_path_embedded: Literal[False] = Field(default=False, alias="sourcePathEmbedded")
    identity_material_embedded: Literal[False] = Field(
        default=False,
        alias="identityMaterialEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    source_truth_authority: Literal[False] = Field(
        default=False,
        alias="sourceTruthAuthority",
    )
    source_access_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAccessAuthorized",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
    )
    artifact_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="artifactMutationAuthorized",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("attested_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Forensic parser runtime attestation")

    @field_validator(
        "source_membership_checked",
        "custody_coordinates_checked",
        "parser_executable_checked",
        "parser_configuration_checked",
        "sandbox_image_checked",
        "exact_worker_profile_checked",
        "exact_surface_checked",
        "exact_rule_set_checked",
        "exact_parser_checked",
        "exact_mount_checked",
        "non_root_checked",
        "network_disabled_checked",
        "dns_disabled_checked",
        "core_dump_disabled_checked",
        "read_only_root_checked",
        "read_only_evidence_mount_checked",
        "evidence_mount_noexec_checked",
        "no_new_privileges_checked",
        "confinement_checked",
        "resource_limits_checked",
        "provenance_preserved_attested",
        "no_mutation_attested",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic parser runtime checked markers must be true")
        return value

    @field_validator(
        "artifact_read_operations",
        "source_write_operations",
        "source_copy_operations",
        "evidence_mutation_operations",
        "source_root_write_operations",
        "artifact_write_operations",
        "artifact_copy_operations",
        "custody_record_write_operations",
        "provenance_record_write_operations",
        "network_requests",
        "dns_queries",
        "host_filesystem_reads",
        "credential_reads",
        "credential_uses",
        "secret_material_reads",
        "device_sessions",
        "plugin_loads",
        "lateral_movement_attempts",
        "target_process_executions",
        "shell_commands",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forensic parser runtime counters must be exact integers")
        return value

    @field_validator(
        "raw_source_embedded",
        "raw_parser_output_embedded",
        "source_path_embedded",
        "identity_material_embedded",
        "secret_material_embedded",
        "credential_material_embedded",
        "source_truth_authority",
        "source_access_authorized",
        "sandbox_invocation_authorized",
        "network_access_authorized",
        "source_mutation_authorized",
        "artifact_mutation_authorized",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic parser runtime receipt cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity_and_observed_ceilings(self) -> Self:
        if (
            self.pre_state != self.post_state
            or self.artifact_sha256 != self.pre_state.artifact_sha256
            or self.artifact_bytes != self.pre_state.artifact_bytes
            or self.custody_binding_id != self.pre_state.custody_binding_id
            or self.custody_binding_digest != self.pre_state.custody_binding_digest
            or self.custody_authority_id != self.pre_state.custody_authority_id
            or self.custody_object_id != self.pre_state.custody_object_id
            or self.authorization_id != self.pre_state.authorization_id
            or self.authorization_digest != self.pre_state.authorization_digest
            or self.observed_artifact_bytes != self.artifact_bytes
            or self.observed_artifact_bytes > self.max_artifact_bytes
            or self.observed_output_bytes > self.max_output_bytes
            or self.observed_runtime_seconds > self.max_runtime_seconds
            or self.observed_peak_memory_mib > self.max_memory_mib
            or self.observed_peak_process_count > self.max_process_count
            or self.observed_parser_work_units > self.max_parser_work_units
            or self.observed_recursion_depth > self.max_recursion_depth
            or self.observed_decompression_ratio > self.max_decompression_ratio
            or self.observed_decompressed_bytes > self.max_decompressed_bytes
            or (
                self.artifact_bytes == 0
                and (
                    self.observed_decompressed_bytes != 0 or self.observed_decompression_ratio != 0
                )
            )
            or (
                self.artifact_bytes > 0
                and self.observed_decompressed_bytes
                > self.artifact_bytes * self.max_decompression_ratio
            )
            or (
                self.artifact_bytes > 0
                and self.observed_decompressed_bytes
                > self.artifact_bytes * self.observed_decompression_ratio
            )
        ):
            raise ValueError("Forensic parser runtime identity or observed ceilings differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-sandbox-runtime-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"forensic-analysis-sandbox-runtime_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Forensic parser runtime receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Forensic parser runtime receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class ForensicEvidenceAnalysisResultReceipt(_FrozenStrictModel):
    """Detached digest-only parser result; callers cannot choose a signal."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-result-receipt/v1alpha1"] = Field(
        default="pajin.dev/forensic-evidence-analysis-result-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisResultReceipt"] = "ForensicEvidenceAnalysisResultReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=112)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    execution_id: _Identifier = Field(alias="executionId")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    preparation_id: _Identifier = Field(alias="preparationId")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    surface: ForensicImmutableArtifactSurfaceRef
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=0, le=536_870_912)
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    result_bytes: int = Field(alias="resultBytes", strict=True, ge=2, le=16_777_216)
    media_type: Literal["application/json"] = Field(default="application/json", alias="mediaType")
    disposition: ForensicEvidenceAnalysisResultDisposition
    received_at: datetime = Field(alias="receivedAt")
    completed: Literal[True] = True
    digest_only: Literal[True] = Field(default=True, alias="digestOnly")
    raw_source_embedded: Literal[False] = Field(default=False, alias="rawSourceEmbedded")
    raw_result_embedded: Literal[False] = Field(default=False, alias="rawResultEmbedded")
    raw_provenance_embedded: Literal[False] = Field(
        default=False,
        alias="rawProvenanceEmbedded",
    )
    source_path_embedded: Literal[False] = Field(default=False, alias="sourcePathEmbedded")
    identity_material_embedded: Literal[False] = Field(
        default=False,
        alias="identityMaterialEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    source_truth_authority: Literal[False] = Field(
        default=False,
        alias="sourceTruthAuthority",
    )
    provenance_truth_authority: Literal[False] = Field(
        default=False,
        alias="provenanceTruthAuthority",
    )
    semantic_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticTruthAuthority",
    )
    evidence_class_verified: Literal[False] = Field(
        default=False,
        alias="evidenceClassVerified",
    )
    source_format_verified: Literal[False] = Field(
        default=False,
        alias="sourceFormatVerified",
    )
    parser_correctness_established: Literal[False] = Field(
        default=False,
        alias="parserCorrectnessEstablished",
    )
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
        return _aware_utc(value, label="Forensic result receipt received-at")

    @field_validator("completed", "digest_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic result receipt completion markers must be true")
        return value

    @field_validator(
        "raw_source_embedded",
        "raw_result_embedded",
        "raw_provenance_embedded",
        "source_path_embedded",
        "identity_material_embedded",
        "secret_material_embedded",
        "credential_material_embedded",
        "source_truth_authority",
        "provenance_truth_authority",
        "semantic_truth_authority",
        "evidence_class_verified",
        "source_format_verified",
        "parser_correctness_established",
        "negative_security_claim",
        "finding_confirmation_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic result receipt cannot embed source or grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-result-receipt/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        receipt_id = f"forensic-analysis-result_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Forensic result receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Forensic result receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class ForensicEvidenceAnalysisOracleSignalMapping(_FrozenStrictModel):
    """Code-owned mapping from exact source class to a review-only signal."""

    surface_class: ForensicSurfaceClass = Field(alias="surfaceClass")
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    review_signal: ForensicEvidenceSignalKind = Field(alias="reviewSignal")


_STRUCTURAL_SIGNAL_MAPPING = (
    ForensicEvidenceAnalysisOracleSignalMapping(
        surfaceClass=ForensicSurfaceClass.ARTIFACT,
        inputKind=ForensicEvidenceInputKind.ARTIFACT_EVIDENCE,
        reviewSignal=ForensicEvidenceSignalKind.ARTIFACT_EVIDENCE,
    ),
    ForensicEvidenceAnalysisOracleSignalMapping(
        surfaceClass=ForensicSurfaceClass.DISK,
        inputKind=ForensicEvidenceInputKind.DISK_EVIDENCE,
        reviewSignal=ForensicEvidenceSignalKind.DISK_EVIDENCE,
    ),
    ForensicEvidenceAnalysisOracleSignalMapping(
        surfaceClass=ForensicSurfaceClass.LOG,
        inputKind=ForensicEvidenceInputKind.LOG_EVIDENCE,
        reviewSignal=ForensicEvidenceSignalKind.LOG_EVIDENCE,
    ),
    ForensicEvidenceAnalysisOracleSignalMapping(
        surfaceClass=ForensicSurfaceClass.MEMORY,
        inputKind=ForensicEvidenceInputKind.MEMORY_EVIDENCE,
        reviewSignal=ForensicEvidenceSignalKind.MEMORY_EVIDENCE,
    ),
)


class ForensicEvidenceAnalysisAdmissionOraclePolicy(_FrozenStrictModel):
    """Fixed structural Oracle; it reads neither source nor parser-result body."""

    api_version: Literal[
        "pajin.dev/forensic-evidence-analysis-admission-oracle-policy/v1alpha1"
    ] = Field(
        default="pajin.dev/forensic-evidence-analysis-admission-oracle-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisAdmissionOraclePolicy"] = (
        "ForensicEvidenceAnalysisAdmissionOraclePolicy"
    )
    policy_id: str = Field(default="", alias="policyId", max_length=112)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    oracle_id: Literal["pajin.oracle.forensic-evidence-analysis-structural"] = Field(
        default="pajin.oracle.forensic-evidence-analysis-structural",
        alias="oracleId",
    )
    oracle_version: Literal["1.0.0"] = Field(default="1.0.0", alias="oracleVersion")
    rule_set: ForensicEvidenceRuleSetRef = Field(
        default_factory=lambda: registered_forensic_evidence_rule_set().reference(),
        alias="ruleSet",
    )
    surface_signal_mapping: tuple[ForensicEvidenceAnalysisOracleSignalMapping, ...] = Field(
        default=_STRUCTURAL_SIGNAL_MAPPING,
        alias="surfaceSignalMapping",
    )
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    structural_only: Literal[True] = Field(default=True, alias="structuralOnly")
    digest_declared_only: Literal[True] = Field(default=True, alias="digestDeclaredOnly")
    caller_signal_accepted: Literal[False] = Field(
        default=False,
        alias="callerSignalAccepted",
    )
    source_read_authorized: Literal[False] = Field(
        default=False,
        alias="sourceReadAuthorized",
    )
    result_body_read_authorized: Literal[False] = Field(
        default=False,
        alias="resultBodyReadAuthorized",
    )
    key_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="keyMaterialAccessAuthorized",
    )
    cryptographic_validation_authority: Literal[False] = Field(
        default=False,
        alias="cryptographicValidationAuthority",
    )
    semantic_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticTruthAuthority",
    )
    finding_production_authorized: Literal[False] = Field(
        default=False,
        alias="findingProductionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("structural_only", "digest_declared_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic structural Oracle markers must be true")
        return value

    @field_validator(
        "caller_signal_accepted",
        "source_read_authorized",
        "result_body_read_authorized",
        "key_material_access_authorized",
        "cryptographic_validation_authority",
        "semantic_truth_authority",
        "finding_production_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic structural Oracle cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if (
            self.rule_set != registered_forensic_evidence_rule_set().reference()
            or self.surface_signal_mapping != _STRUCTURAL_SIGNAL_MAPPING
            or self.output_schema != FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA
        ):
            raise ValueError("Forensic structural Oracle policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-admission-oracle-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"forensic-analysis-oracle-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Forensic structural Oracle policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Forensic structural Oracle policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class ForensicEvidenceAnalysisAdmissionOracleVerdict(_FrozenStrictModel):
    """A recomputed structural verdict, never a forensic Finding or truth claim."""

    verdict_id: str = Field(default="", alias="verdictId", max_length=112)
    verdict_digest: str = Field(default="", alias="verdictDigest", max_length=64)
    policy: ForensicEvidenceAnalysisAdmissionOraclePolicy
    disposition: ForensicEvidenceAnalysisOracleDisposition
    result_disposition: ForensicEvidenceAnalysisResultDisposition = Field(alias="resultDisposition")
    review_signal: ForensicEvidenceSignalKind | None = Field(
        default=None,
        alias="reviewSignal",
    )
    surface: ForensicImmutableArtifactSurfaceRef
    surface_class: ForensicSurfaceClass = Field(alias="surfaceClass")
    mapping: ForensicEvidenceAnalysisOracleSignalMapping
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    custody_binding_id: _Identifier = Field(alias="custodyBindingId")
    custody_binding_digest: _Sha256 = Field(alias="custodyBindingDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=0)
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    result_receipt_id: _Identifier = Field(alias="resultReceiptId")
    result_receipt_digest: _Sha256 = Field(alias="resultReceiptDigest")
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    result_bytes: int = Field(alias="resultBytes", strict=True, ge=2)
    structurally_consistent: Literal[True] = Field(
        default=True,
        alias="structurallyConsistent",
    )
    digest_declared_only: Literal[True] = Field(default=True, alias="digestDeclaredOnly")
    source_read_performed: Literal[False] = Field(
        default=False,
        alias="sourceReadPerformed",
    )
    result_body_read_performed: Literal[False] = Field(
        default=False,
        alias="resultBodyReadPerformed",
    )
    key_material_read_performed: Literal[False] = Field(
        default=False,
        alias="keyMaterialReadPerformed",
    )
    cryptographic_validation_performed: Literal[False] = Field(
        default=False,
        alias="cryptographicValidationPerformed",
    )
    semantic_truth_established: Literal[False] = Field(
        default=False,
        alias="semanticTruthEstablished",
    )
    evidence_class_verified: Literal[False] = Field(
        default=False,
        alias="evidenceClassVerified",
    )
    source_format_verified: Literal[False] = Field(
        default=False,
        alias="sourceFormatVerified",
    )
    parser_correctness_established: Literal[False] = Field(
        default=False,
        alias="parserCorrectnessEstablished",
    )
    negative_security_claim: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaim",
    )
    finding_produced: Literal[False] = Field(default=False, alias="findingProduced")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("structurally_consistent", "digest_declared_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic structural Oracle verdict markers must be true")
        return value

    @field_validator(
        "source_read_performed",
        "result_body_read_performed",
        "key_material_read_performed",
        "cryptographic_validation_performed",
        "semantic_truth_established",
        "evidence_class_verified",
        "source_format_verified",
        "parser_correctness_established",
        "negative_security_claim",
        "finding_produced",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic structural Oracle verdict cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        expected_disposition = ForensicEvidenceAnalysisOracleDisposition(
            self.result_disposition.value
        )
        expected_signal = (
            self.mapping.review_signal
            if self.disposition is ForensicEvidenceAnalysisOracleDisposition.REVIEW
            else None
        )
        if (
            self.policy != registered_forensic_evidence_analysis_oracle_policy()
            or self.disposition is not expected_disposition
            or self.review_signal is not expected_signal
            or self.surface_class is not self.mapping.surface_class
            or self.input_kind is not self.mapping.input_kind
            or self.rule_set != self.policy.rule_set
            or self.output_schema != self.policy.output_schema
        ):
            raise ValueError("Forensic structural Oracle verdict differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verdict_id", "verdict_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-admission-oracle-verdict/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        verdict_id = f"forensic-analysis-oracle-verdict_{digest}"
        if self.verdict_digest and self.verdict_digest != digest:
            raise ValueError("Forensic structural Oracle verdict digest differs")
        if self.verdict_id and self.verdict_id != verdict_id:
            raise ValueError("Forensic structural Oracle verdict ID differs")
        object.__setattr__(self, "verdict_digest", digest)
        object.__setattr__(self, "verdict_id", verdict_id)
        return self


def registered_forensic_evidence_analysis_oracle_policy() -> (
    ForensicEvidenceAnalysisAdmissionOraclePolicy
):
    """Return the exact code-owned structural admission Oracle."""

    return ForensicEvidenceAnalysisAdmissionOraclePolicy()


def recompute_forensic_evidence_analysis_oracle_verdict(
    preparation: ForensicEvidenceAnalysisPreparation,
    result_receipt: ForensicEvidenceAnalysisResultReceipt,
) -> ForensicEvidenceAnalysisAdmissionOracleVerdict:
    """Recompute a class-only verdict without reading source or result-body bytes."""

    canonical_preparation = ForensicEvidenceAnalysisPreparation.model_validate(
        preparation.model_dump(mode="json", by_alias=True)
    )
    canonical_receipt = ForensicEvidenceAnalysisResultReceipt.model_validate(
        result_receipt.model_dump(mode="json", by_alias=True)
    )
    custody = canonical_preparation.artifact_custody
    request = canonical_preparation.analysis_request
    prepared = canonical_preparation.prepared_action
    complete_surface = canonical_preparation.surface
    surface = complete_surface.reference()
    if (
        canonical_receipt.request_id != prepared.request.request_id
        or canonical_receipt.request_digest != prepared.request_digest
        or canonical_receipt.preparation_id != canonical_preparation.preparation_id
        or canonical_receipt.preparation_digest != canonical_preparation.preparation_digest
        or canonical_receipt.input_kind is not canonical_preparation.input_kind
        or canonical_receipt.operation is not canonical_preparation.operation
        or canonical_receipt.parser is not request.parser
        or canonical_receipt.rule_set != request.rule_set
        or canonical_receipt.surface != surface
        or canonical_receipt.artifact_sha256 != custody.artifact_sha256
        or canonical_receipt.artifact_bytes != custody.artifact_bytes
        or canonical_receipt.output_schema != request.output_schema
        or canonical_receipt.result_bytes > request.budget.max_output_bytes
    ):
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic result receipt differs from exact preparation"
        )
    mappings = tuple(
        item
        for item in _STRUCTURAL_SIGNAL_MAPPING
        if item.surface_class is complete_surface.surface_class
        and item.input_kind is canonical_preparation.input_kind
    )
    if len(mappings) != 1:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic structural signal mapping is not exact"
        )
    mapping = mappings[0]
    disposition = ForensicEvidenceAnalysisOracleDisposition(canonical_receipt.disposition.value)
    return ForensicEvidenceAnalysisAdmissionOracleVerdict(
        policy=registered_forensic_evidence_analysis_oracle_policy(),
        disposition=disposition,
        resultDisposition=canonical_receipt.disposition,
        reviewSignal=(
            mapping.review_signal
            if disposition is ForensicEvidenceAnalysisOracleDisposition.REVIEW
            else None
        ),
        surface=surface,
        surfaceClass=complete_surface.surface_class,
        mapping=mapping,
        ruleSet=canonical_receipt.rule_set,
        inputKind=canonical_receipt.input_kind,
        custodyBindingId=custody.custody_binding_id,
        custodyBindingDigest=custody.custody_binding_digest,
        artifactSHA256=canonical_receipt.artifact_sha256,
        artifactBytes=canonical_receipt.artifact_bytes,
        outputSchema=canonical_receipt.output_schema,
        resultReceiptId=canonical_receipt.receipt_id,
        resultReceiptDigest=canonical_receipt.receipt_digest,
        resultBodySha256=canonical_receipt.result_body_sha256,
        resultBytes=canonical_receipt.result_bytes,
    )


class ForensicEvidenceAnalysisExecutionStatement(_FrozenStrictModel):
    """Outer assertion for one already-completed approved parser execution."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-execution-statement/v1alpha1"] = (
        Field(
            default="pajin.dev/forensic-evidence-analysis-execution-statement/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["ForensicEvidenceAnalysisExecutionStatement"] = (
        "ForensicEvidenceAnalysisExecutionStatement"
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
    capability_grant_id: _Identifier = Field(alias="capabilityGrantId")
    capability_grant_digest: _Sha256 = Field(alias="capabilityGrantDigest")
    preparation: ForensicEvidenceAnalysisPreparation
    preparation_id: _Identifier = Field(alias="preparationId")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    analysis_request: ForensicEvidenceAnalysisRequest = Field(alias="analysisRequest")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    action_permit: ActionPermit = Field(alias="actionPermit")
    action_permit_id: _Identifier = Field(alias="actionPermitId")
    action_permit_digest: _Sha256 = Field(alias="actionPermitDigest")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    source_membership: ForensicEvidenceSourceMembershipBundle = Field(alias="sourceMembership")
    source_membership_verification_digest: _Sha256 = Field(
        alias="sourceMembershipVerificationDigest"
    )
    sandbox_runtime: ForensicEvidenceAnalysisSandboxRuntimeReceipt = Field(alias="sandboxRuntime")
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
    host_filesystem_reads: Literal[0] = Field(default=0, alias="hostFilesystemReads")
    source_write_operations: Literal[0] = Field(default=0, alias="sourceWriteOperations")
    source_copy_operations: Literal[0] = Field(default=0, alias="sourceCopyOperations")
    evidence_mutation_operations: Literal[0] = Field(
        default=0,
        alias="evidenceMutationOperations",
    )
    credential_reads: Literal[0] = Field(default=0, alias="credentialReads")
    credential_uses: Literal[0] = Field(default=0, alias="credentialUses")
    secret_material_reads: Literal[0] = Field(default=0, alias="secretMaterialReads")
    device_sessions: Literal[0] = Field(default=0, alias="deviceSessions")
    plugin_loads: Literal[0] = Field(default=0, alias="pluginLoads")
    lateral_movement_attempts: Literal[0] = Field(
        default=0,
        alias="lateralMovementAttempts",
    )
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
    exact_preparation_bound: Literal[True] = Field(
        default=True,
        alias="exactPreparationBound",
    )
    source_membership_attestation_authenticated: Literal[True] = Field(
        default=True,
        alias="sourceMembershipAttestationAuthenticated",
    )
    exact_source_state_bound: Literal[True] = Field(
        default=True,
        alias="exactSourceStateBound",
    )
    offline_sandbox_verified: Literal[True] = Field(
        default=True,
        alias="offlineSandboxVerified",
    )
    result_sealed: Literal[True] = Field(default=True, alias="resultSealed")
    independent_source_truth_established: Literal[False] = Field(
        default=False,
        alias="independentSourceTruthEstablished",
    )
    raw_source_embedded: Literal[False] = Field(default=False, alias="rawSourceEmbedded")
    raw_result_embedded: Literal[False] = Field(default=False, alias="rawResultEmbedded")
    raw_provenance_embedded: Literal[False] = Field(
        default=False,
        alias="rawProvenanceEmbedded",
    )
    source_path_embedded: Literal[False] = Field(default=False, alias="sourcePathEmbedded")
    identity_material_embedded: Literal[False] = Field(
        default=False,
        alias="identityMaterialEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    new_source_access_authorized: Literal[False] = Field(
        default=False,
        alias="newSourceAccessAuthorized",
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
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
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
        return _aware_utc(value, label="Forensic parser execution time")

    @field_validator(
        "request_count",
        "artifact_reads",
        "network_requests",
        "dns_queries",
        "host_filesystem_reads",
        "source_write_operations",
        "source_copy_operations",
        "evidence_mutation_operations",
        "credential_reads",
        "credential_uses",
        "secret_material_reads",
        "device_sessions",
        "plugin_loads",
        "lateral_movement_attempts",
        "target_process_executions",
        "shell_commands",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forensic parser execution counters must be exact integers")
        return value

    @field_validator(
        "gateway_policy_reentered",
        "consumed_permit_verified",
        "approval_receipt_verified",
        "exact_preparation_bound",
        "source_membership_attestation_authenticated",
        "exact_source_state_bound",
        "offline_sandbox_verified",
        "result_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic parser execution verification markers must be true")
        return value

    @field_validator(
        "raw_source_embedded",
        "raw_result_embedded",
        "raw_provenance_embedded",
        "source_path_embedded",
        "identity_material_embedded",
        "secret_material_embedded",
        "credential_material_embedded",
        "independent_source_truth_established",
        "new_source_access_authorized",
        "new_sandbox_invocation_authorized",
        "new_worker_selection_authorized",
        "network_access_authorized",
        "source_mutation_authorized",
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
            raise ValueError("Forensic parser execution cannot grant new authority")
        return value

    @model_validator(mode="after")
    def require_causal_execution(self) -> Self:
        prepared = self.preparation.prepared_action
        source = self.source_membership.attestation
        if (
            self.preparation_id != self.preparation.preparation_id
            or self.preparation_digest != self.preparation.preparation_digest
            or self.analysis_request != self.preparation.analysis_request
            or self.request_id != prepared.request.request_id
            or self.request_digest != prepared.request_digest
            or self.normalized_parameters_digest != prepared.normalized_parameters_digest
            or self.action_permit_id != self.action_permit.permit_id
            or self.action_permit_digest != self.action_permit.permit_digest
            or self.approval_receipt_id != self.approval_receipt.receipt_id
            or self.approval_receipt_digest != self.approval_receipt.receipt_digest
            or self.approval_receipt.action_permit != self.action_permit
            or self.sandbox_runtime.pre_state != source.pre_state
            or self.sandbox_runtime.post_state != source.post_state
            or not (
                source.valid_from
                <= self.started_at
                <= self.sandbox_runtime.attested_at
                <= self.finished_at
                <= source.attested_at
                <= self.issued_at
                <= source.valid_until
            )
            or self.analysis_request.method != "GET"
            or self.gateway_policy_decision.allowed is not True
        ):
            raise ValueError("Forensic parser execution causal authority differs")
        return self

    @property
    def statement_key(self) -> str:
        return sha256(
            canonical_json_bytes(
                self.model_dump(mode="json", by_alias=True),
                label="Forensic evidence analysis execution statement key",
                max_bytes=_MAX_CANONICAL_BYTES,
            )
        ).hexdigest()


class ForensicEvidenceAnalysisExecutionBundle(_FrozenStrictModel):
    """Outer detached parser signature containing one nested source signature."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-execution-bundle/v1alpha1"] = Field(
        default="pajin.dev/forensic-evidence-analysis-execution-bundle/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisExecutionBundle"] = (
        "ForensicEvidenceAnalysisExecutionBundle"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _Identifier = Field(alias="keyId")
    statement: ForensicEvidenceAnalysisExecutionStatement
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_json_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Forensic evidence analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("Forensic execution statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Forensic parser execution signature",
        )
        return self


class ForensicEvidenceAnalysisExecutionVerification(_FrozenStrictModel):
    """Result of both nested source and outer execution verification."""

    valid: Literal[True] = True
    key_id: _Identifier = Field(alias="keyId")
    key_state: ForensicEvidenceAnalysisExecutionKeyState = Field(alias="keyState")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    source_membership_verification: ForensicEvidenceSourceMembershipVerification = Field(
        alias="sourceMembershipVerification"
    )
    issued_at: datetime = Field(alias="issuedAt")

    @field_validator("valid", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic parser execution verification must be true")
        return value


@dataclass(frozen=True, slots=True)
class ForensicEvidenceAnalysisExecutionAttestor:
    """Outer signer that must independently verify the nested source bundle."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
        source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    ) -> ForensicEvidenceAnalysisExecutionAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 forensic execution private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
            source_membership_trust_anchor=source_membership_trust_anchor,
        )

    def __post_init__(self) -> None:
        _require_disjoint_trust_anchors(
            self.source_membership_trust_anchor,
            self.trust_anchor,
        )
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if (
            len(matching) != 1
            or matching[0].state is not ForensicEvidenceAnalysisExecutionKeyState.ACTIVE
        ):
            raise ValueError("Forensic execution signer key is not active")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Forensic execution active public key",
        )
        if public_bytes != expected:
            raise ValueError("Forensic execution private key does not match its trust anchor")

    def attest(
        self,
        statement: ForensicEvidenceAnalysisExecutionStatement,
    ) -> ForensicEvidenceAnalysisExecutionBundle:
        canonical_statement = ForensicEvidenceAnalysisExecutionStatement.model_validate(
            statement.model_dump(mode="json", by_alias=True)
        )
        source_verification = verify_forensic_evidence_source_membership_bundle(
            canonical_statement.source_membership,
            trust_anchor=self.source_membership_trust_anchor,
        )
        sandbox = self.trust_anchor.sandbox
        if (
            canonical_statement.trust_domain != self.trust_anchor.trust_domain
            or canonical_statement.issuer != self.trust_anchor.issuer
            or canonical_statement.sandbox_binding_id != sandbox.sandbox_binding_id
            or canonical_statement.sandbox_binding_digest != sandbox.sandbox_binding_digest
            or canonical_statement.deployment_id != sandbox.deployment_id
            or canonical_statement.source_membership_verification_digest
            != source_verification.verification_digest
        ):
            raise ValueError("Forensic execution statement differs from configured trust")
        key = next(item for item in self.trust_anchor.keys if item.key_id == self.active_key_id)
        if canonical_statement.issued_at < key.not_before or (
            key.not_after is not None and canonical_statement.issued_at >= key.not_after
        ):
            raise ValueError("Forensic execution key is not valid at issue time")
        canonical = canonical_json_bytes(
            canonical_statement.model_dump(mode="json", by_alias=True),
            label="Forensic evidence analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return ForensicEvidenceAnalysisExecutionBundle(
            keyId=self.active_key_id,
            statement=canonical_statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_EXECUTION_SIGNATURE_DOMAIN + canonical)
            ),
        )


def forensic_evidence_analysis_execution_public_key(private_key: bytes) -> str:
    return _ed25519_public_key(private_key)


def forensic_evidence_analysis_execution_bundle_bytes(
    bundle: ForensicEvidenceAnalysisExecutionBundle,
) -> bytes:
    return _pretty_json_bytes(bundle)


def forensic_evidence_analysis_result_receipt_bytes(
    receipt: ForensicEvidenceAnalysisResultReceipt,
) -> bytes:
    return _pretty_json_bytes(receipt)


def forensic_evidence_analysis_gateway_outcome_digest(
    *,
    policy_decision: PolicyDecision,
    request_digest: str,
    capability_grant_digest: str,
    permit_digest: str,
    approval_receipt_digest: str,
    source_membership_verification_digest: str,
    sandbox_runtime_receipt_digest: str,
    result_receipt_digest: str,
) -> str:
    canonical = PolicyDecision.model_validate(policy_decision.model_dump(mode="json"))
    if canonical.allowed is not True:
        raise ValueError("Forensic Gateway outcome requires an allowed policy decision")
    values = (
        ("request", request_digest),
        ("CapabilityGrant", capability_grant_digest),
        ("Permit", permit_digest),
        ("approval receipt", approval_receipt_digest),
        ("source membership", source_membership_verification_digest),
        ("sandbox runtime", sandbox_runtime_receipt_digest),
        ("result receipt", result_receipt_digest),
    )
    if any(
        not isinstance(value, str) or fullmatch(r"^[a-f0-9]{64}$", value) is None
        for _, value in values
    ):
        raise ValueError("Forensic Gateway outcome contains an invalid digest")
    return graph_digest(
        "pajin.workflow.forensic-evidence-analysis-gateway-outcome/v1",
        {
            "policyDecision": canonical.model_dump(mode="json"),
            "requestDigest": request_digest,
            "capabilityGrantDigest": capability_grant_digest,
            "permitDigest": permit_digest,
            "approvalReceiptDigest": approval_receipt_digest,
            "sourceMembershipVerificationDigest": source_membership_verification_digest,
            "sandboxRuntimeReceiptDigest": sandbox_runtime_receipt_digest,
            "resultReceiptDigest": result_receipt_digest,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def verify_forensic_evidence_analysis_execution_bundle(
    bundle: ForensicEvidenceAnalysisExecutionBundle,
    *,
    trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
) -> ForensicEvidenceAnalysisExecutionVerification:
    """Verify independent nested source and outer parser signatures."""

    try:
        canonical_bundle = ForensicEvidenceAnalysisExecutionBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        canonical_anchor = ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        canonical_source_anchor = ForensicEvidenceSourceMembershipTrustAnchor.model_validate(
            source_membership_trust_anchor.model_dump(mode="json", by_alias=True)
        )
        _require_disjoint_trust_anchors(canonical_source_anchor, canonical_anchor)
        statement = canonical_bundle.statement
        source_verification = verify_forensic_evidence_source_membership_bundle(
            statement.source_membership,
            trust_anchor=canonical_source_anchor,
        )
        sandbox = canonical_anchor.sandbox
        if (
            statement.trust_domain != canonical_anchor.trust_domain
            or statement.issuer != canonical_anchor.issuer
            or statement.sandbox_binding_id != sandbox.sandbox_binding_id
            or statement.sandbox_binding_digest != sandbox.sandbox_binding_digest
            or statement.deployment_id != sandbox.deployment_id
            or statement.source_membership_verification_digest
            != source_verification.verification_digest
        ):
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic execution attestation is not trusted"
            )
        matching = [key for key in canonical_anchor.keys if key.key_id == canonical_bundle.key_id]
        if len(matching) != 1:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic execution signing key is not trusted"
            )
        key = matching[0]
        if key.state is ForensicEvidenceAnalysisExecutionKeyState.REVOKED:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic execution signing key is revoked"
            )
        if statement.issued_at < key.not_before or (
            key.not_after is not None and statement.issued_at >= key.not_after
        ):
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic execution signing key is outside its validity window"
            )
        canonical_statement = canonical_json_bytes(
            statement.model_dump(mode="json", by_alias=True),
            label="Forensic evidence analysis execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="Forensic execution public key",
            )
        ).verify(
            _base64url_decode(
                canonical_bundle.signature_base64url,
                expected_length=64,
                label="Forensic execution signature",
            ),
            _EXECUTION_SIGNATURE_DOMAIN + canonical_statement,
        )
        return ForensicEvidenceAnalysisExecutionVerification(
            keyId=key.key_id,
            keyState=key.state,
            trustAnchorDigest=canonical_anchor.digest,
            statementSha256=canonical_bundle.statement_sha256,
            sourceMembershipVerification=source_verification,
            issuedAt=statement.issued_at,
        )
    except ForensicEvidenceAnalysisKnowledgeAdmissionError:
        raise
    except (InvalidSignature, ValueError) as exc:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic execution signature is invalid"
        ) from exc
    except Exception as exc:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic execution attestation is not canonical"
        ) from exc


def _require_disjoint_trust_anchors(
    source_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    execution_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
) -> None:
    source_keys = {item.public_key_base64url for item in source_anchor.keys}
    execution_keys = {item.public_key_base64url for item in execution_anchor.keys}
    if (
        source_keys & execution_keys
        or source_anchor.trust_domain == execution_anchor.trust_domain
        or source_anchor.issuer == execution_anchor.issuer
    ):
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic source and execution trust roles must be disjoint"
        )


@dataclass(frozen=True, slots=True)
class ForensicEvidenceAnalysisObservationSourceInputs:
    """Current authority plus the two detached Graph evidence files."""

    attestation_reference: str
    expected_run_id: str
    activation: ForensicEvidenceAnalysisCapabilityActivation
    campaign: CampaignManifest
    preparation: ForensicEvidenceAnalysisPreparation
    job: CapabilityGraphCampaignJobInput


@dataclass(frozen=True, slots=True)
class VerifiedForensicEvidenceAnalysisObservationSource:
    """One fully reverified already-completed forensic parser execution."""

    preparation: ForensicEvidenceAnalysisPreparation
    job: CapabilityGraphCampaignJobInput
    permit: ActionPermit
    approval_receipt: ActionApprovalConsumptionReceipt
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor
    execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor
    verification: ForensicEvidenceAnalysisExecutionVerification
    bundle: ForensicEvidenceAnalysisExecutionBundle
    result_receipt: ForensicEvidenceAnalysisResultReceipt
    oracle_verdict: ForensicEvidenceAnalysisAdmissionOracleVerdict
    attestation_reference: str
    attestation_sha256: str
    result_receipt_reference: str
    result_receipt_sha256: str
    source_root_digest: str

    @property
    def caller_source_root_sha256(self) -> str:
        return self.bundle.statement.source_membership.attestation.source_root_sha256


class ForensicEvidenceAnalysisKnowledgeAdmissionPolicy(_FrozenStrictModel):
    """Code-owned authority for a neutral Observation and optional open Hypothesis."""

    api_version: Literal[
        "pajin.dev/forensic-evidence-analysis-knowledge-admission-policy/v1alpha1"
    ] = Field(
        default="pajin.dev/forensic-evidence-analysis-knowledge-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ForensicEvidenceAnalysisKnowledgeAdmissionPolicy"] = (
        "ForensicEvidenceAnalysisKnowledgeAdmissionPolicy"
    )
    policy_id: str = Field(default="", alias="policyId", max_length=112)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.forensic-evidence-analysis-knowledge-admission"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_ID,
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(default="1.0.0", alias="producerVersion")
    producer_digest: _Sha256 = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["forensics.analysis-observation"] = Field(
        default="forensics.analysis-observation",
        alias="observationType",
    )
    hypothesis_type: Literal["forensics.forensic-proposition"] = Field(
        default="forensics.forensic-proposition",
        alias="hypothesisType",
    )
    oracle_policy: ForensicEvidenceAnalysisAdmissionOraclePolicy = Field(
        default_factory=registered_forensic_evidence_analysis_oracle_policy,
        alias="oraclePolicy",
    )
    review_signals: tuple[ForensicEvidenceSignalKind, ...] = Field(
        default=(
            ForensicEvidenceSignalKind.ARTIFACT_EVIDENCE,
            ForensicEvidenceSignalKind.DISK_EVIDENCE,
            ForensicEvidenceSignalKind.LOG_EVIDENCE,
            ForensicEvidenceSignalKind.MEMORY_EVIDENCE,
        ),
        alias="reviewSignals",
    )
    knowledge_only: Literal[True] = Field(default=True, alias="knowledgeOnly")
    bounded_hypothesis_enabled: Literal[True] = Field(
        default=True,
        alias="boundedHypothesisEnabled",
    )
    source_truth_authority: Literal[False] = Field(
        default=False,
        alias="sourceTruthAuthority",
    )
    provenance_truth_authority: Literal[False] = Field(
        default=False,
        alias="provenanceTruthAuthority",
    )
    semantic_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticTruthAuthority",
    )
    evidence_class_verified: Literal[False] = Field(
        default=False,
        alias="evidenceClassVerified",
    )
    source_format_verified: Literal[False] = Field(
        default=False,
        alias="sourceFormatVerified",
    )
    parser_correctness_established: Literal[False] = Field(
        default=False,
        alias="parserCorrectnessEstablished",
    )
    negative_security_claim: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaim",
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
            raise ValueError("Forensic knowledge policy markers must be true")
        return value

    @field_validator(
        "source_truth_authority",
        "provenance_truth_authority",
        "semantic_truth_authority",
        "evidence_class_verified",
        "source_format_verified",
        "parser_correctness_established",
        "negative_security_claim",
        "finding_production_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic knowledge policy cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        expected_signals = (
            ForensicEvidenceSignalKind.ARTIFACT_EVIDENCE,
            ForensicEvidenceSignalKind.DISK_EVIDENCE,
            ForensicEvidenceSignalKind.LOG_EVIDENCE,
            ForensicEvidenceSignalKind.MEMORY_EVIDENCE,
        )
        if (
            self.producer_digest != FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST
            or self.oracle_policy != registered_forensic_evidence_analysis_oracle_policy()
            or self.review_signals != expected_signals
        ):
            raise ValueError("Forensic knowledge policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-knowledge-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"forensic-analysis-knowledge-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Forensic knowledge policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Forensic knowledge policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class ForensicGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph Snapshot and its existing single writer."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError("Forensic knowledge admission requires a non-empty Graph Snapshot")
        return self


class _ForensicKnowledgeAuthorityBoundary(_FrozenStrictModel):
    """Negative authority preserved through candidate and admission."""

    raw_source_embedded: Literal[False] = Field(default=False, alias="rawSourceEmbedded")
    raw_result_embedded: Literal[False] = Field(default=False, alias="rawResultEmbedded")
    raw_provenance_embedded: Literal[False] = Field(
        default=False,
        alias="rawProvenanceEmbedded",
    )
    source_path_embedded: Literal[False] = Field(default=False, alias="sourcePathEmbedded")
    identity_material_embedded: Literal[False] = Field(
        default=False,
        alias="identityMaterialEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    source_truth_authority: Literal[False] = Field(
        default=False,
        alias="sourceTruthAuthority",
    )
    provenance_truth_authority: Literal[False] = Field(
        default=False,
        alias="provenanceTruthAuthority",
    )
    custody_truth_authority: Literal[False] = Field(
        default=False,
        alias="custodyTruthAuthority",
    )
    semantic_truth_authority: Literal[False] = Field(
        default=False,
        alias="semanticTruthAuthority",
    )
    evidence_class_verified: Literal[False] = Field(
        default=False,
        alias="evidenceClassVerified",
    )
    source_format_verified: Literal[False] = Field(
        default=False,
        alias="sourceFormatVerified",
    )
    parser_correctness_established: Literal[False] = Field(
        default=False,
        alias="parserCorrectnessEstablished",
    )
    negative_security_claim: Literal[False] = Field(
        default=False,
        alias="negativeSecurityClaim",
    )
    finding_production_authorized: Literal[False] = Field(
        default=False,
        alias="findingProductionAuthorized",
    )
    hypothesis_confirmation_authority: Literal[False] = Field(
        default=False,
        alias="hypothesisConfirmationAuthority",
    )
    source_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMutationAuthorized",
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
    source_access_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAccessAuthorized",
    )
    source_mount_authorized: Literal[False] = Field(
        default=False,
        alias="sourceMountAuthorized",
    )
    source_copy_authorized: Literal[False] = Field(
        default=False,
        alias="sourceCopyAuthorized",
    )
    custody_authorization_authority: Literal[False] = Field(
        default=False,
        alias="custodyAuthorizationAuthority",
    )
    sandbox_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxInvocationAuthorized",
    )
    parser_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="parserInvocationAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    worker_job_materialization_authorized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterializationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    dns_access_authorized: Literal[False] = Field(
        default=False,
        alias="dnsAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    secret_material_access_authorized: Literal[False] = Field(
        default=False,
        alias="secretMaterialAccessAuthorized",
    )
    lateral_movement_authorized: Literal[False] = Field(
        default=False,
        alias="lateralMovementAuthorized",
    )
    target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="targetExecutionAuthorized",
    )
    device_access_authorized: Literal[False] = Field(
        default=False,
        alias="deviceAccessAuthorized",
    )
    plugin_loading_authorized: Literal[False] = Field(
        default=False,
        alias="pluginLoadingAuthorized",
    )
    shell_command_authorized: Literal[False] = Field(
        default=False,
        alias="shellCommandAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    independent_source_truth_established: Literal[False] = Field(
        default=False,
        alias="independentSourceTruthEstablished",
    )

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic knowledge boundary cannot grant authority")
        return value


class ForensicEvidenceAnalysisKnowledgeCandidate(_ForensicKnowledgeAuthorityBoundary):
    """Content-addressed neutral Observation and optional bounded Hypothesis."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-knowledge-candidate/v1alpha1"] = (
        Field(
            default="pajin.dev/forensic-evidence-analysis-knowledge-candidate/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["ForensicEvidenceAnalysisKnowledgeCandidate"] = (
        "ForensicEvidenceAnalysisKnowledgeCandidate"
    )
    candidate_id: str = Field(default="", alias="candidateId", max_length=112)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: ForensicEvidenceAnalysisKnowledgeAdmissionPolicy
    graph: ForensicGraphAdmissionBinding
    preparation: ForensicEvidenceAnalysisPreparation
    surface: ForensicImmutableArtifactSurfaceRef
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    source_execution_snapshot: GraphSnapshotRef = Field(alias="sourceExecutionSnapshot")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    caller_source_root_sha256: _Sha256 = Field(alias="callerSourceRootSHA256")
    source_membership_trust_anchor_digest: _Sha256 = Field(
        alias="sourceMembershipTrustAnchorDigest"
    )
    execution_trust_anchor_digest: _Sha256 = Field(alias="executionTrustAnchorDigest")
    source_membership_verification_digest: _Sha256 = Field(
        alias="sourceMembershipVerificationDigest"
    )
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    attestation_reference: _ArtifactPath = Field(alias="attestationReference")
    attestation_sha256: _Sha256 = Field(alias="attestationSha256")
    result_receipt_reference: _ArtifactPath = Field(alias="resultReceiptReference")
    result_receipt_sha256: _Sha256 = Field(alias="resultReceiptSha256")
    result_receipt_digest: _Sha256 = Field(alias="resultReceiptDigest")
    result_body_sha256: _Sha256 = Field(alias="resultBodySha256")
    result_bytes: int = Field(alias="resultBytes", strict=True, ge=2)
    result_disposition: ForensicEvidenceAnalysisResultDisposition = Field(alias="resultDisposition")
    review_signal: ForensicEvidenceSignalKind | None = Field(
        default=None,
        alias="reviewSignal",
    )
    artifact_sha256: _Sha256 = Field(alias="artifactSHA256")
    artifact_bytes: int = Field(alias="artifactBytes", strict=True, ge=0)
    output_schema: Literal["pajin.forensics.read-only-evidence-analysis-result.v1"] = Field(
        default=FORENSIC_EVIDENCE_ANALYSIS_OUTPUT_SCHEMA,
        alias="outputSchema",
    )
    operation: ForensicEvidenceAnalysisOperation
    parser: ForensicEvidenceParser
    input_kind: ForensicEvidenceInputKind = Field(alias="inputKind")
    rule_set: ForensicEvidenceRuleSetRef = Field(alias="ruleSet")
    oracle_verdict: ForensicEvidenceAnalysisAdmissionOracleVerdict = Field(alias="oracleVerdict")
    oracle_policy_digest: _Sha256 = Field(alias="oraclePolicyDigest")
    oracle_verdict_digest: _Sha256 = Field(alias="oracleVerdictDigest")
    observation_proposal: ObservationProposal = Field(alias="observationProposal")
    hypothesis_proposal: HypothesisProposal | None = Field(
        default=None,
        alias="hypothesisProposal",
    )
    state: Literal["sealed-knowledge-not-admitted"] = "sealed-knowledge-not-admitted"
    sealed_source_assertion_authenticated: Literal[True] = Field(
        default=True,
        alias="sealedSourceAssertionAuthenticated",
    )
    source_membership_attestation_authenticated: Literal[True] = Field(
        default=True,
        alias="sourceMembershipAttestationAuthenticated",
    )
    execution_attestation_authenticated: Literal[True] = Field(
        default=True,
        alias="executionAttestationAuthenticated",
    )
    consumed_permit_verified: Literal[True] = Field(
        default=True,
        alias="consumedPermitVerified",
    )
    approval_receipt_verified: Literal[True] = Field(
        default=True,
        alias="approvalReceiptVerified",
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

    @field_validator(
        "sealed_source_assertion_authenticated",
        "source_membership_attestation_authenticated",
        "execution_attestation_authenticated",
        "consumed_permit_verified",
        "approval_receipt_verified",
        "structural_oracle_recomputed",
        "neutral_observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic sealed knowledge markers must be true")
        return value

    @field_validator("graph_admitted", mode="before")
    @classmethod
    def require_graph_not_admitted(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Forensic candidate must not claim prior Graph admission")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError("Forensic Domain Graph semantics are not registered exactly") from exc
        observation = self.observation_proposal
        evidence = {(item.reference, item.sha256) for item in observation.evidence_nodes}
        expected_evidence = {
            (self.attestation_reference, self.attestation_sha256),
            (self.result_receipt_reference, self.result_receipt_sha256),
        }
        hypothesis = self.hypothesis_proposal
        expected_hypothesis = self.oracle_verdict.review_signal is not None
        if (
            self.surface != self.preparation.surface.reference()
            or self.preparation.surface.domain_graph_type_set != self.domain_graph_type_set
            or self.source_execution_snapshot != self.graph.snapshot
            or self.operation is not self.preparation.operation
            or self.artifact_sha256 != self.preparation.artifact_custody.artifact_sha256
            or self.artifact_bytes != self.preparation.artifact_custody.artifact_bytes
            or self.output_schema != self.preparation.analysis_request.output_schema
            or self.caller_source_root_sha256
            != self.preparation.surface.locator.provenance.source_root_sha256
            or self.parser is not self.preparation.analysis_request.parser
            or self.input_kind is not self.preparation.input_kind
            or self.rule_set != self.preparation.analysis_request.rule_set
            or self.oracle_verdict.policy != self.policy.oracle_policy
            or self.oracle_verdict.surface != self.surface
            or self.oracle_verdict.surface_class is not self.preparation.surface.surface_class
            or self.oracle_verdict.mapping.surface_class
            is not self.preparation.surface.surface_class
            or self.oracle_verdict.rule_set != self.rule_set
            or self.oracle_verdict.input_kind is not self.input_kind
            or self.oracle_verdict.custody_binding_id
            != self.preparation.artifact_custody.custody_binding_id
            or self.oracle_verdict.custody_binding_digest
            != self.preparation.artifact_custody.custody_binding_digest
            or self.oracle_verdict.artifact_sha256 != self.artifact_sha256
            or self.oracle_verdict.artifact_bytes != self.artifact_bytes
            or self.oracle_verdict.output_schema != self.output_schema
            or self.oracle_verdict.result_receipt_digest != self.result_receipt_digest
            or self.oracle_verdict.result_body_sha256 != self.result_body_sha256
            or self.oracle_verdict.result_bytes != self.result_bytes
            or self.oracle_verdict.result_disposition is not self.result_disposition
            or self.oracle_verdict.review_signal is not self.review_signal
            or self.oracle_verdict.policy.policy_digest != self.oracle_policy_digest
            or self.oracle_verdict.verdict_digest != self.oracle_verdict_digest
            or self.attestation_reference
            != forensic_evidence_analysis_execution_bundle_reference(self.attestation_sha256)
            or self.result_receipt_reference
            != forensic_evidence_analysis_result_receipt_reference(self.result_receipt_sha256)
            or semantics.domain_classification.domain is not SecurityDomain.FORENSICS
            or semantics.surface_type != "forensics.immutable-artifact"
            or semantics.locator_schema != "pajin.locator.forensics.immutable-artifact.v1"
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
            or len(observation.lineage.evidence) != 2
            or {(item.reference, item.sha256) for item in observation.lineage.evidence}
            != expected_evidence
            or any(
                item.data_classification != "restricted"
                or item.source_root_digest != self.source_root_digest
                or item.campaign_id != self.graph.snapshot.campaign_id
                or item.media_type != "application/json"
                for item in observation.evidence_nodes
            )
            or observation.action.status is not GraphActionStatus.SUCCEEDED
            or len(observation.edges) != 3
            or sum(
                edge.relation is GraphRelation.PRODUCES
                and edge.source == graph_node_ref(observation.action)
                and edge.target == graph_node_ref(observation.observation)
                for edge in observation.edges
            )
            != 1
            or sorted(
                edge.target.model_dump_json(by_alias=True)
                for edge in observation.edges
                if edge.relation is GraphRelation.SUPPORTED_BY
                and edge.source == graph_node_ref(observation.observation)
            )
            != sorted(
                graph_node_ref(item).model_dump_json(by_alias=True)
                for item in observation.evidence_nodes
            )
            or sum(edge.relation is GraphRelation.SUPPORTED_BY for edge in observation.edges) != 2
            or expected_hypothesis != (hypothesis is not None)
        ):
            raise ValueError("Forensic knowledge candidate differs from sealed semantics")
        if hypothesis is not None:
            signal = self.oracle_verdict.review_signal
            if signal is None:
                raise ValueError("Forensic Hypothesis lacks a code-owned review signal")
            statement, expected_observable = _hypothesis_text(signal)
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
                raise ValueError("Forensic bounded Hypothesis exceeds open knowledge authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-knowledge-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"forensic-analysis-knowledge_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Forensic knowledge candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Forensic knowledge candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class ForensicEvidenceAnalysisKnowledgeAdmission(_ForensicKnowledgeAuthorityBoundary):
    """Proof that sealed forensic knowledge entered only the existing writer."""

    api_version: Literal["pajin.dev/forensic-evidence-analysis-knowledge-admission/v1alpha1"] = (
        Field(
            default=FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["ForensicEvidenceAnalysisKnowledgeAdmission"] = (
        "ForensicEvidenceAnalysisKnowledgeAdmission"
    )
    admission_id: str = Field(default="", alias="admissionId", max_length=112)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: ForensicEvidenceAnalysisKnowledgeCandidate
    observation_graph_event: GraphAdmissionEvent = Field(alias="observationGraphEvent")
    hypothesis_graph_event: GraphAdmissionEvent | None = Field(
        default=None,
        alias="hypothesisGraphEvent",
    )
    state: Literal["registered-not-authorized"] = "registered-not-authorized"
    sealed_source_assertion_authenticated: Literal[True] = Field(
        default=True,
        alias="sealedSourceAssertionAuthenticated",
    )
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

    @field_validator(
        "sealed_source_assertion_authenticated",
        "neutral_observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "graph_single_writer_reused",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Forensic knowledge admission markers must be true")
        return value

    @field_validator("bounded_hypothesis_admitted", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Forensic bounded Hypothesis marker must be boolean")
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
            raise ValueError("Forensic Observation exceeds neutral knowledge authority")
        hypothesis = self.candidate.hypothesis_proposal
        expected_hypothesis = hypothesis is not None
        if (
            self.bounded_hypothesis_admitted is not expected_hypothesis
            or (self.hypothesis_graph_event is not None) is not expected_hypothesis
        ):
            raise ValueError("Forensic bounded Hypothesis admission marker differs")
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
                raise ValueError("Forensic bounded Hypothesis exceeds open knowledge authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-knowledge-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"forensic-analysis-knowledge-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Forensic knowledge admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Forensic knowledge admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def _hypothesis_text(signal: ForensicEvidenceSignalKind) -> tuple[str, str]:
    return {
        ForensicEvidenceSignalKind.DISK_EVIDENCE: (
            "The exact disk-evidence analysis class warrants bounded independent review.",
            "Independent read-only analysis reproduces the same review class for the exact "
            "immutable artifact and custody coordinates.",
        ),
        ForensicEvidenceSignalKind.MEMORY_EVIDENCE: (
            "The exact memory-evidence analysis class warrants bounded independent review.",
            "Independent read-only analysis reproduces the same review class for the exact "
            "immutable artifact and custody coordinates.",
        ),
        ForensicEvidenceSignalKind.LOG_EVIDENCE: (
            "The exact log-evidence analysis class warrants bounded independent review.",
            "Independent read-only analysis reproduces the same review class for the exact "
            "immutable artifact and custody coordinates.",
        ),
        ForensicEvidenceSignalKind.ARTIFACT_EVIDENCE: (
            "The exact artifact-evidence analysis class warrants bounded independent review.",
            "Independent read-only analysis reproduces the same review class for the exact "
            "immutable artifact and custody coordinates.",
        ),
    }[signal]


def forensic_evidence_analysis_knowledge_producer_registration() -> GraphProducerRegistration:
    """Return the exact code-owned Forensics Observation/Hypothesis producer."""

    return GraphProducerRegistration(
        producerId=FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_ID,
        producerVersion=FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION,
        producerDigest=FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST,
        allowedProposalKinds=(
            GraphProposalKind.HYPOTHESIS,
            GraphProposalKind.OBSERVATION,
        ),
    )


class ForensicEvidenceAnalysisKnowledgeAdmissionGate:
    """Reverify both trust roles and reuse the existing Graph single writer."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
        source_root: Path,
        execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
        source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    ) -> None:
        if type(graph_store) is not SQLiteGraphStore:
            raise TypeError("Forensic knowledge admission requires an exact SQLite Graph Store")
        if type(graph_admission) is not GraphAdmissionAuthority:
            raise TypeError("Forensic knowledge admission requires the Graph Admission authority")
        if type(trusted_lineages) is not TrustedGraphLineageRegistry:
            raise TypeError("Forensic knowledge admission requires the trusted lineage registry")
        if type(execution_trust_anchor) is not ForensicEvidenceAnalysisExecutionTrustAnchor:
            raise TypeError(
                "Forensic knowledge admission requires a preconfigured execution trust anchor"
            )
        if type(source_membership_trust_anchor) is not ForensicEvidenceSourceMembershipTrustAnchor:
            raise TypeError(
                "Forensic knowledge admission requires a preconfigured source trust anchor"
            )
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("Forensic knowledge Graph authority wiring differs")
        _require_known_instance_fields(
            execution_trust_anchor,
            label="Forensic execution trust anchor",
        )
        _require_known_instance_fields(
            source_membership_trust_anchor,
            label="Forensic source membership trust anchor",
        )
        canonical_source_root = _canonical_evidence_source_root(source_root)
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages
        self._source_root = canonical_source_root
        self._execution_trust_anchor = ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(
            execution_trust_anchor.model_dump(mode="json", by_alias=True)
        )
        self._source_membership_trust_anchor = (
            ForensicEvidenceSourceMembershipTrustAnchor.model_validate(
                source_membership_trust_anchor.model_dump(mode="json", by_alias=True)
            )
        )
        _require_disjoint_trust_anchors(
            self._source_membership_trust_anchor,
            self._execution_trust_anchor,
        )

    def prepare_candidate(
        self,
        inputs: ForensicEvidenceAnalysisObservationSourceInputs,
        graph: ForensicGraphAdmissionBinding,
    ) -> ForensicEvidenceAnalysisKnowledgeCandidate:
        try:
            if type(graph) is not ForensicGraphAdmissionBinding:
                raise TypeError("Forensic knowledge admission requires an exact Graph binding")
            canonical_graph = ForensicGraphAdmissionBinding.model_validate(graph)
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except ForensicEvidenceAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic knowledge candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: ForensicEvidenceAnalysisObservationSourceInputs,
        candidate: ForensicEvidenceAnalysisKnowledgeCandidate,
    ) -> ForensicEvidenceAnalysisKnowledgeAdmission:
        try:
            if type(candidate) is not ForensicEvidenceAnalysisKnowledgeCandidate:
                raise TypeError("Forensic knowledge admission requires an exact candidate")
            canonical = ForensicEvidenceAnalysisKnowledgeCandidate.model_validate(candidate)
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                    "Forensic knowledge candidate differs from sealed source authority"
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
                    raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                        "Forensic knowledge admission requires a non-empty Graph head"
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
                        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                            "Forensic bounded Hypothesis source is no longer the current Graph head"
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
            return ForensicEvidenceAnalysisKnowledgeAdmission(
                candidate=canonical,
                observationGraphEvent=observation_result.event,
                hypothesisGraphEvent=hypothesis_event,
                boundedHypothesisAdmitted=hypothesis is not None,
            )
        except ForensicEvidenceAnalysisKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic knowledge admission failed closed"
            ) from exc

    def _require_admitted_result(
        self,
        event: GraphAdmissionEvent,
        graph: ForensicGraphAdmissionBinding,
    ) -> None:
        if (
            event.decision is not GraphAdmissionDecision.ADMITTED
            or event.authority_id != graph.authority_id
            or event.authority_digest != graph.authority_digest
        ):
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Graph Admission authority rejected Forensic knowledge"
            )

    def _build_candidate(
        self,
        inputs: ForensicEvidenceAnalysisObservationSourceInputs,
        graph: ForensicGraphAdmissionBinding,
    ) -> ForensicEvidenceAnalysisKnowledgeCandidate:
        source = load_verified_forensic_evidence_analysis_observation_source(
            inputs,
            graph_store=self._graph_store,
            source_root=self._source_root,
            execution_trust_anchor=self._execution_trust_anchor,
            source_membership_trust_anchor=self._source_membership_trust_anchor,
        )
        permit = source.permit
        statement = source.bundle.statement
        receipt = source.result_receipt
        oracle_verdict = source.oracle_verdict
        runtime = statement.sandbox_runtime
        source_verification = source.verification.source_membership_verification
        if graph.snapshot.campaign_id != permit.campaign_id:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic execution source and Graph admission Campaigns differ"
            )
        policy = ForensicEvidenceAnalysisKnowledgeAdmissionPolicy()
        value_digest = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-observation-value/v1",
            {
                "preparationDigest": source.preparation.preparation_digest,
                "surfaceReference": source.preparation.surface.reference().model_dump(
                    mode="json",
                    by_alias=True,
                ),
                "callerSourceRootSHA256": source.caller_source_root_sha256,
                "admissionSourceRootDigest": source.source_root_digest,
                "artifactSHA256": receipt.artifact_sha256,
                "artifactBytes": receipt.artifact_bytes,
                "operation": source.preparation.operation.value,
                "inputKind": source.preparation.input_kind.value,
                "parser": source.preparation.analysis_request.parser.value,
                "ruleSet": source.preparation.analysis_request.rule_set.model_dump(
                    mode="json",
                    by_alias=True,
                ),
                "outputSchema": receipt.output_schema,
                "requestDigest": permit.request_digest,
                "capabilityGrantId": source.job.grant.grant_id,
                "capabilityGrantDigest": capability_grant_digest(source.job.grant),
                "approvalReceiptDigest": source.approval_receipt.receipt_digest,
                "sourceMembershipTrustAnchorDigest": (source.source_membership_trust_anchor.digest),
                "executionTrustAnchorDigest": source.verification.trust_anchor_digest,
                "sourceMembershipVerificationDigest": (source_verification.verification_digest),
                "statementSha256": source.verification.statement_sha256,
                "gatewayOutcomeDigest": statement.gateway_outcome_digest,
                "sandboxRuntimeReceiptDigest": runtime.receipt_digest,
                "runtimeIdentityDigest": runtime.runtime_identity_digest,
                "confinementDigest": runtime.confinement_digest,
                "resultReceiptDigest": receipt.receipt_digest,
                "resultBodySha256": receipt.result_body_sha256,
                "resultBytes": receipt.result_bytes,
                "oraclePolicyDigest": oracle_verdict.policy.policy_digest,
                "oracleVerdictDigest": oracle_verdict.verdict_digest,
                "oracleDisposition": oracle_verdict.disposition.value,
                "resultDisposition": oracle_verdict.result_disposition.value,
                "reviewSignal": (
                    oracle_verdict.review_signal.value
                    if oracle_verdict.review_signal is not None
                    else None
                ),
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
                    mediaType="application/json",
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
            agent_id="agent:forensic-evidence-analysis-observation-admission",
            task_id=f"task:forensic-analysis-observation:{statement.statement_key[:32]}",
        )
        proposal_key = graph_digest(
            "pajin.workflow.forensic-evidence-analysis-observation-proposal-id/v1",
            {
                "sourceRootDigest": source.source_root_digest,
                "callerSourceRootSHA256": source.caller_source_root_sha256,
                "statementSha256": source.verification.statement_sha256,
                "resultReceiptDigest": receipt.receipt_digest,
                "snapshotDigest": graph.snapshot.snapshot_digest,
                "observationNodeId": observation.node_id,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        observation_proposal = ObservationProposal(
            proposalId=f"proposal:forensic-observation:{proposal_key}",
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
                agent_id="agent:forensic-evidence-analysis-hypothesis-admission",
                task_id=f"task:forensic-analysis-hypothesis:{statement.statement_key[:32]}",
            )
            hypothesis_key = graph_digest(
                "pajin.workflow.forensic-evidence-analysis-hypothesis-proposal-id/v1",
                {
                    "observationProposalDigest": observation_proposal.digest(),
                    "hypothesisNodeId": hypothesis.node_id,
                    "reviewSignal": oracle_verdict.review_signal.value,
                },
                max_bytes=_MAX_CANONICAL_BYTES,
            )
            hypothesis_proposal = HypothesisProposal(
                proposalId=f"proposal:forensic-hypothesis:{hypothesis_key}",
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                lineage=hypothesis_lineage,
                hypothesis=hypothesis,
                edges=[hypothesis_edge],
            )
        return ForensicEvidenceAnalysisKnowledgeCandidate(
            policy=policy,
            graph=graph,
            preparation=source.preparation,
            surface=source.preparation.surface.reference(),
            domainGraphTypeSet=source.preparation.surface.domain_graph_type_set,
            sourceExecutionSnapshot=permit.snapshot,
            sourceRunId=permit.run_id,
            sourceRootDigest=source.source_root_digest,
            callerSourceRootSHA256=source.caller_source_root_sha256,
            sourceMembershipTrustAnchorDigest=source.source_membership_trust_anchor.digest,
            executionTrustAnchorDigest=source.verification.trust_anchor_digest,
            sourceMembershipVerificationDigest=source_verification.verification_digest,
            statementSha256=source.verification.statement_sha256,
            approvalReceiptId=source.approval_receipt.receipt_id,
            approvalReceiptDigest=source.approval_receipt.receipt_digest,
            attestationReference=source.attestation_reference,
            attestationSha256=source.attestation_sha256,
            resultReceiptReference=source.result_receipt_reference,
            resultReceiptSha256=source.result_receipt_sha256,
            resultReceiptDigest=receipt.receipt_digest,
            resultBodySha256=receipt.result_body_sha256,
            resultBytes=receipt.result_bytes,
            resultDisposition=oracle_verdict.result_disposition,
            reviewSignal=oracle_verdict.review_signal,
            artifactSHA256=receipt.artifact_sha256,
            artifactBytes=receipt.artifact_bytes,
            outputSchema=receipt.output_schema,
            operation=source.preparation.operation,
            parser=source.preparation.analysis_request.parser,
            inputKind=source.preparation.input_kind,
            ruleSet=source.preparation.analysis_request.rule_set,
            oracleVerdict=oracle_verdict,
            oraclePolicyDigest=oracle_verdict.policy.policy_digest,
            oracleVerdictDigest=oracle_verdict.verdict_digest,
            observationProposal=observation_proposal,
            hypothesisProposal=hypothesis_proposal,
        )

    def _require_current_graph(self, graph: ForensicGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest != getattr(self._graph_admission, "_authority_digest", None)
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic knowledge Graph Admission authority differs"
            )
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic knowledge Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic knowledge Graph Snapshot is not the current canonical head"
            )


def _source_lineage(
    *,
    source: VerifiedForensicEvidenceAnalysisObservationSource,
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


def load_verified_forensic_evidence_analysis_observation_source(
    inputs: ForensicEvidenceAnalysisObservationSourceInputs,
    *,
    graph_store: SQLiteGraphStore,
    source_root: Path,
    execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
) -> VerifiedForensicEvidenceAnalysisObservationSource:
    """Rebuild current authority and verify both signatures plus detached result."""

    if type(inputs) is not ForensicEvidenceAnalysisObservationSourceInputs:
        raise TypeError("Forensic knowledge admission requires exact source inputs")
    if type(graph_store) is not SQLiteGraphStore:
        raise TypeError("Forensic source verification requires the exact SQLite Graph Store")
    if type(execution_trust_anchor) is not ForensicEvidenceAnalysisExecutionTrustAnchor:
        raise TypeError("Forensic source verification requires an execution trust anchor")
    if type(source_membership_trust_anchor) is not ForensicEvidenceSourceMembershipTrustAnchor:
        raise TypeError("Forensic source verification requires a source trust anchor")
    if type(inputs.activation) is not ForensicEvidenceAnalysisCapabilityActivation:
        raise TypeError("Forensic source verification requires current activation")
    canonical_source_root = _canonical_evidence_source_root(source_root)
    _require_source_input_instance_fields(inputs)
    try:
        campaign = CampaignManifest.model_validate(
            inputs.campaign.model_dump(mode="json", by_alias=True)
        )
        preparation = ForensicEvidenceAnalysisPreparation.model_validate(
            inputs.preparation.model_dump(mode="json", by_alias=True)
        )
        job = CapabilityGraphCampaignJobInput.model_validate(
            inputs.job.model_dump(mode="json", by_alias=True)
        )
        execution_anchor = ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(
            execution_trust_anchor.model_dump(mode="json", by_alias=True)
        )
        source_anchor = ForensicEvidenceSourceMembershipTrustAnchor.model_validate(
            source_membership_trust_anchor.model_dump(mode="json", by_alias=True)
        )
        _require_disjoint_trust_anchors(source_anchor, execution_anchor)
        prepared = preparation.prepared_action
        rebuilt = prepare_forensic_evidence_analysis(
            activation=inputs.activation,
            release=preparation.release,
            campaign=campaign,
            surface=preparation.surface,
            operation=preparation.operation,
            parser=BoundedForensicEvidenceParserAdapter(
                preparation.artifact_custody,
                preparation.sandbox,
            ),
            request_id=prepared.request.request_id,
            agent_id=prepared.request.agent_id,
        )
        if rebuilt != preparation:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic preparation differs from current signed and scoped authority"
            )
        if (
            source_anchor.surface != preparation.surface
            or source_anchor.artifact_custody != preparation.artifact_custody
            or execution_anchor.sandbox != preparation.sandbox
            or execution_anchor.capability != preparation.binding.capability
            or execution_anchor.capability_release != preparation.release
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
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic preparation and approved execution inputs differ"
            )
        permits = tuple(
            permit
            for permit in graph_store.permit_store.permits()
            if permit.run_id == inputs.expected_run_id
            and permit.request_id == prepared.request.request_id
        )
        if len(permits) != 1:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic source lacks one exact consumed ActionPermit"
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
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic consumed ActionPermit differs from the prepared action"
            )
        receipts = tuple(
            receipt
            for receipt in graph_store.permit_store.approval_consumptions()
            if receipt.action_permit.permit_id == permit.permit_id
        )
        if len(receipts) != 1:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic source lacks one exact approval consumption receipt"
            )
        approval_receipt = receipts[0]
        if (
            approval_receipt.action_permit != permit
            or approval_receipt.approval != job.approval
            or approval_receipt != build_action_approval_consumption_receipt(job.approval, permit)
        ):
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic approval receipt differs from the consumed action"
            )
        attestation_reference = _artifact_reference(
            inputs.attestation_reference,
            label="Forensic execution attestation",
        )
        attestation_bytes = read_bounded_regular_bytes(
            _artifact_path(canonical_source_root, attestation_reference),
            max_bytes=_MAX_ATTESTATION_BYTES,
            label="Forensic execution attestation",
            require_single_link=True,
        )
        attestation_sha256 = sha256(attestation_bytes).hexdigest()
        _require_exact_evidence_reference(
            attestation_reference,
            expected=forensic_evidence_analysis_execution_bundle_reference(attestation_sha256),
            label="Forensic execution attestation",
        )
        bundle = ForensicEvidenceAnalysisExecutionBundle.model_validate(
            parse_strict_json_bytes(
                attestation_bytes,
                label="Forensic execution attestation",
                max_bytes=_MAX_ATTESTATION_BYTES,
                max_depth=48,
                max_nodes=40_000,
            )
        )
        verification = verify_forensic_evidence_analysis_execution_bundle(
            bundle,
            trust_anchor=execution_anchor,
            source_membership_trust_anchor=source_anchor,
        )
        statement = bundle.statement
        result_reference = _artifact_reference(
            statement.result_receipt_reference,
            label="Forensic analysis result receipt",
        )
        if result_reference == attestation_reference:
            raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
                "Forensic attestation and result receipt must be distinct evidence"
            )
        result_bytes = read_bounded_regular_bytes(
            _artifact_path(canonical_source_root, result_reference),
            max_bytes=_MAX_RECEIPT_BYTES,
            label="Forensic analysis result receipt",
            require_single_link=True,
        )
        result_receipt = ForensicEvidenceAnalysisResultReceipt.model_validate(
            parse_strict_json_bytes(
                result_bytes,
                label="Forensic analysis result receipt",
                max_bytes=_MAX_RECEIPT_BYTES,
                max_depth=24,
                max_nodes=10_000,
            )
        )
        result_sha256 = sha256(result_bytes).hexdigest()
        _require_exact_evidence_reference(
            result_reference,
            expected=forensic_evidence_analysis_result_receipt_reference(result_sha256),
            label="Forensic result receipt",
        )
        oracle_verdict = recompute_forensic_evidence_analysis_oracle_verdict(
            preparation,
            result_receipt,
        )
        _validate_forensic_evidence_analysis_execution_source(
            campaign=campaign,
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=approval_receipt,
            execution_trust_anchor=execution_anchor,
            source_membership_trust_anchor=source_anchor,
            verification=verification,
            statement=statement,
            result_receipt=result_receipt,
            result_receipt_sha256=result_sha256,
            oracle_verdict=oracle_verdict,
        )
        source_root_digest = forensic_evidence_analysis_source_root_digest(
            attestation_reference=attestation_reference,
            attestation_sha256=attestation_sha256,
            result_receipt_reference=result_reference,
            result_receipt_sha256=result_sha256,
            source_membership_trust_anchor_digest=source_anchor.digest,
            execution_trust_anchor_digest=verification.trust_anchor_digest,
            source_membership_attestation_sha256=(
                verification.source_membership_verification.attestation_sha256
            ),
            statement_sha256=verification.statement_sha256,
            oracle_verdict_digest=oracle_verdict.verdict_digest,
        )
        return VerifiedForensicEvidenceAnalysisObservationSource(
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=approval_receipt,
            source_membership_trust_anchor=source_anchor,
            execution_trust_anchor=execution_anchor,
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
    except ForensicEvidenceAnalysisKnowledgeAdmissionError:
        raise
    except Exception as exc:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "sealed Forensic evidence analysis source authority is invalid"
        ) from exc


def _validate_forensic_evidence_analysis_execution_source(
    *,
    campaign: CampaignManifest,
    preparation: ForensicEvidenceAnalysisPreparation,
    job: CapabilityGraphCampaignJobInput,
    permit: ActionPermit,
    approval_receipt: ActionApprovalConsumptionReceipt,
    execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor,
    verification: ForensicEvidenceAnalysisExecutionVerification,
    statement: ForensicEvidenceAnalysisExecutionStatement,
    result_receipt: ForensicEvidenceAnalysisResultReceipt,
    result_receipt_sha256: str,
    oracle_verdict: ForensicEvidenceAnalysisAdmissionOracleVerdict,
) -> None:
    prepared = preparation.prepared_action
    sandbox = preparation.sandbox
    runtime = statement.sandbox_runtime
    custody = preparation.artifact_custody
    request = preparation.analysis_request
    budget = request.budget
    source = statement.source_membership.attestation
    duration = (statement.finished_at - statement.started_at).total_seconds()
    expected_gateway_decision = PolicyEngine().evaluate_tool_request(
        campaign,
        job.grant,
        prepared.request,
        ForensicEvidenceAnalysisTool.spec,
        used_calls=0,
        now=statement.started_at,
    )
    expected_gateway_digest = forensic_evidence_analysis_gateway_outcome_digest(
        policy_decision=expected_gateway_decision,
        request_digest=permit.request_digest,
        capability_grant_digest=capability_grant_digest(job.grant),
        permit_digest=permit.permit_digest,
        approval_receipt_digest=approval_receipt.receipt_digest,
        source_membership_verification_digest=(
            verification.source_membership_verification.verification_digest
        ),
        sandbox_runtime_receipt_digest=runtime.receipt_digest,
        result_receipt_digest=result_receipt.receipt_digest,
    )
    if (
        statement.preparation != preparation
        or statement.action_permit != permit
        or statement.approval_receipt != approval_receipt
        or source_membership_trust_anchor.surface != preparation.surface
        or source_membership_trust_anchor.artifact_custody != custody
        or execution_trust_anchor.sandbox != sandbox
        or execution_trust_anchor.capability != preparation.binding.capability
        or execution_trust_anchor.capability_release != preparation.release
        or statement.gateway_policy_decision != expected_gateway_decision
        or statement.gateway_outcome_digest != expected_gateway_digest
        or statement.sandbox_binding_id != sandbox.sandbox_binding_id
        or statement.sandbox_binding_digest != sandbox.sandbox_binding_digest
        or statement.deployment_id != sandbox.deployment_id
        or statement.campaign_id != campaign.metadata.name
        or statement.campaign_digest != campaign_manifest_digest(campaign)
        or statement.run_id != permit.run_id
        or statement.capability_grant_id != job.grant.grant_id
        or statement.capability_grant_digest != capability_grant_digest(job.grant)
        or statement.preparation_id != preparation.preparation_id
        or statement.preparation_digest != preparation.preparation_digest
        or statement.analysis_request != request
        or statement.request_id != permit.request_id
        or statement.request_digest != permit.request_digest
        or statement.normalized_parameters_digest != permit.normalized_parameters_digest
        or statement.action_permit_id != permit.permit_id
        or statement.action_permit_digest != permit.permit_digest
        or statement.approval_receipt_id != approval_receipt.receipt_id
        or statement.approval_receipt_digest != approval_receipt.receipt_digest
        or statement.source_membership_verification_digest
        != verification.source_membership_verification.verification_digest
        or runtime.sandbox_binding_id != sandbox.sandbox_binding_id
        or runtime.sandbox_binding_digest != sandbox.sandbox_binding_digest
        or runtime.deployment_id != sandbox.deployment_id
        or runtime.worker_profile != sandbox.worker_profile
        or runtime.surface != sandbox.surface.reference()
        or runtime.rule_set != sandbox.rule_set
        or runtime.operation is not sandbox.operation
        or runtime.parser is not sandbox.parser
        or runtime.parser_executable_sha256 != sandbox.parser_executable_sha256
        or runtime.parser_configuration_sha256 != sandbox.parser_configuration_sha256
        or runtime.sandbox_image_sha256 != sandbox.sandbox_image_sha256
        or runtime.run_as_identity != sandbox.run_as_identity
        or runtime.evidence_mount_target != sandbox.evidence_mount_target
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
        or runtime.parser_work_unit != sandbox.parser_work_unit
        or runtime.max_parser_work_units != sandbox.max_parser_work_units
        or runtime.max_recursion_depth != sandbox.max_recursion_depth
        or runtime.max_decompression_ratio != sandbox.max_decompression_ratio
        or runtime.max_decompressed_bytes != sandbox.max_decompressed_bytes
        or runtime.observed_artifact_bytes != budget.artifact_bytes
        or runtime.observed_output_bytes != result_receipt.result_bytes
        or runtime.observed_runtime_seconds < duration
        or runtime.observed_peak_memory_mib > budget.memory_mib
        or runtime.observed_peak_process_count > budget.process_count
        or runtime.observed_parser_work_units
        < max(1, runtime.artifact_bytes, runtime.observed_decompressed_bytes)
        or runtime.network_requests != budget.network_requests
        or runtime.dns_queries != budget.dns_queries
        or runtime.host_filesystem_reads != budget.host_filesystem_reads
        or runtime.source_write_operations != budget.source_write_operations
        or runtime.source_copy_operations != budget.source_copy_operations
        or runtime.evidence_mutation_operations != budget.evidence_mutation_operations
        or runtime.credential_reads != budget.credential_reads
        or runtime.credential_uses != budget.credential_uses
        or runtime.secret_material_reads != budget.secret_material_reads
        or runtime.device_sessions != budget.device_sessions
        or runtime.plugin_loads != budget.plugin_loads
        or runtime.lateral_movement_attempts != budget.lateral_movement_attempts
        or runtime.target_process_executions != budget.target_process_executions
        or runtime.shell_commands != budget.shell_commands
        or runtime.pre_state != source.pre_state
        or runtime.post_state != source.post_state
        or result_receipt.execution_id != statement.execution_id
        or result_receipt.request_id != prepared.request.request_id
        or result_receipt.request_digest != prepared.request_digest
        or result_receipt.preparation_id != preparation.preparation_id
        or result_receipt.preparation_digest != preparation.preparation_digest
        or result_receipt.input_kind is not preparation.input_kind
        or result_receipt.operation is not preparation.operation
        or result_receipt.parser is not request.parser
        or result_receipt.rule_set != request.rule_set
        or result_receipt.surface != preparation.surface.reference()
        or result_receipt.artifact_sha256 != custody.artifact_sha256
        or result_receipt.artifact_bytes != custody.artifact_bytes
        or result_receipt.output_schema != request.output_schema
        or result_receipt.result_bytes > budget.max_output_bytes
        or result_receipt.receipt_id != statement.result_receipt_id
        or result_receipt.receipt_digest != statement.result_receipt_digest
        or result_receipt_sha256 != statement.result_receipt_sha256
        or not (statement.finished_at <= result_receipt.received_at <= statement.issued_at)
        or oracle_verdict
        != recompute_forensic_evidence_analysis_oracle_verdict(
            preparation,
            result_receipt,
        )
        or duration <= 0
        or duration > budget.runtime_seconds
        or not (
            permit.consumed_at
            <= statement.started_at
            <= runtime.attested_at
            <= statement.finished_at
            <= source.attested_at
            <= statement.issued_at
            < permit.expires_at
        )
        or not (
            source.valid_from
            <= statement.started_at
            <= runtime.attested_at
            <= statement.finished_at
            <= source.attested_at
            <= statement.issued_at
            <= source.valid_until
        )
    ):
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "sealed Forensic execution statement differs from current authority"
        )


def _require_source_input_instance_fields(
    inputs: ForensicEvidenceAnalysisObservationSourceInputs,
) -> None:
    _require_known_instance_fields(inputs.activation, label="Forensic source inputs")
    _require_known_instance_fields(inputs.campaign, label="Forensic source inputs")
    _require_known_instance_fields(inputs.preparation, label="Forensic source inputs")
    _require_known_instance_fields(inputs.job, label="Forensic source inputs")


def _artifact_reference(value: str, *, label: str) -> str:
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError) as exc:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
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
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(f"{label} reference is invalid")
    return path.as_posix()


def _artifact_path(root: Path, reference: str) -> Path:
    return root.joinpath(*PurePosixPath(reference).parts)


def _canonical_evidence_source_root(root: Path) -> Path:
    if not isinstance(root, Path):
        raise TypeError("Forensic evidence source root must be an exact Path")
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic evidence source root must be an absolute existing non-symlink directory"
        )
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic evidence source root cannot be resolved"
        ) from exc
    if not resolved.is_absolute() or not resolved.is_dir():
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic evidence source root is not a canonical directory"
        )
    return resolved


def forensic_evidence_analysis_execution_bundle_reference(value: str) -> str:
    """Return the sole code-owned Evidence reference for an execution bundle digest."""

    if type(value) is not str or fullmatch(r"^[a-f0-9]{64}$", value) is None:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic execution bundle digest is invalid"
        )
    return f"evidence/forensic-evidence-analysis-execution-{value}.json"


def forensic_evidence_analysis_result_receipt_reference(value: str) -> str:
    """Return the sole code-owned Evidence reference for a result receipt digest."""

    if type(value) is not str or fullmatch(r"^[a-f0-9]{64}$", value) is None:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic result receipt digest is invalid"
        )
    return f"evidence/forensic-evidence-analysis-result-receipt-{value}.json"


def _require_exact_evidence_reference(
    value: str,
    *,
    expected: str,
    label: str,
) -> None:
    if value != expected:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            f"{label} reference is not content-addressed"
        )


def forensic_evidence_analysis_source_root_digest(
    *,
    attestation_reference: str,
    attestation_sha256: str,
    result_receipt_reference: str,
    result_receipt_sha256: str,
    source_membership_trust_anchor_digest: str,
    execution_trust_anchor_digest: str,
    source_membership_attestation_sha256: str,
    statement_sha256: str,
    oracle_verdict_digest: str,
) -> str:
    """Digest the two admission evidence files and their verified interpretations."""

    canonical_attestation_reference = _artifact_reference(
        attestation_reference,
        label="Forensic execution attestation",
    )
    canonical_result_reference = _artifact_reference(
        result_receipt_reference,
        label="Forensic analysis result receipt",
    )
    if canonical_attestation_reference == canonical_result_reference:
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic attestation and result receipt must be distinct evidence"
        )
    if canonical_attestation_reference != forensic_evidence_analysis_execution_bundle_reference(
        attestation_sha256
    ) or canonical_result_reference != forensic_evidence_analysis_result_receipt_reference(
        result_receipt_sha256
    ):
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic admission evidence references are not content-addressed"
        )
    digest_coordinates = {
        "attestationSha256": attestation_sha256,
        "resultReceiptSha256": result_receipt_sha256,
        "sourceMembershipTrustAnchorDigest": source_membership_trust_anchor_digest,
        "executionTrustAnchorDigest": execution_trust_anchor_digest,
        "sourceMembershipAttestationSha256": source_membership_attestation_sha256,
        "statementSha256": statement_sha256,
        "oracleVerdictDigest": oracle_verdict_digest,
    }
    if any(
        type(value) is not str or fullmatch(r"^[a-f0-9]{64}$", value) is None
        for value in digest_coordinates.values()
    ):
        raise ForensicEvidenceAnalysisKnowledgeAdmissionError(
            "Forensic admission evidence digest coordinate is invalid"
        )
    return graph_digest(
        "pajin.workflow.forensic-evidence-analysis-observation-source-root/v1",
        {
            "attestationReference": canonical_attestation_reference,
            "resultReceiptReference": canonical_result_reference,
            **digest_coordinates,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def _require_admitted_event(
    *,
    event: GraphAdmissionEvent,
    proposal: ObservationProposal | HypothesisProposal,
    graph: ForensicGraphAdmissionBinding,
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
        raise ValueError("Forensic Graph admission differs from its bounded Proposal")


__all__ = [
    "FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_ADMISSION_API_VERSION",
    "FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_DIGEST",
    "FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_ID",
    "FORENSIC_EVIDENCE_ANALYSIS_KNOWLEDGE_PRODUCER_VERSION",
    "ForensicEvidenceAnalysisAdmissionOraclePolicy",
    "ForensicEvidenceAnalysisAdmissionOracleVerdict",
    "ForensicEvidenceAnalysisExecutionAttestor",
    "ForensicEvidenceAnalysisExecutionBundle",
    "ForensicEvidenceAnalysisExecutionKeyState",
    "ForensicEvidenceAnalysisExecutionStatement",
    "ForensicEvidenceAnalysisExecutionTrustAnchor",
    "ForensicEvidenceAnalysisExecutionVerification",
    "ForensicEvidenceAnalysisExecutionVerificationKey",
    "ForensicEvidenceAnalysisKnowledgeAdmission",
    "ForensicEvidenceAnalysisKnowledgeAdmissionError",
    "ForensicEvidenceAnalysisKnowledgeAdmissionGate",
    "ForensicEvidenceAnalysisKnowledgeAdmissionPolicy",
    "ForensicEvidenceAnalysisKnowledgeCandidate",
    "ForensicEvidenceAnalysisObservationSourceInputs",
    "ForensicEvidenceAnalysisOracleDisposition",
    "ForensicEvidenceAnalysisOracleSignalMapping",
    "ForensicEvidenceAnalysisResultDisposition",
    "ForensicEvidenceAnalysisResultReceipt",
    "ForensicEvidenceAnalysisSandboxRuntimeReceipt",
    "ForensicEvidenceSourceMembershipAttestation",
    "ForensicEvidenceSourceMembershipAttestor",
    "ForensicEvidenceSourceMembershipBundle",
    "ForensicEvidenceSourceMembershipKeyState",
    "ForensicEvidenceSourceMembershipTrustAnchor",
    "ForensicEvidenceSourceMembershipVerification",
    "ForensicEvidenceSourceMembershipVerificationKey",
    "ForensicEvidenceSourceState",
    "ForensicGraphAdmissionBinding",
    "VerifiedForensicEvidenceAnalysisObservationSource",
    "forensic_evidence_analysis_execution_bundle_bytes",
    "forensic_evidence_analysis_execution_bundle_reference",
    "forensic_evidence_analysis_execution_public_key",
    "forensic_evidence_analysis_gateway_outcome_digest",
    "forensic_evidence_analysis_knowledge_producer_registration",
    "forensic_evidence_analysis_result_receipt_bytes",
    "forensic_evidence_analysis_result_receipt_reference",
    "forensic_evidence_analysis_source_root_digest",
    "forensic_evidence_source_membership_bundle_bytes",
    "forensic_evidence_source_membership_public_key",
    "load_verified_forensic_evidence_analysis_observation_source",
    "recompute_forensic_evidence_analysis_oracle_verdict",
    "registered_forensic_evidence_analysis_oracle_policy",
    "verify_forensic_evidence_analysis_execution_bundle",
    "verify_forensic_evidence_source_membership_bundle",
]
