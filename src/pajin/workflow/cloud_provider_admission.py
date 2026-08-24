"""CLOUD-001C sealed Cloud provider receipt admission through the Graph writer."""

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
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.cloud_inventory import (
    CloudCampaignScopeBinding,
    CloudCredentialLeaseReference,
    CloudProviderReadRequest,
    CloudReadOnlyCapabilityActivation,
    CloudReadOnlyInventoryPolicyPreparation,
    CloudReadOnlyOperation,
    CloudReadOnlyProviderAdapterRef,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.models import capability_definition_digest
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSAdmission,
    WorkerMTLSTrustPolicy,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.cloud_surfaces import CloudAccountResourceSurfaceRef
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
    GraphNodeKind,
    GraphObservation,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    ObservationProposal,
    graph_digest,
    graph_node_ref,
)
from pajin.graph.projection import GraphSnapshotRef, graph_snapshot_ref
from pajin.graph.sqlite_store import SQLiteGraphStore, load_verified_current_graph_snapshot
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

CLOUD_PROVIDER_OBSERVATION_PRODUCER_ID = "pajin.workflow.cloud-provider-observation-admission"
CLOUD_PROVIDER_OBSERVATION_PRODUCER_VERSION = "1.0.0"
CLOUD_PROVIDER_OBSERVATION_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.cloud-provider-observation-admission/v1"
).hexdigest()
CLOUD_PROVIDER_OBSERVATION_ADMISSION_API_VERSION: Literal[
    "pajin.dev/cloud-provider-observation-admission/v1alpha1"
] = "pajin.dev/cloud-provider-observation-admission/v1alpha1"

_SIGNATURE_DOMAIN = b"pajin.workflow.cloud-provider-execution-attestation/v1\0"
_MAX_ATTESTATION_BYTES = 2 * 1024 * 1024
_MAX_RECEIPT_BYTES = 512 * 1024
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024

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
    "raw_provider_response_embedded",
    "resource_existence_authority",
    "resource_ownership_authority",
    "policy_effect_authority",
    "effective_permission_authority",
    "surface_mutation_authorized",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "provider_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_use_authorized",
    "policy_mutation_authorized",
    "iam_mutation_authorized",
    "container_write_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class CloudProviderObservationAdmissionError(ValueError):
    """Raised when a sealed Cloud execution receipt cannot enter the Graph."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class CloudProviderExecutionKeyState(StrEnum):
    """Lifecycle state for an out-of-band Cloud execution attestation key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


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


class CloudProviderExecutionVerificationKey(_FrozenStrictModel):
    """One externally configured Ed25519 verifier and its lifecycle."""

    key_id: _Identifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(alias="publicKeyBase64url", pattern=r"^[A-Za-z0-9_-]{43}$")
    state: CloudProviderExecutionKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Cloud execution attestation public key",
        )
        not_before = _aware_utc(self.not_before, label="Cloud execution key not-before")
        if self.not_after is not None:
            not_after = _aware_utc(self.not_after, label="Cloud execution key not-after")
            if not_after <= not_before:
                raise ValueError("Cloud execution key validity window is empty")
        if self.state is CloudProviderExecutionKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired Cloud execution key requires not_after")
        if self.state is CloudProviderExecutionKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Cloud execution key requires revoked_at")
            _aware_utc(self.revoked_at, label="Cloud execution key revocation")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked Cloud execution key cannot have revoked_at")
        return self


class CloudProviderExecutionWorkerBinding(_FrozenStrictModel):
    """Deployment-owned Cloud Worker identity binding that grants no new dispatch."""

    api_version: Literal["pajin.dev/cloud-provider-execution-worker-binding/v1alpha1"] = Field(
        default="pajin.dev/cloud-provider-execution-worker-binding/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudProviderExecutionWorkerBinding"] = "CloudProviderExecutionWorkerBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=100)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    deployment_id: _Identifier = Field(alias="deploymentId")
    capability: CodeBackedCapabilityRef
    capability_release: CapabilityReleaseRef = Field(alias="capabilityRelease")
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    worker_mtls_policy: WorkerMTLSTrustPolicy = Field(alias="workerMTLSPolicy")
    worker_identity: WorkerCertificateBinding = Field(alias="workerIdentity")
    provider_adapter: CloudReadOnlyProviderAdapterRef = Field(alias="providerAdapter")
    credential_audience: _Identifier = Field(alias="credentialAudience")
    deployment_owned: Literal[True] = Field(default=True, alias="deploymentOwned")
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    current_activation_bound: Literal[False] = Field(default=False, alias="currentActivationBound")
    campaign_authority_bound: Literal[False] = Field(default=False, alias="campaignAuthorityBound")
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_bound: Literal[False] = Field(default=False, alias="permitBound")
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="providerInvocationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "deployment_owned",
        "binding_only",
        "current_activation_bound",
        "campaign_authority_bound",
        "approval_satisfied",
        "permit_bound",
        "credential_use_authorized",
        "provider_invocation_authorized",
        "graph_admission_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud execution Worker binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        profile = resolve_registered_domain_worker_boundary_profile(self.worker_profile)
        identities = {item.principal_subject: item for item in self.worker_mtls_policy.bindings}
        if (
            profile.domain_classification.domain is not SecurityDomain.CLOUD
            or profile.network_boundary is not WorkerNetworkBoundary.BOUNDED_EGRESS
            or profile.filesystem_boundary is not WorkerFilesystemBoundary.NO_HOST_ACCESS
            or profile.credential_boundary is not WorkerCredentialBoundary.EPHEMERAL_LEASE
            or profile.runtime_boundary is not WorkerRuntimeBoundary.ISOLATED_NON_ROOT
            or identities.get(self.worker_identity.principal_subject) != self.worker_identity
        ):
            raise ValueError("Cloud execution Worker binding differs from code-owned boundaries")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.workflow.cloud-provider-execution-worker-binding/v1",
            material,
        )
        binding_id = f"cloud-provider-worker-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Cloud execution Worker binding digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Cloud execution Worker binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


class CloudProviderExecutionTrustAnchor(_FrozenStrictModel):
    """Out-of-band signer, Worker, adapter, and mTLS trust for one deployment."""

    api_version: Literal["pajin.dev/cloud-provider-execution-trust-anchor/v1alpha1"] = Field(
        default="pajin.dev/cloud-provider-execution-trust-anchor/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudProviderExecutionTrustAnchor"] = "CloudProviderExecutionTrustAnchor"
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    worker_binding: CloudProviderExecutionWorkerBinding = Field(alias="workerBinding")
    keys: tuple[CloudProviderExecutionVerificationKey, ...] = Field(
        min_length=1,
        max_length=32,
    )
    verification_only: Literal[True] = Field(default=True, alias="verificationOnly")
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="providerInvocationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "verification_only",
        "credential_use_authorized",
        "provider_invocation_authorized",
        "graph_admission_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud execution trust-anchor markers must be booleans")
        return value

    @model_validator(mode="after")
    def require_unique_sorted_keyring(self) -> Self:
        key_ids = [key.key_id for key in self.keys]
        if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)):
            raise ValueError("Cloud execution trust-anchor keys must be uniquely sorted")
        active = [key for key in self.keys if key.state is CloudProviderExecutionKeyState.ACTIVE]
        if len(active) != 1:
            raise ValueError("Cloud execution trust anchor requires exactly one active key")
        return self

    @property
    def digest(self) -> str:
        return capability_definition_digest(
            "pajin.workflow.cloud-provider-execution-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
        )


class CloudCredentialUseReceipt(_FrozenStrictModel):
    """Signed audit projection of one already-consumed, now-discarded lease use."""

    api_version: Literal["pajin.dev/cloud-credential-use-receipt/v1alpha1"] = Field(
        default="pajin.dev/cloud-credential-use-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudCredentialUseReceipt"] = "CloudCredentialUseReceipt"
    credential_lease: CloudCredentialLeaseReference = Field(alias="credentialLease")
    broker_rechecked_at: datetime = Field(alias="brokerRecheckedAt")
    materialized_at: datetime = Field(alias="materializedAt")
    used_at: datetime = Field(alias="usedAt")
    discarded_at: datetime = Field(alias="discardedAt")
    use_count: Literal[1] = Field(default=1, alias="useCount")
    broker_lease_rechecked: Literal[True] = Field(default=True, alias="brokerLeaseRechecked")
    lease_materialized: Literal[True] = Field(default=True, alias="leaseMaterialized")
    single_use_consumed: Literal[True] = Field(default=True, alias="singleUseConsumed")
    material_discarded: Literal[True] = Field(default=True, alias="materialDiscarded")
    raw_lease_id_embedded: Literal[False] = Field(default=False, alias="rawLeaseIdEmbedded")
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    ambient_credential_used: Literal[False] = Field(default=False, alias="ambientCredentialUsed")
    new_credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="newCredentialUseAuthorized",
    )

    @field_validator("broker_rechecked_at", "materialized_at", "used_at", "discarded_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Cloud credential-use receipt time")

    @field_validator(
        "broker_lease_rechecked",
        "lease_materialized",
        "single_use_consumed",
        "material_discarded",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cloud credential-use success markers must be true")
        return value

    @field_validator(
        "raw_lease_id_embedded",
        "credential_material_embedded",
        "ambient_credential_used",
        "new_credential_use_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cloud credential-use authority markers must be false")
        return value

    @model_validator(mode="after")
    def require_one_bounded_use(self) -> Self:
        if not (
            self.credential_lease.issued_at
            <= self.broker_rechecked_at
            <= self.materialized_at
            <= self.used_at
            <= self.discarded_at
            < self.credential_lease.expires_at
        ):
            raise ValueError("Cloud credential-use receipt timestamps are inconsistent")
        return self


class CloudProviderResponseReceipt(_FrozenStrictModel):
    """Neutral receipt for one response; provider body and interpreted fields stay external."""

    api_version: Literal["pajin.dev/cloud-provider-response-receipt/v1alpha1"] = Field(
        default="pajin.dev/cloud-provider-response-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudProviderResponseReceipt"] = "CloudProviderResponseReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=100)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    execution_id: _Identifier = Field(alias="executionId")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    route_digest: _Sha256 = Field(alias="routeDigest")
    operation: CloudReadOnlyOperation
    surface: CloudAccountResourceSurfaceRef
    http_status: int = Field(alias="httpStatus", strict=True, ge=200, le=299)
    response_body_sha256: _Sha256 = Field(alias="responseBodySha256")
    response_bytes: int = Field(alias="responseBytes", strict=True, ge=0, le=32 * 1024 * 1024)
    media_type: str = Field(alias="mediaType", min_length=1, max_length=100)
    received_at: datetime = Field(alias="receivedAt")
    request_succeeded: Literal[True] = Field(default=True, alias="requestSucceeded")
    provider_response_hash_recorded: Literal[True] = Field(
        default=True,
        alias="providerResponseHashRecorded",
    )
    raw_provider_response_embedded: Literal[False] = Field(
        default=False,
        alias="rawProviderResponseEmbedded",
    )
    provider_headers_embedded: Literal[False] = Field(
        default=False,
        alias="providerHeadersEmbedded",
    )
    resource_fields_interpreted: Literal[False] = Field(
        default=False,
        alias="resourceFieldsInterpreted",
    )
    policy_fields_interpreted: Literal[False] = Field(
        default=False,
        alias="policyFieldsInterpreted",
    )
    effective_permissions_evaluated: Literal[False] = Field(
        default=False,
        alias="effectivePermissionsEvaluated",
    )
    resource_existence_verified: Literal[False] = Field(
        default=False,
        alias="resourceExistenceVerified",
    )
    resource_ownership_verified: Literal[False] = Field(
        default=False,
        alias="resourceOwnershipVerified",
    )
    credential_material_present: Literal[False] = Field(
        default=False,
        alias="credentialMaterialPresent",
    )
    mutation_performed: Literal[False] = Field(default=False, alias="mutationPerformed")

    @field_validator("received_at")
    @classmethod
    def require_aware_received_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Cloud response receipt time")

    @field_validator("request_succeeded", "provider_response_hash_recorded", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cloud response receipt success markers must be true")
        return value

    @field_validator(
        "raw_provider_response_embedded",
        "provider_headers_embedded",
        "resource_fields_interpreted",
        "policy_fields_interpreted",
        "effective_permissions_evaluated",
        "resource_existence_verified",
        "resource_ownership_verified",
        "credential_material_present",
        "mutation_performed",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cloud response receipt authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_receipt_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = capability_definition_digest(
            "pajin.workflow.cloud-provider-response-receipt/v1",
            material,
        )
        receipt_id = f"cloud-provider-response-receipt_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Cloud provider response receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Cloud provider response receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class CloudProviderExecutionStatement(_FrozenStrictModel):
    """Exact approved GET execution and detached neutral response receipt binding."""

    api_version: Literal["pajin.dev/cloud-provider-execution-statement/v1alpha1"] = Field(
        default="pajin.dev/cloud-provider-execution-statement/v1alpha1",
        alias="apiVersion",
    )
    predicate_type: Literal["pajin.cloud.read-only-provider-execution/v1"] = Field(
        default="pajin.cloud.read-only-provider-execution/v1",
        alias="predicateType",
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    deployment_id: _Identifier = Field(alias="deploymentId")
    worker_binding_id: _Identifier = Field(alias="workerBindingId")
    worker_binding_digest: _Sha256 = Field(alias="workerBindingDigest")
    worker_mtls_admission: WorkerMTLSAdmission = Field(alias="workerMTLSAdmission")
    execution_id: _Identifier = Field(alias="executionId")
    campaign_id: _Identifier = Field(alias="campaignId")
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    run_id: _Identifier = Field(alias="runId")
    preparation_id: _Identifier = Field(alias="preparationId")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    provider_request: CloudProviderReadRequest = Field(alias="providerRequest")
    request_id: _Identifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    action_permit_id: _Identifier = Field(alias="actionPermitId")
    action_permit_digest: _Sha256 = Field(alias="actionPermitDigest")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    credential_use: CloudCredentialUseReceipt = Field(alias="credentialUse")
    response_receipt_reference: _ArtifactPath = Field(alias="responseReceiptReference")
    response_receipt_sha256: _Sha256 = Field(alias="responseReceiptSha256")
    response_receipt_id: _Identifier = Field(alias="responseReceiptId")
    response_receipt_digest: _Sha256 = Field(alias="responseReceiptDigest")
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    issued_at: datetime = Field(alias="issuedAt")
    status: Literal["succeeded"] = "succeeded"
    request_count: Literal[1] = Field(default=1, alias="requestCount")
    provider_write_requests: Literal[0] = Field(default=0, alias="providerWriteRequests")
    method: Literal["GET"] = "GET"
    direct_mtls_verified: Literal[True] = Field(default=True, alias="directMTLSVerified")
    current_broker_lease_verified: Literal[True] = Field(
        default=True,
        alias="currentBrokerLeaseVerified",
    )
    response_receipt_sealed: Literal[True] = Field(default=True, alias="responseReceiptSealed")
    raw_provider_response_embedded: Literal[False] = Field(
        default=False,
        alias="rawProviderResponseEmbedded",
    )
    provider_fields_interpreted: Literal[False] = Field(
        default=False,
        alias="providerFieldsInterpreted",
    )
    policy_effect_evaluated: Literal[False] = Field(
        default=False,
        alias="policyEffectEvaluated",
    )
    new_credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="newCredentialUseAuthorized",
    )
    new_provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="newProviderInvocationAuthorized",
    )
    mutation_authorized: Literal[False] = Field(default=False, alias="mutationAuthorized")

    @field_validator("started_at", "finished_at", "issued_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Cloud execution statement time")

    @field_validator(
        "direct_mtls_verified",
        "current_broker_lease_verified",
        "response_receipt_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cloud execution statement success markers must be true")
        return value

    @field_validator(
        "raw_provider_response_embedded",
        "provider_fields_interpreted",
        "policy_effect_evaluated",
        "new_credential_use_authorized",
        "new_provider_invocation_authorized",
        "mutation_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cloud execution statement authority markers must be false")
        return value

    @model_validator(mode="after")
    def require_causal_execution(self) -> Self:
        if not (
            self.credential_use.materialized_at
            <= self.started_at
            < self.finished_at
            <= self.credential_use.discarded_at
            <= self.issued_at
        ):
            raise ValueError("Cloud execution statement timestamps are inconsistent")
        if self.provider_request.method != "GET":
            raise ValueError("Cloud execution statement requires one exact GET request")
        return self

    @property
    def statement_key(self) -> str:
        """Return a stable local key without conferring signature authority."""

        return sha256(
            canonical_json_bytes(
                self.model_dump(mode="json", by_alias=True),
                label="Cloud execution statement key",
                max_bytes=_MAX_CANONICAL_BYTES,
            )
        ).hexdigest()


class CloudProviderExecutionBundle(_FrozenStrictModel):
    """Detached Ed25519 signature over one Cloud execution statement."""

    api_version: Literal["pajin.dev/cloud-provider-execution-bundle/v1alpha1"] = Field(
        default="pajin.dev/cloud-provider-execution-bundle/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudProviderExecutionBundle"] = "CloudProviderExecutionBundle"
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _Identifier = Field(alias="keyId")
    statement: CloudProviderExecutionStatement
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(alias="signatureBase64url", pattern=r"^[A-Za-z0-9_-]{86}$")

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_json_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Cloud provider execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("Cloud execution statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Cloud execution signature",
        )
        return self


class CloudProviderExecutionVerification(_FrozenStrictModel):
    """Result of verifying caller-supplied Cloud execution trust."""

    valid: Literal[True] = True
    key_id: _Identifier = Field(alias="keyId")
    key_state: CloudProviderExecutionKeyState = Field(alias="keyState")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    issued_at: datetime = Field(alias="issuedAt")


@dataclass(frozen=True, slots=True)
class CloudProviderExecutionAttestor:
    """Signing helper for a deployment-owned runtime; it performs no provider call."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: CloudProviderExecutionTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: CloudProviderExecutionTrustAnchor,
    ) -> CloudProviderExecutionAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 Cloud execution private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if len(matching) != 1 or matching[0].state is not CloudProviderExecutionKeyState.ACTIVE:
            raise ValueError("Cloud execution signer key is not the active trust-anchor key")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Cloud execution active public key",
        )
        if public_bytes != expected:
            raise ValueError("Cloud execution private key does not match its trust anchor")

    def attest(self, statement: CloudProviderExecutionStatement) -> CloudProviderExecutionBundle:
        canonical_statement = CloudProviderExecutionStatement.model_validate(
            statement.model_dump(mode="json", by_alias=True)
        )
        binding = self.trust_anchor.worker_binding
        if (
            canonical_statement.trust_domain != self.trust_anchor.trust_domain
            or canonical_statement.issuer != self.trust_anchor.issuer
            or canonical_statement.deployment_id != binding.deployment_id
            or canonical_statement.worker_binding_id != binding.binding_id
            or canonical_statement.worker_binding_digest != binding.binding_digest
        ):
            raise ValueError("Cloud execution statement differs from its trust anchor")
        key = next(item for item in self.trust_anchor.keys if item.key_id == self.active_key_id)
        issued_at = canonical_statement.issued_at
        if issued_at < key.not_before or (key.not_after is not None and issued_at >= key.not_after):
            raise ValueError("Cloud execution signing key is not valid at statement issue time")
        canonical = canonical_json_bytes(
            canonical_statement.model_dump(mode="json", by_alias=True),
            label="Cloud provider execution statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return CloudProviderExecutionBundle(
            keyId=self.active_key_id,
            statement=canonical_statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


def cloud_provider_execution_public_key(private_key: bytes) -> str:
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


def cloud_provider_execution_bundle_bytes(bundle: CloudProviderExecutionBundle) -> bytes:
    """Serialize a human-readable bundle whose signature covers canonical statement bytes."""

    return (
        json.dumps(
            bundle.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def cloud_provider_response_receipt_bytes(receipt: CloudProviderResponseReceipt) -> bytes:
    """Serialize a detached neutral receipt without the provider body."""

    return (
        json.dumps(
            receipt.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def verify_cloud_provider_execution_bundle(
    bundle: CloudProviderExecutionBundle,
    *,
    trust_anchor: CloudProviderExecutionTrustAnchor,
) -> CloudProviderExecutionVerification:
    """Verify a Cloud execution statement using only caller-supplied trust material."""

    statement = bundle.statement
    binding = trust_anchor.worker_binding
    if (
        statement.trust_domain != trust_anchor.trust_domain
        or statement.issuer != trust_anchor.issuer
        or statement.deployment_id != binding.deployment_id
        or statement.worker_binding_id != binding.binding_id
        or statement.worker_binding_digest != binding.binding_digest
    ):
        raise CloudProviderObservationAdmissionError(
            "Cloud execution issuer or Worker binding is not trusted"
        )
    key = next((item for item in trust_anchor.keys if item.key_id == bundle.key_id), None)
    if key is None:
        raise CloudProviderObservationAdmissionError(
            "Cloud execution signing key is absent from the trust anchor"
        )
    if key.state is CloudProviderExecutionKeyState.REVOKED:
        raise CloudProviderObservationAdmissionError("Cloud execution signing key is revoked")
    issued_at = statement.issued_at
    if issued_at < key.not_before or (key.not_after is not None and issued_at >= key.not_after):
        raise CloudProviderObservationAdmissionError(
            "Cloud execution statement is outside signing-key validity"
        )
    canonical = canonical_json_bytes(
        statement.model_dump(mode="json", by_alias=True),
        label="Cloud provider execution statement",
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    public_key = Ed25519PublicKey.from_public_bytes(
        _base64url_decode(
            key.public_key_base64url,
            expected_length=32,
            label="Cloud execution public key",
        )
    )
    try:
        public_key.verify(
            _base64url_decode(
                bundle.signature_base64url,
                expected_length=64,
                label="Cloud execution signature",
            ),
            _SIGNATURE_DOMAIN + canonical,
        )
    except InvalidSignature as exc:
        raise CloudProviderObservationAdmissionError(
            "Cloud execution signature verification failed"
        ) from exc
    return CloudProviderExecutionVerification(
        keyId=key.key_id,
        keyState=key.state,
        trustAnchorDigest=trust_anchor.digest,
        statementSha256=bundle.statement_sha256,
        issuedAt=statement.issued_at,
    )


@dataclass(frozen=True, slots=True)
class CloudProviderObservationSourceInputs:
    """Current Cloud authority plus two deployment-produced detached evidence files."""

    source_root: Path
    attestation_reference: str
    expected_run_id: str
    activation: CloudReadOnlyCapabilityActivation
    campaign: CampaignManifest
    preparation: CloudReadOnlyInventoryPolicyPreparation
    job: CapabilityGraphCampaignJobInput


@dataclass(frozen=True, slots=True)
class VerifiedCloudProviderObservationSource:
    """One independently verified, already-completed Cloud read-only execution."""

    preparation: CloudReadOnlyInventoryPolicyPreparation
    job: CapabilityGraphCampaignJobInput
    permit: ActionPermit
    approval_receipt: ActionApprovalConsumptionReceipt
    trust_anchor: CloudProviderExecutionTrustAnchor
    verification: CloudProviderExecutionVerification
    bundle: CloudProviderExecutionBundle
    response_receipt: CloudProviderResponseReceipt
    attestation_reference: str
    attestation_sha256: str
    response_receipt_reference: str
    response_receipt_sha256: str
    source_root_digest: str


class CloudProviderObservationAdmissionPolicy(_FrozenStrictModel):
    """Code-owned authority for one neutral Cloud API Observation only."""

    api_version: Literal["pajin.dev/cloud-provider-observation-admission-policy/v1alpha1"] = Field(
        default="pajin.dev/cloud-provider-observation-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudProviderObservationAdmissionPolicy"] = (
        "CloudProviderObservationAdmissionPolicy"
    )
    policy_id: str = Field(default="", alias="policyId", max_length=100)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.cloud-provider-observation-admission"] = Field(
        default="pajin.workflow.cloud-provider-observation-admission",
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="producerVersion",
    )
    producer_digest: _Sha256 = Field(
        default=CLOUD_PROVIDER_OBSERVATION_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["cloud.api-observation"] = Field(
        default="cloud.api-observation",
        alias="observationType",
    )
    observation_only: Literal[True] = Field(default=True, alias="observationOnly")
    hypothesis_production_authorized: Literal[False] = Field(
        default=False,
        alias="hypothesisProductionAuthorized",
    )
    finding_production_authorized: Literal[False] = Field(
        default=False,
        alias="findingProductionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "observation_only",
        "hypothesis_production_authorized",
        "finding_production_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud Observation policy markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        if self.producer_digest != CLOUD_PROVIDER_OBSERVATION_PRODUCER_DIGEST:
            raise ValueError("Cloud Observation producer digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cloud-provider-observation-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"cloud-provider-observation-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Cloud Observation policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Cloud Observation policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class CloudGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph Snapshot and existing single-writer identity."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError("Cloud Observation admission requires a non-empty Graph Snapshot")
        return self


class CloudProviderObservationCandidate(_FrozenStrictModel):
    """Content-addressed neutral Observation proposal built from sealed receipts."""

    api_version: Literal["pajin.dev/cloud-provider-observation-candidate/v1alpha1"] = Field(
        default="pajin.dev/cloud-provider-observation-candidate/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudProviderObservationCandidate"] = "CloudProviderObservationCandidate"
    candidate_id: str = Field(default="", alias="candidateId", max_length=110)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: CloudProviderObservationAdmissionPolicy
    graph: CloudGraphAdmissionBinding
    preparation: CloudReadOnlyInventoryPolicyPreparation
    surface: CloudAccountResourceSurfaceRef
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
    response_receipt_reference: _ArtifactPath = Field(alias="responseReceiptReference")
    response_receipt_sha256: _Sha256 = Field(alias="responseReceiptSha256")
    response_receipt_digest: _Sha256 = Field(alias="responseReceiptDigest")
    response_body_sha256: _Sha256 = Field(alias="responseBodySha256")
    operation: CloudReadOnlyOperation
    http_status: int = Field(alias="httpStatus", strict=True, ge=200, le=299)
    observation_proposal: ObservationProposal = Field(alias="observationProposal")
    state: Literal["sealed-observation-not-admitted"] = "sealed-observation-not-admitted"
    signature_verified: Literal[True] = Field(default=True, alias="signatureVerified")
    consumed_permit_verified: Literal[True] = Field(
        default=True,
        alias="consumedPermitVerified",
    )
    credential_use_receipt_verified: Literal[True] = Field(
        default=True,
        alias="credentialUseReceiptVerified",
    )
    response_receipt_verified: Literal[True] = Field(
        default=True,
        alias="responseReceiptVerified",
    )
    neutral_observation_produced: Literal[True] = Field(
        default=True,
        alias="neutralObservationProduced",
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    raw_provider_response_embedded: Literal[False] = Field(
        default=False,
        alias="rawProviderResponseEmbedded",
    )
    resource_existence_authority: Literal[False] = Field(
        default=False,
        alias="resourceExistenceAuthority",
    )
    resource_ownership_authority: Literal[False] = Field(
        default=False,
        alias="resourceOwnershipAuthority",
    )
    policy_effect_authority: Literal[False] = Field(default=False, alias="policyEffectAuthority")
    effective_permission_authority: Literal[False] = Field(
        default=False,
        alias="effectivePermissionAuthority",
    )
    surface_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="surfaceMutationAuthorized",
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
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    policy_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="policyMutationAuthorized",
    )
    iam_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="iamMutationAuthorized",
    )
    container_write_authorized: Literal[False] = Field(
        default=False,
        alias="containerWriteAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "signature_verified",
        "consumed_permit_verified",
        "credential_use_receipt_verified",
        "response_receipt_verified",
        "neutral_observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cloud sealed Observation markers must be true")
        return value

    @field_validator("graph_admitted", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cloud Observation candidate authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError("Cloud Graph semantics are not registered exactly") from exc
        proposal = self.observation_proposal
        evidence = {(item.reference, item.sha256) for item in proposal.evidence_nodes}
        expected_evidence = {
            (self.attestation_reference, self.attestation_sha256),
            (self.response_receipt_reference, self.response_receipt_sha256),
        }
        expected_edges = {
            (
                GraphRelation.PRODUCES,
                proposal.action.node_id,
                proposal.observation.node_id,
            ),
            *(
                (
                    GraphRelation.SUPPORTED_BY,
                    proposal.observation.node_id,
                    item.node_id,
                )
                for item in proposal.evidence_nodes
            ),
        }
        actual_edges = {
            (edge.relation, edge.source.node_id, edge.target.node_id) for edge in proposal.edges
        }
        expected_root = _cloud_source_root_digest(
            attestation_sha256=self.attestation_sha256,
            response_receipt_sha256=self.response_receipt_sha256,
            trust_anchor_digest=self.trust_anchor_digest,
            statement_sha256=self.statement_sha256,
        )
        if (
            self.surface != self.preparation.surface.reference()
            or self.preparation.surface.domain_graph_type_set != self.domain_graph_type_set
            or semantics.domain_classification.domain is not SecurityDomain.CLOUD
            or semantics.surface_type != "cloud.account-resource"
            or semantics.locator_schema != "pajin.locator.cloud.account-resource.v1"
            or semantics.observation_type != self.policy.observation_type
            or self.operation is not self.preparation.operation
            or self.source_root_digest != expected_root
            or proposal.observation.observation_type != self.policy.observation_type
            or proposal.observation.summary
            != (
                "A separately authorized read-only Cloud provider request produced sealed "
                "API response evidence for the exact bound Cloud Surface."
            )
            or proposal.observation.origin is not GraphContentOrigin.TARGET_DERIVED
            or proposal.observation.confidence != 1.0
            or proposal.producer_id != self.policy.producer_id
            or proposal.producer_version != self.policy.producer_version
            or proposal.producer_digest != self.policy.producer_digest
            or proposal.lineage.campaign_id != self.graph.snapshot.campaign_id
            or proposal.lineage.run_id != self.source_run_id
            or proposal.lineage.source_root_digest != self.source_root_digest
            or evidence != expected_evidence
            or len(proposal.evidence_nodes) != 2
            or len(proposal.edges) != 3
            or actual_edges != expected_edges
            or any(
                edge.authority_id != self.graph.authority_id
                or edge.authority_digest != self.graph.authority_digest
                for edge in proposal.edges
            )
        ):
            raise ValueError("Cloud Observation candidate differs from sealed semantics")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cloud-provider-observation-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"cloud-provider-observation_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Cloud Observation candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Cloud Observation candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class CloudProviderObservationAdmission(_FrozenStrictModel):
    """Proof that one neutral Cloud Observation used the existing Graph writer."""

    api_version: Literal["pajin.dev/cloud-provider-observation-admission/v1alpha1"] = Field(
        default=CLOUD_PROVIDER_OBSERVATION_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudProviderObservationAdmission"] = "CloudProviderObservationAdmission"
    admission_id: str = Field(default="", alias="admissionId", max_length=110)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: CloudProviderObservationCandidate
    observation_graph_event: GraphAdmissionEvent = Field(alias="observationGraphEvent")
    state: Literal["registered-not-authorized"] = "registered-not-authorized"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    neutral_observation_admitted: Literal[True] = Field(
        default=True,
        alias="neutralObservationAdmitted",
    )
    graph_admitted: Literal[True] = Field(default=True, alias="graphAdmitted")
    graph_single_writer_reused: Literal[True] = Field(
        default=True,
        alias="graphSingleWriterReused",
    )
    raw_provider_response_embedded: Literal[False] = Field(
        default=False,
        alias="rawProviderResponseEmbedded",
    )
    resource_existence_authority: Literal[False] = Field(
        default=False,
        alias="resourceExistenceAuthority",
    )
    resource_ownership_authority: Literal[False] = Field(
        default=False,
        alias="resourceOwnershipAuthority",
    )
    policy_effect_authority: Literal[False] = Field(default=False, alias="policyEffectAuthority")
    effective_permission_authority: Literal[False] = Field(
        default=False,
        alias="effectivePermissionAuthority",
    )
    surface_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="surfaceMutationAuthorized",
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
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    policy_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="policyMutationAuthorized",
    )
    iam_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="iamMutationAuthorized",
    )
    container_write_authorized: Literal[False] = Field(
        default=False,
        alias="containerWriteAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "sealed_source_verified",
        "neutral_observation_admitted",
        "graph_admitted",
        "graph_single_writer_reused",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cloud Observation admission markers must be true")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cloud Observation admission cannot carry execution authority")
        return value

    @model_validator(mode="after")
    def bind_admission_identity(self) -> Self:
        proposal = self.candidate.observation_proposal
        _require_admitted_event(
            event=self.observation_graph_event,
            proposal=proposal,
            graph=self.candidate.graph,
        )
        kinds = [node.kind for node in self.observation_graph_event.admitted_nodes]
        if (
            kinds.count(GraphNodeKind.ACTION.value) != 1
            or kinds.count(GraphNodeKind.OBSERVATION.value) != 1
            or kinds.count(GraphNodeKind.EVIDENCE.value) != 2
            or len(kinds) != 4
            or len(self.observation_graph_event.admitted_edges) != 3
            or any(
                edge.relation not in {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
                for edge in self.observation_graph_event.admitted_edges
            )
        ):
            raise ValueError("Cloud Observation admission exceeds neutral knowledge authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.cloud-provider-observation-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"cloud-provider-observation-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Cloud Observation admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Cloud Observation admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def cloud_provider_observation_producer_registration() -> GraphProducerRegistration:
    """Return the exact Observation-only producer registration."""

    return GraphProducerRegistration(
        producerId=CLOUD_PROVIDER_OBSERVATION_PRODUCER_ID,
        producerVersion=CLOUD_PROVIDER_OBSERVATION_PRODUCER_VERSION,
        producerDigest=CLOUD_PROVIDER_OBSERVATION_PRODUCER_DIGEST,
        allowedProposalKinds=(GraphProposalKind.OBSERVATION,),
    )


class CloudProviderObservationAdmissionGate:
    """Reverify detached Cloud receipts and reuse the existing Graph single writer."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
        trust_anchor: CloudProviderExecutionTrustAnchor,
    ) -> None:
        if not isinstance(graph_store, SQLiteGraphStore):
            raise TypeError("Cloud Observation admission requires an exact SQLite Graph Store")
        if not isinstance(graph_admission, GraphAdmissionAuthority):
            raise TypeError("Cloud Observation admission requires the Graph Admission authority")
        if not isinstance(trusted_lineages, TrustedGraphLineageRegistry):
            raise TypeError("Cloud Observation admission requires the trusted lineage registry")
        if not isinstance(trust_anchor, CloudProviderExecutionTrustAnchor):
            raise TypeError("Cloud Observation admission requires a deployment trust anchor")
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("Cloud Observation Graph authority wiring differs")
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages
        self._trust_anchor = CloudProviderExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )

    def prepare_candidate(
        self,
        inputs: CloudProviderObservationSourceInputs,
        graph: CloudGraphAdmissionBinding,
    ) -> CloudProviderObservationCandidate:
        try:
            canonical_graph = CloudGraphAdmissionBinding.model_validate(
                graph.model_dump(mode="json", by_alias=True)
            )
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except CloudProviderObservationAdmissionError:
            raise
        except Exception as exc:
            raise CloudProviderObservationAdmissionError(
                "Cloud Observation candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: CloudProviderObservationSourceInputs,
        candidate: CloudProviderObservationCandidate,
    ) -> CloudProviderObservationAdmission:
        try:
            canonical = CloudProviderObservationCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise CloudProviderObservationAdmissionError(
                    "Cloud Observation candidate differs from sealed source authority"
                )
            proposal = canonical.observation_proposal
            prior = self._graph_store.event_log.event_for_attempt(
                proposal.proposal_id,
                proposal.digest(),
            )
            if prior is None:
                self._require_current_graph(canonical.graph)
                expected_head = canonical.graph.snapshot.event_log_head_digest
                if expected_head is None:
                    raise CloudProviderObservationAdmissionError(
                        "Cloud Observation admission requires a non-empty Graph head"
                    )
                self._trusted_lineages.register(proposal.lineage)
                result = self._graph_admission.submit_if_current(
                    proposal,
                    expected_event_log_head_digest=expected_head,
                )
            else:
                result = self._graph_admission.submit(proposal)
            if (
                result.event.decision is not GraphAdmissionDecision.ADMITTED
                or result.event.authority_id != canonical.graph.authority_id
                or result.event.authority_digest != canonical.graph.authority_digest
            ):
                raise CloudProviderObservationAdmissionError(
                    "Graph Admission authority rejected Cloud Observation"
                )
            return CloudProviderObservationAdmission(
                candidate=canonical,
                observationGraphEvent=result.event,
            )
        except CloudProviderObservationAdmissionError:
            raise
        except Exception as exc:
            raise CloudProviderObservationAdmissionError(
                "Cloud Observation admission failed closed"
            ) from exc

    def _build_candidate(
        self,
        inputs: CloudProviderObservationSourceInputs,
        graph: CloudGraphAdmissionBinding,
    ) -> CloudProviderObservationCandidate:
        source = load_verified_cloud_provider_observation_source(
            inputs,
            graph_store=self._graph_store,
            trust_anchor=self._trust_anchor,
        )
        permit = source.permit
        statement = source.bundle.statement
        receipt = source.response_receipt
        if graph.snapshot.campaign_id != permit.campaign_id:
            raise CloudProviderObservationAdmissionError(
                "Cloud execution source and Graph admission Campaigns differ"
            )
        policy = CloudProviderObservationAdmissionPolicy()
        value_digest = graph_digest(
            "pajin.workflow.cloud-provider-observation-value/v1",
            {
                "preparationDigest": source.preparation.preparation_digest,
                "surfaceReference": source.preparation.surface.reference().model_dump(
                    mode="json", by_alias=True
                ),
                "operation": source.preparation.operation.value,
                "requestDigest": permit.request_digest,
                "approvalReceiptDigest": source.approval_receipt.receipt_digest,
                "trustAnchorDigest": source.verification.trust_anchor_digest,
                "statementSha256": source.verification.statement_sha256,
                "responseReceiptDigest": receipt.receipt_digest,
                "responseBodySha256": receipt.response_body_sha256,
                "responseBytes": receipt.response_bytes,
                "httpStatus": receipt.http_status,
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
            summary=(
                "A separately authorized read-only Cloud provider request produced sealed "
                "API response evidence for the exact bound Cloud Surface."
            ),
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
                    reference=source.response_receipt_reference,
                    sha256=source.response_receipt_sha256,
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
        lineage = GraphProposalLineage(
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            agentId="agent:cloud-provider-observation-admission",
            taskId=f"task:cloud-provider-observation:{statement.statement_key[:32]}",
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
            producedAt=statement.issued_at,
        )
        proposal_key = graph_digest(
            "pajin.workflow.cloud-provider-observation-proposal-id/v1",
            {
                "sourceRootDigest": source.source_root_digest,
                "statementSha256": source.verification.statement_sha256,
                "responseReceiptDigest": receipt.receipt_digest,
                "snapshotDigest": graph.snapshot.snapshot_digest,
                "observationNodeId": observation.node_id,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        proposal = ObservationProposal(
            proposalId=f"proposal:cloud-observation:{proposal_key}",
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            lineage=lineage,
            action=action,
            observation=observation,
            evidenceNodes=evidence_nodes,
            edges=sorted(edges, key=lambda item: item.edge_id),
        )
        return CloudProviderObservationCandidate(
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
            responseReceiptReference=source.response_receipt_reference,
            responseReceiptSha256=source.response_receipt_sha256,
            responseReceiptDigest=receipt.receipt_digest,
            responseBodySha256=receipt.response_body_sha256,
            operation=source.preparation.operation,
            httpStatus=receipt.http_status,
            observationProposal=proposal,
        )

    def _require_current_graph(self, graph: CloudGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest != getattr(self._graph_admission, "_authority_digest", None)
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise CloudProviderObservationAdmissionError(
                "Cloud Observation Graph Admission authority differs"
            )
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise CloudProviderObservationAdmissionError(
                "Cloud Observation Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise CloudProviderObservationAdmissionError(
                "Cloud Observation Graph Snapshot is not the current canonical head"
            )


def load_verified_cloud_provider_observation_source(
    inputs: CloudProviderObservationSourceInputs,
    *,
    graph_store: SQLiteGraphStore,
    trust_anchor: CloudProviderExecutionTrustAnchor,
) -> VerifiedCloudProviderObservationSource:
    """Verify current Cloud authority, consumed Permit, signature, and detached receipt."""

    if not isinstance(inputs, CloudProviderObservationSourceInputs):
        raise TypeError("Cloud Observation admission requires exact source inputs")
    if not isinstance(graph_store, SQLiteGraphStore):
        raise TypeError("Cloud source verification requires the exact SQLite Graph Store")
    if not isinstance(trust_anchor, CloudProviderExecutionTrustAnchor):
        raise TypeError("Cloud source verification requires a deployment trust anchor")
    if not isinstance(inputs.activation, CloudReadOnlyCapabilityActivation):
        raise TypeError("Cloud source verification requires current Cloud activation")
    try:
        campaign = CampaignManifest.model_validate(
            inputs.campaign.model_dump(mode="json", by_alias=True)
        )
        preparation = CloudReadOnlyInventoryPolicyPreparation.model_validate(
            inputs.preparation.model_dump(mode="json", by_alias=True)
        )
        job = CapabilityGraphCampaignJobInput.model_validate(
            inputs.job.model_dump(mode="json", by_alias=True)
        )
        trust_anchor = CloudProviderExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        prepared = preparation.prepared_action
        inputs.activation.resolve_for_dispatch(prepared.capability)
        expected_scope = CloudCampaignScopeBinding(
            campaignName=campaign.metadata.name,
            campaignDigest=campaign_manifest_digest(campaign),
            scope=campaign.spec.scope,
            allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
            allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
        )
        if (
            preparation.release != inputs.activation.activation_set.binding.release
            or preparation.campaign_scope != expected_scope
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
            raise CloudProviderObservationAdmissionError(
                "Cloud preparation and approved execution inputs differ"
            )
        permits = tuple(
            permit
            for permit in graph_store.permit_store.permits()
            if permit.run_id == inputs.expected_run_id
            and permit.request_id == prepared.request.request_id
        )
        if len(permits) != 1:
            raise CloudProviderObservationAdmissionError(
                "Cloud execution source lacks one exact consumed ActionPermit"
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
            raise CloudProviderObservationAdmissionError(
                "Cloud consumed ActionPermit differs from the prepared action"
            )
        receipts = tuple(
            receipt
            for receipt in graph_store.permit_store.approval_consumptions()
            if receipt.action_permit.permit_id == permit.permit_id
        )
        if len(receipts) != 1:
            raise CloudProviderObservationAdmissionError(
                "Cloud execution source lacks one exact approval consumption receipt"
            )
        approval_receipt = receipts[0]
        if (
            approval_receipt.action_permit != permit
            or approval_receipt.approval != job.approval
            or approval_receipt != build_action_approval_consumption_receipt(job.approval, permit)
        ):
            raise CloudProviderObservationAdmissionError(
                "Cloud approval receipt differs from the consumed action"
            )
        attestation_reference = _artifact_reference(
            inputs.attestation_reference,
            label="Cloud execution attestation",
        )
        attestation_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, attestation_reference),
            max_bytes=_MAX_ATTESTATION_BYTES,
            label="Cloud execution attestation",
            require_single_link=True,
        )
        bundle = CloudProviderExecutionBundle.model_validate(
            parse_strict_json_bytes(
                attestation_bytes,
                label="Cloud execution attestation",
                max_bytes=_MAX_ATTESTATION_BYTES,
                max_depth=32,
                max_nodes=20_000,
            )
        )
        verification = verify_cloud_provider_execution_bundle(
            bundle,
            trust_anchor=trust_anchor,
        )
        statement = bundle.statement
        response_reference = _artifact_reference(
            statement.response_receipt_reference,
            label="Cloud provider response receipt",
        )
        if response_reference == attestation_reference:
            raise CloudProviderObservationAdmissionError(
                "Cloud attestation and response receipt must be distinct evidence"
            )
        response_bytes = read_bounded_regular_bytes(
            _artifact_path(inputs.source_root, response_reference),
            max_bytes=_MAX_RECEIPT_BYTES,
            label="Cloud provider response receipt",
            require_single_link=True,
        )
        response_receipt = CloudProviderResponseReceipt.model_validate(
            parse_strict_json_bytes(
                response_bytes,
                label="Cloud provider response receipt",
                max_bytes=_MAX_RECEIPT_BYTES,
                max_depth=20,
                max_nodes=8_000,
            )
        )
        response_sha256 = sha256(response_bytes).hexdigest()
        _validate_cloud_execution_source(
            campaign=campaign,
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=approval_receipt,
            trust_anchor=trust_anchor,
            statement=statement,
            response_receipt=response_receipt,
            response_receipt_sha256=response_sha256,
        )
        attestation_sha256 = sha256(attestation_bytes).hexdigest()
        source_root_digest = _cloud_source_root_digest(
            attestation_sha256=attestation_sha256,
            response_receipt_sha256=response_sha256,
            trust_anchor_digest=verification.trust_anchor_digest,
            statement_sha256=verification.statement_sha256,
        )
        return VerifiedCloudProviderObservationSource(
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=approval_receipt,
            trust_anchor=trust_anchor,
            verification=verification,
            bundle=bundle,
            response_receipt=response_receipt,
            attestation_reference=attestation_reference,
            attestation_sha256=attestation_sha256,
            response_receipt_reference=response_reference,
            response_receipt_sha256=response_sha256,
            source_root_digest=source_root_digest,
        )
    except CloudProviderObservationAdmissionError:
        raise
    except Exception as exc:
        raise CloudProviderObservationAdmissionError(
            "sealed Cloud provider execution source authority is invalid"
        ) from exc


def _validate_cloud_execution_source(
    *,
    campaign: CampaignManifest,
    preparation: CloudReadOnlyInventoryPolicyPreparation,
    job: CapabilityGraphCampaignJobInput,
    permit: ActionPermit,
    approval_receipt: ActionApprovalConsumptionReceipt,
    trust_anchor: CloudProviderExecutionTrustAnchor,
    statement: CloudProviderExecutionStatement,
    response_receipt: CloudProviderResponseReceipt,
    response_receipt_sha256: str,
) -> None:
    prepared = preparation.prepared_action
    binding = trust_anchor.worker_binding
    worker = binding.worker_identity
    mtls = statement.worker_mtls_admission
    credential = statement.credential_use
    if (
        binding.capability != preparation.binding.capability
        or binding.capability_release != preparation.release
        or binding.worker_profile != preparation.binding.worker_profile
        or binding.provider_adapter != preparation.provider_adapter.reference()
        or binding.credential_audience != preparation.credential_lease.audience
        or mtls.policy_id != binding.worker_mtls_policy.policy_id
        or mtls.principal_subject != worker.principal_subject
        or mtls.certificate_spki_sha256 != worker.certificate_spki_sha256
        or mtls.execution_authority is not False
        or response_receipt.execution_id != statement.execution_id
        or statement.campaign_id != campaign.metadata.name
        or statement.campaign_digest != campaign_manifest_digest(campaign)
        or statement.run_id != permit.run_id
        or statement.preparation_id != preparation.preparation_id
        or statement.preparation_digest != preparation.preparation_digest
        or statement.provider_request != preparation.provider_request
        or statement.request_id != permit.request_id
        or statement.request_digest != permit.request_digest
        or statement.normalized_parameters_digest != permit.normalized_parameters_digest
        or statement.action_permit_id != permit.permit_id
        or statement.action_permit_digest != permit.permit_digest
        or statement.approval_receipt_id != approval_receipt.receipt_id
        or statement.approval_receipt_digest != approval_receipt.receipt_digest
        or credential.credential_lease != preparation.credential_lease
        or response_receipt.request_id != prepared.request.request_id
        or response_receipt.request_digest != prepared.request_digest
        or response_receipt.route_digest != preparation.provider_request.route_digest
        or response_receipt.operation is not preparation.operation
        or response_receipt.surface != preparation.surface.reference()
        or response_receipt.response_bytes > preparation.provider_request.budget.max_response_bytes
        or response_receipt.receipt_id != statement.response_receipt_id
        or response_receipt.receipt_digest != statement.response_receipt_digest
        or response_receipt_sha256 != statement.response_receipt_sha256
        or response_receipt.received_at != statement.finished_at
        or not (
            permit.consumed_at
            <= credential.broker_rechecked_at
            <= credential.materialized_at
            <= statement.started_at
            <= credential.used_at
            < statement.finished_at
            <= credential.discarded_at
            < min(permit.expires_at, preparation.credential_lease.expires_at)
        )
    ):
        raise CloudProviderObservationAdmissionError(
            "sealed Cloud provider execution statement differs from current authority"
        )


def _artifact_reference(value: str, *, label: str) -> str:
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError) as exc:
        raise CloudProviderObservationAdmissionError(f"{label} reference is invalid") from exc
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
        raise CloudProviderObservationAdmissionError(f"{label} reference is invalid")
    return path.as_posix()


def _artifact_path(root: Path, reference: str) -> Path:
    parts = PurePosixPath(reference).parts
    return Path(root).resolve().joinpath(*parts)


def _cloud_source_root_digest(
    *,
    attestation_sha256: str,
    response_receipt_sha256: str,
    trust_anchor_digest: str,
    statement_sha256: str,
) -> str:
    return graph_digest(
        "pajin.workflow.cloud-provider-observation-source-root/v1",
        {
            "attestationSha256": attestation_sha256,
            "responseReceiptSha256": response_receipt_sha256,
            "trustAnchorDigest": trust_anchor_digest,
            "statementSha256": statement_sha256,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def _require_admitted_event(
    *,
    event: GraphAdmissionEvent,
    proposal: ObservationProposal,
    graph: CloudGraphAdmissionBinding,
) -> None:
    lineage = proposal.lineage
    expected_nodes = sorted(
        [proposal.action, proposal.observation, *proposal.evidence_nodes],
        key=lambda item: item.node_id,
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
        or event.proposal_kind is not GraphProposalKind.OBSERVATION
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
        raise ValueError("Cloud Graph admission differs from its bounded Proposal")


__all__ = [
    "CLOUD_PROVIDER_OBSERVATION_ADMISSION_API_VERSION",
    "CLOUD_PROVIDER_OBSERVATION_PRODUCER_DIGEST",
    "CLOUD_PROVIDER_OBSERVATION_PRODUCER_ID",
    "CLOUD_PROVIDER_OBSERVATION_PRODUCER_VERSION",
    "CloudCredentialUseReceipt",
    "CloudGraphAdmissionBinding",
    "CloudProviderExecutionAttestor",
    "CloudProviderExecutionBundle",
    "CloudProviderExecutionKeyState",
    "CloudProviderExecutionStatement",
    "CloudProviderExecutionTrustAnchor",
    "CloudProviderExecutionVerification",
    "CloudProviderExecutionVerificationKey",
    "CloudProviderExecutionWorkerBinding",
    "CloudProviderObservationAdmission",
    "CloudProviderObservationAdmissionError",
    "CloudProviderObservationAdmissionGate",
    "CloudProviderObservationAdmissionPolicy",
    "CloudProviderObservationCandidate",
    "CloudProviderObservationSourceInputs",
    "CloudProviderResponseReceipt",
    "VerifiedCloudProviderObservationSource",
    "cloud_provider_execution_bundle_bytes",
    "cloud_provider_execution_public_key",
    "cloud_provider_observation_producer_registration",
    "cloud_provider_response_receipt_bytes",
    "load_verified_cloud_provider_observation_source",
    "verify_cloud_provider_execution_bundle",
]
