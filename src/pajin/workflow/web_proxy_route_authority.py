"""Deployment-signed inert proxy-route authority for WEB-002 controlled validation."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from typing import Literal, Protocol
from zoneinfo import ZoneInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
)
from pajin.benchmark.models import benchmark_digest, canonical_benchmark_json
from pajin.benchmark.scanner_baseline import ScannerBaselineMeasurementPlanAuthority
from pajin.benchmark.scanner_sarif import ZAPScannerRegistration
from pajin.benchmark.target_factory import (
    BenchmarkTargetCoordinate,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
    benchmark_target_coordinate,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetAttempt,
    BenchmarkTargetOperation,
    BenchmarkTargetOperationJournal,
    BenchmarkTargetOperationRecord,
    BenchmarkTargetRecoveryError,
)
from pajin.capabilities.activation import capability_normalized_parameters_digest
from pajin.capabilities.lifecycle import CapabilityLifecycleRegistry, CapabilityReleaseRef
from pajin.capabilities.web_measured_validation import (
    WEB_MEASURED_VALIDATION_REQUEST_UNITS,
    WEB_MEASURED_VALIDATION_TARGET,
    WebMeasuredValidationCapabilityBundle,
)
from pajin.domain.models import (
    CampaignManifest,
    CampaignMode,
    StrictModel,
    ToolRequest,
    ToolRiskTier,
    Weekday,
    WeeklyTestingWindow,
    campaign_manifest_digest,
)
from pajin.graph.approval import ActionApprovalAuthorization
from pajin.runtime.worker import NetworkMode
from pajin.tools.base import http_target_sha256
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    BooleanSQLiProbeTool,
)
from pajin.tools.gateway import canonical_tool_request_digest
from pajin.workflow.web_measured_case_authority import (
    WebMeasuredCaseAuthority,
    WebMeasuredCaseAuthorityRef,
    load_web_measured_case_authority,
)
from pajin.workflow.web_replay_benchmark import WebAPIBenchmarkGroundTruthProfile

WEB_PROXY_ROUTE_RUNTIME_POLICY_API_VERSION: Literal[
    "pajin.dev/web-proxy-route-runtime-policy/v1alpha1"
] = "pajin.dev/web-proxy-route-runtime-policy/v1alpha1"
WEB_PROXY_ROUTE_STATEMENT_API_VERSION: Literal["pajin.dev/web-proxy-route-statement/v1alpha1"] = (
    "pajin.dev/web-proxy-route-statement/v1alpha1"
)
WEB_PROXY_ROUTE_TRUST_ANCHOR_API_VERSION: Literal[
    "pajin.dev/web-proxy-route-trust-anchor/v1alpha1"
] = "pajin.dev/web-proxy-route-trust-anchor/v1alpha1"
WEB_PROXY_ROUTE_VERIFICATION_API_VERSION: Literal[
    "pajin.dev/web-proxy-route-verification/v1alpha1"
] = "pajin.dev/web-proxy-route-verification/v1alpha1"

_SIGNATURE_DOMAIN = b"pajin.web.proxy-route-signature/v1\0"
_MAX_ROUTE_BYTES = 8 * 1024 * 1024
_MAX_ROUTE_TTL = timedelta(minutes=5)
_ROUTE_FALSE_FIELDS = (
    "route_materialized",
    "route_consumed",
    "proxy_attached",
    "worker_attached",
    "proxy_detached",
    "target_cleanup_observed",
    "provider_execution_authorized",
    "network_access_authorized",
    "worker_selected",
    "measurement_observed",
    "graph_write_authorized",
    "finding_authorized",
    "benchmark_validation_floor_satisfied",
    "finding_projection_authorized",
    "product_activation_authorized",
    "report_delivery_authorized",
    "execution_authorized",
)
_VERIFICATION_FALSE_FIELDS = (
    "route_materialized",
    "route_consumed",
    "proxy_attached",
    "worker_attached",
    "proxy_detached",
    "target_cleanup_observed",
    "provider_execution_authorized",
    "network_access_authorized",
    "worker_selected",
    "measurement_observed",
    "graph_write_authorized",
    "finding_authorized",
    "benchmark_validation_floor_satisfied",
    "finding_projection_authorized",
    "product_activation_authorized",
    "report_delivery_authorized",
    "execution_authorized",
)


class WebProxyRouteAuthorityError(RuntimeError):
    """Raised when a WEB-002 proxy route is untrusted, stale, or substituted."""


class WebProxyRouteTargetCleanupInvalidated(WebProxyRouteAuthorityError):
    """Raised only when an otherwise exact live route was invalidated by Target cleanup."""


class WebProxyRouteApprovedAuthorizationStore(Protocol):
    """Read-only durable lookup for one atomically consumed T2 approval and Permit."""

    def approved_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ActionApprovalAuthorization | None: ...


class WebProxyRouteSigningKeyState(StrEnum):
    """Deployment-owned route signing key lifecycle."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class WebProxyRouteVerificationKey(_FrozenStrictModel):
    """One out-of-band Ed25519 route-signing public key."""

    key_id: str = Field(alias="keyId", min_length=1, max_length=200)
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: WebProxyRouteSigningKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @field_validator("not_before", "not_after", "revoked_at")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _aware_utc(value, label="route key time")

    @model_validator(mode="after")
    def bind_key_lifecycle(self) -> WebProxyRouteVerificationKey:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="WEB proxy-route public key",
        )
        if self.not_after is not None and self.not_after <= self.not_before:
            raise ValueError("WEB proxy-route key validity window is empty")
        if self.state is WebProxyRouteSigningKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired WEB proxy-route key requires notAfter")
        if self.state is WebProxyRouteSigningKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked WEB proxy-route key requires revokedAt")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked WEB proxy-route key cannot carry revokedAt")
        return self


class WebProxyRouteTrustAnchor(_FrozenStrictModel):
    """Exact deployment and keyring allowed to sign controlled routes."""

    api_version: Literal["pajin.dev/web-proxy-route-trust-anchor/v1alpha1"] = Field(
        default=WEB_PROXY_ROUTE_TRUST_ANCHOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebProxyRouteTrustAnchor"] = "WebProxyRouteTrustAnchor"
    trust_domain: str = Field(alias="trustDomain", min_length=1, max_length=200)
    issuer: str = Field(min_length=1, max_length=200)
    deployment_id: str = Field(alias="deploymentId", min_length=1, max_length=200)
    keys: tuple[WebProxyRouteVerificationKey, ...] = Field(min_length=1, max_length=16)
    revoked_route_digests: tuple[str, ...] = Field(
        default=(),
        alias="revokedRouteDigests",
        max_length=10_000,
    )
    anchor_digest: str = Field(default="", alias="anchorDigest", max_length=64)

    @field_validator("revoked_route_digests")
    @classmethod
    def require_canonical_revocations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            len(item) != 64 or any(character not in "0123456789abcdef" for character in item)
            for item in value
        ):
            raise ValueError("WEB proxy-route revocations must be unique sorted SHA-256 values")
        return value

    @model_validator(mode="after")
    def bind_anchor(self) -> WebProxyRouteTrustAnchor:
        key_ids = [item.key_id for item in self.keys]
        if key_ids != sorted(set(key_ids)):
            raise ValueError("WEB proxy-route Trust Anchor keys must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"anchor_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-proxy-route-trust-anchor/v1",
            material,
            max_bytes=512 * 1024,
        )
        if self.anchor_digest and self.anchor_digest != digest:
            raise ValueError("WEB proxy-route Trust Anchor Digest differs")
        object.__setattr__(self, "anchor_digest", digest)
        return self


class WebProxyRouteRuntimePolicy(_FrozenStrictModel):
    """Deployment identity and proxy-only topology, without Docker route authority."""

    api_version: Literal["pajin.dev/web-proxy-route-runtime-policy/v1alpha1"] = Field(
        default=WEB_PROXY_ROUTE_RUNTIME_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebProxyRouteRuntimePolicy"] = "WebProxyRouteRuntimePolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=90)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    deployment_id: str = Field(alias="deploymentId", min_length=1, max_length=200)
    claim_ledger_identity_digest: str = Field(
        alias="claimLedgerIdentityDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    gateway_policy_id: str = Field(alias="gatewayPolicyId", min_length=1, max_length=200)
    gateway_policy_version: str = Field(alias="gatewayPolicyVersion", min_length=1, max_length=200)
    gateway_policy_digest: str = Field(
        alias="gatewayPolicyDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    worker_backend_id: str = Field(alias="workerBackendId", min_length=1, max_length=200)
    worker_backend_version: str = Field(alias="workerBackendVersion", min_length=1, max_length=200)
    worker_backend_digest: str = Field(
        alias="workerBackendDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    worker_image: Literal["pajin-worker:dev"] = Field(
        default="pajin-worker:dev", alias="workerImage"
    )
    worker_image_id: str = Field(
        alias="workerImageId",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    proxy_image: Literal["pajin-egress-proxy:dev"] = Field(
        default="pajin-egress-proxy:dev", alias="proxyImage"
    )
    proxy_image_id: str = Field(
        alias="proxyImageId",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    worker_action: Literal["bug-bounty-sqli-probe"] = Field(
        default="bug-bounty-sqli-probe", alias="workerAction"
    )
    worker_network_mode: Literal["egress-proxy"] = Field(
        default=NetworkMode.EGRESS_PROXY.value,
        alias="workerNetworkMode",
    )
    proxy_alias: Literal["egress-proxy"] = Field(default="egress-proxy", alias="proxyAlias")
    target_service_alias: Literal["target"] = Field(default="target", alias="targetServiceAlias")
    target_scheme: Literal["http"] = Field(default="http", alias="targetScheme")
    target_port: Literal[8080] = Field(default=8080, alias="targetPort")
    target_path: Literal["/v1/users/lookup"] = Field(default="/v1/users/lookup", alias="targetPath")
    allowed_method: Literal["GET"] = Field(default="GET", alias="allowedMethod")
    request_budget: Literal[3] = Field(
        default=3,
        alias="requestBudget",
    )
    max_response_bytes_per_request: Literal[32768] = Field(
        default=32768,
        alias="maxResponseBytesPerRequest",
    )
    caller_authored_payload_allowed: Literal[False] = Field(
        default=False, alias="callerAuthoredPayloadAllowed"
    )
    connect_allowed: Literal[False] = Field(default=False, alias="connectAllowed")
    dns_allowed: Literal[False] = Field(default=False, alias="dnsAllowed")
    direct_worker_target_network_attachment_allowed: Literal[False] = Field(
        default=False, alias="directWorkerTargetNetworkAttachmentAllowed"
    )
    host_port_publication_allowed: Literal[False] = Field(
        default=False, alias="hostPortPublicationAllowed"
    )
    registered_only: Literal[True] = Field(default=True, alias="registeredOnly")
    route_materialized: Literal[False] = Field(default=False, alias="routeMaterialized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "target_port",
        "request_budget",
        "max_response_bytes_per_request",
        mode="before",
    )
    @classmethod
    def require_literal_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("WEB proxy-route runtime numbers must be literal integers")
        return value

    @field_validator("registered_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB proxy-route runtime registration marker must be true")
        return value

    @field_validator(
        "caller_authored_payload_allowed",
        "connect_allowed",
        "dns_allowed",
        "direct_worker_target_network_attachment_allowed",
        "host_port_publication_allowed",
        "route_materialized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB proxy-route runtime authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> WebProxyRouteRuntimePolicy:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-proxy-route-runtime-policy/v1",
            material,
            max_bytes=512 * 1024,
        )
        policy_id = f"web-proxy-route-runtime_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("WEB proxy-route runtime policy Digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("WEB proxy-route runtime policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class WebProxyRouteTargetBinding(_FrozenStrictModel):
    """Signed live operation and isolation facts; no raw Docker network name."""

    adapter_id: str = Field(alias="adapterId", min_length=1, max_length=200)
    adapter_version: str = Field(alias="adapterVersion", min_length=1, max_length=200)
    adapter_digest: str = Field(alias="adapterDigest", pattern=r"^[a-f0-9]{64}$")
    target_profile_id: Literal["bug-bounty.api.boolean-sqli-lab"] = Field(alias="targetProfileId")
    target_profile_version: Literal["1.0.0"] = Field(alias="targetProfileVersion")
    target_factory_digest: str = Field(alias="targetFactoryDigest", pattern=r"^[a-f0-9]{64}$")
    target_image_id: str = Field(alias="targetImageId", pattern=r"^sha256:[a-f0-9]{64}$")
    benchmark_worker_image_id: str = Field(
        alias="benchmarkWorkerImageId",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    coordinate_id: str = Field(alias="coordinateId", min_length=1, max_length=110)
    coordinate_digest: str = Field(alias="coordinateDigest", pattern=r"^[a-f0-9]{64}$")
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=110)
    attempt_digest: str = Field(alias="attemptDigest", pattern=r"^[a-f0-9]{64}$")
    isolation_operation_id: str = Field(alias="isolationOperationId", min_length=1, max_length=110)
    isolation_operation_digest: str = Field(
        alias="isolationOperationDigest", pattern=r"^[a-f0-9]{64}$"
    )
    execution_operation_id: str = Field(alias="executionOperationId", min_length=1, max_length=110)
    execution_operation_digest: str = Field(
        alias="executionOperationDigest", pattern=r"^[a-f0-9]{64}$"
    )
    active_fence: int = Field(alias="activeFence", ge=1, le=2**63 - 1)
    isolation_receipt_id: str = Field(alias="isolationReceiptId", min_length=1, max_length=110)
    isolation_receipt_digest: str = Field(alias="isolationReceiptDigest", pattern=r"^[a-f0-9]{64}$")
    isolation_provider_evidence_digest: str = Field(
        alias="isolationProviderEvidenceDigest", pattern=r"^[a-f0-9]{64}$"
    )
    environment_id: str = Field(alias="environmentId", min_length=1, max_length=110)
    isolation_id: str = Field(alias="isolationId", min_length=1, max_length=110)
    target_container_id: str = Field(alias="targetContainerId", pattern=r"^[a-f0-9]{64}$")
    target_network_id: str = Field(alias="targetNetworkId", pattern=r"^[a-f0-9]{64}$")
    target_network_internal: Literal[True] = Field(default=True, alias="targetNetworkInternal")
    published_port_count: Literal[0] = Field(default=0, alias="publishedPortCount")
    target_network_container_count: Literal[1] = Field(
        default=1, alias="targetNetworkContainerCount"
    )
    target_healthy: Literal[True] = Field(default=True, alias="targetHealthy")

    @field_validator(
        "active_fence", "published_port_count", "target_network_container_count", mode="before"
    )
    @classmethod
    def reject_boolean_numbers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("WEB proxy-route Target numbers must be literal integers")
        return value

    @field_validator("target_network_internal", "target_healthy", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB proxy-route Target isolation markers must be true")
        return value


class WebProxyRouteStatement(_FrozenStrictModel):
    """Immutable signed route authority; all materialization state remains false."""

    api_version: Literal["pajin.dev/web-proxy-route-statement/v1alpha1"] = Field(
        default=WEB_PROXY_ROUTE_STATEMENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebProxyRouteStatement"] = "WebProxyRouteStatement"
    route_id: str = Field(default="", alias="routeId", max_length=90)
    route_digest: str = Field(default="", alias="routeDigest", max_length=64)
    purpose: Literal["controlled-validation"] = "controlled-validation"
    route_nonce: str = Field(alias="routeNonce", pattern=r"^[a-f0-9]{32}$")
    trust_domain: str = Field(alias="trustDomain", min_length=1, max_length=200)
    issuer: str = Field(min_length=1, max_length=200)
    deployment_id: str = Field(alias="deploymentId", min_length=1, max_length=200)
    trust_anchor_digest: str = Field(alias="trustAnchorDigest", pattern=r"^[a-f0-9]{64}$")
    signing_key_id: str = Field(alias="signingKeyId", min_length=1, max_length=200)
    measured_case: WebMeasuredCaseAuthorityRef = Field(alias="measuredCase")
    runtime_policy: WebProxyRouteRuntimePolicy = Field(alias="runtimePolicy")
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    campaign_digest: str = Field(alias="campaignDigest", pattern=r"^[a-f0-9]{64}$")
    scope_digest: str = Field(alias="scopeDigest", pattern=r"^[a-f0-9]{64}$")
    envelope_id: str = Field(alias="envelopeId", min_length=1, max_length=100)
    envelope_digest: str = Field(alias="envelopeDigest", pattern=r"^[a-f0-9]{64}$")
    approval_id: str = Field(alias="approvalId", min_length=1, max_length=110)
    approval_digest: str = Field(alias="approvalDigest", pattern=r"^[a-f0-9]{64}$")
    approval_receipt_id: str = Field(alias="approvalReceiptId", min_length=1, max_length=110)
    approval_receipt_digest: str = Field(
        alias="approvalReceiptDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    permit_id: str = Field(alias="permitId", min_length=1, max_length=100)
    permit_digest: str = Field(alias="permitDigest", pattern=r"^[a-f0-9]{64}$")
    dispatch_id: str = Field(alias="dispatchId", min_length=1, max_length=100)
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: str = Field(alias="requestDigest", pattern=r"^[a-f0-9]{64}$")
    request_agent_id: str = Field(alias="requestAgentId", min_length=1, max_length=200)
    target_digest: str = Field(alias="targetDigest", pattern=r"^[a-f0-9]{64}$")
    target: WebProxyRouteTargetBinding
    worker_proxy_network_slot_digest: str = Field(
        alias="workerProxyNetworkSlotDigest", pattern=r"^[a-f0-9]{64}$"
    )
    consumption_slot_digest: str = Field(alias="consumptionSlotDigest", pattern=r"^[a-f0-9]{64}$")
    fence_invalidation_scope_digest: str = Field(
        alias="fenceInvalidationScopeDigest", pattern=r"^[a-f0-9]{64}$"
    )
    issued_at: datetime = Field(alias="issuedAt")
    not_before: datetime = Field(alias="notBefore")
    expires_at: datetime = Field(alias="expiresAt")
    single_use_required: Literal[True] = Field(default=True, alias="singleUseRequired")
    cleanup_invalidation_required: Literal[True] = Field(
        default=True, alias="cleanupInvalidationRequired"
    )
    proxy_only_bridge_required: Literal[True] = Field(default=True, alias="proxyOnlyBridgeRequired")
    route_materialized: Literal[False] = Field(default=False, alias="routeMaterialized")
    route_consumed: Literal[False] = Field(default=False, alias="routeConsumed")
    proxy_attached: Literal[False] = Field(default=False, alias="proxyAttached")
    worker_attached: Literal[False] = Field(default=False, alias="workerAttached")
    proxy_detached: Literal[False] = Field(default=False, alias="proxyDetached")
    target_cleanup_observed: Literal[False] = Field(default=False, alias="targetCleanupObserved")
    provider_execution_authorized: Literal[False] = Field(
        default=False, alias="providerExecutionAuthorized"
    )
    network_access_authorized: Literal[False] = Field(
        default=False, alias="networkAccessAuthorized"
    )
    worker_selected: Literal[False] = Field(default=False, alias="workerSelected")
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    graph_write_authorized: Literal[False] = Field(default=False, alias="graphWriteAuthorized")
    finding_authorized: Literal[False] = Field(default=False, alias="findingAuthorized")
    benchmark_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="benchmarkValidationFloorSatisfied",
    )
    finding_projection_authorized: Literal[False] = Field(
        default=False,
        alias="findingProjectionAuthorized",
    )
    product_activation_authorized: Literal[False] = Field(
        default=False,
        alias="productActivationAuthorized",
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("issued_at", "not_before", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="WEB proxy-route time")

    @field_validator(
        "single_use_required",
        "cleanup_invalidation_required",
        "proxy_only_bridge_required",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB proxy-route lifecycle requirements must be true")
        return value

    @field_validator(*_ROUTE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB proxy-route materialization markers must be false")
        return value

    @model_validator(mode="after")
    def bind_route_identity(self) -> WebProxyRouteStatement:
        if (
            not self.issued_at <= self.not_before < self.expires_at
            or self.expires_at - self.not_before > _MAX_ROUTE_TTL
            or self.runtime_policy.deployment_id != self.deployment_id
        ):
            raise ValueError("WEB proxy-route validity or deployment differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"route_id", "route_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-proxy-route-statement/v1",
            material,
            max_bytes=_MAX_ROUTE_BYTES,
        )
        route_id = f"web-proxy-route_{digest}"
        if self.route_digest and self.route_digest != digest:
            raise ValueError("WEB proxy-route statement Digest differs")
        if self.route_id and self.route_id != route_id:
            raise ValueError("WEB proxy-route statement ID differs")
        object.__setattr__(self, "route_digest", digest)
        object.__setattr__(self, "route_id", route_id)
        return self


class SignedWebProxyRoute(_FrozenStrictModel):
    """Detached deployment signature over one exact route statement."""

    key_id: str = Field(alias="keyId", min_length=1, max_length=200)
    statement: WebProxyRouteStatement
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def bind_signature(self) -> SignedWebProxyRoute:
        if self.key_id != self.statement.signing_key_id:
            raise ValueError("WEB proxy-route signature key differs from statement")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="WEB proxy-route signature",
        )
        return self


class WebProxyRouteBundle(_FrozenStrictModel):
    """Transport bundle for one signed inert route."""

    route: SignedWebProxyRoute

    @property
    def digest(self) -> str:
        return benchmark_digest(
            "pajin.workflow.web-proxy-route-bundle/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_ROUTE_BYTES,
        )


class WebProxyRouteVerification(_FrozenStrictModel):
    """Read-only verification result; it is not a materialization receipt."""

    api_version: Literal["pajin.dev/web-proxy-route-verification/v1alpha1"] = Field(
        default=WEB_PROXY_ROUTE_VERIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebProxyRouteVerification"] = "WebProxyRouteVerification"
    verification_id: str = Field(default="", alias="verificationId", max_length=110)
    verification_digest: str = Field(default="", alias="verificationDigest", max_length=64)
    route_id: str = Field(alias="routeId", min_length=1, max_length=90)
    route_digest: str = Field(alias="routeDigest", pattern=r"^[a-f0-9]{64}$")
    bundle_digest: str = Field(alias="bundleDigest", pattern=r"^[a-f0-9]{64}$")
    signature_verified: Literal[True] = Field(default=True, alias="signatureVerified")
    deployment_identity_verified: Literal[True] = Field(
        default=True, alias="deploymentIdentityVerified"
    )
    target_operation_identity_verified: Literal[True] = Field(
        default=True, alias="targetOperationIdentityVerified"
    )
    current_fence_verified: Literal[True] = Field(default=True, alias="currentFenceVerified")
    freshness_verified: Literal[True] = Field(default=True, alias="freshnessVerified")
    target_isolation_verified: Literal[True] = Field(default=True, alias="targetIsolationVerified")
    approval_consumption_verified: Literal[True] = Field(
        default=True,
        alias="approvalConsumptionVerified",
    )
    target_journal_head_verified: Literal[True] = Field(
        default=True,
        alias="targetJournalHeadVerified",
    )
    proxy_only_bridge_required: Literal[True] = Field(default=True, alias="proxyOnlyBridgeRequired")
    single_use_required: Literal[True] = Field(default=True, alias="singleUseRequired")
    cleanup_invalidation_required: Literal[True] = Field(
        default=True, alias="cleanupInvalidationRequired"
    )
    route_materialized: Literal[False] = Field(default=False, alias="routeMaterialized")
    route_consumed: Literal[False] = Field(default=False, alias="routeConsumed")
    proxy_attached: Literal[False] = Field(default=False, alias="proxyAttached")
    worker_attached: Literal[False] = Field(default=False, alias="workerAttached")
    proxy_detached: Literal[False] = Field(default=False, alias="proxyDetached")
    target_cleanup_observed: Literal[False] = Field(default=False, alias="targetCleanupObserved")
    provider_execution_authorized: Literal[False] = Field(
        default=False, alias="providerExecutionAuthorized"
    )
    network_access_authorized: Literal[False] = Field(
        default=False, alias="networkAccessAuthorized"
    )
    worker_selected: Literal[False] = Field(default=False, alias="workerSelected")
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    graph_write_authorized: Literal[False] = Field(default=False, alias="graphWriteAuthorized")
    finding_authorized: Literal[False] = Field(default=False, alias="findingAuthorized")
    benchmark_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="benchmarkValidationFloorSatisfied",
    )
    finding_projection_authorized: Literal[False] = Field(
        default=False,
        alias="findingProjectionAuthorized",
    )
    product_activation_authorized: Literal[False] = Field(
        default=False,
        alias="productActivationAuthorized",
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "signature_verified",
        "deployment_identity_verified",
        "target_operation_identity_verified",
        "current_fence_verified",
        "freshness_verified",
        "target_isolation_verified",
        "approval_consumption_verified",
        "target_journal_head_verified",
        "proxy_only_bridge_required",
        "single_use_required",
        "cleanup_invalidation_required",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB proxy-route verification markers must be true")
        return value

    @field_validator(*_VERIFICATION_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB proxy-route verification cannot claim materialization")
        return value

    @model_validator(mode="after")
    def bind_verification_identity(self) -> WebProxyRouteVerification:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verification_id", "verification_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.web-proxy-route-verification/v1",
            material,
            max_bytes=512 * 1024,
        )
        verification_id = f"web-proxy-route-verification_{digest}"
        if self.verification_digest and self.verification_digest != digest:
            raise ValueError("WEB proxy-route verification Digest differs")
        if self.verification_id and self.verification_id != verification_id:
            raise ValueError("WEB proxy-route verification ID differs")
        object.__setattr__(self, "verification_digest", digest)
        object.__setattr__(self, "verification_id", verification_id)
        return self


@dataclass(frozen=True, slots=True)
class WebProxyRouteLiveAuthorityContext:
    """Host-owned live inputs required to verify one route immediately before use."""

    trust_anchor: WebProxyRouteTrustAnchor
    measured_case: WebMeasuredCaseAuthority
    capability_bundle: WebMeasuredValidationCapabilityBundle
    capability_lifecycle: CapabilityLifecycleRegistry
    capability_release: CapabilityReleaseRef
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile
    scanner_plan: ScannerBaselineMeasurementPlanAuthority
    scanner_registration: ZAPScannerRegistration
    runtime_policy: WebProxyRouteRuntimePolicy
    target_profile: DockerBugBountyTargetProfile
    target_journal: BenchmarkTargetOperationJournal
    target_attempt_id: str
    isolation_evidence: DockerBenchmarkProviderEvidence
    campaign: CampaignManifest
    approval_store: WebProxyRouteApprovedAuthorizationStore
    approval_id: str
    permit_id: str
    request: ToolRequest

    def verify(
        self,
        bundle: WebProxyRouteBundle,
        *,
        evaluated_at: datetime,
    ) -> WebProxyRouteVerification:
        if type(self) is not WebProxyRouteLiveAuthorityContext:
            raise WebProxyRouteAuthorityError(
                "WEB proxy-route live authority context requires its exact type"
            )
        return verify_web_proxy_route_authority(
            bundle,
            trust_anchor=self.trust_anchor,
            measured_case=self.measured_case,
            capability_bundle=self.capability_bundle,
            capability_lifecycle=self.capability_lifecycle,
            capability_release=self.capability_release,
            private_ground_truth_profile=self.private_ground_truth_profile,
            scanner_plan=self.scanner_plan,
            scanner_registration=self.scanner_registration,
            runtime_policy=self.runtime_policy,
            target_profile=self.target_profile,
            target_journal=self.target_journal,
            target_attempt_id=self.target_attempt_id,
            isolation_evidence=self.isolation_evidence,
            campaign=self.campaign,
            approval_store=self.approval_store,
            approval_id=self.approval_id,
            permit_id=self.permit_id,
            request=self.request,
            evaluated_at=evaluated_at,
        )

    def verify_cleanup_invalidated_history(
        self,
        bundle: WebProxyRouteBundle,
        *,
        evaluated_at: datetime,
    ) -> None:
        """Verify one terminal cleanup denial without reviving live route authority."""

        if type(self) is not WebProxyRouteLiveAuthorityContext:
            raise WebProxyRouteAuthorityError(
                "historical WEB proxy-route context requires its exact type"
            )
        verify_cleanup_invalidated_web_proxy_route_history(
            bundle,
            trust_anchor=self.trust_anchor,
            measured_case=self.measured_case,
            capability_bundle=self.capability_bundle,
            capability_lifecycle=self.capability_lifecycle,
            capability_release=self.capability_release,
            private_ground_truth_profile=self.private_ground_truth_profile,
            scanner_plan=self.scanner_plan,
            scanner_registration=self.scanner_registration,
            runtime_policy=self.runtime_policy,
            target_profile=self.target_profile,
            target_journal=self.target_journal,
            target_attempt_id=self.target_attempt_id,
            isolation_evidence=self.isolation_evidence,
            campaign=self.campaign,
            approval_store=self.approval_store,
            approval_id=self.approval_id,
            permit_id=self.permit_id,
            request=self.request,
            evaluated_at=evaluated_at,
        )


@dataclass(frozen=True, slots=True)
class WebProxyRouteAuthoritySigner:
    """Deployment-only signer; private bytes never enter an artifact."""

    key: WebProxyRouteVerificationKey
    private_key: Ed25519PrivateKey
    trust_anchor: WebProxyRouteTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        key: WebProxyRouteVerificationKey,
        private_key: bytes,
        trust_anchor: WebProxyRouteTrustAnchor,
    ) -> WebProxyRouteAuthoritySigner:
        if len(private_key) != 32:
            raise ValueError("WEB proxy-route Ed25519 private key must contain 32 bytes")
        signer = cls(
            key=key,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )
        signer._validate_identity()
        return signer

    def _validate_identity(self) -> None:
        registered = next((item for item in self.trust_anchor.keys if item == self.key), None)
        actual = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            self.key.public_key_base64url,
            expected_length=32,
            label="WEB proxy-route public key",
        )
        if registered is None or actual != expected:
            raise ValueError("WEB proxy-route signer differs from Trust Anchor")

    def issue(
        self,
        *,
        measured_case: WebMeasuredCaseAuthority,
        capability_bundle: WebMeasuredValidationCapabilityBundle,
        capability_lifecycle: CapabilityLifecycleRegistry,
        capability_release: CapabilityReleaseRef,
        private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
        scanner_plan: ScannerBaselineMeasurementPlanAuthority,
        scanner_registration: ZAPScannerRegistration,
        runtime_policy: WebProxyRouteRuntimePolicy,
        target_profile: DockerBugBountyTargetProfile,
        target_journal: BenchmarkTargetOperationJournal,
        target_attempt_id: str,
        isolation_evidence: DockerBenchmarkProviderEvidence,
        campaign: CampaignManifest,
        approval_store: WebProxyRouteApprovedAuthorizationStore,
        approval_id: str,
        permit_id: str,
        request: ToolRequest,
        route_nonce: str,
        issued_at: datetime,
        not_before: datetime,
        expires_at: datetime,
    ) -> WebProxyRouteBundle:
        """Issue an inert route from durable approval and Target journal authority."""

        try:
            self._validate_identity()
            if self.key.state is not WebProxyRouteSigningKeyState.ACTIVE:
                raise WebProxyRouteAuthorityError("WEB proxy-route signer key is not active")
            statement = _build_route_statement(
                trust_anchor=self.trust_anchor,
                signing_key=self.key,
                measured_case=measured_case,
                capability_bundle=capability_bundle,
                capability_lifecycle=capability_lifecycle,
                capability_release=capability_release,
                private_ground_truth_profile=private_ground_truth_profile,
                scanner_plan=scanner_plan,
                scanner_registration=scanner_registration,
                runtime_policy=runtime_policy,
                target_profile=target_profile,
                target_journal=target_journal,
                target_attempt_id=target_attempt_id,
                isolation_evidence=isolation_evidence,
                campaign=campaign,
                approval_store=approval_store,
                approval_id=approval_id,
                permit_id=permit_id,
                request=request,
                route_nonce=route_nonce,
                issued_at=issued_at,
                not_before=not_before,
                expires_at=expires_at,
            )
            _require_key_usable(self.key, at=statement.issued_at)
            signature = self.private_key.sign(_SIGNATURE_DOMAIN + _statement_bytes(statement))
            return WebProxyRouteBundle(
                route=SignedWebProxyRoute(
                    keyId=self.key.key_id,
                    statement=statement,
                    signatureBase64url=_base64url_encode(signature),
                )
            )
        except WebProxyRouteAuthorityError:
            raise
        except (AttributeError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise WebProxyRouteAuthorityError("WEB proxy-route issuance failed closed") from exc


def registered_web_proxy_route_runtime_policy(
    *,
    deployment_id: str,
    gateway_policy_id: str,
    gateway_policy_version: str,
    claim_ledger_identity_digest: str,
    gateway_policy_digest: str,
    worker_backend_id: str,
    worker_backend_version: str,
    worker_backend_digest: str,
    worker_image_id: str,
    proxy_image_id: str,
) -> WebProxyRouteRuntimePolicy:
    """Register immutable deployment identities without selecting or starting a Worker."""

    return WebProxyRouteRuntimePolicy(
        deploymentId=deployment_id,
        gatewayPolicyId=gateway_policy_id,
        gatewayPolicyVersion=gateway_policy_version,
        gatewayPolicyDigest=gateway_policy_digest,
        claimLedgerIdentityDigest=claim_ledger_identity_digest,
        workerBackendId=worker_backend_id,
        workerBackendVersion=worker_backend_version,
        workerBackendDigest=worker_backend_digest,
        workerImageId=worker_image_id,
        proxyImageId=proxy_image_id,
    )


def web_proxy_route_public_key_base64url(private_key: bytes) -> str:
    """Derive the canonical public key string for an out-of-band seed."""

    if len(private_key) != 32:
        raise ValueError("WEB proxy-route Ed25519 private key must contain 32 bytes")
    public = (
        Ed25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    return _base64url_encode(public)


def verify_web_proxy_route_authority(
    bundle: WebProxyRouteBundle,
    *,
    trust_anchor: WebProxyRouteTrustAnchor,
    measured_case: WebMeasuredCaseAuthority,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    capability_lifecycle: CapabilityLifecycleRegistry,
    capability_release: CapabilityReleaseRef,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
    runtime_policy: WebProxyRouteRuntimePolicy,
    target_profile: DockerBugBountyTargetProfile,
    target_journal: BenchmarkTargetOperationJournal,
    target_attempt_id: str,
    isolation_evidence: DockerBenchmarkProviderEvidence,
    campaign: CampaignManifest,
    approval_store: WebProxyRouteApprovedAuthorizationStore,
    approval_id: str,
    permit_id: str,
    request: ToolRequest,
    evaluated_at: datetime,
) -> WebProxyRouteVerification:
    """Verify a current route without consuming or materializing it."""

    try:
        canonical_bundle = WebProxyRouteBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        anchor = WebProxyRouteTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        statement = canonical_bundle.route.statement
        now = _aware_utc(evaluated_at, label="WEB proxy-route evaluation time")
        key = next(item for item in anchor.keys if item.key_id == canonical_bundle.route.key_id)
        _require_key_usable(key, at=now)
        if (
            statement.trust_anchor_digest != anchor.anchor_digest
            or statement.trust_domain != anchor.trust_domain
            or statement.issuer != anchor.issuer
            or statement.deployment_id != anchor.deployment_id
            or statement.route_digest in anchor.revoked_route_digests
            or not statement.not_before <= now < statement.expires_at
        ):
            raise ValueError("WEB proxy-route Trust Anchor, revocation, or freshness differs")
        public_key = Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="WEB proxy-route public key",
            )
        )
        public_key.verify(
            _base64url_decode(
                canonical_bundle.route.signature_base64url,
                expected_length=64,
                label="WEB proxy-route signature",
            ),
            _SIGNATURE_DOMAIN + _statement_bytes(statement),
        )

        def expected_statement(
            *,
            target_context: _RouteTargetJournalContext | None = None,
        ) -> WebProxyRouteStatement:
            return _build_route_statement(
                trust_anchor=anchor,
                signing_key=key,
                measured_case=measured_case,
                capability_bundle=capability_bundle,
                capability_lifecycle=capability_lifecycle,
                capability_release=capability_release,
                private_ground_truth_profile=private_ground_truth_profile,
                scanner_plan=scanner_plan,
                scanner_registration=scanner_registration,
                runtime_policy=runtime_policy,
                target_profile=target_profile,
                target_journal=target_journal,
                target_attempt_id=target_attempt_id,
                isolation_evidence=isolation_evidence,
                campaign=campaign,
                approval_store=approval_store,
                approval_id=approval_id,
                permit_id=permit_id,
                request=request,
                route_nonce=statement.route_nonce,
                issued_at=statement.issued_at,
                not_before=statement.not_before,
                expires_at=statement.expires_at,
                _target_context=target_context,
            )

        try:
            expected = expected_statement()
        except BenchmarkTargetRecoveryError as live_target_error:
            completed_context = _completed_cleanup_before_route_target_context(
                target_journal,
                attempt_id=target_attempt_id,
                execution_operation_id=statement.target.execution_operation_id,
                issued_at=statement.issued_at,
                evaluated_at=now,
            )
            expected = expected_statement(target_context=completed_context)
            if statement != expected:
                raise ValueError(
                    "WEB proxy-route differs from its exact pre-cleanup context"
                ) from live_target_error
            raise WebProxyRouteTargetCleanupInvalidated(
                "WEB proxy-route was invalidated by completed Target cleanup"
            ) from live_target_error
        if statement != expected:
            raise ValueError("WEB proxy-route differs from current exact context")
        return WebProxyRouteVerification(
            routeId=statement.route_id,
            routeDigest=statement.route_digest,
            bundleDigest=canonical_bundle.digest,
        )
    except WebProxyRouteAuthorityError:
        raise
    except (
        AttributeError,
        InvalidSignature,
        RuntimeError,
        StopIteration,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WebProxyRouteAuthorityError("WEB proxy-route verification failed closed") from exc


def verify_cleanup_invalidated_web_proxy_route_history(
    bundle: WebProxyRouteBundle,
    *,
    trust_anchor: WebProxyRouteTrustAnchor,
    measured_case: WebMeasuredCaseAuthority,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    capability_lifecycle: CapabilityLifecycleRegistry,
    capability_release: CapabilityReleaseRef,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
    runtime_policy: WebProxyRouteRuntimePolicy,
    target_profile: DockerBugBountyTargetProfile,
    target_journal: BenchmarkTargetOperationJournal,
    target_attempt_id: str,
    isolation_evidence: DockerBenchmarkProviderEvidence,
    campaign: CampaignManifest,
    approval_store: WebProxyRouteApprovedAuthorizationStore,
    approval_id: str,
    permit_id: str,
    request: ToolRequest,
    evaluated_at: datetime,
) -> None:
    """Verify signed cleanup-invalidated history without granting route authority."""

    try:
        if (
            type(bundle) is not WebProxyRouteBundle
            or type(trust_anchor) is not WebProxyRouteTrustAnchor
        ):
            raise TypeError("historical WEB proxy-route verification requires exact artifact types")
        canonical_bundle = WebProxyRouteBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        anchor = WebProxyRouteTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        if canonical_bundle != bundle or anchor != trust_anchor:
            raise ValueError("historical WEB proxy-route artifacts are not canonical")
        statement = canonical_bundle.route.statement
        denied_at = _aware_utc(
            evaluated_at,
            label="historical WEB proxy-route denial time",
        )
        key = next(item for item in anchor.keys if item.key_id == canonical_bundle.route.key_id)
        _require_key_usable(key, at=denied_at)
        if (
            statement.trust_anchor_digest != anchor.anchor_digest
            or statement.trust_domain != anchor.trust_domain
            or statement.issuer != anchor.issuer
            or statement.deployment_id != anchor.deployment_id
            or statement.route_digest in anchor.revoked_route_digests
            or not statement.not_before <= denied_at < statement.expires_at
        ):
            raise ValueError("historical WEB proxy-route Trust Anchor or denial time differs")
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="WEB proxy-route public key",
            )
        ).verify(
            _base64url_decode(
                canonical_bundle.route.signature_base64url,
                expected_length=64,
                label="WEB proxy-route signature",
            ),
            _SIGNATURE_DOMAIN + _statement_bytes(statement),
        )
        target_context = _completed_cleanup_before_route_target_context(
            target_journal,
            attempt_id=target_attempt_id,
            execution_operation_id=statement.target.execution_operation_id,
            issued_at=statement.issued_at,
            evaluated_at=denied_at,
            require_latest_scope_fence=False,
        )
        expected = _build_route_statement(
            trust_anchor=anchor,
            signing_key=key,
            measured_case=measured_case,
            capability_bundle=capability_bundle,
            capability_lifecycle=capability_lifecycle,
            capability_release=capability_release,
            private_ground_truth_profile=private_ground_truth_profile,
            scanner_plan=scanner_plan,
            scanner_registration=scanner_registration,
            runtime_policy=runtime_policy,
            target_profile=target_profile,
            target_journal=target_journal,
            target_attempt_id=target_attempt_id,
            isolation_evidence=isolation_evidence,
            campaign=campaign,
            approval_store=approval_store,
            approval_id=approval_id,
            permit_id=permit_id,
            request=request,
            route_nonce=statement.route_nonce,
            issued_at=statement.issued_at,
            not_before=statement.not_before,
            expires_at=statement.expires_at,
            _target_context=target_context,
        )
        if statement != expected:
            raise ValueError(
                "historical WEB proxy-route differs from its exact denial predecessors"
            )
    except WebProxyRouteAuthorityError:
        raise
    except (
        AttributeError,
        InvalidSignature,
        RuntimeError,
        StopIteration,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WebProxyRouteAuthorityError(
            "historical cleanup-invalidated WEB proxy-route verification failed closed"
        ) from exc


def load_web_proxy_route_verification(
    verification: WebProxyRouteVerification,
    bundle: WebProxyRouteBundle,
    *,
    trust_anchor: WebProxyRouteTrustAnchor,
    measured_case: WebMeasuredCaseAuthority,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    capability_lifecycle: CapabilityLifecycleRegistry,
    capability_release: CapabilityReleaseRef,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
    runtime_policy: WebProxyRouteRuntimePolicy,
    target_profile: DockerBugBountyTargetProfile,
    target_journal: BenchmarkTargetOperationJournal,
    target_attempt_id: str,
    isolation_evidence: DockerBenchmarkProviderEvidence,
    campaign: CampaignManifest,
    approval_store: WebProxyRouteApprovedAuthorizationStore,
    approval_id: str,
    permit_id: str,
    request: ToolRequest,
    evaluated_at: datetime,
) -> WebProxyRouteVerification:
    """Reopen a verification artifact only by repeating every live authority check."""

    try:
        candidate = WebProxyRouteVerification.model_validate(
            verification.model_dump(mode="json", by_alias=True)
        )
        expected = verify_web_proxy_route_authority(
            bundle,
            trust_anchor=trust_anchor,
            measured_case=measured_case,
            capability_bundle=capability_bundle,
            capability_lifecycle=capability_lifecycle,
            capability_release=capability_release,
            private_ground_truth_profile=private_ground_truth_profile,
            scanner_plan=scanner_plan,
            scanner_registration=scanner_registration,
            runtime_policy=runtime_policy,
            target_profile=target_profile,
            target_journal=target_journal,
            target_attempt_id=target_attempt_id,
            isolation_evidence=isolation_evidence,
            campaign=campaign,
            approval_store=approval_store,
            approval_id=approval_id,
            permit_id=permit_id,
            request=request,
            evaluated_at=evaluated_at,
        )
        if candidate != expected:
            raise ValueError("WEB proxy-route verification artifact differs")
        return expected.model_copy(deep=True)
    except WebProxyRouteAuthorityError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise WebProxyRouteAuthorityError(
            "WEB proxy-route verification reload failed closed"
        ) from exc


def load_spent_web_proxy_route_verification(
    verification: WebProxyRouteVerification,
    bundle: WebProxyRouteBundle,
    *,
    trust_anchor: WebProxyRouteTrustAnchor,
) -> WebProxyRouteVerification:
    """Reopen a consumed route as historical evidence without reviving authority.

    Live verification intentionally stops succeeding after Target cleanup changes the
    journal head. A sealed WEB-002D result still needs to prove that the exact route
    was signed by a key usable at issuance and that its pre-execution verification
    artifact names that route. This loader performs only those historical checks;
    it does not check current freshness and cannot authorize another execution.
    """

    try:
        if (
            type(verification) is not WebProxyRouteVerification
            or type(bundle) is not WebProxyRouteBundle
            or type(trust_anchor) is not WebProxyRouteTrustAnchor
        ):
            raise TypeError("spent WEB proxy-route evidence requires exact model types")
        candidate = WebProxyRouteVerification.model_validate(
            verification.model_dump(mode="json", by_alias=True)
        )
        canonical_bundle = WebProxyRouteBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        anchor = WebProxyRouteTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        statement = canonical_bundle.route.statement
        key = next(item for item in anchor.keys if item.key_id == canonical_bundle.route.key_id)
        _require_key_usable(key, at=statement.issued_at)
        if (
            statement.trust_anchor_digest != anchor.anchor_digest
            or statement.trust_domain != anchor.trust_domain
            or statement.issuer != anchor.issuer
            or statement.deployment_id != anchor.deployment_id
            or statement.route_digest in anchor.revoked_route_digests
            or not statement.issued_at <= statement.not_before < statement.expires_at
        ):
            raise ValueError("spent WEB proxy-route Trust Anchor or validity differs")
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="WEB proxy-route public key",
            )
        ).verify(
            _base64url_decode(
                canonical_bundle.route.signature_base64url,
                expected_length=64,
                label="WEB proxy-route signature",
            ),
            _SIGNATURE_DOMAIN + _statement_bytes(statement),
        )
        if (
            candidate.route_id != statement.route_id
            or candidate.route_digest != statement.route_digest
            or candidate.bundle_digest != canonical_bundle.digest
        ):
            raise ValueError("spent WEB proxy-route verification identity differs")
        return candidate.model_copy(deep=True)
    except WebProxyRouteAuthorityError:
        raise
    except (
        AttributeError,
        InvalidSignature,
        RuntimeError,
        StopIteration,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WebProxyRouteAuthorityError(
            "spent WEB proxy-route verification failed closed"
        ) from exc


def _build_route_statement(
    *,
    trust_anchor: WebProxyRouteTrustAnchor,
    signing_key: WebProxyRouteVerificationKey,
    measured_case: WebMeasuredCaseAuthority,
    capability_bundle: WebMeasuredValidationCapabilityBundle,
    capability_lifecycle: CapabilityLifecycleRegistry,
    capability_release: CapabilityReleaseRef,
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile,
    scanner_plan: ScannerBaselineMeasurementPlanAuthority,
    scanner_registration: ZAPScannerRegistration,
    runtime_policy: WebProxyRouteRuntimePolicy,
    target_profile: DockerBugBountyTargetProfile,
    target_journal: BenchmarkTargetOperationJournal,
    target_attempt_id: str,
    isolation_evidence: DockerBenchmarkProviderEvidence,
    campaign: CampaignManifest,
    approval_store: WebProxyRouteApprovedAuthorizationStore,
    approval_id: str,
    permit_id: str,
    request: ToolRequest,
    route_nonce: str,
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
    _target_context: _RouteTargetJournalContext | None = None,
) -> WebProxyRouteStatement:
    issue_time = _aware_utc(issued_at, label="WEB proxy-route issue time")
    route_not_before = _aware_utc(not_before, label="WEB proxy-route not-before time")
    route_expires_at = _aware_utc(expires_at, label="WEB proxy-route expiry time")
    policy = WebProxyRouteRuntimePolicy.model_validate(
        runtime_policy.model_dump(mode="json", by_alias=True)
    )
    profile = DockerBugBountyTargetProfile.model_validate(
        target_profile.model_dump(mode="json", by_alias=True)
    )
    target_context = _target_context or _current_route_target_context(
        target_journal,
        attempt_id=target_attempt_id,
        issued_at=issue_time,
    )
    adapter = target_context.adapter
    trusted_coordinate = target_context.coordinate
    trusted_attempt = target_context.attempt
    active_fence = target_context.active_fence
    isolation_operation = target_context.isolation_operation
    receipt = target_context.isolation_receipt
    operation = target_context.execution_operation
    case = load_web_measured_case_authority(
        measured_case,
        capability_bundle=capability_bundle,
        lifecycle=capability_lifecycle,
        release=capability_release,
        target_adapter=adapter,
        private_ground_truth_profile=private_ground_truth_profile,
        scanner_plan=scanner_plan,
        scanner_registration=scanner_registration,
    )
    expected_target_coordinate = benchmark_target_coordinate(
        case.scanner_plan.manifest,
        arm_id=trusted_coordinate.arm.arm_id,
        seed=trusted_coordinate.seed,
        repetition=trusted_coordinate.repetition,
    )
    matching_scanner_coordinates = tuple(
        item
        for item in case.scanner_plan.coordinates
        if item.manifest_digest == trusted_coordinate.manifest_digest
        and item.arm_id == trusted_coordinate.arm.arm_id
        and item.seed == trusted_coordinate.seed
        and item.repetition == trusted_coordinate.repetition
    )
    evidence = DockerBenchmarkProviderEvidence.model_validate(
        isolation_evidence.model_dump(mode="json", by_alias=True)
    )
    trusted_campaign = CampaignManifest.model_validate(
        campaign.model_dump(mode="json", by_alias=True)
    )
    authorization = _approved_route_authorization(
        approval_store,
        approval_id=approval_id,
        permit_id=permit_id,
    )
    approval = authorization.approval
    approval_receipt = authorization.receipt
    trusted_envelope = approval.mission_envelope
    trusted_permit = authorization.action.permit
    proposal = approval.proposal
    trusted_request = ToolRequest.model_validate(request.model_dump(mode="json", by_alias=True))
    if (
        case.target_adapter != adapter
        or case.target_registration.target_profile_id != profile.profile_id
        or case.target_registration.target_profile_version != profile.profile_version
        or case.target_registration.target_factory_digest != profile.target_factory_digest
        or adapter.target_factory_digest != profile.target_factory_digest
        or trusted_coordinate != expected_target_coordinate
        or len(matching_scanner_coordinates) != 1
        or trusted_attempt.adapter_digest != adapter.adapter_digest
        or trusted_attempt.coordinate_digest != trusted_coordinate.coordinate_digest
        or trusted_attempt.fence != active_fence
        or isolation_operation.attempt_id != trusted_attempt.attempt_id
        or isolation_operation.attempt_digest != trusted_attempt.attempt_digest
        or isolation_operation.adapter_digest != adapter.adapter_digest
        or isolation_operation.coordinate_digest != trusted_coordinate.coordinate_digest
        or isolation_operation.fence != active_fence
        or isolation_operation.stage != "isolation"
        or isolation_operation.ordinal != 1
        or operation.attempt_id != trusted_attempt.attempt_id
        or operation.attempt_digest != trusted_attempt.attempt_digest
        or operation.adapter_digest != adapter.adapter_digest
        or operation.coordinate_digest != trusted_coordinate.coordinate_digest
        or operation.fence != active_fence
        or operation.stage != "execution"
        or operation.ordinal != 1
        or receipt.stage != "isolation"
        or receipt.status != "succeeded"
        or receipt.operation_id != isolation_operation.operation_id
        or receipt.adapter_digest != adapter.adapter_digest
        or receipt.coordinate_digest != trusted_coordinate.coordinate_digest
        or evidence.stage != "isolation"
        or evidence.evidence_digest != receipt.provider_evidence_digest
        or evidence.operation_id != isolation_operation.operation_id
        or evidence.operation_digest != isolation_operation.operation_digest
        or evidence.fence != active_fence
        or evidence.adapter_digest != adapter.adapter_digest
        or evidence.coordinate_digest != trusted_coordinate.coordinate_digest
        or evidence.environment_id != receipt.environment_id
        or evidence.isolation_id != receipt.isolation_id
        or receipt.isolation_id is None
        or evidence.target_image_id != profile.target_image_id
        or evidence.worker_image_id != profile.worker_image_id
        or evidence.target_container_id is None
        or evidence.network_id is None
        or evidence.network_internal is not True
        or evidence.published_port_count != 0
        or evidence.network_container_count != 1
        or evidence.target_healthy is not True
        or not trusted_attempt.started_at <= receipt.started_at
        or not receipt.started_at <= evidence.observed_at <= receipt.completed_at
        or receipt.completed_at > issue_time
    ):
        raise ValueError("WEB proxy-route Target operation or isolation evidence differs")
    campaign_digest = campaign_manifest_digest(trusted_campaign)
    request_digest = canonical_tool_request_digest(trusted_request)
    action_capability = case.profile.action_capability.reference()
    matching_targets = [
        item
        for item in trusted_campaign.spec.targets
        if item.endpoint == WEB_MEASURED_VALIDATION_TARGET
    ]
    if (
        trusted_campaign.metadata.name != trusted_envelope.campaign_id
        or trusted_campaign.spec.mode is not CampaignMode.BUG_BOUNTY
        or len(matching_targets) != 1
        or trusted_campaign.spec.scope.allow != [WEB_MEASURED_VALIDATION_TARGET]
        or trusted_campaign.spec.scope.deny
        or "GET" not in trusted_campaign.spec.rules_of_engagement.allowed_methods
        or trusted_campaign.spec.rules_of_engagement.max_tool_risk_tier < ToolRiskTier.T2
        or trusted_campaign.spec.rules_of_engagement.allow_private_networks is not True
        or not trusted_campaign.spec.authorization.is_active(issue_time)
        or not _campaign_testing_window_allows_interval(
            trusted_campaign,
            start=issue_time,
            end=route_expires_at,
        )
        or trusted_envelope.source_campaign_digest != campaign_digest
        or trusted_envelope.profile_id != case.profile.profile_id
        or trusted_envelope.profile_version != case.profile.profile_version
        or trusted_envelope.profile_digest != case.profile.profile_digest
        or action_capability not in trusted_envelope.allowed_capabilities
        or trusted_permit.target_digest not in trusted_envelope.allowed_target_digests
        or approval.campaign_digest != campaign_digest
        or approval.release.release_id != case.capability_release.release_id
        or approval.release.release_digest != case.capability_release.release_digest
        or approval.release.capability_id != case.profile.capability.capability.capability_id
        or approval.release.capability_version
        != case.profile.capability.capability.capability_version
        or approval.release.capability_digest
        != case.profile.capability.capability.capability_digest
        or approval.side_effect_class != "read-only"
        or approval.cleanup_required is not False
        or proposal.capability != action_capability
        or proposal.target_digest != trusted_permit.target_digest
        or proposal.request_id != trusted_request.request_id
        or proposal.request_digest != request_digest
        or proposal.normalized_parameters_digest
        != capability_normalized_parameters_digest(trusted_request.arguments)
        or proposal.reservation != trusted_permit.reservation
        or trusted_permit.campaign_id != trusted_envelope.campaign_id
        or trusted_permit.run_id != trusted_envelope.run_id
        or trusted_permit.compiler_id != trusted_envelope.compiler_id
        or trusted_permit.compiler_version != trusted_envelope.compiler_version
        or trusted_permit.compiler_digest != trusted_envelope.compiler_digest
        or trusted_permit.envelope_id != trusted_envelope.envelope_id
        or trusted_permit.envelope_digest != trusted_envelope.envelope_digest
        or trusted_permit.capability != action_capability
        or trusted_permit.target_digest != http_target_sha256(trusted_request.target)
        or trusted_permit.request_id != trusted_request.request_id
        or trusted_permit.request_digest != request_digest
        or trusted_permit.normalized_parameters_digest
        != capability_normalized_parameters_digest(trusted_request.arguments)
        or trusted_permit.reservation.request_units != WEB_MEASURED_VALIDATION_REQUEST_UNITS
        or trusted_permit.reservation.cost_microusd != 0
        or not trusted_permit.consumed_at <= issue_time < trusted_permit.expires_at
        or not trusted_envelope.not_before <= issue_time < trusted_envelope.expires_at
        or route_not_before < trusted_permit.consumed_at
        or route_expires_at > trusted_permit.expires_at
        or route_not_before < approval.not_before
        or route_expires_at > approval.expires_at
        or route_not_before < trusted_envelope.not_before
        or route_expires_at > trusted_envelope.expires_at
        or route_not_before < trusted_campaign.spec.authorization.approved_at
        or route_expires_at > trusted_campaign.spec.authorization.expires_at
        or trusted_request.tool_id != BooleanSQLiProbeTool.spec.tool_id
        or trusted_request.target != WEB_MEASURED_VALIDATION_TARGET
        or trusted_request.method != "GET"
        or trusted_request.arguments != {"scenario_id": BOOLEAN_SQLI_SCENARIO}
        or policy.deployment_id != trust_anchor.deployment_id
    ):
        raise ValueError(
            "WEB proxy-route Campaign, approval, Permit, request, or deployment differs"
        )
    target_binding = WebProxyRouteTargetBinding(
        adapterId=adapter.adapter_id,
        adapterVersion=adapter.adapter_version,
        adapterDigest=adapter.adapter_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        targetImageId=profile.target_image_id,
        benchmarkWorkerImageId=profile.worker_image_id,
        coordinateId=trusted_coordinate.coordinate_id,
        coordinateDigest=trusted_coordinate.coordinate_digest,
        attemptId=trusted_attempt.attempt_id,
        attemptDigest=trusted_attempt.attempt_digest,
        isolationOperationId=isolation_operation.operation_id,
        isolationOperationDigest=isolation_operation.operation_digest,
        executionOperationId=operation.operation_id,
        executionOperationDigest=operation.operation_digest,
        activeFence=active_fence,
        isolationReceiptId=receipt.receipt_id,
        isolationReceiptDigest=receipt.receipt_digest,
        isolationProviderEvidenceDigest=evidence.evidence_digest,
        environmentId=receipt.environment_id,
        isolationId=receipt.isolation_id,
        targetContainerId=evidence.target_container_id,
        targetNetworkId=evidence.network_id,
    )
    consumption_slot_material = {
        "approvalDigest": approval.approval_digest,
        "approvalReceiptDigest": approval_receipt.receipt_digest,
        "permitDigest": trusted_permit.permit_digest,
    }
    consumption_slot_digest = benchmark_digest(
        "pajin.workflow.web-proxy-route-consumption-slot/v1",
        consumption_slot_material,
        max_bytes=128 * 1024,
    )
    network_slot_material = {
        "measuredCase": case.reference().model_dump(mode="json", by_alias=True),
        "runtimePolicyDigest": policy.policy_digest,
        "isolationOperationDigest": isolation_operation.operation_digest,
        "operationDigest": operation.operation_digest,
        "consumptionSlotDigest": consumption_slot_digest,
        "routeNonce": route_nonce,
    }
    return WebProxyRouteStatement(
        routeNonce=route_nonce,
        trustDomain=trust_anchor.trust_domain,
        issuer=trust_anchor.issuer,
        deploymentId=trust_anchor.deployment_id,
        trustAnchorDigest=trust_anchor.anchor_digest,
        signingKeyId=signing_key.key_id,
        measuredCase=case.reference(),
        runtimePolicy=policy,
        campaignId=trusted_envelope.campaign_id,
        campaignDigest=campaign_digest,
        scopeDigest=benchmark_digest(
            "pajin.workflow.web-proxy-route-scope/v1",
            trusted_campaign.spec.scope.model_dump(mode="json", by_alias=True),
            max_bytes=256 * 1024,
        ),
        envelopeId=trusted_envelope.envelope_id,
        envelopeDigest=trusted_envelope.envelope_digest,
        approvalId=approval.approval_id,
        approvalDigest=approval.approval_digest,
        approvalReceiptId=approval_receipt.receipt_id,
        approvalReceiptDigest=approval_receipt.receipt_digest,
        permitId=trusted_permit.permit_id,
        permitDigest=trusted_permit.permit_digest,
        dispatchId=trusted_permit.dispatch_id,
        requestId=trusted_request.request_id,
        requestDigest=request_digest,
        requestAgentId=trusted_request.agent_id,
        targetDigest=trusted_permit.target_digest,
        target=target_binding,
        workerProxyNetworkSlotDigest=benchmark_digest(
            "pajin.workflow.web-proxy-route-worker-network-slot/v1",
            network_slot_material,
            max_bytes=512 * 1024,
        ),
        consumptionSlotDigest=consumption_slot_digest,
        fenceInvalidationScopeDigest=benchmark_digest(
            "pajin.workflow.web-proxy-route-fence-invalidation/v1",
            {
                "adapterDigest": adapter.adapter_digest,
                "coordinateDigest": trusted_coordinate.coordinate_digest,
            },
            max_bytes=128 * 1024,
        ),
        issuedAt=issue_time,
        notBefore=route_not_before,
        expiresAt=route_expires_at,
    )


def _approved_route_authorization(
    store: WebProxyRouteApprovedAuthorizationStore,
    *,
    approval_id: str,
    permit_id: str,
) -> ActionApprovalAuthorization:
    stored = store.approved_authorization(approval_id, permit_id)
    if stored is None:
        raise ValueError("WEB proxy-route approval consumption is not durably registered")
    authorization = ActionApprovalAuthorization.model_validate(
        stored.model_dump(mode="json", by_alias=True)
    )
    if (
        authorization.approval.approval_id != approval_id
        or authorization.action.permit.permit_id != permit_id
        or authorization.action.newly_consumed is not False
        or authorization.receipt.approval != authorization.approval
        or authorization.receipt.action_permit != authorization.action.permit
    ):
        raise ValueError("WEB proxy-route durable approval authorization differs")
    return authorization


@dataclass(frozen=True, slots=True)
class _RouteTargetJournalContext:
    adapter: RegisteredBenchmarkTargetFactoryAdapter
    coordinate: BenchmarkTargetCoordinate
    attempt: BenchmarkTargetAttempt
    active_fence: int
    isolation_operation: BenchmarkTargetOperation
    isolation_receipt: BenchmarkTargetStageReceipt
    execution_operation: BenchmarkTargetOperation


def _current_route_target_context(
    journal: BenchmarkTargetOperationJournal,
    *,
    attempt_id: str,
    issued_at: datetime,
) -> _RouteTargetJournalContext:
    (
        adapter,
        coordinate,
        attempt,
        active_fence,
        records,
    ) = journal.current_open_attempt(attempt_id)
    canonical_records = tuple(
        BenchmarkTargetOperationRecord.model_validate(record.model_dump(mode="json", by_alias=True))
        for record in records
    )
    expected_sequence = (
        ("intent", "reset"),
        ("receipt", "reset"),
        ("intent", "isolation"),
        ("receipt", "isolation"),
        ("intent", "execution"),
    )
    actual_sequence = tuple(
        (record.record_type, record.operation.stage) for record in canonical_records
    )
    record_times = tuple(record.occurred_at for record in canonical_records)
    if (
        attempt.attempt_id != attempt_id
        or type(active_fence) is not int
        or active_fence != attempt.fence
        or actual_sequence != expected_sequence
        or attempt.started_at > record_times[0]
        or any(previous > current for previous, current in pairwise(record_times))
        or record_times[-1] > issued_at
    ):
        raise ValueError("WEB proxy-route Target journal head is not issuable")
    reset_intent = canonical_records[0].operation
    reset_receipt_record = canonical_records[1]
    reset_receipt = reset_receipt_record.receipt
    isolation_intent = canonical_records[2].operation
    isolation_receipt_record = canonical_records[3]
    isolation_receipt = isolation_receipt_record.receipt
    execution_intent = canonical_records[4].operation
    if (
        reset_receipt is None
        or reset_intent.ordinal != 1
        or reset_receipt_record.operation != reset_intent
        or reset_receipt.operation_id != reset_intent.operation_id
        or reset_receipt.status != "succeeded"
        or canonical_records[0].occurred_at > reset_receipt.started_at
        or reset_receipt.completed_at > reset_receipt_record.occurred_at
        or isolation_receipt is None
        or isolation_intent.ordinal != 1
        or isolation_receipt_record.operation != isolation_intent
        or isolation_receipt.operation_id != isolation_intent.operation_id
        or isolation_receipt.status != "succeeded"
        or reset_receipt.environment_id != isolation_receipt.environment_id
        or reset_receipt.completed_at > isolation_receipt.started_at
        or canonical_records[2].occurred_at > isolation_receipt.started_at
        or isolation_receipt.completed_at > isolation_receipt_record.occurred_at
        or execution_intent.stage != "execution"
        or execution_intent.ordinal != 1
        or canonical_records[4].receipt is not None
    ):
        raise ValueError("WEB proxy-route Target journal lifecycle differs")
    return _RouteTargetJournalContext(
        adapter=adapter,
        coordinate=coordinate,
        attempt=attempt,
        active_fence=active_fence,
        isolation_operation=isolation_intent,
        isolation_receipt=isolation_receipt,
        execution_operation=execution_intent,
    )


def _completed_cleanup_before_route_target_context(
    journal: BenchmarkTargetOperationJournal,
    *,
    attempt_id: str,
    execution_operation_id: str,
    issued_at: datetime,
    evaluated_at: datetime,
    require_latest_scope_fence: bool = True,
) -> _RouteTargetJournalContext:
    adapter, coordinate, attempt, records = journal.completed_attempt_for_operation(
        execution_operation_id
    )
    canonical_records = tuple(
        BenchmarkTargetOperationRecord.model_validate(record.model_dump(mode="json", by_alias=True))
        for record in records
    )
    expected_sequence = (
        ("intent", "reset"),
        ("receipt", "reset"),
        ("intent", "isolation"),
        ("receipt", "isolation"),
        ("intent", "execution"),
        ("intent", "cleanup"),
        ("receipt", "cleanup"),
    )
    actual_sequence = tuple(
        (record.record_type, record.operation.stage) for record in canonical_records
    )
    if (
        attempt.attempt_id != attempt_id
        or attempt.fence < 1
        or (
            require_latest_scope_fence
            and journal.latest_scope_fence(
                adapter_digest=adapter.adapter_digest,
                coordinate_digest=coordinate.coordinate_digest,
            )
            != attempt.fence
        )
        or actual_sequence != expected_sequence
        or tuple(record.sequence for record in canonical_records) != tuple(range(1, 8))
        or tuple(record.previous_record_digest for record in canonical_records)
        != (None, *(record.record_digest for record in canonical_records[:-1]))
        or any(
            record.operation.attempt_id != attempt.attempt_id
            or record.operation.attempt_digest != attempt.attempt_digest
            or record.operation.adapter_digest != adapter.adapter_digest
            or record.operation.coordinate_digest != coordinate.coordinate_digest
            or record.operation.fence != attempt.fence
            for record in canonical_records
        )
    ):
        raise ValueError("WEB proxy-route completed Target journal identity differs")
    reset_intent = canonical_records[0]
    reset_result = canonical_records[1]
    isolation_intent = canonical_records[2]
    isolation_result = canonical_records[3]
    execution_intent = canonical_records[4]
    cleanup_intent = canonical_records[5]
    cleanup_result = canonical_records[6]
    reset_receipt = reset_result.receipt
    isolation_receipt = isolation_result.receipt
    cleanup_receipt = cleanup_result.receipt
    record_times = tuple(record.occurred_at for record in canonical_records)
    if (
        reset_receipt is None
        or isolation_receipt is None
        or cleanup_receipt is None
        or reset_intent.operation.ordinal != 1
        or isolation_intent.operation.ordinal != 1
        or execution_intent.operation.ordinal != 1
        or cleanup_intent.operation.ordinal != 1
        or reset_result.operation != reset_intent.operation
        or isolation_result.operation != isolation_intent.operation
        or cleanup_result.operation != cleanup_intent.operation
        or reset_receipt.status != "succeeded"
        or isolation_receipt.status != "succeeded"
        or cleanup_receipt.status != "succeeded"
        or execution_intent.operation.operation_id != execution_operation_id
        or reset_receipt.environment_id != isolation_receipt.environment_id
        or isolation_receipt.environment_id != cleanup_receipt.environment_id
        or isolation_receipt.isolation_id is None
        or isolation_receipt.isolation_id != cleanup_receipt.isolation_id
        or attempt.started_at > record_times[0]
        or any(previous > current for previous, current in pairwise(record_times))
        or reset_intent.occurred_at > reset_receipt.started_at
        or reset_receipt.completed_at > reset_result.occurred_at
        or reset_receipt.completed_at > isolation_receipt.started_at
        or isolation_intent.occurred_at > isolation_receipt.started_at
        or isolation_receipt.completed_at > isolation_result.occurred_at
        or execution_intent.occurred_at > issued_at
        or issued_at > cleanup_intent.occurred_at
        or cleanup_intent.occurred_at > cleanup_receipt.started_at
        or cleanup_receipt.completed_at > cleanup_result.occurred_at
        or cleanup_result.occurred_at > evaluated_at
    ):
        raise ValueError("WEB proxy-route cleanup-before-verification journal differs")
    return _RouteTargetJournalContext(
        adapter=adapter,
        coordinate=coordinate,
        attempt=attempt,
        active_fence=attempt.fence,
        isolation_operation=isolation_intent.operation,
        isolation_receipt=isolation_receipt,
        execution_operation=execution_intent.operation,
    )


def _require_key_usable(key: WebProxyRouteVerificationKey, *, at: datetime) -> None:
    evaluated = _aware_utc(at, label="WEB proxy-route key evaluation")
    if (
        key.state is not WebProxyRouteSigningKeyState.ACTIVE
        or evaluated < key.not_before
        or (key.not_after is not None and evaluated >= key.not_after)
        or (key.revoked_at is not None and evaluated >= key.revoked_at)
    ):
        raise WebProxyRouteAuthorityError("WEB proxy-route signing key is not currently usable")


def _campaign_testing_window_allows_interval(
    campaign: CampaignManifest,
    *,
    start: datetime,
    end: datetime,
) -> bool:
    windows = campaign.spec.rules_of_engagement.testing_windows
    return not windows or any(
        _weekly_testing_window_contains_interval(window, start=start, end=end) for window in windows
    )


def _weekly_testing_window_contains_interval(
    window: WeeklyTestingWindow,
    *,
    start: datetime,
    end: datetime,
) -> bool:
    if start >= end or not window.is_active(start):
        return False
    zone = ZoneInfo(window.timezone)
    local_start = start.astimezone(zone)
    local_day = local_start.date()
    local_time = local_start.timetz().replace(tzinfo=None)
    weekdays = tuple(Weekday)

    if window.start_time == window.end_time:
        if weekdays[local_start.weekday()] not in window.days:
            return False
        boundary_day = local_day + timedelta(days=1)
        for _ in range(6):
            if weekdays[boundary_day.weekday()] not in window.days:
                break
            boundary_day += timedelta(days=1)
        occurrence_end = datetime.combine(
            boundary_day,
            window.end_time,
            tzinfo=zone,
        ).replace(fold=1)
    elif window.start_time < window.end_time:
        if weekdays[local_start.weekday()] not in window.days:
            return False
        occurrence_end = datetime.combine(
            local_day,
            window.end_time,
            tzinfo=zone,
        ).replace(fold=1)
    else:
        start_day = local_day if local_time >= window.start_time else local_day - timedelta(days=1)
        if weekdays[start_day.weekday()] not in window.days:
            return False
        occurrence_end = datetime.combine(
            start_day + timedelta(days=1),
            window.end_time,
            tzinfo=zone,
        ).replace(fold=1)

    final_active_instant = end - timedelta(microseconds=1)
    return end <= occurrence_end.astimezone(UTC) and window.is_active(final_active_instant)


def _statement_bytes(statement: WebProxyRouteStatement) -> bytes:
    return canonical_benchmark_json(
        statement.model_dump(mode="json", by_alias=True),
        label="WebProxyRouteStatement",
        max_bytes=_MAX_ROUTE_BYTES,
    )


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires an explicit UTC offset")
    return value.astimezone(UTC)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must contain {expected_length} canonical bytes")
    return decoded


__all__ = [
    "WEB_PROXY_ROUTE_RUNTIME_POLICY_API_VERSION",
    "WEB_PROXY_ROUTE_STATEMENT_API_VERSION",
    "WEB_PROXY_ROUTE_TRUST_ANCHOR_API_VERSION",
    "WEB_PROXY_ROUTE_VERIFICATION_API_VERSION",
    "SignedWebProxyRoute",
    "WebProxyRouteApprovedAuthorizationStore",
    "WebProxyRouteAuthorityError",
    "WebProxyRouteAuthoritySigner",
    "WebProxyRouteBundle",
    "WebProxyRouteLiveAuthorityContext",
    "WebProxyRouteRuntimePolicy",
    "WebProxyRouteSigningKeyState",
    "WebProxyRouteStatement",
    "WebProxyRouteTargetBinding",
    "WebProxyRouteTargetCleanupInvalidated",
    "WebProxyRouteTrustAnchor",
    "WebProxyRouteVerification",
    "WebProxyRouteVerificationKey",
    "load_spent_web_proxy_route_verification",
    "load_web_proxy_route_verification",
    "registered_web_proxy_route_runtime_policy",
    "verify_cleanup_invalidated_web_proxy_route_history",
    "verify_web_proxy_route_authority",
    "web_proxy_route_public_key_base64url",
]
