"""External one-call authorization verification for live Web analysis.

The verifier is deliberately outside every execution path.  It verifies one
detached Ed25519 statement against independently pinned admission, request,
model, and transport inputs, then returns an auditable result that is still
not dispatch-ready.  Durable nonce consumption belongs to the adjacent live
claim journal; this module owns no replay cache, runtime, Provider, target, or
downstream assessment authority.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from hmac import compare_digest
from typing import Annotated, Final, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.web_assessment.analysis_capacity_v2 import WebAnalysisCapacityV2Pin
from pajin.web_assessment.analysis_live_claim_journal import (
    WebAnalysisOneCallAuthorizationCoordinate,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    CompactSkillBoundWebAnalysisLiveRequest,
)
from pajin.web_assessment.analysis_transport import WebAnalysisTransportRuntimePin

WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_TRUST_ANCHOR_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-trust-anchor/v1alpha1"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_STATEMENT_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-statement/v1alpha1"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_BUNDLE_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-bundle/v1alpha1"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_VERIFICATION_API_VERSION: Final = (
    "pajin.dev/verified-web-analysis-one-call-authorization/v1alpha1"
)

WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_MAX_LIFETIME: Final = timedelta(seconds=180)

_SIGNATURE_DOMAIN = b"pajin.web-analysis.one-call-authorization-statement/v1\0"
_MAX_TRUST_ANCHOR_BYTES = 64 * 1024
_MAX_BUNDLE_BYTES = 512 * 1024
_MAX_VERIFICATION_BYTES = 512 * 1024
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_IMAGE_ID_PATTERN = r"^sha256:[a-f0-9]{64}$"
_AUTHORITY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_NONCE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]
_ImageID = Annotated[str, Field(pattern=_IMAGE_ID_PATTERN)]
_AuthorityIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=_AUTHORITY_ID_PATTERN),
]
_Nonce = Annotated[str, Field(min_length=16, max_length=256, pattern=_NONCE_PATTERN)]


class WebAnalysisOneCallAuthorizationError(ValueError):
    """Raised when external one-call authorization cannot be trusted exactly."""


class WebAnalysisOneCallAuthorizationKeyState(StrEnum):
    """Lifecycle state for an independently provisioned verification key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _canonical_bytes(value: object, *, label: str, max_bytes: int) -> bytes:
    return canonical_json_bytes(value, label=label, max_bytes=max_bytes)


def _canonical_sha256(value: object, *, label: str, max_bytes: int) -> str:
    return sha256(_canonical_bytes(value, label=label, max_bytes=max_bytes)).hexdigest()


def _domain_digest(domain: str, value: object, *, label: str, max_bytes: int) -> str:
    wire = _canonical_bytes(value, label=label, max_bytes=max_bytes)
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + wire).hexdigest()


def _require_aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
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
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("Web analysis authorization verification markers must be literal true")
    return True


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis authorization authority markers must be literal false")
    return False


def _literal_zero(value: object) -> Literal[0]:
    if type(value) is not int or value != 0:
        raise ValueError("Web analysis authorization zero counts must be exact integer zero")
    return 0


def _literal_one(value: object) -> Literal[1]:
    if type(value) is not int or value != 1:
        raise ValueError("Web analysis authorization one-call counts must be exact integer one")
    return 1


class _FrozenAuthorizationModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class WebAnalysisOneCallAuthorizationVerificationKey(_FrozenAuthorizationModel):
    """One public Ed25519 key provisioned outside the execution code path."""

    key_id: _AuthorityIdentifier = Field(alias="keyId")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: WebAnalysisOneCallAuthorizationKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Web analysis authorization public key",
        )
        not_before = _require_aware_utc(self.not_before, label="key not-before time")
        if self.not_after is not None:
            not_after = _require_aware_utc(self.not_after, label="key not-after time")
            if not_after <= not_before:
                raise ValueError("Web analysis authorization key validity window is empty")
        if self.state is WebAnalysisOneCallAuthorizationKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired Web analysis authorization key requires notAfter")
        if self.state is WebAnalysisOneCallAuthorizationKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Web analysis authorization key requires revokedAt")
            revoked_at = _require_aware_utc(self.revoked_at, label="key revocation time")
            if revoked_at < not_before:
                raise ValueError("Web analysis authorization key revocation predates validity")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked Web analysis authorization key cannot have revokedAt")
        return self


class WebAnalysisOneCallAuthorizationTrustAnchor(_FrozenAuthorizationModel):
    """Independently retained issuer, trust domain, and verification keyring."""

    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-trust-anchor/v1alpha1"] = (
        Field(
            default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_TRUST_ANCHOR_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["WebAnalysisOneCallAuthorizationTrustAnchor"] = (
        "WebAnalysisOneCallAuthorizationTrustAnchor"
    )
    trust_domain: _AuthorityIdentifier = Field(alias="trustDomain")
    issuer: _AuthorityIdentifier
    keys: tuple[WebAnalysisOneCallAuthorizationVerificationKey, ...] = Field(
        min_length=1,
        max_length=32,
    )

    @model_validator(mode="after")
    def require_unique_sorted_keyring(self) -> Self:
        key_ids = tuple(key.key_id for key in self.keys)
        if key_ids != tuple(sorted(set(key_ids))):
            raise ValueError("Web analysis authorization keys must be uniquely sorted")
        public_keys = tuple(key.public_key_base64url for key in self.keys)
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("Web analysis authorization public keys must be unique")
        active_count = sum(
            key.state is WebAnalysisOneCallAuthorizationKeyState.ACTIVE for key in self.keys
        )
        if active_count != 1:
            raise ValueError("Web analysis authorization trust anchor requires one active key")
        return self

    @property
    def digest(self) -> str:
        return _domain_digest(
            "pajin.web-analysis.one-call-authorization-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization trust anchor",
            max_bytes=_MAX_TRUST_ANCHOR_BYTES,
        )


class WebAnalysisOneCallAuthorizationStatement(_FrozenAuthorizationModel):
    """External grant for exactly one prepared compact model completion."""

    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-statement/v1alpha1"] = (
        Field(
            default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_STATEMENT_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["WebAnalysisOneCallAuthorizationStatement"] = (
        "WebAnalysisOneCallAuthorizationStatement"
    )
    purpose: Literal["prepared-compact-web-analysis-one-model-completion"] = (
        "prepared-compact-web-analysis-one-model-completion"
    )
    trust_domain: _AuthorityIdentifier = Field(alias="trustDomain")
    issuer: _AuthorityIdentifier
    signing_key_id: _AuthorityIdentifier = Field(alias="signingKeyId")
    nonce: _Nonce

    admission_id: str = Field(
        alias="admissionId",
        max_length=110,
        pattern=r"^prepared-compact-web-analysis:.+",
    )
    admission_digest: _Sha256 = Field(alias="admissionDigest")
    preparation_run_id: str = Field(
        alias="preparationRunId",
        max_length=100,
        pattern=_RUN_ID_PATTERN,
    )
    preparation_run_root_digest: _Sha256 = Field(alias="preparationRunRootDigest")
    preparation_identity: _Sha256 = Field(alias="preparationIdentity")
    preparation_index_digest: _Sha256 = Field(alias="preparationIndexDigest")
    live_request_digest: _Sha256 = Field(alias="liveRequestDigest")

    provider_id: str = Field(
        alias="providerId",
        min_length=2,
        max_length=31,
        pattern=r"^[a-z0-9][a-z0-9-]{1,30}$",
    )
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    provider_chat_request_digest: _Sha256 = Field(alias="providerChatRequestDigest")
    compact_projection_digest: _Sha256 = Field(alias="compactProjectionDigest")
    response_schema_digest: _Sha256 = Field(alias="responseSchemaDigest")

    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    model_pin_digest: _Sha256 = Field(alias="modelPinDigest")
    model_sha256: _Sha256 = Field(alias="modelSha256")
    model_size_bytes: int = Field(alias="modelSizeBytes", strict=True, ge=1)
    model_image: str = Field(alias="modelImage", min_length=1, max_length=500)
    model_platform_manifest: _ImageID = Field(alias="modelPlatformManifest")

    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    transport_version: Literal["pajin.web-analysis.provider-transport/v2"] = Field(
        alias="transportVersion"
    )
    worker_action: Literal["openai-chat-completion-v3"] = Field(alias="workerAction")
    worker_image: _ImageID = Field(alias="workerImage")
    proxy_image: _ImageID = Field(alias="proxyImage")

    issued_at: datetime = Field(alias="issuedAt")
    not_before: datetime = Field(alias="notBefore")
    expires_at: datetime = Field(alias="expiresAt")
    attempt: Literal[1]
    maximum_dispatch_count: Literal[1] = Field(alias="maximumDispatchCount")
    one_model_completion_grant_count: Literal[1] = Field(alias="oneModelCompletionGrantCount")
    tools_allowed: Literal[False] = Field(alias="toolsAllowed")
    streaming_allowed: Literal[False] = Field(alias="streamingAllowed")
    target_request_authority: Literal[False] = Field(alias="targetRequestAuthority")
    tool_request_authority: Literal[False] = Field(alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    report_authority: Literal[False] = Field(alias="reportAuthority")
    delivery_authority: Literal[False] = Field(alias="deliveryAuthority")
    retry_authority: Literal[False] = Field(alias="retryAuthority")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    general_execution_authority: Literal[False] = Field(alias="generalExecutionAuthority")
    automatic_redispatch_authority: Literal[False] = Field(alias="automaticRedispatchAuthority")
    campaign_approval_reinterpreted: Literal[False] = Field(alias="campaignApprovalReinterpreted")

    @field_validator(
        "attempt",
        "maximum_dispatch_count",
        "one_model_completion_grant_count",
        mode="before",
    )
    @classmethod
    def require_one_call(cls, value: object) -> Literal[1]:
        return _literal_one(value)

    @field_validator(
        "tools_allowed",
        "streaming_allowed",
        "target_request_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "finding_authority",
        "graph_admission_authority",
        "report_authority",
        "delivery_authority",
        "retry_authority",
        "scope_expansion_authority",
        "general_execution_authority",
        "automatic_redispatch_authority",
        "campaign_approval_reinterpreted",
        mode="before",
    )
    @classmethod
    def require_no_downstream_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def require_bounded_validity(self) -> Self:
        issued_at = _require_aware_utc(self.issued_at, label="authorization issue time")
        not_before = _require_aware_utc(self.not_before, label="authorization not-before time")
        expires_at = _require_aware_utc(self.expires_at, label="authorization expiry time")
        if not issued_at <= not_before < expires_at:
            raise ValueError("Web analysis authorization validity window is inconsistent")
        if expires_at - issued_at > WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_MAX_LIFETIME:
            raise ValueError("Web analysis authorization lifetime exceeds 180 seconds")
        return self


class SignedWebAnalysisOneCallAuthorization(_FrozenAuthorizationModel):
    """Detached Ed25519 signature over one canonical authorization statement."""

    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-bundle/v1alpha1"] = Field(
        default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_BUNDLE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SignedWebAnalysisOneCallAuthorization"] = "SignedWebAnalysisOneCallAuthorization"
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _AuthorityIdentifier = Field(alias="keyId")
    statement: WebAnalysisOneCallAuthorizationStatement
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def bind_envelope(self) -> Self:
        canonical = _canonical_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization statement",
            max_bytes=_MAX_BUNDLE_BYTES,
        )
        if not compare_digest(sha256(canonical).hexdigest(), self.statement_sha256):
            raise ValueError("Web analysis authorization statement digest differs")
        if self.key_id != self.statement.signing_key_id:
            raise ValueError("Web analysis authorization bundle key differs from its statement")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Web analysis authorization signature",
        )
        return self

    @property
    def digest(self) -> str:
        return _canonical_sha256(
            self.model_dump(mode="json", by_alias=True),
            label="signed Web analysis one-call authorization",
            max_bytes=_MAX_BUNDLE_BYTES,
        )


class VerifiedWebAnalysisOneCallAuthorization(_FrozenAuthorizationModel):
    """Auditable verification result that is not itself dispatch-ready."""

    api_version: Literal["pajin.dev/verified-web-analysis-one-call-authorization/v1alpha1"] = Field(
        default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_VERIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["VerifiedWebAnalysisOneCallAuthorization"] = (
        "VerifiedWebAnalysisOneCallAuthorization"
    )
    verification_id: str = Field(default="", alias="verificationId", max_length=110)
    verification_digest: str = Field(default="", alias="verificationDigest", max_length=64)
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    authorization_envelope_digest: _Sha256 = Field(alias="authorizationEnvelopeDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signing_key_id: _AuthorityIdentifier = Field(alias="signingKeyId")
    issuer: _AuthorityIdentifier
    nonce: _Nonce
    coordinate: WebAnalysisOneCallAuthorizationCoordinate
    admission_id: str = Field(alias="admissionId", min_length=1, max_length=110)
    admission_digest: _Sha256 = Field(alias="admissionDigest")
    preparation_identity: _Sha256 = Field(alias="preparationIdentity")
    live_request_digest: _Sha256 = Field(alias="liveRequestDigest")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    provider_chat_request_digest: _Sha256 = Field(alias="providerChatRequestDigest")
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    evaluated_at: datetime = Field(alias="evaluatedAt")
    expires_at: datetime = Field(alias="expiresAt")
    one_model_completion_grant_count: Literal[1] = Field(alias="oneModelCompletionGrantCount")
    dispatch_count: Literal[0] = Field(default=0, alias="dispatchCount")
    status: Literal["verified-external-one-call-not-claimed-no-dispatch"] = (
        "verified-external-one-call-not-claimed-no-dispatch"
    )
    authorization_verified: Literal[True] = Field(default=True, alias="authorizationVerified")
    issuer_signature_verified: Literal[True] = Field(
        default=True,
        alias="issuerSignatureVerified",
    )
    admission_bound: Literal[True] = Field(default=True, alias="admissionBound")
    preparation_bound: Literal[True] = Field(default=True, alias="preparationBound")
    live_request_bound: Literal[True] = Field(default=True, alias="liveRequestBound")
    model_selection_bound: Literal[True] = Field(default=True, alias="modelSelectionBound")
    transport_bound: Literal[True] = Field(default=True, alias="transportBound")
    validity_bound: Literal[True] = Field(default=True, alias="validityBound")
    nonce_bound: Literal[True] = Field(default=True, alias="nonceBound")
    external_one_model_completion_grant_verified: Literal[True] = Field(
        default=True,
        alias="externalOneModelCompletionGrantVerified",
    )
    authorization_consumed: Literal[False] = Field(
        default=False,
        alias="authorizationConsumed",
    )
    durable_claim_present: Literal[False] = Field(default=False, alias="durableClaimPresent")
    live_materialization_attested: Literal[False] = Field(
        default=False,
        alias="liveMaterializationAttested",
    )
    dispatch_ready: Literal[False] = Field(default=False, alias="dispatchReady")
    provider_dispatch_authority: Literal[False] = Field(
        default=False,
        alias="providerDispatchAuthority",
    )
    target_request_authority: Literal[False] = Field(
        default=False,
        alias="targetRequestAuthority",
    )
    tool_request_authority: Literal[False] = Field(default=False, alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(default=False, alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthority",
    )
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")
    delivery_authority: Literal[False] = Field(default=False, alias="deliveryAuthority")
    retry_authority: Literal[False] = Field(default=False, alias="retryAuthority")
    scope_expansion_authority: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthority",
    )
    general_execution_authority: Literal[False] = Field(
        default=False,
        alias="generalExecutionAuthority",
    )
    automatic_redispatch_authority: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthority",
    )
    campaign_approval_reinterpreted: Literal[False] = Field(
        default=False,
        alias="campaignApprovalReinterpreted",
    )

    @field_validator(
        "authorization_verified",
        "issuer_signature_verified",
        "admission_bound",
        "preparation_bound",
        "live_request_bound",
        "model_selection_bound",
        "transport_bound",
        "validity_bound",
        "nonce_bound",
        "external_one_model_completion_grant_verified",
        mode="before",
    )
    @classmethod
    def require_verification_markers(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator("one_model_completion_grant_count", mode="before")
    @classmethod
    def require_one_grant(cls, value: object) -> Literal[1]:
        return _literal_one(value)

    @field_validator("dispatch_count", mode="before")
    @classmethod
    def require_zero_dispatches(cls, value: object) -> Literal[0]:
        return _literal_zero(value)

    @field_validator(
        "authorization_consumed",
        "durable_claim_present",
        "live_materialization_attested",
        "dispatch_ready",
        "provider_dispatch_authority",
        "target_request_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "finding_authority",
        "graph_admission_authority",
        "report_authority",
        "delivery_authority",
        "retry_authority",
        "scope_expansion_authority",
        "general_execution_authority",
        "automatic_redispatch_authority",
        "campaign_approval_reinterpreted",
        mode="before",
    )
    @classmethod
    def require_no_runtime_or_downstream_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("evaluated_at", "expires_at")
    @classmethod
    def require_aware_verification_time(cls, value: datetime) -> datetime:
        return _require_aware_utc(value, label="Web analysis authorization verification time")

    @model_validator(mode="after")
    def bind_verification(self) -> Self:
        if self.evaluated_at >= self.expires_at:
            raise ValueError("Verified Web analysis authorization is not active")
        coordinate = self.coordinate
        if (
            coordinate.issuer != self.issuer
            or coordinate.key_id != self.signing_key_id
            or coordinate.nonce != self.nonce
            or coordinate.authorization_envelope_digest != self.authorization_envelope_digest
        ):
            raise ValueError("Verified Web analysis authorization coordinate differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verification_id", "verification_digest"},
        )
        digest = _domain_digest(
            "pajin.web-analysis.one-call-authorization-verification/v1",
            material,
            label="verified Web analysis one-call authorization",
            max_bytes=_MAX_VERIFICATION_BYTES,
        )
        verification_id = f"web-analysis-one-call-authorization:{digest}"
        if self.verification_digest and not compare_digest(self.verification_digest, digest):
            raise ValueError("Verified Web analysis authorization digest differs")
        if self.verification_id and self.verification_id != verification_id:
            raise ValueError("Verified Web analysis authorization ID differs")
        object.__setattr__(self, "verification_digest", digest)
        object.__setattr__(self, "verification_id", verification_id)
        return self


def parse_web_analysis_one_call_authorization_trust_anchor(
    content: bytes,
) -> WebAnalysisOneCallAuthorizationTrustAnchor:
    """Parse a bounded duplicate-key-rejecting external trust anchor."""

    try:
        decoded = parse_strict_json_bytes(
            content,
            label="Web analysis one-call authorization trust anchor",
            max_bytes=_MAX_TRUST_ANCHOR_BYTES,
            max_depth=12,
            max_nodes=2_000,
        )
        canonical = _canonical_bytes(
            decoded,
            label="Web analysis one-call authorization trust anchor",
            max_bytes=_MAX_TRUST_ANCHOR_BYTES,
        )
        return WebAnalysisOneCallAuthorizationTrustAnchor.model_validate_json(canonical)
    except WebAnalysisOneCallAuthorizationError:
        raise
    except Exception as exc:
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis one-call authorization trust anchor is invalid"
        ) from exc


def parse_signed_web_analysis_one_call_authorization(
    content: bytes,
) -> SignedWebAnalysisOneCallAuthorization:
    """Parse a bounded duplicate-key-rejecting signed authorization bundle."""

    try:
        decoded = parse_strict_json_bytes(
            content,
            label="signed Web analysis one-call authorization",
            max_bytes=_MAX_BUNDLE_BYTES,
            max_depth=20,
            max_nodes=20_000,
        )
        canonical = _canonical_bytes(
            decoded,
            label="signed Web analysis one-call authorization",
            max_bytes=_MAX_BUNDLE_BYTES,
        )
        return SignedWebAnalysisOneCallAuthorization.model_validate_json(canonical)
    except WebAnalysisOneCallAuthorizationError:
        raise
    except Exception as exc:
        raise WebAnalysisOneCallAuthorizationError(
            "Signed Web analysis one-call authorization is invalid"
        ) from exc


def _canonical_trust_anchor(
    value: object,
) -> WebAnalysisOneCallAuthorizationTrustAnchor:
    if type(value) is not WebAnalysisOneCallAuthorizationTrustAnchor:
        raise TypeError("Web analysis authorization requires its exact external trust-anchor type")
    anchor = value
    assert isinstance(anchor, WebAnalysisOneCallAuthorizationTrustAnchor)
    return parse_web_analysis_one_call_authorization_trust_anchor(
        _canonical_bytes(
            anchor.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization trust anchor",
            max_bytes=_MAX_TRUST_ANCHOR_BYTES,
        )
    )


def _canonical_bundle(value: object) -> SignedWebAnalysisOneCallAuthorization:
    if type(value) is not SignedWebAnalysisOneCallAuthorization:
        raise TypeError("Web analysis authorization requires its exact signed bundle type")
    bundle = value
    assert isinstance(bundle, SignedWebAnalysisOneCallAuthorization)
    return parse_signed_web_analysis_one_call_authorization(
        _canonical_bytes(
            bundle.model_dump(mode="json", by_alias=True),
            label="signed Web analysis one-call authorization",
            max_bytes=_MAX_BUNDLE_BYTES,
        )
    )


def _canonical_admission(
    value: object,
) -> PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope:
    if type(value) is not PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope:
        raise TypeError("Web analysis authorization requires the exact admission envelope type")
    admission = value
    assert isinstance(admission, PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope)
    return PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate_json(
        admission.model_dump_json(by_alias=True)
    )


def _canonical_live_request(value: object) -> CompactSkillBoundWebAnalysisLiveRequest:
    if type(value) is not CompactSkillBoundWebAnalysisLiveRequest:
        raise TypeError("Web analysis authorization requires the exact live request type")
    request = value
    assert isinstance(request, CompactSkillBoundWebAnalysisLiveRequest)
    return CompactSkillBoundWebAnalysisLiveRequest.model_validate_json(
        request.model_dump_json(by_alias=True)
    )


def _canonical_capacity_pin(value: object) -> WebAnalysisCapacityV2Pin:
    if type(value) is not WebAnalysisCapacityV2Pin:
        raise TypeError("Web analysis authorization requires the exact Capacity v2 Pin type")
    pin = value
    assert isinstance(pin, WebAnalysisCapacityV2Pin)
    return WebAnalysisCapacityV2Pin.model_validate_json(pin.model_dump_json(by_alias=True))


def _canonical_transport_pin(value: object) -> WebAnalysisTransportRuntimePin:
    if type(value) is not WebAnalysisTransportRuntimePin:
        raise TypeError("Web analysis authorization requires the exact transport Pin type")
    pin = value
    assert isinstance(pin, WebAnalysisTransportRuntimePin)
    return WebAnalysisTransportRuntimePin.model_validate_json(pin.model_dump_json(by_alias=True))


def _require_exact_bindings(
    *,
    statement: WebAnalysisOneCallAuthorizationStatement,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    capacity_pin: WebAnalysisCapacityV2Pin,
    transport_pin: WebAnalysisTransportRuntimePin,
) -> None:
    if (
        admission.live_request_digest != live_request.request_digest
        or admission.provider_registration_digest != live_request.provider_registration_digest
        or admission.provider_chat_request_digest != live_request.chat_request_digest
        or admission.compact_projection_digest != live_request.compact_projection_digest
    ):
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis admission differs from the exact live request"
        )
    if (
        admission.capacity_pin_digest != capacity_pin.pin_digest
        or live_request.capacity_compact_projection_digest != capacity_pin.compact_projection_digest
        or live_request.capacity_chat_request_digest != capacity_pin.chat_request_digest
    ):
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis admission or request differs from the Capacity v2 Pin"
        )
    if (
        admission.transport_pin_digest != transport_pin.pin_digest
        or capacity_pin.transport_pin_digest != transport_pin.pin_digest
    ):
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis admission or Capacity v2 Pin differs from the transport Pin"
        )
    registration = live_request.provider_registration
    if registration.model != capacity_pin.model_id:
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis Provider model differs from the Capacity v2 model"
        )
    expected = (
        statement.admission_id,
        statement.admission_digest,
        statement.preparation_run_id,
        statement.preparation_run_root_digest,
        statement.preparation_identity,
        statement.preparation_index_digest,
        statement.live_request_digest,
        statement.provider_id,
        statement.model_id,
        statement.provider_registration_digest,
        statement.provider_chat_request_digest,
        statement.compact_projection_digest,
        statement.response_schema_digest,
        statement.capacity_pin_digest,
        statement.model_pin_digest,
        statement.model_sha256,
        statement.model_size_bytes,
        statement.model_image,
        statement.model_platform_manifest,
        statement.transport_pin_digest,
        statement.transport_version,
        statement.worker_action,
        statement.worker_image,
        statement.proxy_image,
    )
    actual = (
        admission.admission_id,
        admission.admission_digest,
        admission.preparation_run_id,
        admission.preparation_run_root_digest,
        admission.preparation_digest,
        admission.preparation_index_digest,
        live_request.request_digest,
        registration.provider_id,
        registration.model,
        live_request.provider_registration_digest,
        live_request.chat_request_digest,
        live_request.compact_projection_digest,
        admission.response_schema_digest,
        capacity_pin.pin_digest,
        capacity_pin.model_pin_digest,
        capacity_pin.model_sha256,
        capacity_pin.model_size_bytes,
        capacity_pin.model_image,
        capacity_pin.model_platform_manifest,
        transport_pin.pin_digest,
        transport_pin.transport_version,
        transport_pin.worker_action,
        transport_pin.worker_image,
        transport_pin.proxy_image,
    )
    if expected != actual:
        raise WebAnalysisOneCallAuthorizationError(
            "Signed Web analysis authorization differs from an exact live input"
        )


@dataclass(frozen=True, slots=True)
class WebAnalysisOneCallAuthorizationVerifier:
    """Pure verifier configured by an independently retained trust-anchor digest."""

    trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor
    expected_trust_anchor_digest: str
    clock: Callable[[], datetime] = _utc_now

    def __post_init__(self) -> None:
        try:
            anchor = _canonical_trust_anchor(self.trust_anchor)
            expected = self.expected_trust_anchor_digest
            if (
                type(expected) is not str
                or len(expected) != 64
                or any(character not in "0123456789abcdef" for character in expected)
                or not compare_digest(anchor.digest, expected)
            ):
                raise ValueError(
                    "Web analysis authorization trust anchor differs from its independent digest"
                )
            if not callable(self.clock):
                raise TypeError("Web analysis authorization clock must be callable")
            object.__setattr__(self, "trust_anchor", anchor)
        except WebAnalysisOneCallAuthorizationError:
            raise
        except Exception as exc:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization verifier configuration failed closed"
            ) from exc

    def verify(
        self,
        authorization: SignedWebAnalysisOneCallAuthorization,
        *,
        admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
        live_request: CompactSkillBoundWebAnalysisLiveRequest,
        capacity_pin: WebAnalysisCapacityV2Pin,
        transport_pin: WebAnalysisTransportRuntimePin,
    ) -> VerifiedWebAnalysisOneCallAuthorization:
        """Verify an external grant without claiming, materializing, or dispatching."""

        try:
            anchor = _canonical_trust_anchor(self.trust_anchor)
            if not compare_digest(anchor.digest, self.expected_trust_anchor_digest):
                raise WebAnalysisOneCallAuthorizationError(
                    "Web analysis authorization trust anchor drifted from its independent digest"
                )
            bundle = _canonical_bundle(authorization)
            canonical_admission = _canonical_admission(admission)
            canonical_request = _canonical_live_request(live_request)
            canonical_capacity = _canonical_capacity_pin(capacity_pin)
            canonical_transport = _canonical_transport_pin(transport_pin)
            evaluated_at = _require_aware_utc(
                self.clock(),
                label="authorization evaluation time",
            )
            self._verify_issuer_signature_and_validity(
                bundle,
                trust_anchor=anchor,
                evaluated_at=evaluated_at,
            )
            _require_exact_bindings(
                statement=bundle.statement,
                admission=canonical_admission,
                live_request=canonical_request,
                capacity_pin=canonical_capacity,
                transport_pin=canonical_transport,
            )
            statement = bundle.statement
            coordinate = WebAnalysisOneCallAuthorizationCoordinate(
                authorizationEnvelopeDigest=bundle.digest,
                issuer=statement.issuer,
                keyId=bundle.key_id,
                nonce=statement.nonce,
            )
            return VerifiedWebAnalysisOneCallAuthorization(
                trustAnchorDigest=anchor.digest,
                authorizationEnvelopeDigest=bundle.digest,
                statementSha256=bundle.statement_sha256,
                signingKeyId=bundle.key_id,
                issuer=statement.issuer,
                nonce=statement.nonce,
                coordinate=coordinate,
                admissionId=canonical_admission.admission_id,
                admissionDigest=canonical_admission.admission_digest,
                preparationIdentity=canonical_admission.preparation_digest,
                liveRequestDigest=canonical_request.request_digest,
                providerRegistrationDigest=canonical_request.provider_registration_digest,
                providerChatRequestDigest=canonical_request.chat_request_digest,
                modelId=canonical_capacity.model_id,
                capacityPinDigest=canonical_capacity.pin_digest,
                transportPinDigest=canonical_transport.pin_digest,
                evaluatedAt=evaluated_at,
                expiresAt=statement.expires_at,
                oneModelCompletionGrantCount=statement.one_model_completion_grant_count,
            )
        except WebAnalysisOneCallAuthorizationError:
            raise
        except Exception as exc:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization verification failed closed"
            ) from exc

    def _verify_issuer_signature_and_validity(
        self,
        bundle: SignedWebAnalysisOneCallAuthorization,
        *,
        trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor,
        evaluated_at: datetime,
    ) -> None:
        statement = bundle.statement
        anchor = trust_anchor
        if statement.trust_domain != anchor.trust_domain or statement.issuer != anchor.issuer:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis authorization issuer or trust domain is not trusted"
            )
        key = next((item for item in anchor.keys if item.key_id == bundle.key_id), None)
        if key is None:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis authorization signing key is absent from the trust anchor"
            )
        if key.state is not WebAnalysisOneCallAuthorizationKeyState.ACTIVE:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis authorization signing key is not active"
            )
        issued_at = _require_aware_utc(statement.issued_at, label="authorization issue time")
        not_before = _require_aware_utc(statement.not_before, label="authorization not-before time")
        expires_at = _require_aware_utc(statement.expires_at, label="authorization expiry time")
        key_not_before = _require_aware_utc(key.not_before, label="key not-before time")
        if issued_at < key_not_before or not_before < key_not_before:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis authorization predates signing-key validity"
            )
        if key.not_after is not None:
            key_not_after = _require_aware_utc(key.not_after, label="key not-after time")
            if expires_at > key_not_after or evaluated_at >= key_not_after:
                raise WebAnalysisOneCallAuthorizationError(
                    "Web analysis authorization exceeds signing-key validity"
                )
        if not not_before <= evaluated_at < expires_at:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization is not currently valid"
            )
        statement_wire = _canonical_bytes(
            statement.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization statement",
            max_bytes=_MAX_BUNDLE_BYTES,
        )
        public_key = Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                expected_length=32,
                label="Web analysis authorization public key",
            )
        )
        try:
            public_key.verify(
                _base64url_decode(
                    bundle.signature_base64url,
                    expected_length=64,
                    label="Web analysis authorization signature",
                ),
                _SIGNATURE_DOMAIN + statement_wire,
            )
        except InvalidSignature as exc:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization signature verification failed"
            ) from exc


__all__ = [
    "SignedWebAnalysisOneCallAuthorization",
    "VerifiedWebAnalysisOneCallAuthorization",
    "WebAnalysisOneCallAuthorizationError",
    "WebAnalysisOneCallAuthorizationKeyState",
    "WebAnalysisOneCallAuthorizationStatement",
    "WebAnalysisOneCallAuthorizationTrustAnchor",
    "WebAnalysisOneCallAuthorizationVerificationKey",
    "WebAnalysisOneCallAuthorizationVerifier",
    "parse_signed_web_analysis_one_call_authorization",
    "parse_web_analysis_one_call_authorization_trust_anchor",
]
