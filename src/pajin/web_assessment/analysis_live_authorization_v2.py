"""Compact-runtime-bound external authorization for one WEB-007 completion.

This additive verifier keeps signing material outside the PAJIN execution
package.  It binds the previously admitted lineage transport together with
the effective compact runtime and transport pins.  The module can assemble an
unsigned statement and verify a detached signature, but it cannot sign,
claim, materialize, dispatch, or grant downstream assessment authority.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
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
from pajin.web_assessment.analysis_compact_live_pins import (
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
    verify_compact_web_analysis_live_pin_binding,
)
from pajin.web_assessment.analysis_live_authorization import (
    WebAnalysisOneCallAuthorizationError,
    WebAnalysisOneCallAuthorizationKeyState,
    WebAnalysisOneCallAuthorizationTrustAnchor,
)
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

WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_REQUEST_V2_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-request/v1alpha2"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_STATEMENT_V2_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-statement/v1alpha2"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_BUNDLE_V2_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-bundle/v1alpha2"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_VERIFICATION_V2_API_VERSION: Final = (
    "pajin.dev/verified-web-analysis-one-call-authorization/v1alpha2"
)
WEB_ANALYSIS_COMPACT_PROVIDER_TRANSPORT_VERSION: Final = (
    "pajin.web-analysis.compact-provider-transport/v1"
)

_SIGNATURE_DOMAIN_V2 = b"pajin.web-analysis.one-call-authorization-statement/v2\0"
_MAX_REQUEST_BYTES = 512 * 1024
_MAX_BUNDLE_BYTES = 768 * 1024
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


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _canonical_bytes(value: object, *, label: str, max_bytes: int) -> bytes:
    return canonical_json_bytes(value, label=label, max_bytes=max_bytes)


def _domain_digest(domain: str, value: object, *, label: str, max_bytes: int) -> str:
    wire = _canonical_bytes(value, label=label, max_bytes=max_bytes)
    return sha256(domain.encode("ascii", errors="strict") + b"\0" + wire).hexdigest()


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != expected_length or canonical != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis authorization authority markers must be literal false")
    return False


def _literal_one(value: object) -> Literal[1]:
    if type(value) is not int or value != 1:
        raise ValueError("Web analysis authorization one-call counts must be exact integer one")
    return 1


def _literal_zero(value: object) -> Literal[0]:
    if type(value) is not int or value != 0:
        raise ValueError("Web analysis authorization dispatch count must be exact integer zero")
    return 0


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("Web analysis authorization verification markers must be literal true")
    return True


def _canonical_trust_anchor(
    value: object,
) -> WebAnalysisOneCallAuthorizationTrustAnchor:
    if type(value) is not WebAnalysisOneCallAuthorizationTrustAnchor:
        raise TypeError("Web analysis authorization requires the exact trust-anchor type")
    anchor = value
    assert isinstance(anchor, WebAnalysisOneCallAuthorizationTrustAnchor)
    return WebAnalysisOneCallAuthorizationTrustAnchor.model_validate_json(
        anchor.model_dump_json(by_alias=True)
    )


def _canonical_admission(
    value: object,
) -> PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope:
    if type(value) is not PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope:
        raise TypeError("Web analysis authorization requires the exact admission type")
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


def _canonical_lineage_transport_pin(value: object) -> WebAnalysisTransportRuntimePin:
    if type(value) is not WebAnalysisTransportRuntimePin:
        raise TypeError("Web analysis authorization requires the exact lineage transport Pin type")
    pin = value
    assert isinstance(pin, WebAnalysisTransportRuntimePin)
    return WebAnalysisTransportRuntimePin.model_validate_json(pin.model_dump_json(by_alias=True))


def _canonical_request(value: object) -> WebAnalysisOneCallAuthorizationRequestV2:
    if type(value) is not WebAnalysisOneCallAuthorizationRequestV2:
        raise TypeError("Web analysis authorization requires the exact v2 request type")
    request = value
    assert isinstance(request, WebAnalysisOneCallAuthorizationRequestV2)
    return WebAnalysisOneCallAuthorizationRequestV2.model_validate_json(
        request.model_dump_json(by_alias=True)
    )


def _canonical_bundle(value: object) -> SignedWebAnalysisOneCallAuthorizationV2:
    if type(value) is not SignedWebAnalysisOneCallAuthorizationV2:
        raise TypeError("Web analysis authorization requires the exact signed v2 bundle type")
    bundle = value
    assert isinstance(bundle, SignedWebAnalysisOneCallAuthorizationV2)
    return parse_signed_web_analysis_one_call_authorization_v2(
        _canonical_bytes(
            bundle.model_dump(mode="json", by_alias=True),
            label="signed Web analysis one-call authorization v2",
            max_bytes=_MAX_BUNDLE_BYTES - 1,
        )
        + b"\n"
    )


class _FrozenAuthorizationV2Model(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class WebAnalysisOneCallAuthorizationRequestV2(_FrozenAuthorizationV2Model):
    """Signer-neutral exact request for one compact live authorization."""

    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-request/v1alpha2"] = Field(
        default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_REQUEST_V2_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAnalysisOneCallAuthorizationRequestV2"] = (
        "WebAnalysisOneCallAuthorizationRequestV2"
    )
    request_digest: str = Field(default="", alias="requestDigest", max_length=64)
    status: Literal["exact-inputs-not-authorized-no-dispatch"] = (
        "exact-inputs-not-authorized-no-dispatch"
    )
    admission_id: str = Field(
        alias="admissionId",
        max_length=110,
        pattern=r"^prepared-compact-web-analysis:.+",
    )
    admission_digest: _Sha256 = Field(alias="admissionDigest")
    preparation_run_id: str = Field(alias="preparationRunId", pattern=_RUN_ID_PATTERN)
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
    lineage_transport_pin_digest: _Sha256 = Field(alias="lineageTransportPinDigest")
    lineage_transport_version: Literal["pajin.web-analysis.provider-transport/v2"] = Field(
        alias="lineageTransportVersion"
    )
    compact_runtime_pin_digest: _Sha256 = Field(alias="compactRuntimePinDigest")
    compact_transport_pin_digest: _Sha256 = Field(alias="compactTransportPinDigest")
    compact_transport_version: Literal["pajin.web-analysis.compact-provider-transport/v1"] = Field(
        alias="compactTransportVersion"
    )
    worker_action: Literal["openai-chat-completion-v3"] = Field(alias="workerAction")
    worker_image: _ImageID = Field(alias="workerImage")
    proxy_image: _ImageID = Field(alias="proxyImage")
    context_tokens: Literal[4096] = Field(alias="contextTokens")
    maximum_completion_tokens: Literal[1024] = Field(alias="maximumCompletionTokens")
    provider_dispatch_authority: Literal[False] = Field(
        default=False, alias="providerDispatchAuthority"
    )
    target_request_authority: Literal[False] = Field(default=False, alias="targetRequestAuthority")
    tool_request_authority: Literal[False] = Field(default=False, alias="toolRequestAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False, alias="graphAdmissionAuthority"
    )
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")
    retry_authority: Literal[False] = Field(default=False, alias="retryAuthority")

    @field_validator(
        "provider_dispatch_authority",
        "target_request_authority",
        "tool_request_authority",
        "finding_authority",
        "graph_admission_authority",
        "report_authority",
        "retry_authority",
        mode="before",
    )
    @classmethod
    def require_no_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_request(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"request_digest"})
        digest = _domain_digest(
            "pajin.web-analysis.one-call-authorization-request/v2",
            material,
            label="Web analysis one-call authorization request v2",
            max_bytes=_MAX_REQUEST_BYTES,
        )
        if self.request_digest and not compare_digest(self.request_digest, digest):
            raise ValueError("Web analysis authorization request digest differs")
        object.__setattr__(self, "request_digest", digest)
        return self


class WebAnalysisOneCallAuthorizationStatementV2(_FrozenAuthorizationV2Model):
    """Externally issuable grant over one exact compact runtime request."""

    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-statement/v1alpha2"] = (
        Field(
            default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_STATEMENT_V2_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["WebAnalysisOneCallAuthorizationStatementV2"] = (
        "WebAnalysisOneCallAuthorizationStatementV2"
    )
    purpose: Literal["prepared-compact-web-analysis-one-model-completion-v2"] = (
        "prepared-compact-web-analysis-one-model-completion-v2"
    )
    trust_domain: _AuthorityIdentifier = Field(alias="trustDomain")
    issuer: _AuthorityIdentifier
    signing_key_id: _AuthorityIdentifier = Field(alias="signingKeyId")
    nonce: _Nonce
    request: WebAnalysisOneCallAuthorizationRequestV2
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
        issued_at = _aware_utc(self.issued_at, label="authorization issue time")
        not_before = _aware_utc(self.not_before, label="authorization not-before time")
        expires_at = _aware_utc(self.expires_at, label="authorization expiry time")
        if not issued_at <= not_before < expires_at:
            raise ValueError("Web analysis authorization validity window is inconsistent")
        if (expires_at - issued_at).total_seconds() > 180:
            raise ValueError("Web analysis authorization lifetime exceeds 180 seconds")
        return self


class SignedWebAnalysisOneCallAuthorizationV2(_FrozenAuthorizationV2Model):
    """Detached Ed25519 bundle over one v2 statement."""

    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-bundle/v1alpha2"] = Field(
        default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_BUNDLE_V2_API_VERSION, alias="apiVersion"
    )
    kind: Literal["SignedWebAnalysisOneCallAuthorizationV2"] = (
        "SignedWebAnalysisOneCallAuthorizationV2"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _AuthorityIdentifier = Field(alias="keyId")
    statement: WebAnalysisOneCallAuthorizationStatementV2
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def bind_envelope(self) -> Self:
        canonical = _canonical_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization statement v2",
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
        return sha256(
            _canonical_bytes(
                self.model_dump(mode="json", by_alias=True),
                label="signed Web analysis one-call authorization v2",
                max_bytes=_MAX_BUNDLE_BYTES,
            )
        ).hexdigest()


class VerifiedWebAnalysisOneCallAuthorizationV2(_FrozenAuthorizationV2Model):
    """Versioned compact-runtime verification result with no dispatch authority."""

    api_version: Literal["pajin.dev/verified-web-analysis-one-call-authorization/v1alpha2"] = Field(
        default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_VERIFICATION_V2_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["VerifiedWebAnalysisOneCallAuthorizationV2"] = (
        "VerifiedWebAnalysisOneCallAuthorizationV2"
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
    lineage_transport_pin_digest: _Sha256 = Field(alias="lineageTransportPinDigest")
    compact_runtime_pin_digest: _Sha256 = Field(alias="compactRuntimePinDigest")
    compact_transport_pin_digest: _Sha256 = Field(alias="compactTransportPinDigest")
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    evaluated_at: datetime = Field(alias="evaluatedAt")
    expires_at: datetime = Field(alias="expiresAt")
    one_model_completion_grant_count: Literal[1] = Field(alias="oneModelCompletionGrantCount")
    dispatch_count: Literal[0] = Field(default=0, alias="dispatchCount")
    status: Literal["verified-external-compact-one-call-not-claimed-no-dispatch"] = (
        "verified-external-compact-one-call-not-claimed-no-dispatch"
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
    compact_runtime_bound: Literal[True] = Field(default=True, alias="compactRuntimeBound")
    compact_transport_bound: Literal[True] = Field(default=True, alias="compactTransportBound")
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
    target_request_authority: Literal[False] = Field(default=False, alias="targetRequestAuthority")
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
        "compact_runtime_bound",
        "compact_transport_bound",
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
        return _aware_utc(value, label="Web analysis authorization verification time")

    @model_validator(mode="after")
    def bind_verification(self) -> Self:
        if self.evaluated_at >= self.expires_at:
            raise ValueError("Verified Web analysis authorization v2 is not active")
        coordinate = self.coordinate
        if (
            coordinate.issuer != self.issuer
            or coordinate.key_id != self.signing_key_id
            or coordinate.nonce != self.nonce
            or coordinate.authorization_envelope_digest != self.authorization_envelope_digest
        ):
            raise ValueError("Verified Web analysis authorization v2 coordinate differs")
        if self.transport_pin_digest != self.compact_transport_pin_digest:
            raise ValueError("Verified Web analysis authorization v2 transport alias differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verification_id", "verification_digest"},
        )
        digest = _domain_digest(
            "pajin.web-analysis.one-call-authorization-verification/v2",
            material,
            label="verified Web analysis one-call authorization v2",
            max_bytes=_MAX_VERIFICATION_BYTES,
        )
        verification_id = f"web-analysis-one-call-authorization-v2:{digest}"
        if self.verification_digest and not compare_digest(self.verification_digest, digest):
            raise ValueError("Verified Web analysis authorization v2 digest differs")
        if self.verification_id and self.verification_id != verification_id:
            raise ValueError("Verified Web analysis authorization v2 ID differs")
        object.__setattr__(self, "verification_digest", digest)
        object.__setattr__(self, "verification_id", verification_id)
        return self


def build_web_analysis_one_call_authorization_request_v2(
    *,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    capacity_pin: WebAnalysisCapacityV2Pin,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    compact_runtime_pin: CompactWebAnalysisRuntimePin,
    compact_transport_pin: CompactWebAnalysisTransportPin,
) -> WebAnalysisOneCallAuthorizationRequestV2:
    """Build signer-neutral exact bindings; no live or signing authority is created."""

    try:
        exact_admission = _canonical_admission(admission)
        exact_request = _canonical_live_request(live_request)
        exact_capacity = _canonical_capacity_pin(capacity_pin)
        exact_lineage = _canonical_lineage_transport_pin(lineage_transport_pin)
        exact_runtime, exact_transport = verify_compact_web_analysis_live_pin_binding(
            compact_runtime_pin,
            compact_transport_pin,
            capacity=exact_capacity,
            live_request=exact_request,
            lineage_transport_pin=exact_lineage,
            expected_runtime_pin_digest=compact_runtime_pin.pin_digest,
            expected_transport_pin_digest=compact_transport_pin.pin_digest,
        )
        registration = exact_request.provider_registration
        if (
            exact_admission.live_request_digest != exact_request.request_digest
            or exact_admission.provider_registration_digest
            != exact_request.provider_registration_digest
            or exact_admission.provider_chat_request_digest != exact_request.chat_request_digest
            or exact_admission.compact_projection_digest != exact_request.compact_projection_digest
            or exact_admission.capacity_pin_digest != exact_capacity.pin_digest
            or exact_admission.transport_pin_digest != exact_lineage.pin_digest
            or exact_capacity.transport_pin_digest != exact_lineage.pin_digest
            or exact_admission.context_tokens != exact_runtime.context_tokens
            or exact_admission.completion_tokens != exact_runtime.completion_tokens
            or exact_capacity.completion_tokens != 1024
            or exact_request.chat_request.max_completion_tokens != 1024
            or registration.model != exact_capacity.model_id
            or registration.model != exact_runtime.model_id
        ):
            raise ValueError("Web analysis authorization inputs differ")
        return WebAnalysisOneCallAuthorizationRequestV2(
            admissionId=exact_admission.admission_id,
            admissionDigest=exact_admission.admission_digest,
            preparationRunId=exact_admission.preparation_run_id,
            preparationRunRootDigest=exact_admission.preparation_run_root_digest,
            preparationIdentity=exact_admission.preparation_digest,
            preparationIndexDigest=exact_admission.preparation_index_digest,
            liveRequestDigest=exact_request.request_digest,
            providerId=registration.provider_id,
            modelId=registration.model,
            providerRegistrationDigest=exact_request.provider_registration_digest,
            providerChatRequestDigest=exact_request.chat_request_digest,
            compactProjectionDigest=exact_request.compact_projection_digest,
            responseSchemaDigest=exact_admission.response_schema_digest,
            capacityPinDigest=exact_capacity.pin_digest,
            modelPinDigest=exact_capacity.model_pin_digest,
            modelSha256=exact_capacity.model_sha256,
            modelSizeBytes=exact_capacity.model_size_bytes,
            modelImage=exact_capacity.model_image,
            modelPlatformManifest=exact_capacity.model_platform_manifest,
            lineageTransportPinDigest=exact_lineage.pin_digest,
            lineageTransportVersion=exact_lineage.transport_version,
            compactRuntimePinDigest=exact_runtime.pin_digest,
            compactTransportPinDigest=exact_transport.pin_digest,
            compactTransportVersion=exact_transport.transport_version,
            workerAction=exact_transport.worker_action,
            workerImage=exact_transport.worker_image,
            proxyImage=exact_transport.proxy_image,
            contextTokens=exact_runtime.context_tokens,
            maximumCompletionTokens=exact_runtime.completion_tokens,
        )
    except WebAnalysisOneCallAuthorizationError:
        raise
    except Exception as exc:
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis one-call authorization request v2 construction failed closed"
        ) from exc


def build_web_analysis_one_call_authorization_statement_v2(
    request: WebAnalysisOneCallAuthorizationRequestV2,
    *,
    trust_domain: str,
    issuer: str,
    signing_key_id: str,
    nonce: str,
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> WebAnalysisOneCallAuthorizationStatementV2:
    """Assemble an unsigned statement for an external signer."""

    try:
        exact_request = _canonical_request(request)
        return WebAnalysisOneCallAuthorizationStatementV2(
            trustDomain=trust_domain,
            issuer=issuer,
            signingKeyId=signing_key_id,
            nonce=nonce,
            request=exact_request,
            issuedAt=issued_at,
            notBefore=not_before,
            expiresAt=expires_at,
            attempt=1,
            maximumDispatchCount=1,
            oneModelCompletionGrantCount=1,
            toolsAllowed=False,
            streamingAllowed=False,
            targetRequestAuthority=False,
            toolRequestAuthority=False,
            capabilityAuthority=False,
            permitAuthority=False,
            findingAuthority=False,
            graphAdmissionAuthority=False,
            reportAuthority=False,
            deliveryAuthority=False,
            retryAuthority=False,
            scopeExpansionAuthority=False,
            generalExecutionAuthority=False,
            automaticRedispatchAuthority=False,
            campaignApprovalReinterpreted=False,
        )
    except WebAnalysisOneCallAuthorizationError:
        raise
    except Exception as exc:
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis one-call authorization statement v2 construction failed closed"
        ) from exc


def authorization_statement_signing_bytes_v2(
    statement: WebAnalysisOneCallAuthorizationStatementV2,
) -> bytes:
    """Return the domain-separated canonical bytes consumed by an external signer."""

    try:
        if type(statement) is not WebAnalysisOneCallAuthorizationStatementV2:
            raise TypeError("Web analysis authorization requires the exact v2 statement type")
        exact = WebAnalysisOneCallAuthorizationStatementV2.model_validate_json(
            statement.model_dump_json(by_alias=True)
        )
        return _SIGNATURE_DOMAIN_V2 + _canonical_bytes(
            exact.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization statement v2",
            max_bytes=_MAX_BUNDLE_BYTES,
        )
    except WebAnalysisOneCallAuthorizationError:
        raise
    except Exception as exc:
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis one-call authorization signing bytes v2 failed closed"
        ) from exc


def parse_web_analysis_one_call_authorization_request_v2(
    content: bytes,
) -> WebAnalysisOneCallAuthorizationRequestV2:
    """Parse a bounded duplicate-key-rejecting signer-neutral request."""

    try:
        decoded = parse_strict_json_bytes(
            content,
            label="Web analysis one-call authorization request v2",
            max_bytes=_MAX_REQUEST_BYTES,
            max_depth=20,
            max_nodes=20_000,
        )
        canonical = _canonical_bytes(
            decoded,
            label="Web analysis one-call authorization request v2",
            max_bytes=_MAX_REQUEST_BYTES - 1,
        )
        if content != canonical + b"\n":
            raise ValueError(
                "Web analysis one-call authorization request v2 must be canonical JSON plus LF"
            )
        return WebAnalysisOneCallAuthorizationRequestV2.model_validate_json(canonical)
    except WebAnalysisOneCallAuthorizationError:
        raise
    except Exception as exc:
        raise WebAnalysisOneCallAuthorizationError(
            "Web analysis one-call authorization request v2 is invalid"
        ) from exc


def parse_signed_web_analysis_one_call_authorization_v2(
    content: bytes,
) -> SignedWebAnalysisOneCallAuthorizationV2:
    """Parse a bounded duplicate-key-rejecting signed v2 bundle."""

    try:
        decoded = parse_strict_json_bytes(
            content,
            label="signed Web analysis one-call authorization v2",
            max_bytes=_MAX_BUNDLE_BYTES,
            max_depth=24,
            max_nodes=30_000,
        )
        canonical = _canonical_bytes(
            decoded,
            label="signed Web analysis one-call authorization v2",
            max_bytes=_MAX_BUNDLE_BYTES - 1,
        )
        if content != canonical + b"\n":
            raise ValueError(
                "Signed Web analysis one-call authorization v2 must be canonical JSON plus LF"
            )
        return SignedWebAnalysisOneCallAuthorizationV2.model_validate_json(canonical)
    except WebAnalysisOneCallAuthorizationError:
        raise
    except Exception as exc:
        raise WebAnalysisOneCallAuthorizationError(
            "Signed Web analysis one-call authorization v2 is invalid"
        ) from exc


@dataclass(frozen=True, slots=True)
class WebAnalysisOneCallAuthorizationVerifierV2:
    """Pure v2 verifier configured by a separately retained trust-anchor digest."""

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
                raise ValueError("Web analysis authorization trust anchor differs")
            if not callable(self.clock):
                raise TypeError("Web analysis authorization clock must be callable")
            object.__setattr__(self, "trust_anchor", anchor)
        except WebAnalysisOneCallAuthorizationError:
            raise
        except Exception as exc:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization verifier v2 configuration failed closed"
            ) from exc

    def verify(
        self,
        authorization: SignedWebAnalysisOneCallAuthorizationV2,
        *,
        admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
        live_request: CompactSkillBoundWebAnalysisLiveRequest,
        capacity_pin: WebAnalysisCapacityV2Pin,
        lineage_transport_pin: WebAnalysisTransportRuntimePin,
        compact_runtime_pin: CompactWebAnalysisRuntimePin,
        compact_transport_pin: CompactWebAnalysisTransportPin,
    ) -> VerifiedWebAnalysisOneCallAuthorizationV2:
        """Verify one v2 grant without claiming, materializing, or dispatching."""

        try:
            anchor = _canonical_trust_anchor(self.trust_anchor)
            if not compare_digest(anchor.digest, self.expected_trust_anchor_digest):
                raise WebAnalysisOneCallAuthorizationError(
                    "Web analysis authorization trust anchor drifted from its independent digest"
                )
            bundle = _canonical_bundle(authorization)
            expected_request = build_web_analysis_one_call_authorization_request_v2(
                admission=admission,
                live_request=live_request,
                capacity_pin=capacity_pin,
                lineage_transport_pin=lineage_transport_pin,
                compact_runtime_pin=compact_runtime_pin,
                compact_transport_pin=compact_transport_pin,
            )
            if bundle.statement.request != expected_request:
                raise WebAnalysisOneCallAuthorizationError(
                    "Signed Web analysis authorization differs from exact compact live inputs"
                )
            evaluated_at = _aware_utc(self.clock(), label="authorization evaluation time")
            self._verify_issuer_signature_and_validity(
                bundle,
                trust_anchor=anchor,
                evaluated_at=evaluated_at,
            )
            statement = bundle.statement
            request = statement.request
            coordinate = WebAnalysisOneCallAuthorizationCoordinate(
                authorizationEnvelopeDigest=bundle.digest,
                issuer=statement.issuer,
                keyId=bundle.key_id,
                nonce=statement.nonce,
            )
            return VerifiedWebAnalysisOneCallAuthorizationV2(
                trustAnchorDigest=anchor.digest,
                authorizationEnvelopeDigest=bundle.digest,
                statementSha256=bundle.statement_sha256,
                signingKeyId=bundle.key_id,
                issuer=statement.issuer,
                nonce=statement.nonce,
                coordinate=coordinate,
                admissionId=request.admission_id,
                admissionDigest=request.admission_digest,
                preparationIdentity=request.preparation_identity,
                liveRequestDigest=request.live_request_digest,
                providerRegistrationDigest=request.provider_registration_digest,
                providerChatRequestDigest=request.provider_chat_request_digest,
                modelId=request.model_id,
                capacityPinDigest=request.capacity_pin_digest,
                lineageTransportPinDigest=request.lineage_transport_pin_digest,
                compactRuntimePinDigest=request.compact_runtime_pin_digest,
                compactTransportPinDigest=request.compact_transport_pin_digest,
                transportPinDigest=request.compact_transport_pin_digest,
                evaluatedAt=evaluated_at,
                expiresAt=statement.expires_at,
                oneModelCompletionGrantCount=statement.one_model_completion_grant_count,
            )
        except WebAnalysisOneCallAuthorizationError:
            raise
        except Exception as exc:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization verification v2 failed closed"
            ) from exc

    def _verify_issuer_signature_and_validity(
        self,
        bundle: SignedWebAnalysisOneCallAuthorizationV2,
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
        issued_at = _aware_utc(statement.issued_at, label="authorization issue time")
        not_before = _aware_utc(statement.not_before, label="authorization not-before time")
        expires_at = _aware_utc(statement.expires_at, label="authorization expiry time")
        key_not_before = _aware_utc(key.not_before, label="key not-before time")
        if issued_at < key_not_before or not_before < key_not_before:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis authorization predates signing-key validity"
            )
        if key.not_after is not None:
            key_not_after = _aware_utc(key.not_after, label="key not-after time")
            if expires_at > key_not_after or evaluated_at >= key_not_after:
                raise WebAnalysisOneCallAuthorizationError(
                    "Web analysis authorization exceeds signing-key validity"
                )
        if not not_before <= evaluated_at < expires_at:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization is not currently valid"
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
                authorization_statement_signing_bytes_v2(statement),
            )
        except InvalidSignature as exc:
            raise WebAnalysisOneCallAuthorizationError(
                "Web analysis one-call authorization signature verification failed"
            ) from exc


__all__ = [
    "WEB_ANALYSIS_COMPACT_PROVIDER_TRANSPORT_VERSION",
    "WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_BUNDLE_V2_API_VERSION",
    "WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_REQUEST_V2_API_VERSION",
    "WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_STATEMENT_V2_API_VERSION",
    "WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_VERIFICATION_V2_API_VERSION",
    "SignedWebAnalysisOneCallAuthorizationV2",
    "VerifiedWebAnalysisOneCallAuthorizationV2",
    "WebAnalysisOneCallAuthorizationRequestV2",
    "WebAnalysisOneCallAuthorizationStatementV2",
    "WebAnalysisOneCallAuthorizationVerifierV2",
    "authorization_statement_signing_bytes_v2",
    "build_web_analysis_one_call_authorization_request_v2",
    "build_web_analysis_one_call_authorization_statement_v2",
    "parse_signed_web_analysis_one_call_authorization_v2",
    "parse_web_analysis_one_call_authorization_request_v2",
]
