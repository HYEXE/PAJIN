"""Self-contained public-wire contracts for the offline authorization issuer.

This module intentionally depends only on the Python standard library and
Pydantic.  The execution package is an independent consumer of the emitted
wire; importing execution, runtime, journal, Provider, Worker, target, or
receipt code into the private-key process would collapse that boundary.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from hmac import compare_digest
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_TRUST_ANCHOR_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-trust-anchor/v1alpha1"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_REQUEST_V2_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-request/v1alpha2"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_STATEMENT_V2_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-statement/v1alpha2"
)
WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_BUNDLE_V2_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-bundle/v1alpha2"
)

SIGNATURE_DOMAIN_V2: Final = b"pajin.web-analysis.one-call-authorization-statement/v2\0"
MAX_TRUST_ANCHOR_BYTES: Final = 64 * 1024
MAX_REQUEST_BYTES: Final = 512 * 1024
MAX_BUNDLE_BYTES: Final = 768 * 1024

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


class WebAnalysisOneCallAuthorizationKeyState(StrEnum):
    """Lifecycle state represented by the shared public trust-anchor wire."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


def canonical_json_bytes(value: object, *, label: str, max_bytes: int | None = None) -> bytes:
    """Encode the exact compact, sorted, UTF-8 JSON used by the public wire."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if max_bytes is not None and len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the canonical byte limit")
    return encoded


def parse_strict_json_bytes(
    content: bytes,
    *,
    label: str,
    max_bytes: int,
    max_depth: int,
    max_nodes: int,
) -> object:
    """Parse bounded UTF-8 JSON while rejecting duplicate keys and non-finite values."""

    if not isinstance(content, bytes):
        raise TypeError(f"{label} content must be bytes")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if type(max_depth) is not int or max_depth < 0:
        raise ValueError("max_depth must be a non-negative integer")
    if type(max_nodes) is not int or max_nodes < 1:
        raise ValueError("max_nodes must be a positive integer")
    if len(content) > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte limit")
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    _preflight_json_structure(
        text,
        label=label,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> NoReturn:
        raise ValueError(f"non-finite JSON constant is forbidden: {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite JSON number is forbidden")
        return parsed

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    _validate_decoded_json(
        decoded,
        label=label,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    return decoded


def _preflight_json_structure(
    text: str,
    *,
    label: str,
    max_depth: int,
    max_nodes: int,
) -> None:
    stack: list[str] = []
    tokens = 0
    index = 0
    while index < len(text):
        character = text[index]
        if character.isspace() or character in {",", ":"}:
            index += 1
            continue
        if character == '"':
            index += 1
            closed = False
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    closed = True
                    break
                index += 1
            if not closed:
                raise ValueError(f"{label} is not strict JSON")
            tokens += 1
        elif character in {"{", "["}:
            if len(stack) > max_depth:
                raise ValueError(f"{label} exceeds the JSON nesting-depth limit")
            stack.append(character)
            tokens += 1
            index += 1
        elif character in {"}", "]"}:
            expected = "{" if character == "}" else "["
            if not stack or stack.pop() != expected:
                raise ValueError(f"{label} is not strict JSON")
            index += 1
            continue
        else:
            while index < len(text) and not (text[index].isspace() or text[index] in "{}[],:"):
                index += 1
            tokens += 1
        if tokens > max_nodes:
            raise ValueError(f"{label} exceeds the JSON node-count limit")
    if stack:
        raise ValueError(f"{label} is not strict JSON")


def _validate_decoded_json(
    decoded: object,
    *,
    label: str,
    max_depth: int,
    max_nodes: int,
) -> None:
    stack: list[tuple[object, int]] = [(decoded, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(f"{label} exceeds the JSON node-count limit")
        if depth > max_depth:
            raise ValueError(f"{label} exceeds the JSON nesting-depth limit")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif (
            value is None
            or isinstance(value, (str, bool, int))
            or (isinstance(value, float) and math.isfinite(value))
        ):
            continue
        else:  # pragma: no cover - stdlib JSON decoder shape invariant
            raise ValueError(f"{label} contains a non-JSON value")


def _domain_digest(domain: str, value: object, *, label: str, max_bytes: int) -> str:
    wire = canonical_json_bytes(value, label=label, max_bytes=max_bytes)
    return sha256(domain.encode("ascii", errors="strict") + b"\0" + wire).hexdigest()


def _aware_utc(value: datetime, *, label: str) -> datetime:
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


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis authorization authority markers must be literal false")
    return False


def _literal_one(value: object) -> Literal[1]:
    if type(value) is not int or value != 1:
        raise ValueError("Web analysis authorization one-call counts must be exact integer one")
    return 1


class _FrozenAuthorizationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class WebAnalysisOneCallAuthorizationVerificationKey(_FrozenAuthorizationModel):
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
        not_before = _aware_utc(self.not_before, label="key not-before time")
        if self.not_after is not None:
            not_after = _aware_utc(self.not_after, label="key not-after time")
            if not_after <= not_before:
                raise ValueError("Web analysis authorization key validity window is empty")
        if self.state is WebAnalysisOneCallAuthorizationKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired Web analysis authorization key requires notAfter")
        if self.state is WebAnalysisOneCallAuthorizationKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Web analysis authorization key requires revokedAt")
            revoked_at = _aware_utc(self.revoked_at, label="key revocation time")
            if revoked_at < not_before:
                raise ValueError("Web analysis authorization key revocation predates validity")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked Web analysis authorization key cannot have revokedAt")
        return self


class WebAnalysisOneCallAuthorizationTrustAnchor(_FrozenAuthorizationModel):
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
            max_bytes=MAX_TRUST_ANCHOR_BYTES,
        )


class WebAnalysisOneCallAuthorizationRequestV2(_FrozenAuthorizationModel):
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
        default=False,
        alias="providerDispatchAuthority",
    )
    target_request_authority: Literal[False] = Field(default=False, alias="targetRequestAuthority")
    tool_request_authority: Literal[False] = Field(default=False, alias="toolRequestAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthority",
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
            max_bytes=MAX_REQUEST_BYTES,
        )
        if self.request_digest and not compare_digest(self.request_digest, digest):
            raise ValueError("Web analysis authorization request digest differs")
        object.__setattr__(self, "request_digest", digest)
        return self


class WebAnalysisOneCallAuthorizationStatementV2(_FrozenAuthorizationModel):
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


class SignedWebAnalysisOneCallAuthorizationV2(_FrozenAuthorizationModel):
    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-bundle/v1alpha2"] = Field(
        default=WEB_ANALYSIS_ONE_CALL_AUTHORIZATION_BUNDLE_V2_API_VERSION,
        alias="apiVersion",
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
        canonical = canonical_json_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization statement v2",
            max_bytes=MAX_BUNDLE_BYTES,
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
            canonical_json_bytes(
                self.model_dump(mode="json", by_alias=True),
                label="signed Web analysis one-call authorization v2",
                max_bytes=MAX_BUNDLE_BYTES,
            )
        ).hexdigest()


def parse_web_analysis_one_call_authorization_trust_anchor(
    content: bytes,
) -> WebAnalysisOneCallAuthorizationTrustAnchor:
    decoded = parse_strict_json_bytes(
        content,
        label="Web analysis one-call authorization trust anchor",
        max_bytes=MAX_TRUST_ANCHOR_BYTES,
        max_depth=12,
        max_nodes=2_000,
    )
    canonical = canonical_json_bytes(
        decoded,
        label="Web analysis one-call authorization trust anchor",
        max_bytes=MAX_TRUST_ANCHOR_BYTES,
    )
    return WebAnalysisOneCallAuthorizationTrustAnchor.model_validate_json(canonical)


def parse_web_analysis_one_call_authorization_request_v2(
    content: bytes,
) -> WebAnalysisOneCallAuthorizationRequestV2:
    decoded = parse_strict_json_bytes(
        content,
        label="Web analysis one-call authorization request v2",
        max_bytes=MAX_REQUEST_BYTES,
        max_depth=20,
        max_nodes=20_000,
    )
    canonical = canonical_json_bytes(
        decoded,
        label="Web analysis one-call authorization request v2",
        max_bytes=MAX_REQUEST_BYTES - 1,
    )
    if content != canonical + b"\n":
        raise ValueError(
            "Web analysis one-call authorization request v2 must be canonical JSON plus LF"
        )
    return WebAnalysisOneCallAuthorizationRequestV2.model_validate_json(canonical)


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
    if type(request) is not WebAnalysisOneCallAuthorizationRequestV2:
        raise TypeError("Web analysis authorization requires the exact offline v2 request type")
    exact_request = WebAnalysisOneCallAuthorizationRequestV2.model_validate_json(
        request.model_dump_json(by_alias=True)
    )
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


def authorization_statement_signing_bytes_v2(
    statement: WebAnalysisOneCallAuthorizationStatementV2,
) -> bytes:
    if type(statement) is not WebAnalysisOneCallAuthorizationStatementV2:
        raise TypeError("Web analysis authorization requires the exact offline v2 statement type")
    exact = WebAnalysisOneCallAuthorizationStatementV2.model_validate_json(
        statement.model_dump_json(by_alias=True)
    )
    return SIGNATURE_DOMAIN_V2 + canonical_json_bytes(
        exact.model_dump(mode="json", by_alias=True),
        label="Web analysis one-call authorization statement v2",
        max_bytes=MAX_BUNDLE_BYTES,
    )


__all__ = [
    "MAX_BUNDLE_BYTES",
    "MAX_REQUEST_BYTES",
    "MAX_TRUST_ANCHOR_BYTES",
    "SignedWebAnalysisOneCallAuthorizationV2",
    "WebAnalysisOneCallAuthorizationKeyState",
    "WebAnalysisOneCallAuthorizationRequestV2",
    "WebAnalysisOneCallAuthorizationStatementV2",
    "WebAnalysisOneCallAuthorizationTrustAnchor",
    "WebAnalysisOneCallAuthorizationVerificationKey",
    "authorization_statement_signing_bytes_v2",
    "build_web_analysis_one_call_authorization_statement_v2",
    "canonical_json_bytes",
    "parse_strict_json_bytes",
    "parse_web_analysis_one_call_authorization_request_v2",
    "parse_web_analysis_one_call_authorization_trust_anchor",
]
