"""Deployment-pinned OIDC human identity admission for the Control Plane."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.security import AuthenticationError
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes

_MAX_POLICY_BYTES = 256 * 1024
_MAX_TOKEN_BYTES = 16 * 1024
_MAX_JWT_HEADER_BYTES = 2 * 1024
_MAX_JWT_CLAIMS_BYTES = 12 * 1024
_MAX_RSA_PUBLIC_KEY_BYTES = 2 * 1024
_MAX_NUMERIC_DATE = 253_402_300_799
_JWT_HEADER_KEYS = frozenset({"alg", "kid", "typ"})
_ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class OIDCVerificationKeyState(StrEnum):
    """Lifecycle state of one deployment-pinned authorization-server key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, max_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > max_bytes * 2:
        raise ValueError(f"{label} must be bounded canonical base64url")
    padding_bytes = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            value + padding_bytes,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be bounded canonical base64url") from exc
    if len(decoded) > max_bytes or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be bounded canonical base64url")
    return decoded


def _require_aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _load_rsa_public_key(value: str) -> rsa.RSAPublicKey:
    encoded = _base64url_decode(
        value,
        max_bytes=_MAX_RSA_PUBLIC_KEY_BYTES,
        label="OIDC verification public key",
    )
    try:
        public_key = serialization.load_der_public_key(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("OIDC verification key must be DER SubjectPublicKeyInfo") from exc
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
        raise ValueError("OIDC RS256 verification key must be RSA with at least 2048 bits")
    return public_key


class OIDCVerificationKey(_FrozenStrictModel):
    """One RS256 key pinned by deployment policy instead of token-controlled URLs."""

    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    algorithm: Literal["RS256"] = "RS256"
    public_key_spki_base64url: str = Field(min_length=1, max_length=3_000)
    state: OIDCVerificationKeyState
    not_before: datetime
    not_after: datetime | None = None
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def require_valid_key_and_lifecycle(self) -> Self:
        _load_rsa_public_key(self.public_key_spki_base64url)
        not_before = _require_aware_utc(self.not_before, label="OIDC key not-before time")
        if self.not_after is not None:
            not_after = _require_aware_utc(self.not_after, label="OIDC key not-after time")
            if not_after <= not_before:
                raise ValueError("OIDC verification key validity window is empty")
        if self.state is OIDCVerificationKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired OIDC verification key requires not_after")
        if self.state is OIDCVerificationKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked OIDC verification key requires revoked_at")
            _require_aware_utc(self.revoked_at, label="OIDC key revocation time")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked OIDC verification key cannot have revoked_at")
        return self


class OIDCHumanIdentityMapping(_FrozenStrictModel):
    """Deployment-owned mapping from one provider subject to local authority."""

    provider_subject: str = Field(pattern=r"^[\x21-\x7e]{1,255}$")
    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    roles: frozenset[PrincipalRole] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def require_human_separation_of_duties(self) -> Self:
        if PrincipalRole.WORKER in self.roles:
            raise ValueError("OIDC human identities cannot receive Worker authority")
        if {PrincipalRole.OPERATOR, PrincipalRole.APPROVER} <= self.roles:
            raise ValueError("OIDC identity cannot combine operator and approver authority")
        return self

    def principal(self) -> Principal:
        return Principal(subject=self.principal_subject, roles=self.roles)


class OIDCHumanTrustPolicy(_FrozenStrictModel):
    """Versioned offline trust and MFA policy for JWT access-token admission."""

    api_version: Literal["pajin.control-plane.oidc-human-trust-policy/v1"] = (
        "pajin.control-plane.oidc-human-trust-policy/v1"
    )
    policy_id: str = Field(pattern=r"^oidc-human-policy_[0-9a-f]{32}$")
    issuer: str = Field(min_length=1, max_length=500)
    audience: str = Field(pattern=r"^[\x21-\x7e]{1,500}$")
    client_id: str = Field(pattern=r"^[\x21-\x7e]{1,200}$")
    required_scope: str = Field(pattern=r"^[\x21-\x7e]{1,200}$")
    required_acr: str = Field(pattern=r"^[\x21-\x7e]{1,500}$")
    required_amr: frozenset[str] = Field(min_length=1, max_length=8)
    maximum_token_lifetime_seconds: int = Field(ge=60, le=3_600)
    maximum_authentication_age_seconds: int = Field(ge=60, le=86_400)
    clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    keys: tuple[OIDCVerificationKey, ...] = Field(min_length=1, max_length=32)
    identities: tuple[OIDCHumanIdentityMapping, ...] = Field(min_length=1, max_length=256)

    @field_validator("issuer")
    @classmethod
    def require_https_issuer(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("OIDC issuer must be an absolute credential-free HTTPS URL") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.netloc
            or any(character.isspace() for character in value)
            or port == 0
        ):
            raise ValueError("OIDC issuer must be an absolute credential-free HTTPS URL")
        return value

    @field_validator("required_amr")
    @classmethod
    def require_bounded_amr_values(cls, value: frozenset[str]) -> frozenset[str]:
        if any(
            not isinstance(item, str)
            or not item
            or len(item) > 100
            or any(not 0x21 <= ord(character) <= 0x7E for character in item)
            for item in value
        ):
            raise ValueError("required OIDC amr values must be bounded visible ASCII")
        return value

    @model_validator(mode="after")
    def require_unique_authorities(self) -> Self:
        key_ids = [key.key_id for key in self.keys]
        if len(key_ids) != len(set(key_ids)):
            raise ValueError("OIDC verification key IDs must be unique")
        provider_subjects = [identity.provider_subject for identity in self.identities]
        if len(provider_subjects) != len(set(provider_subjects)):
            raise ValueError("OIDC provider subjects must be unique")
        principal_subjects = [identity.principal_subject for identity in self.identities]
        if len(principal_subjects) != len(set(principal_subjects)):
            raise ValueError("OIDC principal subjects must be unique")
        return self


def parse_oidc_human_trust_policy(content: bytes) -> OIDCHumanTrustPolicy:
    """Parse one bounded strict-JSON deployment policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="OIDC human trust policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=24,
        max_nodes=8_192,
    )
    return OIDCHumanTrustPolicy.model_validate(decoded)


class OIDCHumanAuthenticator:
    """Verify one RFC 9068-shaped, MFA-bound access token without network I/O."""

    def __init__(
        self,
        policy: OIDCHumanTrustPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(UTC))
        self._keys = {key.key_id: key for key in policy.keys}
        self._identities = {
            identity.provider_subject: identity.principal() for identity in policy.identities
        }

    def authenticate(self, token: str) -> Principal:
        try:
            return self._authenticate(token)
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise AuthenticationError("invalid bearer credential") from exc

    def _authenticate(self, token: str) -> Principal:  # noqa: C901
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= _MAX_TOKEN_BYTES
            or any(not 0x21 <= ord(character) <= 0x7E for character in token)
        ):
            raise ValueError("OIDC access token is invalid")
        segments = token.split(".")
        if len(segments) != 3 or any(not segment for segment in segments):
            raise ValueError("OIDC access token is not compact JWS")
        header_bytes = _base64url_decode(
            segments[0],
            max_bytes=_MAX_JWT_HEADER_BYTES,
            label="OIDC access-token header",
        )
        claims_bytes = _base64url_decode(
            segments[1],
            max_bytes=_MAX_JWT_CLAIMS_BYTES,
            label="OIDC access-token claims",
        )
        header = parse_strict_json_bytes(
            header_bytes,
            label="OIDC access-token header",
            max_bytes=_MAX_JWT_HEADER_BYTES,
            max_depth=4,
            max_nodes=32,
        )
        claims = parse_strict_json_bytes(
            claims_bytes,
            label="OIDC access-token claims",
            max_bytes=_MAX_JWT_CLAIMS_BYTES,
            max_depth=8,
            max_nodes=512,
        )
        if not isinstance(header, dict) or set(header) != _JWT_HEADER_KEYS:
            raise ValueError("OIDC access-token header is not the supported profile")
        token_type = header.get("typ")
        if (
            header.get("alg") != "RS256"
            or not isinstance(token_type, str)
            or token_type.lower() not in _ACCESS_TOKEN_TYPES
        ):
            raise ValueError("OIDC access-token header is not the supported profile")
        key_id = header.get("kid")
        if not isinstance(key_id, str):
            raise ValueError("OIDC access token has no trusted key ID")
        key = self._keys.get(key_id)
        if key is None or key.state is OIDCVerificationKeyState.REVOKED:
            raise ValueError("OIDC access token has no trusted key")
        public_key = _load_rsa_public_key(key.public_key_spki_base64url)
        signature = _base64url_decode(
            segments[2],
            max_bytes=public_key.key_size // 8,
            label="OIDC access-token signature",
        )
        if len(signature) != public_key.key_size // 8:
            raise ValueError("OIDC access-token signature has the wrong length")
        public_key.verify(
            signature,
            f"{segments[0]}.{segments[1]}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        if not isinstance(claims, dict):
            raise ValueError("OIDC access-token claims must be an object")

        now = _require_aware_utc(self._clock(), label="OIDC verifier clock")
        now_timestamp = int(now.timestamp())
        skew = self._policy.clock_skew_seconds
        issued_at = _numeric_date(claims, "iat")
        expires_at = _numeric_date(claims, "exp")
        authenticated_at = _numeric_date(claims, "auth_time")
        not_before = _optional_numeric_date(claims, "nbf")
        if issued_at > now_timestamp + skew or expires_at <= now_timestamp - skew:
            raise ValueError("OIDC access token is not currently valid")
        if not_before is not None and not_before > now_timestamp + skew:
            raise ValueError("OIDC access token is not currently valid")
        if expires_at <= issued_at:
            raise ValueError("OIDC access-token lifetime is empty")
        if expires_at - issued_at > self._policy.maximum_token_lifetime_seconds:
            raise ValueError("OIDC access-token lifetime exceeds policy")
        if authenticated_at > issued_at:
            raise ValueError("OIDC authentication time is after token issuance")
        if now_timestamp - authenticated_at > (
            self._policy.maximum_authentication_age_seconds + skew
        ):
            raise ValueError("OIDC authentication is too old")
        key_not_before = int(_require_aware_utc(key.not_before, label="OIDC key time").timestamp())
        if issued_at < key_not_before:
            raise ValueError("OIDC token predates its verification key")
        if key.not_after is not None:
            key_not_after = int(
                _require_aware_utc(key.not_after, label="OIDC key time").timestamp()
            )
            if issued_at >= key_not_after:
                raise ValueError("OIDC token was issued after key retirement")

        if claims.get("iss") != self._policy.issuer:
            raise ValueError("OIDC token issuer does not match policy")
        audience = claims.get("aud")
        if audience != self._policy.audience and audience != [self._policy.audience]:
            raise ValueError("OIDC token audience does not match policy")
        if claims.get("client_id") != self._policy.client_id:
            raise ValueError("OIDC token client does not match policy")
        if claims.get("acr") != self._policy.required_acr:
            raise ValueError("OIDC token authentication context does not match policy")
        amr = claims.get("amr")
        if (
            not isinstance(amr, list)
            or not amr
            or any(not isinstance(item, str) or not item for item in amr)
            or len(amr) != len(set(amr))
            or not self._policy.required_amr.issubset(amr)
        ):
            raise ValueError("OIDC token authentication methods do not match policy")
        scope = claims.get("scope")
        if not isinstance(scope, str):
            raise ValueError("OIDC token scope is missing")
        scopes = scope.split(" ")
        if (
            not scopes
            or any(not item for item in scopes)
            or len(scopes) != len(set(scopes))
            or self._policy.required_scope not in scopes
        ):
            raise ValueError("OIDC token scope does not match policy")
        jti = claims.get("jti")
        if (
            not isinstance(jti, str)
            or not 1 <= len(jti) <= 256
            or any(not 0x21 <= ord(character) <= 0x7E for character in jti)
        ):
            raise ValueError("OIDC token ID is invalid")
        subject = claims.get("sub")
        if not isinstance(subject, str):
            raise ValueError("OIDC token subject is invalid")
        principal = self._identities.get(subject)
        if principal is None:
            raise ValueError("OIDC token subject is not registered")
        return principal


def _numeric_date(claims: dict[str, object], name: str) -> int:
    value = claims.get(name)
    if type(value) is not int or not 0 <= value <= _MAX_NUMERIC_DATE:
        raise ValueError(f"OIDC {name} claim must be a bounded integer NumericDate")
    return value


def _optional_numeric_date(claims: dict[str, object], name: str) -> int | None:
    if name not in claims:
        return None
    return _numeric_date(claims, name)
