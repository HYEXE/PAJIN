"""Target-issued, challenge-bound receipts for exact Replay HTTP exchanges."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes

_SIGNATURE_DOMAIN = b"pajin.replay.target-execution-receipt/v1\0"
_CHALLENGE_DOMAIN = b"pajin.replay.target-execution-challenge/v1\0"


def canonical_target_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_target_json_sha256(value: object) -> str:
    return sha256(canonical_target_json(value)).hexdigest()


def _require_aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


class TargetAttestationKeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class TargetAttestationVerificationKey(StrictModel):
    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    state: TargetAttestationKeyState
    not_before: datetime
    not_after: datetime | None = None
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="target attestation public key",
        )
        not_before = _require_aware_utc(self.not_before, label="key not-before time")
        if self.not_after is not None:
            not_after = _require_aware_utc(self.not_after, label="key not-after time")
            if not_after <= not_before:
                raise ValueError("target attestation key validity window is empty")
        if self.state is TargetAttestationKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired target attestation key requires not_after")
        if self.state is TargetAttestationKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked target attestation key requires revoked_at")
            _require_aware_utc(self.revoked_at, label="key revocation time")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked target attestation key cannot have revoked_at")
        return self


class TargetAttestationTrustAnchor(StrictModel):
    api_version: Literal["pajin.replay.target-attestation-trust-anchor/v1"] = (
        "pajin.replay.target-attestation-trust-anchor/v1"
    )
    trust_domain: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    issuer: str = Field(min_length=1, max_length=200)
    target_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    keys: list[TargetAttestationVerificationKey] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def require_unique_sorted_keyring(self) -> Self:
        key_ids = [key.key_id for key in self.keys]
        if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)):
            raise ValueError("target attestation keys must be uniquely sorted")
        if len([key for key in self.keys if key.state is TargetAttestationKeyState.ACTIVE]) != 1:
            raise ValueError("target attestation trust anchor requires one active key")
        return self

    @property
    def digest(self) -> str:
        return canonical_target_json_sha256(self.model_dump(mode="json"))


class TargetAttestationTrustRegistryEntry(StrictModel):
    """One exact Target URL route to one independently versioned trust anchor."""

    target: str = Field(min_length=1, max_length=2_000)
    trust_anchor: TargetAttestationTrustAnchor

    @field_validator("target")
    @classmethod
    def require_canonical_exact_target(cls, value: str) -> str:
        # Local import avoids the policy package's ToolSpec import cycle.
        from pajin.policy.scope import normalize_target_url

        if normalize_target_url(value) != value:
            raise ValueError("target trust registry route must use a canonical exact URL")
        return value

    @property
    def target_sha256(self) -> str:
        return sha256(self.target.encode("utf-8")).hexdigest()


class TargetAttestationTrustRegistry(StrictModel):
    """Versioned, fail-closed mapping from exact Target URLs to public anchors."""

    api_version: Literal["pajin.replay.target-attestation-trust-registry/v1"] = (
        "pajin.replay.target-attestation-trust-registry/v1"
    )
    registry_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    entries: list[TargetAttestationTrustRegistryEntry] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_unique_sorted_routes(self) -> Self:
        targets = [entry.target for entry in self.entries]
        if targets != sorted(targets) or len(targets) != len(set(targets)):
            raise ValueError("target trust registry routes must be uniquely sorted")
        return self

    def resolve(self, target: str) -> TargetAttestationTrustAnchor:
        for entry in self.entries:
            if entry.target == target:
                return entry.trust_anchor
        raise ValueError("target is absent from the exact trust registry")

    @property
    def digest(self) -> str:
        return canonical_target_json_sha256(self.model_dump(mode="json"))


class TargetExecutionChallenge(StrictModel):
    """Control Plane challenge derived from one durable Replay Tool permit."""

    api_version: Literal["pajin.replay.target-execution-challenge/v1"] = (
        "pajin.replay.target-execution-challenge/v1"
    )
    challenge_id: str = Field(pattern=r"^target-challenge_[a-f0-9]{32}$")
    permit_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    replay_request_id: str = Field(pattern=r"^tool_replay_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    call_ordinal: int = Field(strict=True, ge=1, le=20)
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    method: Literal["POST"]
    compiled_argument_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def require_fresh_canonical_identity(self) -> Self:
        issued_at = _require_aware_utc(self.issued_at, label="target challenge issue time")
        expires_at = _require_aware_utc(self.expires_at, label="target challenge expiry time")
        if not issued_at < expires_at <= issued_at + timedelta(seconds=30):
            raise ValueError("target execution challenge must have a bounded 30-second lifetime")
        material = self.model_dump(
            mode="json",
            exclude={"challenge_id"},
        )
        expected = (
            "target-challenge_"
            + sha256(_CHALLENGE_DOMAIN + canonical_target_json(material)).hexdigest()[:32]
        )
        if self.challenge_id != expected:
            raise ValueError("target execution challenge identity is inconsistent")
        return self

    @property
    def digest(self) -> str:
        return canonical_target_json_sha256(self.model_dump(mode="json"))


def derive_target_execution_challenge(
    *,
    permit_digest: str,
    replay_request_id: str,
    batch_id: str,
    item_id: str,
    ticket_id: str,
    fencing_value: int,
    call_ordinal: int,
    target: str,
    method: str,
    compiled_argument_digest: str,
    issued_at: datetime,
    expires_at: datetime,
) -> TargetExecutionChallenge:
    normalized_issued_at = _require_aware_utc(
        issued_at,
        label="target challenge issue time",
    )
    normalized_expires_at = _require_aware_utc(
        expires_at,
        label="target challenge expiry time",
    )
    target_sha256 = sha256(target.encode("utf-8")).hexdigest()
    if method.upper() != "POST":
        raise ValueError("target execution challenge requires POST")
    normalized_method: Literal["POST"] = "POST"
    provisional = TargetExecutionChallenge.model_construct(
        challenge_id=f"target-challenge_{'0' * 32}",
        permit_digest=permit_digest,
        replay_request_id=replay_request_id,
        batch_id=batch_id,
        item_id=item_id,
        ticket_id=ticket_id,
        fencing_value=fencing_value,
        call_ordinal=call_ordinal,
        target_sha256=target_sha256,
        method=normalized_method,
        compiled_argument_digest=compiled_argument_digest,
        issued_at=normalized_issued_at,
        expires_at=normalized_expires_at,
    )
    material = provisional.model_dump(mode="json", exclude={"challenge_id"})
    challenge_id = (
        "target-challenge_"
        + sha256(_CHALLENGE_DOMAIN + canonical_target_json(material)).hexdigest()[:32]
    )
    return TargetExecutionChallenge(
        challenge_id=challenge_id,
        permit_digest=permit_digest,
        replay_request_id=replay_request_id,
        batch_id=batch_id,
        item_id=item_id,
        ticket_id=ticket_id,
        fencing_value=fencing_value,
        call_ordinal=call_ordinal,
        target_sha256=target_sha256,
        method=normalized_method,
        compiled_argument_digest=compiled_argument_digest,
        issued_at=normalized_issued_at,
        expires_at=normalized_expires_at,
    )


class TargetExecutionReceiptStatement(StrictModel):
    api_version: Literal["pajin.replay.target-execution-statement/v1"] = (
        "pajin.replay.target-execution-statement/v1"
    )
    predicate_type: Literal["pajin.replay.target-observed-http-exchange/v1"] = (
        "pajin.replay.target-observed-http-exchange/v1"
    )
    trust_domain: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    issuer: str = Field(min_length=1, max_length=200)
    target_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    challenge_id: str = Field(pattern=r"^target-challenge_[a-f0-9]{32}$")
    challenge_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    permit_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    replay_request_id: str = Field(pattern=r"^tool_replay_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    call_ordinal: int = Field(strict=True, ge=1, le=20)
    exchange_ordinal: int = Field(strict=True, ge=1, le=20)
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    method: Literal["POST"]
    request_json_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal[200] = 200
    issued_at: datetime

    @model_validator(mode="after")
    def require_aware_issue_time(self) -> Self:
        _require_aware_utc(self.issued_at, label="target receipt issue time")
        return self


class TargetExecutionReceipt(StrictModel):
    api_version: Literal["pajin.replay.target-execution-receipt/v1"] = (
        "pajin.replay.target-execution-receipt/v1"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    statement: TargetExecutionReceiptStatement
    statement_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_base64url: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_target_json(self.statement.model_dump(mode="json"))
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("target receipt statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="target receipt signature",
        )
        return self

    @property
    def digest(self) -> str:
        return canonical_target_json_sha256(self.model_dump(mode="json"))


class TargetExecutionProxyBinding(StrictModel):
    """Executor-signed binding between one Target receipt and one host proxy receipt."""

    api_version: Literal["pajin.replay.target-proxy-binding/v1"] = (
        "pajin.replay.target-proxy-binding/v1"
    )
    replay_request_id: str = Field(pattern=r"^tool_replay_[0-9a-f]{32}$")
    exchange_ordinal: int = Field(strict=True, ge=1, le=20)
    challenge_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_receipt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    proxy_sequence: int = Field(strict=True, ge=1, le=100)
    proxy_method: Literal["POST"]
    proxy_target: str = Field(min_length=1, max_length=2_000)
    proxy_target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    proxy_address: str = Field(min_length=1, max_length=100)
    proxy_status: int = Field(strict=True, ge=200, le=299)
    proxy_request_json_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    proxy_response_body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    proxy_response_json_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @property
    def digest(self) -> str:
        return canonical_target_json_sha256(self.model_dump(mode="json"))


class TargetExecutionTLSBinding(StrictModel):
    """Executor-signed join of opaque TLS routing and Target-signed application data."""

    api_version: Literal["pajin.replay.target-tls-binding/v1"] = (
        "pajin.replay.target-tls-binding/v1"
    )
    replay_request_id: str = Field(pattern=r"^tool_replay_[0-9a-f]{32}$")
    exchange_ordinal: int = Field(strict=True, ge=1, le=20)
    challenge_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_receipt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    connect_sequence: int = Field(strict=True, ge=1, le=100)
    connect_authority: str = Field(min_length=3, max_length=300)
    connect_authority_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    connect_address: str = Field(min_length=1, max_length=100)
    application_method: Literal["POST"]
    transcript_request_json_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    transcript_response_json_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @property
    def digest(self) -> str:
        return canonical_target_json_sha256(self.model_dump(mode="json"))


TargetExecutionTransportBinding = TargetExecutionProxyBinding | TargetExecutionTLSBinding


class TargetExecutionVerificationSummary(StrictModel):
    valid: Literal[True] = True
    trust_anchor_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    trust_registry_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$",
        exclude_if=lambda value: value is None,
    )
    trust_registry_digest: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        exclude_if=lambda value: value is None,
    )
    proof_set_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_count: int = Field(strict=True, ge=1, le=400)
    receipt_digests: list[str] = Field(min_length=1, max_length=400)
    key_ids: list[str] = Field(min_length=1, max_length=32)

    @field_validator("receipt_digests")
    @classmethod
    def require_receipt_digests(cls, value: list[str]) -> list[str]:
        if any(
            len(item) != 64 or any(character not in "0123456789abcdef" for character in item)
            for item in value
        ):
            raise ValueError("target receipt digests must be lowercase SHA-256")
        if len(value) != len(set(value)):
            raise ValueError("target receipt digests must be unique")
        return value

    @field_validator("key_ids")
    @classmethod
    def require_sorted_key_ids(cls, value: list[str]) -> list[str]:
        if value != sorted(value) or len(value) != len(set(value)):
            raise ValueError("target receipt key IDs must be uniquely sorted")
        return value

    @model_validator(mode="after")
    def require_exact_count(self) -> Self:
        if self.receipt_count != len(self.receipt_digests):
            raise ValueError("target receipt count differs from its digest set")
        if (self.trust_registry_id is None) != (self.trust_registry_digest is None):
            raise ValueError("target trust registry identity and digest must be present together")
        return self

    @property
    def digest(self) -> str:
        return canonical_target_json_sha256(self.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class TargetExecutionAttestor:
    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: TargetAttestationTrustAnchor
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: TargetAttestationTrustAnchor,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> TargetExecutionAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 target attestation private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
            clock=clock,
        )

    def __post_init__(self) -> None:
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if len(matching) != 1 or matching[0].state is not TargetAttestationKeyState.ACTIVE:
            raise ValueError("target signer key is not the active trust-anchor key")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="target attestation active public key",
        )
        if public_bytes != expected:
            raise ValueError("target private key does not match its trust anchor")

    def attest(
        self,
        statement_fields: dict[str, object],
        *,
        issued_at: datetime | None = None,
    ) -> TargetExecutionReceipt:
        timestamp = _require_aware_utc(
            issued_at or self.clock(),
            label="target receipt issue time",
        )
        active_key = next(key for key in self.trust_anchor.keys if key.key_id == self.active_key_id)
        if timestamp < _require_aware_utc(active_key.not_before, label="key not-before time"):
            raise ValueError("target signing key is not valid at the issue time")
        if active_key.not_after is not None and timestamp >= _require_aware_utc(
            active_key.not_after,
            label="key not-after time",
        ):
            raise ValueError("target signing key is not valid at the issue time")
        statement = TargetExecutionReceiptStatement.model_validate(
            {
                **statement_fields,
                "trust_domain": self.trust_anchor.trust_domain,
                "issuer": self.trust_anchor.issuer,
                "target_profile": self.trust_anchor.target_profile,
                "issued_at": timestamp,
            }
        )
        canonical = canonical_target_json(statement.model_dump(mode="json"))
        return TargetExecutionReceipt(
            key_id=self.active_key_id,
            statement=statement,
            statement_sha256=sha256(canonical).hexdigest(),
            signature_base64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


def target_public_key_base64url(private_key: bytes) -> str:
    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def target_private_key_bytes_from_base64url(value: str) -> bytes:
    return _base64url_decode(
        value,
        expected_length=32,
        label="Ed25519 target attestation private key",
    )


def parse_target_attestation_trust_anchor(
    content: bytes,
) -> TargetAttestationTrustAnchor:
    decoded = parse_strict_json_bytes(
        content,
        label="target attestation trust anchor",
        max_bytes=64 * 1024,
        max_depth=12,
        max_nodes=2_000,
    )
    return TargetAttestationTrustAnchor.model_validate(decoded)


def parse_target_attestation_trust_registry(
    content: bytes,
) -> TargetAttestationTrustRegistry:
    decoded = parse_strict_json_bytes(
        content,
        label="target attestation trust registry",
        max_bytes=512 * 1024,
        max_depth=16,
        max_nodes=20_000,
    )
    return TargetAttestationTrustRegistry.model_validate(decoded)


def verify_target_execution_receipt(
    receipt: TargetExecutionReceipt,
    *,
    trust_anchor: TargetAttestationTrustAnchor,
) -> str:
    statement = receipt.statement
    if (
        statement.trust_domain != trust_anchor.trust_domain
        or statement.issuer != trust_anchor.issuer
        or statement.target_profile != trust_anchor.target_profile
    ):
        raise ValueError("target receipt issuer, profile, or trust domain is not trusted")
    key = next((item for item in trust_anchor.keys if item.key_id == receipt.key_id), None)
    if key is None:
        raise ValueError("target receipt key is absent from the trust anchor")
    if key.state is TargetAttestationKeyState.REVOKED:
        raise ValueError("target receipt key is revoked")
    issued_at = _require_aware_utc(statement.issued_at, label="target receipt issue time")
    if issued_at < _require_aware_utc(key.not_before, label="key not-before time"):
        raise ValueError("target receipt predates signing-key validity")
    if key.not_after is not None and issued_at >= _require_aware_utc(
        key.not_after,
        label="key not-after time",
    ):
        raise ValueError("target receipt was issued after signing-key expiry")
    canonical = canonical_target_json(statement.model_dump(mode="json"))
    public_key = Ed25519PublicKey.from_public_bytes(
        _base64url_decode(
            key.public_key_base64url,
            expected_length=32,
            label="target attestation public key",
        )
    )
    try:
        public_key.verify(
            _base64url_decode(
                receipt.signature_base64url,
                expected_length=64,
                label="target receipt signature",
            ),
            _SIGNATURE_DOMAIN + canonical,
        )
    except InvalidSignature as exc:
        raise ValueError("target receipt signature verification failed") from exc
    return key.key_id
