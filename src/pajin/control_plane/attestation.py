"""Portable public-key attestation for Claim-specific Replay receipts."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, model_validator

from pajin.control_plane.models import (
    ReplayClaimProjectionInputAuthority,
    canonical_control_plane_json,
)
from pajin.domain.models import StrictModel
from pajin.replay.tickets import replay_context_digest
from pajin.runtime.safe_files import (
    load_bounded_strict_json,
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)

PORTABLE_REPLAY_ATTESTATION_PATH = Path("validation/v1alpha1/portable-replay-attestation.json")
PORTABLE_REPLAY_ATTESTATION_POLICY_VERSION: Literal["pajin.kisa-claim-attestation:v3"] = (
    "pajin.kisa-claim-attestation:v3"
)
_SIGNATURE_DOMAIN = b"pajin.control-plane.replay-attestation-signature/v1\0"
_MAX_ATTESTATION_BYTES = 8 * 1024 * 1024
_MAX_ATTESTATION_DEPTH = 48
_MAX_ATTESTATION_NODES = 250_000


class ReplayAttestationVerificationError(ValueError):
    """Raised when a portable Replay attestation cannot be trusted."""


class ReplayAttestationKeyState(StrEnum):
    """Lifecycle state published by an external trust anchor."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


def _require_aware_utc(value: datetime, *, label: str) -> datetime:
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
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


class ReplayAttestationVerificationKey(StrictModel):
    """One externally trusted Ed25519 verification key and its lifecycle."""

    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    state: ReplayAttestationKeyState
    not_before: datetime
    not_after: datetime | None = None
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def require_valid_key_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Replay attestation public key",
        )
        not_before = _require_aware_utc(self.not_before, label="key not-before time")
        if self.not_after is not None:
            not_after = _require_aware_utc(self.not_after, label="key not-after time")
            if not_after <= not_before:
                raise ValueError("Replay attestation key validity window is empty")
        if (
            self.state is ReplayAttestationKeyState.RETIRED
            and self.not_after is None
        ):
            raise ValueError("retired Replay attestation key requires not_after")
        if self.state is ReplayAttestationKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Replay attestation key requires revoked_at")
            _require_aware_utc(self.revoked_at, label="key revocation time")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked Replay attestation key cannot have revoked_at")
        return self


class ReplayAttestationTrustAnchor(StrictModel):
    """Out-of-band trust material required by the portable verifier."""

    api_version: Literal["pajin.control-plane.replay-attestation-trust-anchor/v1"] = (
        "pajin.control-plane.replay-attestation-trust-anchor/v1"
    )
    trust_domain: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    issuer: str = Field(min_length=1, max_length=200)
    keys: list[ReplayAttestationVerificationKey] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def require_unique_sorted_keyring(self) -> Self:
        key_ids = [key.key_id for key in self.keys]
        if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)):
            raise ValueError("Replay attestation trust-anchor keys must be uniquely sorted")
        active = [key for key in self.keys if key.state is ReplayAttestationKeyState.ACTIVE]
        if len(active) != 1:
            raise ValueError("Replay attestation trust anchor requires exactly one active key")
        return self

    @property
    def digest(self) -> str:
        return sha256(canonical_control_plane_json(self.model_dump(mode="json"))).hexdigest()


class PortableReplayAttestationStatement(StrictModel):
    """Exact Claim receipt authority signed by the Control Plane."""

    api_version: Literal["pajin.control-plane.replay-attestation-statement/v1"] = (
        "pajin.control-plane.replay-attestation-statement/v1"
    )
    predicate_type: Literal["pajin.claim-replay-receipts/v1"] = "pajin.claim-replay-receipts/v1"
    trust_domain: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    issuer: str = Field(min_length=1, max_length=200)
    policy_version: Literal["pajin.kisa-claim-attestation:v3"] = (
        PORTABLE_REPLAY_ATTESTATION_POLICY_VERSION
    )
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    input_authority: ReplayClaimProjectionInputAuthority
    input_authority_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_count: int = Field(strict=True, ge=1, le=3_000)
    issued_at: datetime

    @model_validator(mode="after")
    def require_exact_claim_receipt_authority(self) -> Self:
        if self.input_authority.batch_id != self.batch_id:
            raise ValueError("Replay attestation belongs to another batch")
        if self.input_authority_digest != replay_context_digest(
            self.input_authority.model_dump(mode="json", by_alias=True)
        ):
            raise ValueError("Replay attestation input authority digest is inconsistent")
        if self.receipt_count != len(self.input_authority.items):
            raise ValueError("Replay attestation receipt count is inconsistent")
        _require_aware_utc(self.issued_at, label="Replay attestation issue time")
        return self


class PortableReplayAttestationBundle(StrictModel):
    """Detached signature bundle embedded in the sealed public projection."""

    api_version: Literal["pajin.control-plane.replay-attestation-bundle/v1"] = (
        "pajin.control-plane.replay-attestation-bundle/v1"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    statement: PortableReplayAttestationStatement
    statement_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_base64url: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_control_plane_json(self.statement.model_dump(mode="json"))
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("Replay attestation statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Replay attestation signature",
        )
        return self


class ReplayAttestationVerificationResult(StrictModel):
    """Portable verification result without any server-side secret."""

    valid: Literal[True] = True
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    key_state: ReplayAttestationKeyState
    trust_anchor_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_authority_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_count: int = Field(strict=True, ge=1, le=3_000)
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class ReplayAttestor:
    """Sign Claim receipt authority with one active Ed25519 private key."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: ReplayAttestationTrustAnchor
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: ReplayAttestationTrustAnchor,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> ReplayAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 Replay attestation private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
            clock=clock,
        )

    def __post_init__(self) -> None:
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if len(matching) != 1 or matching[0].state is not ReplayAttestationKeyState.ACTIVE:
            raise ValueError("Replay attestation signer key is not the active trust-anchor key")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Replay attestation active public key",
        )
        if public_bytes != expected:
            raise ValueError("Replay attestation private key does not match its trust anchor")

    def attest(
        self,
        authority: ReplayClaimProjectionInputAuthority,
        *,
        authority_digest: str,
        issued_at: datetime | None = None,
    ) -> PortableReplayAttestationBundle:
        timestamp = _require_aware_utc(
            issued_at or self.clock(),
            label="Replay attestation issue time",
        )
        active_key = next(
            key
            for key in self.trust_anchor.keys
            if key.key_id == self.active_key_id
        )
        not_before = _require_aware_utc(
            active_key.not_before,
            label="key not-before time",
        )
        if timestamp < not_before or (
            active_key.not_after is not None
            and timestamp
            >= _require_aware_utc(active_key.not_after, label="key not-after time")
        ):
            raise ValueError(
                "Replay attestation signing key is not valid at the issue time"
            )
        statement = PortableReplayAttestationStatement(
            trust_domain=self.trust_anchor.trust_domain,
            issuer=self.trust_anchor.issuer,
            batch_id=authority.batch_id,
            input_authority=authority,
            input_authority_digest=authority_digest,
            receipt_count=len(authority.items),
            issued_at=timestamp,
        )
        canonical = canonical_control_plane_json(statement.model_dump(mode="json"))
        signature = self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
        return PortableReplayAttestationBundle(
            key_id=self.active_key_id,
            statement=statement,
            statement_sha256=sha256(canonical).hexdigest(),
            signature_base64url=_base64url_encode(signature),
        )


def public_key_base64url(private_key: bytes) -> str:
    """Derive the public trust-anchor value for one raw 32-byte Ed25519 seed."""

    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def private_key_bytes_from_base64url(value: str) -> bytes:
    """Decode one raw Ed25519 seed from an environment-safe representation."""

    return _base64url_decode(
        value,
        expected_length=32,
        label="Ed25519 Replay attestation private key",
    )


def portable_replay_attestation_bytes(bundle: PortableReplayAttestationBundle) -> bytes:
    """Serialize one human-readable bundle whose signature covers canonical bytes."""

    return (
        json.dumps(
            bundle.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def parse_portable_replay_attestation(
    content: bytes,
) -> PortableReplayAttestationBundle:
    """Parse one resource-bounded detached bundle."""

    decoded = parse_strict_json_bytes(
        content,
        label="portable Replay attestation",
        max_bytes=_MAX_ATTESTATION_BYTES,
        max_depth=_MAX_ATTESTATION_DEPTH,
        max_nodes=_MAX_ATTESTATION_NODES,
    )
    return PortableReplayAttestationBundle.model_validate(decoded)


def load_portable_replay_attestation(
    root: Path,
) -> PortableReplayAttestationBundle:
    """Load the attestation embedded in a resolved projection Artifact."""

    return load_portable_replay_attestation_file(root.resolve() / PORTABLE_REPLAY_ATTESTATION_PATH)


def load_portable_replay_attestation_file(
    path: Path,
) -> PortableReplayAttestationBundle:
    """Load a detached bundle file for verification outside the Control Plane host."""

    return parse_portable_replay_attestation(
        read_bounded_regular_bytes(
            path,
            max_bytes=_MAX_ATTESTATION_BYTES,
            label="portable Replay attestation",
            require_single_link=True,
        )
    )


def load_replay_attestation_trust_anchor(path: Path) -> ReplayAttestationTrustAnchor:
    """Load an explicit out-of-band trust anchor from a bounded JSON file."""

    decoded = load_bounded_strict_json(
        path,
        max_bytes=64 * 1024,
        max_depth=12,
        max_nodes=2_000,
        label="Replay attestation trust anchor",
        require_single_link=True,
    )
    return ReplayAttestationTrustAnchor.model_validate(decoded)


def parse_replay_attestation_trust_anchor(
    content: bytes,
) -> ReplayAttestationTrustAnchor:
    """Parse bounded trust-anchor JSON supplied by deployment configuration."""

    decoded = parse_strict_json_bytes(
        content,
        label="Replay attestation trust anchor",
        max_bytes=64 * 1024,
        max_depth=12,
        max_nodes=2_000,
    )
    return ReplayAttestationTrustAnchor.model_validate(decoded)


def verify_portable_replay_attestation(
    bundle: PortableReplayAttestationBundle,
    *,
    trust_anchor: ReplayAttestationTrustAnchor,
) -> ReplayAttestationVerificationResult:
    """Verify with caller-supplied trust rather than bundle-supplied key material."""

    statement = bundle.statement
    if (
        statement.trust_domain != trust_anchor.trust_domain
        or statement.issuer != trust_anchor.issuer
    ):
        raise ReplayAttestationVerificationError(
            "Replay attestation issuer or trust domain is not trusted"
        )
    key = next((item for item in trust_anchor.keys if item.key_id == bundle.key_id), None)
    if key is None:
        raise ReplayAttestationVerificationError(
            "Replay attestation signing key is absent from the trust anchor"
        )
    if key.state is ReplayAttestationKeyState.REVOKED:
        raise ReplayAttestationVerificationError("Replay attestation signing key is revoked")
    issued_at = _require_aware_utc(statement.issued_at, label="Replay attestation issue time")
    not_before = _require_aware_utc(key.not_before, label="key not-before time")
    if issued_at < not_before:
        raise ReplayAttestationVerificationError("Replay attestation predates signing-key validity")
    if key.not_after is not None and issued_at >= _require_aware_utc(
        key.not_after,
        label="key not-after time",
    ):
        raise ReplayAttestationVerificationError(
            "Replay attestation was issued after signing-key expiry"
        )
    canonical = canonical_control_plane_json(statement.model_dump(mode="json"))
    public_key = Ed25519PublicKey.from_public_bytes(
        _base64url_decode(
            key.public_key_base64url,
            expected_length=32,
            label="Replay attestation public key",
        )
    )
    try:
        public_key.verify(
            _base64url_decode(
                bundle.signature_base64url,
                expected_length=64,
                label="Replay attestation signature",
            ),
            _SIGNATURE_DOMAIN + canonical,
        )
    except InvalidSignature as exc:
        raise ReplayAttestationVerificationError(
            "Replay attestation signature verification failed"
        ) from exc
    return ReplayAttestationVerificationResult(
        batch_id=statement.batch_id,
        key_id=key.key_id,
        key_state=key.state,
        trust_anchor_digest=trust_anchor.digest,
        input_authority_digest=statement.input_authority_digest,
        receipt_count=statement.receipt_count,
        issued_at=statement.issued_at,
    )
