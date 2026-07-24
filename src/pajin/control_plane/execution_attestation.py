"""Independent workload-key attestation for one exact Replay execution."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
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

_SIGNATURE_DOMAIN = b"pajin.replay.executor-execution-attestation/v1\0"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


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


class ExecutorAttestationKeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class ExecutorAttestationVerificationKey(StrictModel):
    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    state: ExecutorAttestationKeyState
    not_before: datetime
    not_after: datetime | None = None
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def require_valid_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="executor attestation public key",
        )
        not_before = _require_aware_utc(self.not_before, label="key not-before time")
        if self.not_after is not None:
            not_after = _require_aware_utc(self.not_after, label="key not-after time")
            if not_after <= not_before:
                raise ValueError("executor attestation key validity window is empty")
        if self.state is ExecutorAttestationKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired executor attestation key requires not_after")
        if self.state is ExecutorAttestationKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked executor attestation key requires revoked_at")
            _require_aware_utc(self.revoked_at, label="key revocation time")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked executor attestation key cannot have revoked_at")
        return self


class ExecutorAttestationTrustAnchor(StrictModel):
    api_version: Literal["pajin.replay.executor-attestation-trust-anchor/v1"] = (
        "pajin.replay.executor-attestation-trust-anchor/v1"
    )
    trust_domain: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    issuer: str = Field(min_length=1, max_length=200)
    keys: list[ExecutorAttestationVerificationKey] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def require_unique_sorted_keyring(self) -> Self:
        key_ids = [key.key_id for key in self.keys]
        if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)):
            raise ValueError("executor attestation keys must be uniquely sorted")
        if (
            len(
                [
                    key
                    for key in self.keys
                    if key.state is ExecutorAttestationKeyState.ACTIVE
                ]
            )
            != 1
        ):
            raise ValueError("executor attestation trust anchor requires one active key")
        return self

    @property
    def digest(self) -> str:
        return sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


class ExecutorExecutionStatement(StrictModel):
    """Executor-issued observation, without claiming independent Target identity."""

    api_version: Literal["pajin.replay.executor-execution-statement/v1"] = (
        "pajin.replay.executor-execution-statement/v1"
    )
    predicate_type: Literal["pajin.replay.executor-observed-execution/v1"] = (
        "pajin.replay.executor-observed-execution/v1"
    )
    trust_domain: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    issuer: str = Field(min_length=1, max_length=200)
    executor_profile: Literal["kisa-exact-v1"] = "kisa-exact-v1"
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    job_id: str = Field(pattern=r"^job_[0-9a-f]{32}$")
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    source_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    execution_context_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    permit_digests: list[str] = Field(min_length=1, max_length=20)
    replay_request_ids: list[str] = Field(min_length=1, max_length=20)
    artifact_bundle_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_bundle_file_count: int = Field(strict=True, ge=1, le=256)
    artifact_bundle_total_bytes: int = Field(strict=True, ge=1, le=2 * 1024 * 1024)
    artifact_set_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: datetime

    @field_validator("permit_digests")
    @classmethod
    def require_permit_digests(cls, value: list[str]) -> list[str]:
        if any(
            len(item) != 64 or any(character not in "0123456789abcdef" for character in item)
            for item in value
        ):
            raise ValueError("executor attestation permit digests must be lowercase SHA-256")
        if len(value) != len(set(value)):
            raise ValueError("executor attestation permit digests must be unique")
        return value

    @field_validator("replay_request_ids")
    @classmethod
    def require_replay_request_ids(cls, value: list[str]) -> list[str]:
        if any(
            len(item) != len("tool_replay_") + 32
            or not item.startswith("tool_replay_")
            or any(character not in "0123456789abcdef" for character in item[12:])
            for item in value
        ):
            raise ValueError("executor attestation Replay request IDs are invalid")
        if len(value) != len(set(value)):
            raise ValueError("executor attestation Replay request IDs must be unique")
        return value

    @model_validator(mode="after")
    def require_exact_call_cardinality(self) -> Self:
        if len(self.permit_digests) != len(self.replay_request_ids):
            raise ValueError("executor attestation permit and request counts differ")
        _require_aware_utc(self.issued_at, label="executor attestation issue time")
        return self


class ExecutorExecutionAttestation(StrictModel):
    api_version: Literal["pajin.replay.executor-execution-attestation/v1"] = (
        "pajin.replay.executor-execution-attestation/v1"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    statement: ExecutorExecutionStatement
    statement_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_base64url: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = _canonical_json(self.statement.model_dump(mode="json"))
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("executor attestation statement digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="executor attestation signature",
        )
        return self

    @property
    def digest(self) -> str:
        return sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


class ExecutorExecutionVerificationResult(StrictModel):
    valid: Literal[True] = True
    key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    key_state: ExecutorAttestationKeyState
    trust_anchor_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    attestation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_bundle_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class ExecutorExecutionAttestor:
    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: ExecutorAttestationTrustAnchor
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: ExecutorAttestationTrustAnchor,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> ExecutorExecutionAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 executor attestation private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
            clock=clock,
        )

    def __post_init__(self) -> None:
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if len(matching) != 1 or matching[0].state is not ExecutorAttestationKeyState.ACTIVE:
            raise ValueError("executor signer key is not the active trust-anchor key")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="executor attestation active public key",
        )
        if public_bytes != expected:
            raise ValueError("executor private key does not match its trust anchor")

    def attest(
        self,
        statement_fields: dict[str, object],
        *,
        issued_at: datetime | None = None,
    ) -> ExecutorExecutionAttestation:
        timestamp = _require_aware_utc(
            issued_at or self.clock(),
            label="executor attestation issue time",
        )
        active_key = next(
            key for key in self.trust_anchor.keys if key.key_id == self.active_key_id
        )
        if timestamp < _require_aware_utc(active_key.not_before, label="key not-before time"):
            raise ValueError("executor signing key is not valid at the issue time")
        if active_key.not_after is not None and timestamp >= _require_aware_utc(
            active_key.not_after,
            label="key not-after time",
        ):
            raise ValueError("executor signing key is not valid at the issue time")
        statement = ExecutorExecutionStatement.model_validate(
            {
                **statement_fields,
                "trust_domain": self.trust_anchor.trust_domain,
                "issuer": self.trust_anchor.issuer,
                "issued_at": timestamp,
            }
        )
        canonical = _canonical_json(statement.model_dump(mode="json"))
        return ExecutorExecutionAttestation(
            key_id=self.active_key_id,
            statement=statement,
            statement_sha256=sha256(canonical).hexdigest(),
            signature_base64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


def executor_public_key_base64url(private_key: bytes) -> str:
    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def executor_private_key_bytes_from_base64url(value: str) -> bytes:
    return _base64url_decode(
        value,
        expected_length=32,
        label="Ed25519 executor attestation private key",
    )


def executor_execution_attestation_bytes(
    bundle: ExecutorExecutionAttestation,
) -> bytes:
    return (
        json.dumps(
            bundle.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def parse_executor_attestation_trust_anchor(
    content: bytes,
) -> ExecutorAttestationTrustAnchor:
    decoded = parse_strict_json_bytes(
        content,
        label="executor attestation trust anchor",
        max_bytes=64 * 1024,
        max_depth=12,
        max_nodes=2_000,
    )
    return ExecutorAttestationTrustAnchor.model_validate(decoded)


def verify_executor_execution_attestation(
    bundle: ExecutorExecutionAttestation,
    *,
    trust_anchor: ExecutorAttestationTrustAnchor,
) -> ExecutorExecutionVerificationResult:
    statement = bundle.statement
    if (
        statement.trust_domain != trust_anchor.trust_domain
        or statement.issuer != trust_anchor.issuer
    ):
        raise ValueError("executor attestation issuer or trust domain is not trusted")
    key = next((item for item in trust_anchor.keys if item.key_id == bundle.key_id), None)
    if key is None:
        raise ValueError("executor attestation key is absent from the trust anchor")
    if key.state is ExecutorAttestationKeyState.REVOKED:
        raise ValueError("executor attestation key is revoked")
    issued_at = _require_aware_utc(statement.issued_at, label="executor attestation issue time")
    if issued_at < _require_aware_utc(key.not_before, label="key not-before time"):
        raise ValueError("executor attestation predates signing-key validity")
    if key.not_after is not None and issued_at >= _require_aware_utc(
        key.not_after,
        label="key not-after time",
    ):
        raise ValueError("executor attestation was issued after signing-key expiry")
    canonical = _canonical_json(statement.model_dump(mode="json"))
    public_key = Ed25519PublicKey.from_public_bytes(
        _base64url_decode(
            key.public_key_base64url,
            expected_length=32,
            label="executor attestation public key",
        )
    )
    try:
        public_key.verify(
            _base64url_decode(
                bundle.signature_base64url,
                expected_length=64,
                label="executor attestation signature",
            ),
            _SIGNATURE_DOMAIN + canonical,
        )
    except InvalidSignature as exc:
        raise ValueError("executor attestation signature verification failed") from exc
    return ExecutorExecutionVerificationResult(
        key_id=key.key_id,
        key_state=key.state,
        trust_anchor_digest=trust_anchor.digest,
        attestation_digest=bundle.digest,
        artifact_bundle_manifest_sha256=statement.artifact_bundle_manifest_sha256,
        issued_at=statement.issued_at,
    )
