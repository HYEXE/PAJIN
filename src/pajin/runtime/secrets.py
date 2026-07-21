"""In-memory secret registration, bounded leases, and defensive redaction."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from threading import Lock
from typing import Any
from urllib.parse import quote, quote_plus
from uuid import uuid4

from pydantic import Field, field_validator

from pajin.domain.models import StrictModel

_MIN_SECRET_LENGTH = 1
_MAX_SECRET_LENGTH = 16_384
_MIN_TRANSFORMED_VARIANT_LENGTH = 8
_REDACTION_MARKER = "<redacted-secret>"
_LEASE_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z")


def _require_utf8(value: str, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be valid Unicode encodable as UTF-8") from exc


def _validate_secret_value(value: str) -> None:
    if not isinstance(value, str):
        raise TypeError("secret value must be a string")
    if not _MIN_SECRET_LENGTH <= len(value) <= _MAX_SECRET_LENGTH:
        raise ValueError(
            f"secret value must contain between {_MIN_SECRET_LENGTH} and "
            f"{_MAX_SECRET_LENGTH} characters"
        )
    _require_utf8(value, label="secret value")


def _validate_lease_scope(value: str) -> None:
    if not isinstance(value, str):
        raise TypeError("secret lease scope must be a string")
    if _LEASE_SCOPE.fullmatch(value) is None:
        raise ValueError("secret lease scope must be a safe identifier")
    _require_utf8(value, label="secret lease scope")


class SecretLeaseStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SecretLease(StrictModel):
    lease_id: str = Field(default_factory=lambda: f"lease_{uuid4().hex}")
    secret_ref_fingerprint: str
    audience: str
    binding: str
    scope: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$",
    )
    issued_at: datetime
    expires_at: datetime
    max_uses: int = Field(default=1, ge=1, le=10)
    remaining_uses: int = Field(default=1, ge=0, le=10)
    status: SecretLeaseStatus = SecretLeaseStatus.ACTIVE
    revoked_reason: str | None = None

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_lease_scope(value)
        return value


@dataclass(frozen=True, repr=False)
class SecretMaterial:
    lease_id: str
    binding: str
    value: str

    def __post_init__(self) -> None:
        _validate_secret_value(self.value)

    def __repr__(self) -> str:
        return (
            f"SecretMaterial(lease_id={self.lease_id!r}, "
            f"binding={self.binding!r}, value=<redacted>)"
        )


class SecretBroker:
    """Keep plaintext credentials in memory and expose them only through one-use leases."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._secrets: dict[str, str] = {}
        self._leases: dict[str, SecretLease] = {}
        self._lease_refs: dict[str, str] = {}
        self._lock = Lock()

    def register(self, secret_ref: str, value: str) -> None:
        if not isinstance(secret_ref, str):
            raise TypeError("secret reference must be a string")
        if not secret_ref or len(secret_ref) > 200:
            raise ValueError("secret reference must contain between 1 and 200 characters")
        _require_utf8(secret_ref, label="secret reference")
        _validate_secret_value(value)
        with self._lock:
            if secret_ref in self._secrets:
                raise ValueError("secret reference is already registered")
            self._secrets[secret_ref] = value

    def issue(
        self,
        secret_ref: str,
        *,
        audience: str,
        binding: str,
        scope: str | None = None,
        ttl_seconds: int = 30,
        max_uses: int = 1,
    ) -> SecretLease:
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("secret lease TTL must be between 1 and 300 seconds")
        if not 1 <= max_uses <= 10:
            raise ValueError("secret lease uses must be between 1 and 10")
        if scope is not None:
            _validate_lease_scope(scope)
        with self._lock:
            if secret_ref not in self._secrets:
                raise KeyError("secret reference is not registered")
            now = self._now()
            lease = SecretLease(
                secret_ref_fingerprint=self.fingerprint(secret_ref),
                audience=audience,
                binding=binding,
                scope=scope,
                issued_at=now,
                expires_at=now + timedelta(seconds=ttl_seconds),
                max_uses=max_uses,
                remaining_uses=max_uses,
            )
            self._leases[lease.lease_id] = lease
            self._lease_refs[lease.lease_id] = secret_ref
            return lease.model_copy(deep=True)

    def materialize(
        self,
        lease_id: str,
        *,
        audience: str,
        scope: str | None = None,
    ) -> SecretMaterial:
        if scope is not None:
            _validate_lease_scope(scope)
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise KeyError("unknown secret lease")
            self._require_scope(lease, scope)
            now = self._now()
            if lease.status is SecretLeaseStatus.ACTIVE and now >= lease.expires_at:
                lease.status = SecretLeaseStatus.EXPIRED
                lease.revoked_reason = "lease TTL expired"
            if lease.status is not SecretLeaseStatus.ACTIVE:
                raise PermissionError(f"secret lease is {lease.status.value}")
            if lease.audience != audience:
                raise PermissionError("secret lease audience mismatch")
            if lease.remaining_uses < 1:
                raise PermissionError("secret lease has no remaining uses")
            lease.remaining_uses -= 1
            secret_ref = self._lease_refs[lease_id]
            return SecretMaterial(
                lease_id=lease.lease_id,
                binding=lease.binding,
                value=self._secrets[secret_ref],
            )

    def revoke(
        self,
        lease_id: str,
        reason: str,
        *,
        scope: str | None = None,
    ) -> SecretLease:
        if scope is not None:
            _validate_lease_scope(scope)
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise KeyError("unknown secret lease")
            self._require_scope(lease, scope)
            if lease.status is SecretLeaseStatus.ACTIVE:
                lease.status = SecretLeaseStatus.REVOKED
                lease.revoked_reason = reason
            return lease.model_copy(deep=True)

    def revoke_all(self, reason: str) -> list[SecretLease]:
        """Revoke every active lease, retained for process-wide shutdown compatibility."""

        with self._lock:
            revoked: list[SecretLease] = []
            for lease in self._leases.values():
                if lease.status is SecretLeaseStatus.ACTIVE:
                    lease.status = SecretLeaseStatus.REVOKED
                    lease.revoked_reason = reason
                    revoked.append(lease.model_copy(deep=True))
            return revoked

    def revoke_scope(self, scope: str, reason: str) -> list[SecretLease]:
        """Revoke active leases owned by exactly one Run scope."""

        _validate_lease_scope(scope)
        with self._lock:
            revoked: list[SecretLease] = []
            for lease in self._leases.values():
                if lease.scope == scope and lease.status is SecretLeaseStatus.ACTIVE:
                    lease.status = SecretLeaseStatus.REVOKED
                    lease.revoked_reason = reason
                    revoked.append(lease.model_copy(deep=True))
            return revoked

    def snapshot(self) -> list[dict[str, object]]:
        """Return the process-wide view, retained for diagnostics and compatibility."""

        with self._lock:
            return self._snapshot(self._leases.values())

    def snapshot_scope(self, scope: str) -> list[dict[str, object]]:
        """Return only leases owned by exactly one Run scope."""

        _validate_lease_scope(scope)
        with self._lock:
            return self._snapshot(lease for lease in self._leases.values() if lease.scope == scope)

    @staticmethod
    def fingerprint(secret_ref: str) -> str:
        return sha256(_require_utf8(secret_ref, label="secret reference")).hexdigest()[:16]

    def _now(self) -> datetime:
        value = self._clock()
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    @staticmethod
    def _require_scope(lease: SecretLease, scope: str | None) -> None:
        if lease.scope != scope:
            raise PermissionError("secret lease scope mismatch")

    @staticmethod
    def _snapshot(leases: Iterable[SecretLease]) -> list[dict[str, object]]:
        return [
            lease.model_dump(mode="json")
            for lease in sorted(
                leases,
                key=lambda item: (item.issued_at, item.lease_id),
            )
        ]


def _secret_variants(value: str) -> set[str]:
    encoded = value.encode("utf-8")
    standard_base64 = base64.b64encode(encoded).decode("ascii")
    urlsafe_base64 = base64.urlsafe_b64encode(encoded).decode("ascii")
    transformed = {
        encoded.hex(),
        encoded.hex().upper(),
        standard_base64,
        standard_base64.rstrip("="),
        urlsafe_base64,
        urlsafe_base64.rstrip("="),
        quote(value, safe=""),
        quote_plus(value, safe=""),
        json.dumps(value, ensure_ascii=False)[1:-1],
        json.dumps(value, ensure_ascii=True)[1:-1],
    }
    # Very short encodings (for example ``78`` or ``eA`` for ``x``) are common
    # unrelated text. Redacting them globally creates broad false positives while
    # adding little protection for credentials too short to be realistic tokens.
    return {value} | {
        variant for variant in transformed if len(variant) >= _MIN_TRANSFORMED_VARIANT_LENGTH
    }


def redact_text(value: str, materials: list[SecretMaterial]) -> str:
    redacted = value
    variants = {
        variant for material in materials for variant in _secret_variants(material.value) if variant
    }
    for variant in sorted(variants, key=len, reverse=True):
        replacement = (
            _REDACTION_MARKER if len(variant) >= len(_REDACTION_MARKER) else "*" * len(variant)
        )
        redacted = redacted.replace(variant, replacement)
    return redacted


def redact_value(value: Any, materials: list[SecretMaterial]) -> Any:
    if isinstance(value, str):
        return redact_text(value, materials)
    if isinstance(value, dict):
        return {
            redact_text(key, materials) if isinstance(key, str) else key: redact_value(
                item, materials
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item, materials) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, materials) for item in value)
    return value
