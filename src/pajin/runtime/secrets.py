"""In-memory secret registration, bounded leases, and defensive redaction."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from threading import Lock
from typing import Any
from uuid import uuid4

from pydantic import Field

from pajin.domain.models import StrictModel


class SecretLeaseStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SecretLease(StrictModel):
    lease_id: str = Field(default_factory=lambda: f"lease_{uuid4().hex}")
    secret_ref_fingerprint: str
    audience: str
    binding: str
    issued_at: datetime
    expires_at: datetime
    max_uses: int = Field(default=1, ge=1, le=10)
    remaining_uses: int = Field(default=1, ge=0, le=10)
    status: SecretLeaseStatus = SecretLeaseStatus.ACTIVE
    revoked_reason: str | None = None


@dataclass(frozen=True, repr=False)
class SecretMaterial:
    lease_id: str
    binding: str
    value: str

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
        if not secret_ref or len(secret_ref) > 200:
            raise ValueError("secret reference must contain between 1 and 200 characters")
        if not value or len(value) > 16_384:
            raise ValueError("secret value must contain between 1 and 16384 characters")
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
        ttl_seconds: int = 30,
        max_uses: int = 1,
    ) -> SecretLease:
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("secret lease TTL must be between 1 and 300 seconds")
        if not 1 <= max_uses <= 10:
            raise ValueError("secret lease uses must be between 1 and 10")
        with self._lock:
            if secret_ref not in self._secrets:
                raise KeyError("secret reference is not registered")
            now = self._now()
            lease = SecretLease(
                secret_ref_fingerprint=self.fingerprint(secret_ref),
                audience=audience,
                binding=binding,
                issued_at=now,
                expires_at=now + timedelta(seconds=ttl_seconds),
                max_uses=max_uses,
                remaining_uses=max_uses,
            )
            self._leases[lease.lease_id] = lease
            self._lease_refs[lease.lease_id] = secret_ref
            return lease.model_copy(deep=True)

    def materialize(self, lease_id: str, *, audience: str) -> SecretMaterial:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise KeyError("unknown secret lease")
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

    def revoke(self, lease_id: str, reason: str) -> SecretLease:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise KeyError("unknown secret lease")
            if lease.status is SecretLeaseStatus.ACTIVE:
                lease.status = SecretLeaseStatus.REVOKED
                lease.revoked_reason = reason
            return lease.model_copy(deep=True)

    def revoke_all(self, reason: str) -> list[SecretLease]:
        with self._lock:
            revoked: list[SecretLease] = []
            for lease in self._leases.values():
                if lease.status is SecretLeaseStatus.ACTIVE:
                    lease.status = SecretLeaseStatus.REVOKED
                    lease.revoked_reason = reason
                    revoked.append(lease.model_copy(deep=True))
            return revoked

    def snapshot(self) -> list[dict[str, object]]:
        with self._lock:
            return [
                lease.model_dump(mode="json")
                for lease in sorted(self._leases.values(), key=lambda item: item.issued_at)
            ]

    @staticmethod
    def fingerprint(secret_ref: str) -> str:
        return sha256(secret_ref.encode("utf-8")).hexdigest()[:16]

    def _now(self) -> datetime:
        value = self._clock()
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def redact_text(value: str, materials: list[SecretMaterial]) -> str:
    redacted = value
    for material in sorted(materials, key=lambda item: len(item.value), reverse=True):
        redacted = redacted.replace(material.value, "<redacted-secret>")
    return redacted


def redact_value(value: Any, materials: list[SecretMaterial]) -> Any:
    if isinstance(value, str):
        return redact_text(value, materials)
    if isinstance(value, dict):
        return {key: redact_value(item, materials) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item, materials) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, materials) for item in value)
    return value
