"""Authentication and signed-checkpoint primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from pajin.control_plane.models import Principal, validate_bounded_json_object

_MIN_BEARER_TOKEN_BYTES = 32
_MAX_BEARER_TOKEN_BYTES = 4 * 1024


class AuthenticationError(RuntimeError):
    """Raised when an API credential is missing or invalid."""


class CheckpointIntegrityError(RuntimeError):
    """Raised when stored checkpoint content no longer matches its signature."""


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def validate_bearer_token(token: str, *, label: str = "Control Plane bearer token") -> str:
    """Require one bounded header-safe opaque credential without exposing it."""

    if not isinstance(token, str):
        raise ValueError(f"{label} must be a string")
    if not _MIN_BEARER_TOKEN_BYTES <= len(token) <= _MAX_BEARER_TOKEN_BYTES:
        raise ValueError(
            f"{label} must contain between {_MIN_BEARER_TOKEN_BYTES} and "
            f"{_MAX_BEARER_TOKEN_BYTES} visible ASCII characters"
        )
    if any(not 0x21 <= ord(character) <= 0x7E for character in token):
        raise ValueError(f"{label} must contain only visible ASCII without spaces or controls")
    return token


class TokenAuthenticator:
    """Authenticate opaque bearer tokens without retaining their plaintext values."""

    def __init__(self, credentials: dict[str, Principal]) -> None:
        if not credentials:
            raise ValueError("at least one Control Plane credential is required")
        self._principals = [
            (
                token_digest(
                    validate_bearer_token(
                        token,
                        label="Control Plane bearer credential",
                    )
                ),
                principal,
            )
            for token, principal in credentials.items()
        ]

    def authenticate(self, token: str) -> Principal:
        try:
            candidate = token_digest(validate_bearer_token(token))
        except ValueError as exc:
            raise AuthenticationError("invalid bearer credential") from exc
        matched: Principal | None = None
        for digest, principal in self._principals:
            if hmac.compare_digest(candidate, digest):
                matched = principal
        if matched is None:
            raise AuthenticationError("invalid bearer credential")
        return matched


@dataclass(frozen=True)
class CheckpointSignature:
    payload_sha256: str
    signature: str
    key_id: str


class CheckpointSigner:
    """Sign canonical checkpoint envelopes with a rotatable HMAC keyring."""

    def __init__(self, *, active_key_id: str, keys: dict[str, bytes]) -> None:
        if active_key_id not in keys:
            raise ValueError("active checkpoint signing key is absent from keyring")
        if not keys or any(len(value) < 32 for value in keys.values()):
            raise ValueError("checkpoint signing keys must contain at least 32 bytes")
        self._active_key_id = active_key_id
        self._keys = dict(keys)

    @staticmethod
    def canonical_json(value: Any) -> bytes:
        validate_bounded_json_object(value)
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def sign(
        self,
        *,
        checkpoint_id: str,
        run_id: str,
        sequence: int,
        schema_version: int,
        payload: dict[str, Any],
    ) -> CheckpointSignature:
        payload_digest = hashlib.sha256(self.canonical_json(payload)).hexdigest()
        envelope = self._envelope(
            checkpoint_id=checkpoint_id,
            run_id=run_id,
            sequence=sequence,
            schema_version=schema_version,
            payload_sha256=payload_digest,
            key_id=self._active_key_id,
        )
        signature = hmac.new(
            self._keys[self._active_key_id], self.canonical_json(envelope), hashlib.sha256
        ).hexdigest()
        return CheckpointSignature(
            payload_sha256=payload_digest,
            signature=signature,
            key_id=self._active_key_id,
        )

    def verify(
        self,
        *,
        checkpoint_id: str,
        run_id: str,
        sequence: int,
        schema_version: int,
        payload: dict[str, Any],
        payload_sha256: str,
        signature: str,
        key_id: str,
    ) -> None:
        key = self._keys.get(key_id)
        actual_payload_digest = hashlib.sha256(self.canonical_json(payload)).hexdigest()
        if key is None or not hmac.compare_digest(actual_payload_digest, payload_sha256):
            raise CheckpointIntegrityError("checkpoint payload integrity verification failed")
        envelope = self._envelope(
            checkpoint_id=checkpoint_id,
            run_id=run_id,
            sequence=sequence,
            schema_version=schema_version,
            payload_sha256=payload_sha256,
            key_id=key_id,
        )
        expected = hmac.new(key, self.canonical_json(envelope), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise CheckpointIntegrityError("checkpoint signature verification failed")

    @staticmethod
    def _envelope(
        *,
        checkpoint_id: str,
        run_id: str,
        sequence: int,
        schema_version: int,
        payload_sha256: str,
        key_id: str,
    ) -> dict[str, object]:
        return {
            "checkpointId": checkpoint_id,
            "keyId": key_id,
            "payloadSha256": payload_sha256,
            "runId": run_id,
            "schemaVersion": schema_version,
            "sequence": sequence,
        }
