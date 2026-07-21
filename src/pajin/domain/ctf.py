"""Shared, mode-independent contracts for bounded synthetic CTF Tools."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from hmac import compare_digest
from re import fullmatch
from typing import Literal

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel

CTF_WEB_BACKUP_PATH = "/backup/config.json.bak"
CTF_WEB_LAB_HOST = "host.docker.internal"
CTF_WEB_LAB_PORT = 8780
CTF_CRYPTO_ARTIFACT_HOST = "artifact.invalid"
CTF_MAX_INLINE_ARTIFACT_BYTES = 4_096


class CTFScenario(StrEnum):
    """Stable scenario identities shared by the CTF Mode and its Tool adapters."""

    WEB_EXPOSED_BACKUP_CONFIG = "web.exposed-backup-config"
    CRYPTO_SINGLE_BYTE_XOR = "crypto.single-byte-xor"


class CTFInlineArtifact(StrictModel):
    """One bounded, content-addressed artifact safe to pass to an offline Tool."""

    encoding: Literal["hex"] = "hex"
    data: str = Field(min_length=2, max_length=CTF_MAX_INLINE_ARTIFACT_BYTES * 2)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    media_type: Literal["application/octet-stream"] = Field(
        default="application/octet-stream",
        alias="mediaType",
    )

    @model_validator(mode="after")
    def verify_content_address(self) -> CTFInlineArtifact:
        if fullmatch(r"[a-f0-9]+", self.data) is None:
            raise ValueError("CTF inline artifact data must be lowercase hexadecimal")
        if len(self.data) % 2:
            raise ValueError("CTF inline artifact hex must contain complete bytes")
        try:
            decoded = bytes.fromhex(self.data)
        except ValueError as exc:
            raise ValueError("CTF inline artifact data must be lowercase hexadecimal") from exc
        if not 1 <= len(decoded) <= CTF_MAX_INLINE_ARTIFACT_BYTES:
            raise ValueError("CTF inline artifact exceeds the bounded size")
        observed = sha256(decoded).hexdigest()
        if not compare_digest(observed, self.sha256):
            raise ValueError("CTF inline artifact SHA-256 does not match its decoded bytes")
        return self
