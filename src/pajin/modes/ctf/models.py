"""Typed contracts for local-only CTF category Mode Packs."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from hmac import compare_digest
from re import fullmatch
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from pajin.domain.models import Authorization, Budgets, StrictModel
from pajin.policy.scope import normalize_target_url

CTF_WEB_BACKUP_PATH = "/backup/config.json.bak"
CTF_WEB_LAB_HOST = "host.docker.internal"
CTF_WEB_LAB_PORT = 8780
CTF_CRYPTO_ARTIFACT_HOST = "artifact.invalid"
CTF_MAX_INLINE_ARTIFACT_BYTES = 4_096


class CTFCategory(StrEnum):
    WEB = "web"
    CRYPTO = "crypto"


class CTFEnvironmentType(StrEnum):
    LOCAL_DOCKER = "local-docker"


class CTFScenario(StrEnum):
    WEB_EXPOSED_BACKUP_CONFIG = "web.exposed-backup-config"
    CRYPTO_SINGLE_BYTE_XOR = "crypto.single-byte-xor"


class CTFSolveStatus(StrEnum):
    SOLVED = "solved"
    UNSOLVED = "unsolved"
    INVALID_FLAG = "invalid-flag"


def default_ctf_budgets() -> Budgets:
    return Budgets(
        durationSeconds=60,
        maxCostUsd=0,
        maxAgents=5,
        maxSpawnDepth=1,
        maxToolCalls=1,
        maxModelCalls=0,
        maxModelTokens=0,
    )


class CTFChallengeMetadata(StrictModel):
    name: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    display_name: str = Field(alias="displayName", min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)


class CTFEnvironment(StrictModel):
    type: Literal[CTFEnvironmentType.LOCAL_DOCKER] = CTFEnvironmentType.LOCAL_DOCKER


class CTFChallengeScope(StrictModel):
    entry_point: str = Field(alias="entryPoint")

    @field_validator("entry_point")
    @classmethod
    def require_fixed_local_web_lab(cls, value: str) -> str:
        normalized = normalize_target_url(value)
        parsed = urlsplit(normalized)
        if parsed.scheme != "http":
            raise ValueError("CTF Web MVP requires the local HTTP lab")
        if parsed.hostname != CTF_WEB_LAB_HOST or parsed.port != CTF_WEB_LAB_PORT:
            raise ValueError("CTF Web MVP target must use host.docker.internal:8780")
        if parsed.path != CTF_WEB_BACKUP_PATH or parsed.query:
            raise ValueError(f"CTF Web MVP entry point must be {CTF_WEB_BACKUP_PATH}")
        return normalized


class CTFInlineArtifact(StrictModel):
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


class CTFFlagSpec(StrictModel):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    format: Literal["PAJIN{...}"] = "PAJIN{...}"


class CTFChallengeSpec(StrictModel):
    category: CTFCategory
    scenario: CTFScenario
    environment: CTFEnvironment
    scope: CTFChallengeScope | None = None
    artifact: CTFInlineArtifact | None = None
    authorization: Authorization
    flag: CTFFlagSpec
    objectives: list[str] = Field(min_length=1, max_length=5)
    budgets: Budgets = Field(default_factory=default_ctf_budgets)

    @model_validator(mode="after")
    def enforce_category_contract_and_budget(self) -> CTFChallengeSpec:
        if self.category is CTFCategory.WEB:
            if self.scenario is not CTFScenario.WEB_EXPOSED_BACKUP_CONFIG:
                raise ValueError("CTF Web category requires the exposed-backup scenario")
            if self.scope is None or self.artifact is not None:
                raise ValueError("CTF Web category requires scope and forbids inline artifact")
        elif self.category is CTFCategory.CRYPTO:
            if self.scenario is not CTFScenario.CRYPTO_SINGLE_BYTE_XOR:
                raise ValueError("CTF Crypto category requires the single-byte XOR scenario")
            if self.artifact is None or self.scope is not None:
                raise ValueError("CTF Crypto category requires inline artifact and forbids scope")

        authorization = self.authorization
        for field_name, value in (
            ("approvedAt", authorization.approved_at),
            ("expiresAt", authorization.expires_at),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"CTF authorization {field_name} must include a UTC offset or Z")

        budgets = self.budgets
        if budgets.max_agents != 5 or budgets.max_spawn_depth != 1:
            raise ValueError("CTF MVP requires exactly five agents and spawn depth one")
        if budgets.max_tool_calls != 1:
            raise ValueError("CTF MVP permits exactly one fixed Tool call")
        if budgets.max_model_calls != 0 or budgets.max_model_tokens != 0:
            raise ValueError("CTF MVP does not permit model-provider calls")
        if budgets.max_cost_usd != 0:
            raise ValueError("CTF MVP requires a zero external-service cost budget")
        if budgets.duration_seconds > 120:
            raise ValueError("CTF MVP duration cannot exceed 120 seconds")
        return self


class CTFChallengeManifest(StrictModel):
    api_version: str = Field(alias="apiVersion", pattern=r"^pajin\.dev/v1alpha1$")
    kind: str = Field(pattern=r"^CTFChallenge$")
    metadata: CTFChallengeMetadata
    spec: CTFChallengeSpec


class CTFRunResult(StrictModel):
    run_id: str
    challenge_id: str
    category: CTFCategory
    scenario: CTFScenario
    status: CTFSolveStatus
    candidate_flag: str | None = None
    candidate_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence: list[str] = Field(default_factory=list)
    verifier: Literal["independent-validator"] = "independent-validator"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def require_solved_flag_material(self) -> CTFRunResult:
        if self.status is CTFSolveStatus.SOLVED:
            if self.candidate_flag is None or self.candidate_sha256 != self.expected_sha256:
                raise ValueError("solved CTF result requires a digest-matched candidate flag")
            if not self.evidence:
                raise ValueError("solved CTF result requires Specialist evidence")
        return self
