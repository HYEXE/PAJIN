"""Typed contracts for the local-only CTF Web Mode vertical slice."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from pajin.domain.models import Authorization, Budgets, StrictModel
from pajin.policy.scope import normalize_target_url

CTF_WEB_BACKUP_PATH = "/backup/config.json.bak"
CTF_WEB_LAB_HOST = "host.docker.internal"
CTF_WEB_LAB_PORT = 8780


class CTFCategory(StrEnum):
    WEB = "web"


class CTFEnvironmentType(StrEnum):
    LOCAL_DOCKER = "local-docker"


class CTFScenario(StrEnum):
    WEB_EXPOSED_BACKUP_CONFIG = "web.exposed-backup-config"


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


class CTFFlagSpec(StrictModel):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    format: Literal["PAJIN{...}"] = "PAJIN{...}"


class CTFChallengeSpec(StrictModel):
    category: Literal[CTFCategory.WEB] = CTFCategory.WEB
    scenario: Literal[CTFScenario.WEB_EXPOSED_BACKUP_CONFIG] = CTFScenario.WEB_EXPOSED_BACKUP_CONFIG
    environment: CTFEnvironment
    scope: CTFChallengeScope
    authorization: Authorization
    flag: CTFFlagSpec
    objectives: list[str] = Field(min_length=1, max_length=5)
    budgets: Budgets = Field(default_factory=default_ctf_budgets)

    @model_validator(mode="after")
    def enforce_local_mvp_budget_ceiling(self) -> CTFChallengeSpec:
        authorization = self.authorization
        for field_name, value in (
            ("approvedAt", authorization.approved_at),
            ("expiresAt", authorization.expires_at),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"CTF authorization {field_name} must include a UTC offset or Z")

        budgets = self.budgets
        if budgets.max_agents != 5 or budgets.max_spawn_depth != 1:
            raise ValueError("CTF Web MVP requires exactly five agents and spawn depth one")
        if budgets.max_tool_calls != 1:
            raise ValueError("CTF Web MVP permits exactly one fixed Tool call")
        if budgets.max_model_calls != 0 or budgets.max_model_tokens != 0:
            raise ValueError("CTF Web MVP does not permit model-provider calls")
        if budgets.max_cost_usd != 0:
            raise ValueError("CTF Web MVP requires a zero external-service cost budget")
        if budgets.duration_seconds > 120:
            raise ValueError("CTF Web MVP duration cannot exceed 120 seconds")
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
