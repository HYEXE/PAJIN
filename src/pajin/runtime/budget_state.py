"""Versioned conservative budget checkpoints for a trusted local journal."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import Budgets
from pajin.runtime.safe_files import parse_strict_json_bytes

_Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
MAX_BUDGET_CHECKPOINT_BYTES = 16_384


def _canonical(value: object) -> bytes:
    # Keep this foundational module independent of Discovery's runtime imports.
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) > MAX_BUDGET_CHECKPOINT_BYTES:
        raise ValueError("budget checkpoint exceeds its canonical byte limit")
    return encoded


class BudgetPersistenceError(RuntimeError):
    """Durable accounting could not be established; dispatch must not proceed."""


class _BudgetModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always", allow_inf_nan=False
    )


class BudgetScope(_BudgetModel):
    campaign_digest: _Digest
    role: Literal["campaign", "supervisor"]
    policy_digest: _Digest | None
    limits: Budgets

    @model_validator(mode="after")
    def require_policy_scope(self) -> Self:
        if (self.role == "campaign") != (self.policy_digest is None):
            raise ValueError("budget scope differs from its policy role")
        object.__setattr__(
            self, "limits", Budgets.model_validate_json(self.limits.model_dump_json())
        )
        return self

    @property
    def scope_id(self) -> str:
        return sha256(
            b"pajin.budget-scope/v1\x00" + self.campaign_digest.encode() + self.role.encode()
        ).hexdigest()


class BudgetUsage(_BudgetModel):
    agent_count: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    model_prompt_tokens: int = Field(ge=0)
    model_completion_tokens: int = Field(ge=0)
    cost_usd: float = Field(ge=0)
    elapsed_seconds: float = Field(ge=0)

    def require_within(self, limits: Budgets) -> None:
        if (
            self.agent_count > limits.max_agents
            or self.tool_calls > limits.max_tool_calls
            or self.model_calls > limits.max_model_calls
            or self.model_prompt_tokens + self.model_completion_tokens > limits.max_model_tokens
            or self.cost_usd > limits.max_cost_usd
        ):
            raise BudgetPersistenceError("stored consumption exceeds the pinned budget limits")


class BudgetCheckpoint(_BudgetModel):
    api_version: Literal["pajin.dev/budget-checkpoint/v1alpha1"] = (
        "pajin.dev/budget-checkpoint/v1alpha1"
    )
    scope: BudgetScope
    revision: int = Field(ge=1, le=2_147_483_647)
    previous_digest: _Digest | None
    owner_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    origin_at: datetime
    recorded_at: datetime
    usage: BudgetUsage
    checkpoint_digest: str = ""

    @field_validator("origin_at", "recorded_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("budget timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_checkpoint(self) -> Self:
        if (self.revision == 1) != (self.previous_digest is None):
            raise ValueError("budget checkpoint predecessor differs from its revision")
        if self.recorded_at < self.origin_at:
            raise ValueError("budget checkpoint predates its accounting origin")
        self.usage.require_within(self.scope.limits)
        digest = sha256(
            b"pajin.budget-checkpoint/v1\x00"
            + _canonical(
                self.model_dump(mode="json", exclude={"checkpoint_digest"}),
            )
        ).hexdigest()
        if self.checkpoint_digest and self.checkpoint_digest != digest:
            raise ValueError("budget checkpoint digest differs")
        object.__setattr__(self, "checkpoint_digest", digest)
        return self


def budget_checkpoint_bytes(checkpoint: BudgetCheckpoint) -> bytes:
    return _canonical(checkpoint.model_dump(mode="json"))


def parse_budget_checkpoint(value: str) -> BudgetCheckpoint:
    try:
        encoded = value.encode("utf-8")
        parse_strict_json_bytes(
            encoded, label="budget checkpoint", max_bytes=MAX_BUDGET_CHECKPOINT_BYTES
        )
        checkpoint = BudgetCheckpoint.model_validate_json(encoded)
        if budget_checkpoint_bytes(checkpoint) != encoded:
            raise ValueError("budget checkpoint is not canonical")
        return checkpoint
    except (ValueError, TypeError) as exc:
        raise BudgetPersistenceError("stored budget checkpoint is invalid") from exc


BUDGET_TABLE = "supervisor_budget_checkpoints"
BUDGET_SCHEMA_SQL = {
    ("table", BUDGET_TABLE): """
        CREATE TABLE supervisor_budget_checkpoints (
            scope_id TEXT NOT NULL CHECK(length(scope_id) = 64),
            revision INTEGER NOT NULL CHECK(revision > 0 AND revision <= 2147483647),
            checkpoint_digest TEXT NOT NULL UNIQUE CHECK(length(checkpoint_digest) = 64),
            payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) <= 16384),
            PRIMARY KEY (scope_id, revision)
        ) STRICT
    """,
    ("trigger", "supervisor_budget_checkpoints_no_update"): """
        CREATE TRIGGER supervisor_budget_checkpoints_no_update
        BEFORE UPDATE ON supervisor_budget_checkpoints
        BEGIN SELECT RAISE(ABORT, 'budget checkpoints are append-only'); END
    """,
    ("trigger", "supervisor_budget_checkpoints_no_delete"): """
        CREATE TRIGGER supervisor_budget_checkpoints_no_delete
        BEFORE DELETE ON supervisor_budget_checkpoints
        BEGIN SELECT RAISE(ABORT, 'budget checkpoints are append-only'); END
    """,
    ("trigger", "supervisor_budget_checkpoints_no_replace"): """
        CREATE TRIGGER supervisor_budget_checkpoints_no_replace
        BEFORE INSERT ON supervisor_budget_checkpoints
        WHEN EXISTS (
            SELECT 1 FROM supervisor_budget_checkpoints
            WHERE (scope_id = NEW.scope_id AND revision = NEW.revision)
               OR checkpoint_digest = NEW.checkpoint_digest
               OR (NEW.rowid != -1 AND rowid = NEW.rowid)
        )
        BEGIN SELECT RAISE(ABORT, 'budget checkpoints cannot be replaced'); END
    """,
}
