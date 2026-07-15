"""Campaign-wide budgets and cooperative cancellation controls."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from time import monotonic

from pydantic import BaseModel, ConfigDict, Field

from pajin.domain.models import Budgets


class BudgetExceeded(RuntimeError):
    """Raised before an operation would exceed a campaign budget."""


class CancellationKind(StrEnum):
    """Fail-closed reasons that can stop one trusted execution stack."""

    RUN_CANCELLED = "run-cancelled"
    LEASE_LOST = "lease-lost"
    HEARTBEAT_UNAVAILABLE = "heartbeat-unavailable"
    DAEMON_SHUTDOWN = "daemon-shutdown"
    CALLER_CANCELLED = "caller-cancelled"


class CancellationCleanupStatus(StrEnum):
    """Monotonic local cleanup state for one execution cancellation."""

    OBSERVED = "observed"
    CLEANUP_COMPLETED = "cleanup-completed"
    EXECUTOR_DRAINED = "executor-drained"
    QUIESCED = "quiesced"
    INCOMPLETE = "incomplete"


class ExecutionCancellationSnapshot(BaseModel):
    """Serializable, secret-free cancellation state retained by Workers and Runs."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    api_version: str = Field(
        default="pajin.dev/execution-cancellation/v1",
        alias="apiVersion",
    )
    job_id: str | None = Field(default=None, alias="jobId")
    control_plane_run_id: str | None = Field(default=None, alias="controlPlaneRunId")
    kind: CancellationKind
    reason: str
    observed_at: datetime = Field(alias="observedAt")
    engine: str | None = None
    engine_run_id: str | None = Field(default=None, alias="engineRunId")
    cleanup_status: CancellationCleanupStatus = Field(alias="cleanupStatus")
    forced_at: datetime | None = Field(default=None, alias="forcedAt")
    cleanup_completed_at: datetime | None = Field(default=None, alias="cleanupCompletedAt")
    executor_drained_at: datetime | None = Field(default=None, alias="executorDrainedAt")
    cleanup_error: str | None = Field(default=None, alias="cleanupError")


@dataclass(frozen=True)
class ExecutionRunBinding:
    """Internal link to a local RunStore; paths are not serialized in receipts."""

    engine: str
    run_id: str
    path: Path


class ExecutionCancellationContext:
    """One-way cooperative signal and monotonic cleanup receipt for one Job execution."""

    def __init__(
        self,
        *,
        job_id: str | None = None,
        control_plane_run_id: str | None = None,
    ) -> None:
        self._job_id = job_id
        self._control_plane_run_id = control_plane_run_id
        self._event = asyncio.Event()
        self._kind: CancellationKind | None = None
        self._reason: str | None = None
        self._observed_at: datetime | None = None
        self._binding: ExecutionRunBinding | None = None
        self._cleanup_status: CancellationCleanupStatus | None = None
        self._forced_at: datetime | None = None
        self._cleanup_completed_at: datetime | None = None
        self._executor_drained_at: datetime | None = None
        self._cleanup_error: str | None = None
        self._children: list[ExecutionCancellationContext] = []

    @property
    def active(self) -> bool:
        return self._event.is_set()

    @property
    def binding(self) -> ExecutionRunBinding | None:
        return self._binding

    def cancel(self, kind: CancellationKind, reason: str) -> bool:
        """Activate once; later signals cannot replace the first observed cause."""

        if self.active:
            return False
        bounded_reason = reason.strip()[:500]
        self._kind = kind
        self._reason = bounded_reason or "execution cancellation requested"
        self._observed_at = datetime.now(UTC)
        self._cleanup_status = CancellationCleanupStatus.OBSERVED
        self._event.set()
        for child in tuple(self._children):
            child.cancel(kind, self._reason)
        return True

    def fork_for_run(
        self,
        *,
        engine: str,
        run_id: str,
        path: Path,
    ) -> ExecutionCancellationContext:
        """Create a run-local child signal without rebinding the parent Run."""

        child = ExecutionCancellationContext(
            job_id=self._job_id,
            control_plane_run_id=self._control_plane_run_id,
        )
        child.bind_run(engine=engine, run_id=run_id, path=path)
        if self.active:
            snapshot = self.snapshot()
            child.cancel(snapshot.kind, snapshot.reason)
        self._children.append(child)
        return child

    def bind_run(self, *, engine: str, run_id: str, path: Path) -> None:
        binding = ExecutionRunBinding(
            engine=engine[:100],
            run_id=run_id,
            path=path.resolve(),
        )
        if self._binding is not None and self._binding != binding:
            raise ValueError("execution cancellation context is already bound to another Run")
        self._binding = binding

    def mark_forced(self) -> None:
        self._require_active()
        if self._forced_at is None:
            self._forced_at = datetime.now(UTC)

    def mark_cleanup_completed(self) -> None:
        self._require_active()
        if self._cleanup_status is CancellationCleanupStatus.INCOMPLETE:
            return
        if self._cleanup_completed_at is None:
            self._cleanup_completed_at = datetime.now(UTC)
        self._cleanup_status = (
            CancellationCleanupStatus.QUIESCED
            if self._executor_drained_at is not None
            else CancellationCleanupStatus.CLEANUP_COMPLETED
        )

    def mark_executor_drained(self) -> None:
        self._require_active()
        if self._cleanup_status is CancellationCleanupStatus.INCOMPLETE:
            return
        if self._executor_drained_at is None:
            self._executor_drained_at = datetime.now(UTC)
        self._cleanup_status = (
            CancellationCleanupStatus.QUIESCED
            if self._cleanup_completed_at is not None
            else CancellationCleanupStatus.EXECUTOR_DRAINED
        )

    def mark_incomplete(self, error: str) -> None:
        self._require_active()
        self._cleanup_error = error.strip()[:500] or "execution cleanup did not complete"
        self._cleanup_status = CancellationCleanupStatus.INCOMPLETE

    async def wait(self) -> ExecutionCancellationSnapshot:
        await self._event.wait()
        return self.snapshot()

    def snapshot(self) -> ExecutionCancellationSnapshot:
        self._require_active()
        assert self._kind is not None
        assert self._reason is not None
        assert self._observed_at is not None
        assert self._cleanup_status is not None
        return ExecutionCancellationSnapshot(
            jobId=self._job_id,
            controlPlaneRunId=self._control_plane_run_id,
            kind=self._kind,
            reason=self._reason,
            observedAt=self._observed_at,
            engine=self._binding.engine if self._binding else None,
            engineRunId=self._binding.run_id if self._binding else None,
            cleanupStatus=self._cleanup_status,
            forcedAt=self._forced_at,
            cleanupCompletedAt=self._cleanup_completed_at,
            executorDrainedAt=self._executor_drained_at,
            cleanupError=self._cleanup_error,
        )

    def _require_active(self) -> None:
        if not self.active:
            raise RuntimeError("execution cancellation has not been requested")


class ControlSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool
    reason: str | None
    source: str | None


class KillSwitch:
    """One-way cancellation signal that can also be driven by a local signal file."""

    def __init__(self, signal_path: Path | None = None) -> None:
        self._signal_path = signal_path.resolve() if signal_path else None
        self._active = False
        self._reason: str | None = None
        self._source: str | None = None

    @property
    def active(self) -> bool:
        return self._active

    @property
    def reason(self) -> str | None:
        return self._reason

    def activate(self, reason: str, *, source: str = "operator") -> bool:
        if self._active:
            return False
        self._active = True
        self._reason = reason[:500]
        self._source = source[:100]
        return True

    def poll(self) -> bool:
        if self._active or self._signal_path is None or not self._signal_path.is_file():
            return self._active
        try:
            reason = self._signal_path.read_text(encoding="utf-8")[:500].strip()
        except OSError:
            reason = "kill-switch signal file detected"
        self.activate(reason or "kill-switch signal file detected", source="signal-file")
        return True

    def snapshot(self) -> ControlSnapshot:
        return ControlSnapshot(active=self._active, reason=self._reason, source=self._source)

    async def wait(self, *, poll_interval: float = 0.05) -> str:
        """Wait cooperatively until an operator, policy, or signal file activates the switch."""

        while not self.poll():
            await asyncio.sleep(poll_interval)
        return self._reason or "campaign cancelled"


@dataclass
class BudgetController:
    """Reserve bounded campaign resources before agents or tools are started."""

    budgets: Budgets
    _started: float = field(init=False)
    agent_count: int = field(init=False, default=0)
    tool_calls: int = field(init=False, default=0)
    model_calls: int = field(init=False, default=0)
    model_prompt_tokens: int = field(init=False, default=0)
    model_completion_tokens: int = field(init=False, default=0)
    cost_usd: float = field(init=False, default=0.0)
    _elapsed_offset_seconds: float = field(init=False, default=0.0)

    def __post_init__(self) -> None:
        self._started = monotonic()
        self.agent_count = 0
        self.tool_calls = 0
        self.model_calls = 0
        self.model_prompt_tokens = 0
        self.model_completion_tokens = 0
        self.cost_usd = 0.0
        self._elapsed_offset_seconds = 0.0

    @property
    def elapsed_seconds(self) -> float:
        return self._elapsed_offset_seconds + monotonic() - self._started

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.budgets.duration_seconds - self.elapsed_seconds)

    def reserve_agent(self, *, depth: int) -> None:
        self.check_duration()
        if depth > self.budgets.max_spawn_depth:
            raise BudgetExceeded("maximum agent spawn depth exceeded")
        if self.agent_count >= self.budgets.max_agents:
            raise BudgetExceeded("maximum agent count exceeded")
        self.agent_count += 1

    def check_tool_call(self) -> None:
        self.check_duration()
        if self.tool_calls >= self.budgets.max_tool_calls:
            raise BudgetExceeded("maximum tool-call budget exceeded")

    def record_tool_call(self) -> None:
        if self.tool_calls >= self.budgets.max_tool_calls:
            raise BudgetExceeded("maximum tool-call budget exceeded")
        self.tool_calls += 1

    def record_cost(self, amount_usd: float) -> None:
        if amount_usd < 0:
            raise ValueError("cost cannot be negative")
        if self.cost_usd + amount_usd > self.budgets.max_cost_usd:
            raise BudgetExceeded("maximum campaign cost exceeded")
        self.cost_usd += amount_usd

    def check_model_call(self) -> None:
        self.check_duration()
        if self.model_calls >= self.budgets.max_model_calls:
            raise BudgetExceeded("maximum model-call budget exceeded")

    def record_model_call(self) -> None:
        self.check_model_call()
        self.model_calls += 1

    def record_model_usage(
        self,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> None:
        if prompt_tokens < 0 or completion_tokens < 0:
            raise ValueError("model token usage cannot be negative")
        total = prompt_tokens + completion_tokens
        used = self.model_prompt_tokens + self.model_completion_tokens
        if used + total > self.budgets.max_model_tokens:
            raise BudgetExceeded("maximum model-token budget exceeded")
        if cost_usd < 0:
            raise ValueError("cost cannot be negative")
        if self.cost_usd + cost_usd > self.budgets.max_cost_usd:
            raise BudgetExceeded("maximum campaign cost exceeded")
        self.model_prompt_tokens += prompt_tokens
        self.model_completion_tokens += completion_tokens
        self.cost_usd += cost_usd

    def restore_usage(
        self,
        *,
        agent_count: int,
        tool_calls: int,
        model_calls: int,
        model_prompt_tokens: int,
        model_completion_tokens: int,
        cost_usd: float,
        elapsed_seconds: float,
    ) -> None:
        if any(
            value != 0
            for value in (
                self.tool_calls,
                self.agent_count,
                self.model_calls,
                self.model_prompt_tokens,
                self.model_completion_tokens,
                self.cost_usd,
                self._elapsed_offset_seconds,
            )
        ):
            raise ValueError("budget usage can be restored only before execution")
        if not 0 <= agent_count <= self.budgets.max_agents:
            raise BudgetExceeded("restored agent usage exceeds campaign budget")
        if not 0 <= tool_calls <= self.budgets.max_tool_calls:
            raise BudgetExceeded("restored tool-call usage exceeds campaign budget")
        if not 0 <= model_calls <= self.budgets.max_model_calls:
            raise BudgetExceeded("restored model-call usage exceeds campaign budget")
        total_tokens = model_prompt_tokens + model_completion_tokens
        if model_prompt_tokens < 0 or model_completion_tokens < 0:
            raise ValueError("restored model token usage cannot be negative")
        if total_tokens > self.budgets.max_model_tokens:
            raise BudgetExceeded("restored model-token usage exceeds campaign budget")
        if not 0 <= cost_usd <= self.budgets.max_cost_usd:
            raise BudgetExceeded("restored cost exceeds campaign budget")
        if not 0 <= elapsed_seconds < self.budgets.duration_seconds:
            raise BudgetExceeded("restored duration exceeds campaign budget")
        self.agent_count = agent_count
        self.tool_calls = tool_calls
        self.model_calls = model_calls
        self.model_prompt_tokens = model_prompt_tokens
        self.model_completion_tokens = model_completion_tokens
        self.cost_usd = cost_usd
        self._elapsed_offset_seconds = elapsed_seconds
        self._started = monotonic()

    def check_duration(self) -> None:
        if self.remaining_seconds <= 0:
            raise BudgetExceeded("maximum campaign duration exceeded")

    def snapshot(self) -> dict[str, object]:
        return {
            "agentCount": self.agent_count,
            "maxAgents": self.budgets.max_agents,
            "toolCalls": self.tool_calls,
            "maxToolCalls": self.budgets.max_tool_calls,
            "modelCalls": self.model_calls,
            "maxModelCalls": self.budgets.max_model_calls,
            "modelPromptTokens": self.model_prompt_tokens,
            "modelCompletionTokens": self.model_completion_tokens,
            "modelTokens": self.model_prompt_tokens + self.model_completion_tokens,
            "maxModelTokens": self.budgets.max_model_tokens,
            "costUsd": self.cost_usd,
            "maxCostUsd": self.budgets.max_cost_usd,
            "elapsedSeconds": round(self.elapsed_seconds, 6),
            "durationSeconds": self.budgets.duration_seconds,
        }
