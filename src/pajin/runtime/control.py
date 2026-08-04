"""Campaign-wide budgets and cooperative cancellation controls."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from math import isfinite
from pathlib import Path
from threading import RLock
from time import monotonic
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from pajin.domain.models import Budgets
from pajin.runtime.safe_files import read_bounded_regular_bytes

_KILL_SWITCH_SIGNAL_MAX_BYTES = 2_048
_KILL_SWITCH_REASON_MAX_CHARS = 500
_KILL_SWITCH_FALLBACK_REASON = "kill-switch signal file detected"


class BudgetExceeded(RuntimeError):
    """Raised before an operation would exceed a campaign budget."""


@dataclass(frozen=True)
class ModelUsageReservation:
    """One conservative in-flight model call, Tool call, token, and cost reservation."""

    reservation_id: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    tool_calls: int
    model_calls: int


@dataclass(frozen=True)
class DualModelUsageReservation:
    """One exact reservation charged to Campaign and dedicated model budgets."""

    reservation_id: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    tool_calls: int
    model_calls: int


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
        for child in tuple(self._children):
            if child.active:
                child.mark_forced()

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
        self._signal_path = (
            Path(os.path.abspath(os.fspath(signal_path.expanduser()))) if signal_path else None
        )
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
        self._reason = reason[:_KILL_SWITCH_REASON_MAX_CHARS]
        self._source = source[:100]
        return True

    def poll(self) -> bool:
        if self._active or self._signal_path is None:
            return self._active
        try:
            self._signal_path.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            self.activate(_KILL_SWITCH_FALLBACK_REASON, source="signal-file")
            return True
        try:
            reason = read_bounded_regular_bytes(
                self._signal_path,
                max_bytes=_KILL_SWITCH_SIGNAL_MAX_BYTES,
                label="kill-switch signal",
                require_single_link=True,
            ).decode("utf-8")
        except (OSError, UnicodeError, ValueError):
            reason = _KILL_SWITCH_FALLBACK_REASON
        self.activate(
            reason[:_KILL_SWITCH_REASON_MAX_CHARS].strip() or _KILL_SWITCH_FALLBACK_REASON,
            source="signal-file",
        )
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
    _usage_lock: RLock = field(init=False, repr=False, compare=False)
    _model_usage_reservations: dict[str, ModelUsageReservation] = field(
        init=False,
        default_factory=dict,
        repr=False,
    )

    def __post_init__(self) -> None:
        self.budgets = Budgets.model_validate(
            self.budgets.model_dump(mode="python", by_alias=True)
        )
        self._usage_lock = RLock()
        self._started = monotonic()
        self.agent_count = 0
        self.tool_calls = 0
        self.model_calls = 0
        self.model_prompt_tokens = 0
        self.model_completion_tokens = 0
        self.cost_usd = 0.0
        self._elapsed_offset_seconds = 0.0
        self._model_usage_reservations = {}

    @property
    def elapsed_seconds(self) -> float:
        with self._usage_lock:
            return self._elapsed_offset_seconds + monotonic() - self._started

    @property
    def remaining_seconds(self) -> float:
        with self._usage_lock:
            return max(0.0, self.budgets.duration_seconds - self.elapsed_seconds)

    def reserve_agent(self, *, depth: int) -> None:
        with self._usage_lock:
            self.check_duration()
            if depth > self.budgets.max_spawn_depth:
                raise BudgetExceeded("maximum agent spawn depth exceeded")
            if self.agent_count >= self.budgets.max_agents:
                raise BudgetExceeded("maximum agent count exceeded")
            self.agent_count += 1

    def check_tool_call(self) -> None:
        with self._usage_lock:
            self.check_duration()
            if self.tool_calls >= self.budgets.max_tool_calls:
                raise BudgetExceeded("maximum tool-call budget exceeded")

    def record_tool_call(self) -> None:
        with self._usage_lock:
            if self.tool_calls >= self.budgets.max_tool_calls:
                raise BudgetExceeded("maximum tool-call budget exceeded")
            self.tool_calls += 1

    def record_cost(self, amount_usd: float) -> None:
        with self._usage_lock:
            if type(amount_usd) not in {int, float}:
                raise ValueError("cost must be a finite JSON number")
            if not isfinite(amount_usd) or amount_usd < 0:
                raise ValueError("cost must be finite and non-negative")
            if self.cost_usd + amount_usd > self.budgets.max_cost_usd:
                raise BudgetExceeded("maximum campaign cost exceeded")
            self.cost_usd += amount_usd

    def check_model_call(self) -> None:
        with self._usage_lock:
            self.check_duration()
            if self.model_calls >= self.budgets.max_model_calls:
                raise BudgetExceeded("maximum model-call budget exceeded")

    def record_model_call(self) -> None:
        with self._usage_lock:
            self.check_model_call()
            self.model_calls += 1

    def record_model_usage(
        self,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> None:
        with self._usage_lock:
            self._check_model_usage_capacity(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost_usd,
            )
            self.model_prompt_tokens += prompt_tokens
            self.model_completion_tokens += completion_tokens
            self.cost_usd += cost_usd

    def _check_model_usage_capacity(
        self,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> None:
        with self._usage_lock:
            if type(prompt_tokens) is not int or type(completion_tokens) is not int:
                raise ValueError("model token usage must use JSON integers")
            if prompt_tokens < 0 or completion_tokens < 0:
                raise ValueError("model token usage cannot be negative")
            total = prompt_tokens + completion_tokens
            used = self.model_prompt_tokens + self.model_completion_tokens
            if used + total > self.budgets.max_model_tokens:
                raise BudgetExceeded("maximum model-token budget exceeded")
            if type(cost_usd) not in {int, float}:
                raise ValueError("model cost usage must be a finite JSON number")
            if not isfinite(cost_usd) or cost_usd < 0:
                raise ValueError("cost must be finite and non-negative")
            if self.cost_usd + cost_usd > self.budgets.max_cost_usd:
                raise BudgetExceeded("maximum campaign cost exceeded")

    def reserve_model_usage(
        self,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> ModelUsageReservation:
        """Atomically charge one model/Tool call and its bound before dispatch."""

        with self._usage_lock:
            self.check_tool_call()
            self.check_model_call()
            self._check_model_usage_capacity(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost_usd,
            )
            reservation = ModelUsageReservation(
                reservation_id=f"model-reservation_{uuid4().hex}",
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost_usd,
                tool_calls=1,
                model_calls=1,
            )
            self.tool_calls += reservation.tool_calls
            self.model_calls += reservation.model_calls
            self.model_prompt_tokens += prompt_tokens
            self.model_completion_tokens += completion_tokens
            self.cost_usd += cost_usd
            self._model_usage_reservations[reservation.reservation_id] = reservation
            return reservation

    def settle_model_usage(
        self,
        reservation: ModelUsageReservation,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> None:
        """Replace one active conservative reservation with trusted actual usage."""

        with self._usage_lock:
            self._require_model_usage_reservation(reservation)
            if type(prompt_tokens) is not int or type(completion_tokens) is not int:
                raise ValueError("model token usage must use JSON integers")
            if prompt_tokens < 0 or completion_tokens < 0:
                raise ValueError("model token usage cannot be negative")
            if type(cost_usd) not in {int, float}:
                raise ValueError("model cost usage must be a finite JSON number")
            if not isfinite(cost_usd) or cost_usd < 0:
                raise ValueError("cost must be finite and non-negative")
            if (
                prompt_tokens > reservation.prompt_tokens
                or completion_tokens > reservation.completion_tokens
                or cost_usd > reservation.cost_usd
            ):
                self.commit_model_usage_reservation(reservation)
                raise BudgetExceeded("model usage exceeded its conservative reservation")

            del self._model_usage_reservations[reservation.reservation_id]
            self.model_prompt_tokens -= reservation.prompt_tokens - prompt_tokens
            self.model_completion_tokens -= reservation.completion_tokens - completion_tokens
            self.cost_usd = max(0.0, self.cost_usd - (reservation.cost_usd - cost_usd))

    def commit_model_usage_reservation(self, reservation: ModelUsageReservation) -> None:
        """Consume an active reservation at its bound when actual usage is unknowable."""

        with self._usage_lock:
            self._require_model_usage_reservation(reservation)
            del self._model_usage_reservations[reservation.reservation_id]

    def release_model_usage_reservation(self, reservation: ModelUsageReservation) -> None:
        """Release a reservation only when the model request provably was not dispatched."""

        with self._usage_lock:
            self._require_model_usage_reservation(reservation)
            del self._model_usage_reservations[reservation.reservation_id]
            self.tool_calls -= reservation.tool_calls
            self.model_calls -= reservation.model_calls
            self.model_prompt_tokens -= reservation.prompt_tokens
            self.model_completion_tokens -= reservation.completion_tokens
            self.cost_usd = max(0.0, self.cost_usd - reservation.cost_usd)

    def _require_model_usage_reservation(
        self,
        reservation: ModelUsageReservation,
    ) -> None:
        with self._usage_lock:
            active = self._model_usage_reservations.get(reservation.reservation_id)
            if active is not reservation:
                raise ValueError("model usage reservation is not active on this budget")

    def restore_usage(
        self,
        *,
        agent_count: object,
        tool_calls: object,
        model_calls: object,
        model_prompt_tokens: object,
        model_completion_tokens: object,
        cost_usd: object,
        elapsed_seconds: object,
    ) -> None:
        with self._usage_lock:
            if self._model_usage_reservations or any(
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
            integer_usage = {
                "agent count": agent_count,
                "tool-call count": tool_calls,
                "model-call count": model_calls,
                "model prompt tokens": model_prompt_tokens,
                "model completion tokens": model_completion_tokens,
            }
            for label, value in integer_usage.items():
                if type(value) is not int:
                    raise ValueError(f"restored {label} must use a JSON integer")
            if type(cost_usd) not in {int, float}:
                raise ValueError("restored cost must be a finite JSON number")
            if type(elapsed_seconds) not in {int, float}:
                raise ValueError("restored duration must be a finite JSON number")
            assert isinstance(agent_count, int)
            assert isinstance(tool_calls, int)
            assert isinstance(model_calls, int)
            assert isinstance(model_prompt_tokens, int)
            assert isinstance(model_completion_tokens, int)
            assert isinstance(cost_usd, (int, float))
            assert isinstance(elapsed_seconds, (int, float))
            if not isfinite(cost_usd):
                raise ValueError("restored cost must be a finite JSON number")
            if not isfinite(elapsed_seconds):
                raise ValueError("restored duration must be a finite JSON number")
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
            if not isfinite(cost_usd) or not 0 <= cost_usd <= self.budgets.max_cost_usd:
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
        with self._usage_lock:
            if self.remaining_seconds <= 0:
                raise BudgetExceeded("maximum campaign duration exceeded")

    def snapshot(self) -> dict[str, object]:
        with self._usage_lock:
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


class DualModelUsageBudget:
    """Atomically reserve the same model usage on Campaign and dedicated budgets."""

    def __init__(
        self,
        campaign_budget: BudgetController,
        dedicated_budget: BudgetController,
    ) -> None:
        if campaign_budget is dedicated_budget:
            raise ValueError("dual model budget requires two distinct controllers")
        self._campaign_budget = campaign_budget
        self._dedicated_budget = dedicated_budget
        self._ordered_budgets = tuple(
            sorted((campaign_budget, dedicated_budget), key=id)
        )
        self._reservations: dict[
            str,
            tuple[
                DualModelUsageReservation,
                ModelUsageReservation,
                ModelUsageReservation,
            ],
        ] = {}

    @property
    def remaining_seconds(self) -> float:
        first, second = self._ordered_budgets
        with first._usage_lock, second._usage_lock:
            return min(
                self._campaign_budget.remaining_seconds,
                self._dedicated_budget.remaining_seconds,
            )

    def binds_campaign_budget(self, budget: BudgetController) -> bool:
        """Return whether this dual boundary charges the supplied Campaign ledger."""

        return self._campaign_budget is budget

    def check_tool_call(self) -> None:
        first, second = self._ordered_budgets
        with first._usage_lock, second._usage_lock:
            self._campaign_budget.check_tool_call()
            self._dedicated_budget.check_tool_call()

    def check_model_call(self) -> None:
        first, second = self._ordered_budgets
        with first._usage_lock, second._usage_lock:
            self._campaign_budget.check_model_call()
            self._dedicated_budget.check_model_call()

    def reserve_model_usage(
        self,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> DualModelUsageReservation:
        first, second = self._ordered_budgets
        with first._usage_lock, second._usage_lock:
            campaign_reservation = self._campaign_budget.reserve_model_usage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost_usd,
            )
            dedicated_reservation: ModelUsageReservation | None = None
            reservation: DualModelUsageReservation | None = None
            try:
                dedicated_reservation = self._dedicated_budget.reserve_model_usage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    cost_usd=cost_usd,
                )
                reservation = DualModelUsageReservation(
                    reservation_id=f"dual-model-reservation_{uuid4().hex}",
                    prompt_tokens=campaign_reservation.prompt_tokens,
                    completion_tokens=campaign_reservation.completion_tokens,
                    cost_usd=campaign_reservation.cost_usd,
                    tool_calls=campaign_reservation.tool_calls,
                    model_calls=campaign_reservation.model_calls,
                )
                self._reservations[reservation.reservation_id] = (
                    reservation,
                    campaign_reservation,
                    dedicated_reservation,
                )
            except BaseException:
                if reservation is not None:
                    self._reservations.pop(reservation.reservation_id, None)
                if dedicated_reservation is not None:
                    self._dedicated_budget.release_model_usage_reservation(
                        dedicated_reservation
                    )
                self._campaign_budget.release_model_usage_reservation(
                    campaign_reservation
                )
                raise
            return reservation

    def commit_model_usage_reservation(
        self,
        reservation: DualModelUsageReservation,
    ) -> None:
        first, second = self._ordered_budgets
        with first._usage_lock, second._usage_lock:
            campaign_reservation, dedicated_reservation = self._require_reservation(
                reservation
            )
            self._campaign_budget._require_model_usage_reservation(
                campaign_reservation
            )
            self._dedicated_budget._require_model_usage_reservation(
                dedicated_reservation
            )
            self._campaign_budget.commit_model_usage_reservation(
                campaign_reservation
            )
            self._dedicated_budget.commit_model_usage_reservation(
                dedicated_reservation
            )
            del self._reservations[reservation.reservation_id]

    def release_model_usage_reservation(
        self,
        reservation: DualModelUsageReservation,
    ) -> None:
        first, second = self._ordered_budgets
        with first._usage_lock, second._usage_lock:
            campaign_reservation, dedicated_reservation = self._require_reservation(
                reservation
            )
            self._campaign_budget._require_model_usage_reservation(
                campaign_reservation
            )
            self._dedicated_budget._require_model_usage_reservation(
                dedicated_reservation
            )
            self._campaign_budget.release_model_usage_reservation(
                campaign_reservation
            )
            self._dedicated_budget.release_model_usage_reservation(
                dedicated_reservation
            )
            del self._reservations[reservation.reservation_id]

    def _require_reservation(
        self,
        reservation: DualModelUsageReservation,
    ) -> tuple[ModelUsageReservation, ModelUsageReservation]:
        active = self._reservations.get(reservation.reservation_id)
        if active is None or active[0] is not reservation:
            raise ValueError("dual model usage reservation is not active")
        return active[1], active[2]
