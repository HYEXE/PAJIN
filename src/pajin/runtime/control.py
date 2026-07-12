"""Campaign-wide budgets and cooperative cancellation controls."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic

from pydantic import BaseModel, ConfigDict

from pajin.domain.models import Budgets


class BudgetExceeded(RuntimeError):
    """Raised before an operation would exceed a campaign budget."""


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
    cost_usd: float = field(init=False, default=0.0)

    def __post_init__(self) -> None:
        self._started = monotonic()
        self.agent_count = 0
        self.tool_calls = 0
        self.cost_usd = 0.0

    @property
    def elapsed_seconds(self) -> float:
        return monotonic() - self._started

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

    def check_duration(self) -> None:
        if self.remaining_seconds <= 0:
            raise BudgetExceeded("maximum campaign duration exceeded")

    def snapshot(self) -> dict[str, object]:
        return {
            "agentCount": self.agent_count,
            "maxAgents": self.budgets.max_agents,
            "toolCalls": self.tool_calls,
            "maxToolCalls": self.budgets.max_tool_calls,
            "costUsd": self.cost_usd,
            "maxCostUsd": self.budgets.max_cost_usd,
            "elapsedSeconds": round(self.elapsed_seconds, 6),
            "durationSeconds": self.budgets.duration_seconds,
        }
