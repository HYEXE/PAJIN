"""Pre-dispatch accounting around an existing code-owned Gateway operation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from pajin.runtime.control import BudgetController

if TYPE_CHECKING:
    from pajin.tools.gateway import GatewayOutcome


async def budgeted_tool_call(
    budget: BudgetController, operation: Callable[[], Awaitable[GatewayOutcome]]
) -> GatewayOutcome:
    reservation = budget.reserve_tool_usage()
    try:
        outcome = await operation()
    except BaseException as exc:
        try:
            budget.commit_tool_usage_reservation(reservation)
        except Exception:
            # The durable reservation already covers this uncertain execution.
            # Preserve cancellation so the runner can seal its cleanup receipt.
            exc.add_note("Tool budget accounting failed; retain the reservation and recover.")
        raise
    if outcome.executed:
        budget.commit_tool_usage_reservation(reservation)
    else:
        budget.release_tool_usage_reservation(reservation)
    return outcome
