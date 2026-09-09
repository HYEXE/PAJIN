"""First-work conservative budgets for exact authenticated Control Plane Runs."""

from __future__ import annotations

import sqlite3
from collections.abc import Awaitable, Callable
from hashlib import sha256
from pathlib import Path

from pajin.control_plane.models import JobView, replay_execution_component_digest
from pajin.domain.models import CampaignManifest
from pajin.runtime.control import BudgetController


class RunBudgetError(ValueError):
    """This Run has no complete, currently usable durable budget."""


class RunBudgetRegistry:
    """Select only code-derived journal paths; a Job cannot supply another store."""

    def __init__(self, root: Path) -> None:
        self._root = root.absolute()

    def bind(
        self, job: JobView, campaign: CampaignManifest, *, original_input: object,
        resuming: bool = False,
    ) -> BudgetController:
        try:
            return self._bind(job, campaign, original_input=original_input, resuming=resuming)
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            raise RunBudgetError("Control Plane Run budget could not be recovered") from None

    def _bind(
        self, job: JobView, campaign: CampaignManifest, *, original_input: object, resuming: bool,
    ) -> BudgetController:
        from pajin.supervision.invocation_journal import SupervisorInvocationJournal
        from pajin.supervision.run_binding import SupervisorRunBinding

        campaign = CampaignManifest.model_validate(campaign.model_dump(mode="python"))
        campaign_digest = replay_execution_component_digest(campaign)
        binding = SupervisorRunBinding(
            controlPlaneRunId=job.run_id,
            campaignDigest=campaign_digest,
            inputDigest=replay_execution_component_digest({
                "kind": job.kind, "input": original_input,
            }),
            budgetMode="campaign-only",
        )
        filename = sha256(job.run_id.encode("ascii")).hexdigest() + ".sqlite3"
        journal = SupervisorInvocationJournal(
            self._root / filename,
            run_binding=binding,
            allow_create=(job.attempts == 1 and not resuming),
        )
        budget = BudgetController(campaign.spec.budgets)
        journal.bind_campaign_budget(campaign_digest=campaign_digest, campaign=budget)
        return budget


async def run_budgeted_action[Result](
    budget: BudgetController | None,
    operation: Callable[[], Awaitable[Result]],
    *,
    dispatched: Callable[[Result], bool],
) -> Result:
    """Retain an upper-bound Tool charge for failed/uncertain Capability dispatch."""
    if budget is None:
        return await operation()
    reservation = budget.reserve_tool_usage()
    try:
        result = await operation()
    except BaseException as exc:
        try:
            budget.commit_tool_usage_reservation(reservation)
        except Exception:
            exc.add_note("Action accounting failed; retain the reservation and recover.")
        raise
    if dispatched(result):
        budget.commit_tool_usage_reservation(reservation)
    else:
        budget.release_tool_usage_reservation(reservation)
    return result
