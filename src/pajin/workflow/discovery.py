"""Opt-in composition of one Recon wave before the existing local campaign."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pajin.discovery.recon import ReconWaveOutcome, SingleReconWaveRunner
from pajin.domain.models import CampaignManifest
from pajin.runtime.control import BudgetController, ExecutionCancellationContext
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.local import RunOutcome


class _LocalCampaign(Protocol):
    async def run(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> RunOutcome: ...


@dataclass(frozen=True, slots=True)
class DiscoveryCampaignOutcome:
    """Separate Recon authority and unchanged existing campaign outcome."""

    recon: ReconWaveOutcome | None
    campaign: RunOutcome


class DiscoveryCampaignRunner:
    """Run A3 only behind an explicit flag and never feed Surfaces to the Planner."""

    def __init__(
        self,
        *,
        campaign: _LocalCampaign,
        recon: SingleReconWaveRunner | None = None,
    ) -> None:
        self._campaign = campaign
        self._recon = recon

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        enable_recon: bool = False,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> DiscoveryCampaignOutcome:
        if type(enable_recon) is not bool:
            raise TypeError("Recon feature flag must be a boolean")
        if cancellation is not None and cancellation.binding is not None:
            raise ValueError("execution cancellation context is already bound to another Run")
        if not enable_recon:
            outcome = await self._campaign.run(
                campaign,
                cancellation=cancellation,
                budget=budget,
                rate_limits=rate_limits,
            )
            return DiscoveryCampaignOutcome(recon=None, campaign=outcome)
        if self._recon is None:
            raise ValueError("Recon was enabled without a configured Recon runner")

        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="python", by_alias=True)
        )
        if budget is not None and budget.budgets != authoritative_campaign.spec.budgets:
            raise ValueError("shared budget does not match the Campaign budget contract")
        shared_budget = budget or BudgetController(authoritative_campaign.spec.budgets)
        shared_rate_limits = rate_limits or RequestRateLimitLedger()
        recon_outcome = await self._recon.run(
            authoritative_campaign,
            cancellation=cancellation,
            budget=shared_budget,
            rate_limits=shared_rate_limits,
        )
        # A3 intentionally passes no Surface or admission object to the existing Planner.
        campaign_outcome = await self._campaign.run(
            authoritative_campaign,
            cancellation=cancellation,
            budget=shared_budget,
            rate_limits=shared_rate_limits,
        )
        return DiscoveryCampaignOutcome(
            recon=recon_outcome,
            campaign=campaign_outcome,
        )
