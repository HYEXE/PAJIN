"""Opt-in Discovery waves before the unchanged existing local campaign."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pajin.discovery.hypothesis import (
    DynamicHypothesisWaveRunner,
    HypothesisWaveOutcome,
)
from pajin.discovery.recon import ReconWaveOutcome, SingleReconWaveRunner
from pajin.discovery.replanning import (
    BoundedReplanningOutcome,
    BoundedReplanningRunner,
)
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
    """Separate Discovery authorities and unchanged existing campaign outcome."""

    recon: ReconWaveOutcome | None
    hypothesis_wave: HypothesisWaveOutcome | None
    replanning: BoundedReplanningOutcome | None
    campaign: RunOutcome


class DiscoveryCampaignRunner:
    """Run A3-A5/ORCH-002 without changing the existing Planner input."""

    def __init__(
        self,
        *,
        campaign: _LocalCampaign,
        recon: SingleReconWaveRunner | None = None,
        hypothesis_wave: DynamicHypothesisWaveRunner | None = None,
        replanning: BoundedReplanningRunner | None = None,
    ) -> None:
        self._campaign = campaign
        self._recon = recon
        self._hypothesis_wave = hypothesis_wave
        self._replanning = replanning

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        enable_recon: bool = False,
        enable_hypothesis_wave: bool = False,
        enable_replanning: bool = False,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> DiscoveryCampaignOutcome:
        if type(enable_recon) is not bool:
            raise TypeError("Recon feature flag must be a boolean")
        if type(enable_hypothesis_wave) is not bool:
            raise TypeError("Hypothesis Wave feature flag must be a boolean")
        if type(enable_replanning) is not bool:
            raise TypeError("Bounded Replanning feature flag must be a boolean")
        if enable_hypothesis_wave and not enable_recon:
            raise ValueError("Hypothesis Wave requires the trusted Recon projection")
        if enable_replanning and not enable_hypothesis_wave:
            raise ValueError("Bounded Replanning requires the initial Hypothesis Wave")
        if enable_recon and self._recon is None:
            raise ValueError("Recon was enabled without a configured Recon runner")
        if enable_hypothesis_wave and self._hypothesis_wave is None:
            raise ValueError("Hypothesis Wave was enabled without a configured Hypothesis runner")
        if enable_replanning and self._replanning is None:
            raise ValueError(
                "Bounded Replanning was enabled without a configured Replanning runner"
            )
        if cancellation is not None and cancellation.binding is not None:
            raise ValueError("execution cancellation context is already bound to another Run")
        if not enable_recon:
            outcome = await self._campaign.run(
                campaign,
                cancellation=cancellation,
                budget=budget,
                rate_limits=rate_limits,
            )
            return DiscoveryCampaignOutcome(
                recon=None,
                hypothesis_wave=None,
                replanning=None,
                campaign=outcome,
            )
        assert self._recon is not None

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
        hypothesis_outcome = None
        replanning_outcome = None
        if enable_hypothesis_wave:
            assert self._hypothesis_wave is not None
            hypothesis_outcome = await self._hypothesis_wave.run(
                authoritative_campaign,
                recon_outcome,
                cancellation=cancellation,
                budget=shared_budget,
                rate_limits=shared_rate_limits,
            )
        if enable_replanning:
            assert self._replanning is not None
            assert hypothesis_outcome is not None
            replanning_outcome = await self._replanning.run(
                authoritative_campaign,
                recon_outcome,
                hypothesis_outcome,
                cancellation=cancellation,
                budget=shared_budget,
                rate_limits=shared_rate_limits,
            )
        # ORCH-002 still passes no Surface, Hypothesis, Observation, or result into
        # the existing one-time Planner. Its bounded multi-wave authority remains
        # a separate Run.
        campaign_outcome = await self._campaign.run(
            authoritative_campaign,
            cancellation=cancellation,
            budget=shared_budget,
            rate_limits=shared_rate_limits,
        )
        return DiscoveryCampaignOutcome(
            recon=recon_outcome,
            hypothesis_wave=hypothesis_outcome,
            replanning=replanning_outcome,
            campaign=campaign_outcome,
        )
