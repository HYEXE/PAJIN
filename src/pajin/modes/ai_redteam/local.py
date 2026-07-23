"""Explicit single-process Local orchestration for KISA replay confirmation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pajin.agents.base import CandidateValidation
from pajin.domain.models import AgentPlan, CampaignManifest, CampaignMode, Finding, ToolResult
from pajin.domain.validation import CandidateFinding
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.catalog import KISA_CATALOG, KISACatalog
from pajin.modes.ai_redteam.replay import KISAReplayBatchOutcome, KISAReplayCoordinator
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime, KISAValidatorRuntime
from pajin.policy.engine import PolicyEngine
from pajin.replay.tickets import ReplayTicketAuthority
from pajin.runtime.control import BudgetController, ExecutionCancellationContext
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.confirmation import apply_confirmed_gate
from pajin.workflow.local import LocalCampaignRunner, RunOutcome
from pajin.workflow.validation_artifacts import VERSIONED_VALIDATION_REPORT_PATH


class KISALocalAgentRuntime:
    """Expose one trusted AgentRuntime identity over KISA planning and validation ports."""

    __slots__ = ("_planner", "_validator")
    agent_id = "trusted-core:kisa-local-agent"

    def __init__(
        self,
        *,
        planner: KISAPlannerRuntime,
        validator: KISAValidatorRuntime,
    ) -> None:
        self._planner = planner
        self._validator = validator

    @property
    def repetitions(self) -> int:
        """Return the source-plan repetition count owned by the KISA planner."""

        return self._planner.thresholds.repetitions

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        return await self._planner.plan(campaign)

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        return await self._validator.validate(campaign, plan, results)

    async def validate_candidates(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        candidates: list[CandidateFinding],
    ) -> CandidateValidation:
        return await self._validator.validate_candidates(campaign, plan, results, candidates)


@dataclass(frozen=True, slots=True)
class KISALocalReplayOutcome:
    """Local source outcome and its replay batch with read-only ticket verification."""

    outcome: RunOutcome
    batch: KISAReplayBatchOutcome


class KISALocalReplayOrchestrator:
    """Run one KISA source and its restricted replays through a single Local writer.

    This is deliberately an in-process, single-writer boundary. It does not provide a
    cross-process Gate lock or a generic replay registry; those belong to the durable
    Control Plane orchestration boundary.
    """

    def __init__(
        self,
        *,
        agents: KISALocalAgentRuntime,
        tools: ToolRegistry,
        policy: PolicyEngine,
        worker: WorkerBackend,
        output_root: Path,
        ticket_authority_factory: Callable[[], ReplayTicketAuthority],
        repetitions: int = 2,
        catalog: KISACatalog = KISA_CATALOG,
    ) -> None:
        if not 2 <= repetitions <= 20:
            raise ValueError("KISA Local repetitions must be between 2 and 20")
        if agents.repetitions != repetitions:
            raise ValueError("KISA Local source and replay repetitions must use the same contract")
        self._agents = agents
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._output_root = output_root
        self._ticket_authority_factory = ticket_authority_factory
        self._repetitions = repetitions
        self._catalog = catalog
        self._running = False

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> KISALocalReplayOutcome:
        """Create a sealed source, verify complete replay coverage, and project Gate results."""

        if campaign.spec.mode is not CampaignMode.AI_REDTEAM:
            raise ValueError("KISA Local replay requires an AI Red Team Campaign")
        if self._agents.repetitions != self._repetitions:
            raise ValueError("KISA Local source and replay repetitions changed after setup")
        if self._running:
            raise RuntimeError("KISA Local replay orchestration is single-writer per instance")
        self._running = True
        try:
            live_budget = budget or BudgetController(campaign.spec.budgets)
            live_rate_limits = rate_limits or RequestRateLimitLedger()
            source_runner = LocalCampaignRunner(
                agents=self._agents,
                tools=self._tools,
                policy=self._policy,
                worker=self._worker,
                output_root=self._output_root,
                candidate_producer=KISACandidateProducer(catalog=self._catalog),
            )
            outcome = await source_runner.run(
                campaign,
                cancellation=cancellation,
                budget=live_budget,
                rate_limits=live_rate_limits,
            )
            coordinator = KISAReplayCoordinator(
                tools=self._tools,
                policy=self._policy,
                worker=self._worker,
                output_root=self._output_root / "local-replay",
                repetitions=self._repetitions,
                required_successes=self._repetitions,
                catalog=self._catalog,
                ticket_authority_factory=self._ticket_authority_factory,
            )
            batch = await coordinator.reproduce(
                campaign,
                outcome.run_path,
                budget=live_budget,
                rate_limits=live_rate_limits,
                cancellation=cancellation,
            )

            # This reload is mandatory even when the batch is empty: it proves that
            # the sealed receipts exactly cover the coordinator's eligible set.
            batch.verified_records(outcome.run_path)
            if batch.confirmation_results:
                projection = apply_confirmed_gate(
                    source_run_path=outcome.run_path,
                    replay_run_paths=[
                        result.run_path for result in batch.confirmation_results.values()
                    ],
                    tickets=batch.tickets,
                )
                outcome = outcome.model_copy(
                    update={
                        "validation": projection.validation,
                        "findings": projection.product_confirmed_findings,
                        "report_path": outcome.run_path / VERSIONED_VALIDATION_REPORT_PATH,
                    }
                )
            return KISALocalReplayOutcome(outcome=outcome, batch=batch)
        finally:
            self._running = False
