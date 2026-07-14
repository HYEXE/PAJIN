"""Local durable-enough vertical slice for a PAJIN campaign."""

from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from pajin.agents.base import AgentRuntime
from pajin.domain.models import CampaignManifest, CapabilityGrant, Finding, ToolResult
from pajin.policy.engine import PolicyEngine
from pajin.reporting.markdown import render_markdown_report
from pajin.runtime.control import ExecutionCancellationContext
from pajin.runtime.store import RunStore
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.workflow.cancellation import (
    await_with_cancellation,
    ensure_cancellation_context,
    record_engine_cleanup,
)


class RunOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    run_path: Path
    tool_results: list[ToolResult]
    findings: list[Finding]
    report_path: Path


class LocalCampaignRunner:
    """Run a campaign locally while preserving policy and audit boundaries."""

    def __init__(
        self,
        *,
        agents: AgentRuntime,
        tools: ToolRegistry,
        policy: PolicyEngine,
        worker: WorkerBackend,
        output_root: Path,
    ) -> None:
        self._agents = agents
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._output_root = output_root

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> RunOutcome:
        store = RunStore.create(self._output_root, campaign.metadata.name)
        if cancellation is not None:
            cancellation.bind_run(
                engine="local-campaign",
                run_id=store.run_id,
                path=store.path,
            )
        try:
            return await await_with_cancellation(
                self._execute(campaign, store),
                cancellation,
            )
        except asyncio.CancelledError:
            context = ensure_cancellation_context(
                cancellation,
                engine="local-campaign",
                store=store,
            )
            receipt = record_engine_cleanup(store, context)
            store.write_json(
                "run.json",
                {
                    "runId": store.run_id,
                    "status": "cancelled",
                    "cancellationReceipt": receipt,
                },
            )
            store.append_event(
                "campaign.cancelled",
                {
                    "reason": context.snapshot().reason,
                    "cancellationReceipt": receipt,
                },
            )
            store.seal()
            raise

    async def _execute(self, campaign: CampaignManifest, store: RunStore) -> RunOutcome:
        store.append_event(
            "campaign.started",
            {"campaign": campaign.metadata.name, "mode": campaign.spec.mode.value},
        )
        store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))

        grant = CapabilityGrant(
            subject=self._agents.agent_id,
            campaign=campaign.metadata.name,
            tools=self._tools.tool_ids(),
            targets={target.endpoint for target in campaign.spec.targets},
            max_risk_tier=campaign.spec.rules_of_engagement.max_tool_risk_tier,
            max_calls=campaign.spec.budgets.max_tool_calls,
            expires_at=campaign.spec.authorization.expires_at,
            delegable=True,
        )
        store.append_event(
            "capability.issued",
            grant.model_dump(mode="json"),
        )

        plan = await self._agents.plan(campaign)
        store.write_json("plan.json", plan.model_dump(mode="json"))
        store.append_event("agent.plan.created", {"steps": len(plan.steps)})

        gateway = ToolGateway(
            policy=self._policy,
            tools=self._tools,
            worker=self._worker,
            store=store,
        )
        results: list[ToolResult] = []
        used_calls = 0
        for step in plan.steps:
            outcome = await gateway.execute(
                campaign,
                grant,
                step.request,
                used_calls=used_calls,
            )
            if outcome.executed:
                used_calls += 1
            results.append(outcome.result)

        findings = await self._agents.validate(campaign, plan, results)
        confirmed = [finding for finding in findings if finding.validated]
        store.write_json(
            "findings.json", [finding.model_dump(mode="json") for finding in confirmed]
        )
        store.append_event(
            "findings.validated",
            {"candidateCount": len(findings), "confirmedCount": len(confirmed)},
        )

        report = render_markdown_report(campaign, store.run_id, plan, results, confirmed)
        report_relative_path = store.write_text("report.md", report)
        store.append_event("campaign.completed", {"report": report_relative_path})
        store.seal()
        return RunOutcome(
            run_id=store.run_id,
            run_path=store.path,
            tool_results=results,
            findings=confirmed,
            report_path=store.path / report_relative_path,
        )
