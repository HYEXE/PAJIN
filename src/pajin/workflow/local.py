"""Local durable-enough vertical slice for a PAJIN campaign."""

from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from pajin.agents.base import AgentRuntime, CandidateProducerRuntime
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CapabilityGrant,
    Finding,
    ToolResult,
)
from pajin.domain.validation import FindingValidationSet, ValidationReasonCode
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
from pajin.workflow.validation import validate_findings
from pajin.workflow.validation_artifacts import write_validation_artifacts


class RunOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    run_path: Path
    tool_results: list[ToolResult]
    findings: list[Finding]
    validation: FindingValidationSet
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
        candidate_producer: CandidateProducerRuntime | None = None,
    ) -> None:
        self._agents = agents
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._output_root = output_root
        self._candidate_producer = candidate_producer

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

        proposed_plan = await self._agents.plan(campaign)
        plan = AgentPlan.model_validate(proposed_plan.model_dump())
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

        admitted_candidates = []
        authoritative_request_ids: set[str] = set()
        authoritative_claim_keys: set[tuple[str, str]] = set()
        if self._candidate_producer is not None:
            production = self._candidate_producer.produce(
                campaign,
                plan,
                results,
            )
            admitted_candidates = list(production.candidates)
            authoritative_request_ids = set(production.authoritative_request_ids)
            authoritative_claim_keys = set(production.authoritative_claim_keys)
            store.append_event(
                "candidate-set.produced",
                {
                    "producerId": self._candidate_producer.producer_id,
                    "candidateCount": len(admitted_candidates),
                    "authoritativeRequestCount": len(authoritative_request_ids),
                    "authoritativeClaimCount": len(authoritative_claim_keys),
                    "candidateIds": [candidate.candidate_id for candidate in admitted_candidates],
                },
            )

        def finalize_without_validator(
            reason: ValidationReasonCode,
        ) -> FindingValidationSet:
            incomplete_validation = validate_findings(
                campaign,
                results,
                [],
                store,
                validator_id=self._agents.agent_id,
                admitted_candidates=admitted_candidates,
                producer_authoritative_request_ids=authoritative_request_ids,
                producer_authoritative_claim_keys=authoritative_claim_keys,
                validator_unavailable_reason=reason,
            )
            write_validation_artifacts(store, incomplete_validation)
            store.write_json("findings.json", [])
            return incomplete_validation

        try:
            findings = await self._agents.validate(campaign, plan, results)
        except asyncio.CancelledError:
            try:
                finalize_without_validator(ValidationReasonCode.VALIDATOR_CANCELLED)
            except Exception as exc:
                store.append_event(
                    "validation.snapshot.failed",
                    {"errorType": type(exc).__name__},
                )
            raise
        except Exception as exc:
            try:
                finalize_without_validator(ValidationReasonCode.VALIDATOR_UNAVAILABLE)
            except Exception as snapshot_exc:
                store.append_event(
                    "validation.snapshot.failed",
                    {"errorType": type(snapshot_exc).__name__},
                )
            store.write_json(
                "run.json",
                {"runId": store.run_id, "status": "failed", "stage": "validation"},
            )
            store.append_event(
                "campaign.failed",
                {"stage": "validation", "errorType": type(exc).__name__},
            )
            store.seal()
            raise
        validation = validate_findings(
            campaign,
            results,
            findings,
            store,
            validator_id=self._agents.agent_id,
            admitted_candidates=admitted_candidates,
            producer_authoritative_request_ids=authoritative_request_ids,
            producer_authoritative_claim_keys=authoritative_claim_keys,
        )
        confirmed = validation.confirmed_findings
        write_validation_artifacts(store, validation)
        store.write_json(
            "findings.json", [finding.model_dump(mode="json") for finding in confirmed]
        )

        report = render_markdown_report(
            campaign,
            store.run_id,
            plan,
            results,
            confirmed,
            validation,
        )
        report_relative_path = store.write_text("report.md", report)
        store.append_event("campaign.completed", {"report": report_relative_path})
        store.seal()
        return RunOutcome(
            run_id=store.run_id,
            run_path=store.path,
            tool_results=results,
            findings=confirmed,
            validation=validation,
            report_path=store.path / report_relative_path,
        )
