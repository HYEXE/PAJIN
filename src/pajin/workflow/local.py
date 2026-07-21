"""Local durable-enough vertical slice for a PAJIN campaign."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from pajin.agents.base import (
    AgentRuntime,
    CandidateAuthority,
    CandidateAwareValidatorRuntime,
    CandidateProducerRuntime,
    CandidateValidation,
)
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    ToolResult,
)
from pajin.domain.validation import (
    FindingValidationSet,
    ValidationReasonCode,
    ValidatorOutputArtifact,
)
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.policy.engine import PolicyEngine
from pajin.reporting.markdown import render_markdown_report
from pajin.runtime.control import BudgetController, BudgetExceeded, ExecutionCancellationContext
from pajin.runtime.error_safety import (
    audit_safe_exception_diagnostic,
    audit_safe_exception_type,
)
from pajin.runtime.execution_context import WorkerExecutionContext, worker_execution_context
from pajin.runtime.store import RunStore
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger, ToolGateway
from pajin.workflow.cancellation import (
    await_with_campaign_deadline,
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


class LocalToolExecutionError(RuntimeError):
    """Raised when a policy-compiled local campaign Tool call fails closed."""


@dataclass
class _LocalExecutionState:
    budget: BudgetController
    rate_limits: RequestRateLimitLedger
    execution_context: WorkerExecutionContext
    ledger: CapabilityLedger | None = None
    stage: str = "initialization"


def _add_terminalization_failure_note(
    original: BaseException,
    terminal_error: BaseException,
) -> None:
    """Attach a useful terminalization note without copying exception details."""

    original.add_note(
        "local Run terminalization failed: "
        + audit_safe_exception_diagnostic(
            terminal_error,
            stage="run-terminalization",
        )
    )


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
        self._execution_context = worker_execution_context(worker)
        self._output_root = output_root
        self._candidate_producer = candidate_producer

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> RunOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="python", by_alias=True)
        )
        if budget is not None and budget.budgets != authoritative_campaign.spec.budgets:
            raise ValueError("shared budget does not match the Campaign budget contract")
        if cancellation is not None and cancellation.binding is not None:
            raise ValueError("execution cancellation context is already bound to another Run")
        budget = budget or BudgetController(authoritative_campaign.spec.budgets)
        rate_limits = rate_limits or RequestRateLimitLedger()
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        state = _LocalExecutionState(
            budget=budget,
            rate_limits=rate_limits,
            execution_context=self._execution_context,
        )
        try:
            store.write_json(
                "execution-context.json",
                state.execution_context.model_dump(mode="json", by_alias=True),
            )
            if cancellation is not None:
                cancellation.bind_run(
                    engine="local-campaign",
                    run_id=store.run_id,
                    path=store.path,
                )
            return await await_with_campaign_deadline(
                self._execute(authoritative_campaign, store, state),
                budget,
                cancellation,
            )
        except asyncio.CancelledError as exc:
            context = ensure_cancellation_context(
                cancellation,
                engine="local-campaign",
                store=store,
            )
            receipt = record_engine_cleanup(store, context)
            try:
                self._terminalize_failure(
                    store,
                    state,
                    status="cancelled",
                    error_type=audit_safe_exception_type(exc),
                    cancellation_receipt=receipt,
                )
            except Exception as terminal_error:
                _add_terminalization_failure_note(exc, terminal_error)
            raise
        except BudgetExceeded as exc:
            try:
                self._terminalize_failure(
                    store,
                    state,
                    status="budget-exhausted",
                    error_type=audit_safe_exception_type(exc),
                )
            except Exception as terminal_error:
                _add_terminalization_failure_note(exc, terminal_error)
            raise
        except Exception as exc:
            try:
                self._terminalize_failure(
                    store,
                    state,
                    status="failed",
                    error_type=audit_safe_exception_type(exc),
                )
            except Exception as terminal_error:
                _add_terminalization_failure_note(exc, terminal_error)
            raise

    async def _execute(
        self,
        campaign: CampaignManifest,
        store: RunStore,
        state: _LocalExecutionState,
    ) -> RunOutcome:
        budget = state.budget
        rate_limits = state.rate_limits
        agent_id = self._agents.agent_id
        store.append_event(
            "campaign.started",
            {
                "campaign": campaign.metadata.name,
                "mode": campaign.spec.mode.value,
                "workerBackend": state.execution_context.backend,
                "simulated": state.execution_context.simulated,
            },
        )
        store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))

        state.stage = "capability-issuance"
        ledger = CapabilityLedger(max_depth=campaign.spec.budgets.max_spawn_depth)
        state.ledger = ledger
        can_delegate_execution = campaign.spec.budgets.max_spawn_depth >= 1
        root_grant = ledger.issue_root(
            campaign,
            subject=(f"supervisor:{agent_id}" if can_delegate_execution else agent_id),
            tools=self._tools.tool_ids(),
            targets={target.endpoint for target in campaign.spec.targets},
        )
        store.append_event(
            "capability.issued",
            root_grant.model_dump(mode="json"),
        )
        grant = root_grant
        if can_delegate_execution:
            grant = ledger.delegate(
                root_grant.grant_id,
                subject=agent_id,
                tools=set(root_grant.tools),
                targets=set(root_grant.targets),
                max_risk_tier=root_grant.max_risk_tier,
                max_calls=root_grant.max_calls,
            )
            store.append_event(
                "capability.issued",
                grant.model_dump(mode="json"),
            )

        state.stage = "planning"
        proposed_plan = await self._agents.plan(campaign.model_copy(deep=True))
        plan = AgentPlan.model_validate(proposed_plan.model_dump())
        plan = plan.model_copy(
            update={
                "steps": [
                    step.model_copy(
                        update={"request": step.request.model_copy(update={"agent_id": agent_id})}
                    )
                    for step in plan.steps
                ]
            }
        )
        store.write_json("plan.json", plan.model_dump(mode="json"))
        store.append_event("agent.plan.created", {"steps": len(plan.steps)})

        gateway = ToolGateway(
            policy=self._policy,
            tools=self._tools,
            worker=self._worker,
            store=store,
            rate_limits=rate_limits,
        )
        results: list[ToolResult] = []
        state.stage = "tool-execution"
        for step in plan.steps:
            budget.check_tool_call()
            if not ledger.can_consume(grant.grant_id):
                raise CapabilityError("local capability has no remaining authorized call")
            used_calls = grant.max_calls - ledger.record(grant.grant_id).remaining_calls
            outcome = await gateway.execute(
                campaign,
                grant,
                step.request,
                used_calls=used_calls,
            )
            if outcome.executed:
                ledger.consume(grant.grant_id)
                budget.record_tool_call()
            results.append(outcome.result)
        failed_tool_calls = sum(not result.success for result in results)
        if failed_tool_calls:
            raise LocalToolExecutionError(
                f"local campaign failed {failed_tool_calls} of {len(results)} Tool calls"
            )

        admitted_candidates = []
        authoritative_request_claims: set[CandidateAuthority] = set()
        if self._candidate_producer is not None:
            state.stage = "candidate-production"
            producer_id = self._candidate_producer.producer_id
            production = self._candidate_producer.produce(
                campaign.model_copy(deep=True),
                plan.model_copy(deep=True),
                [result.model_copy(deep=True) for result in results],
            )
            admitted_candidates = [
                candidate.model_copy(deep=True) for candidate in production.candidates
            ]
            authoritative_request_claims = set(production.authoritative_request_claims)
            store.append_event(
                "candidate-set.produced",
                {
                    "producerId": producer_id,
                    "candidateCount": len(admitted_candidates),
                    "authoritativeRequestCount": len(production.authoritative_request_ids),
                    "authoritativeClaimCount": len(production.authoritative_claim_keys),
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
                validator_id=agent_id,
                admitted_candidates=admitted_candidates,
                producer_authoritative_request_claims=authoritative_request_claims,
                validator_unavailable_reason=reason,
            )
            write_validation_artifacts(store, incomplete_validation)
            store.write_json("findings.json", [])
            return incomplete_validation

        state.stage = "validation"
        validator_campaign = campaign.model_copy(deep=True)
        validator_plan = plan.model_copy(deep=True)
        validator_results = [result.model_copy(deep=True) for result in results]
        validator_output_artifact: ValidatorOutputArtifact | None = None
        try:
            if isinstance(self._agents, CandidateAwareValidatorRuntime):
                raw_validator_output = await self._agents.validate_candidates(
                    validator_campaign,
                    validator_plan,
                    validator_results,
                    [candidate.model_copy(deep=True) for candidate in admitted_candidates],
                )
                validator_output = CandidateValidation.model_validate(
                    raw_validator_output.model_dump(mode="python")
                )
                findings = validator_output.findings
                validator_assessments = validator_output.assessments
            else:
                raw_findings = await self._agents.validate(
                    validator_campaign,
                    validator_plan,
                    validator_results,
                )
                findings = [
                    Finding.model_validate(finding.model_dump(mode="python"))
                    for finding in raw_findings
                ]
                validator_assessments = None
            validator_output_artifact = ValidatorOutputArtifact(
                sourceRunId=store.run_id,
                validatorId=agent_id,
                validationTaskId="task:local-candidate-validation",
                findings=[finding.model_copy(deep=True) for finding in findings],
                assessments=[
                    assessment.model_copy(deep=True) for assessment in (validator_assessments or [])
                ],
            )
        except asyncio.CancelledError:
            try:
                finalize_without_validator(ValidationReasonCode.VALIDATOR_CANCELLED)
            except Exception as exc:
                store.append_event(
                    "validation.snapshot.failed",
                    {"errorType": audit_safe_exception_type(exc)},
                )
            raise
        except Exception:
            try:
                finalize_without_validator(ValidationReasonCode.VALIDATOR_UNAVAILABLE)
            except Exception as snapshot_exc:
                store.append_event(
                    "validation.snapshot.failed",
                    {"errorType": audit_safe_exception_type(snapshot_exc)},
                )
            raise
        validation = validate_findings(
            campaign,
            results,
            findings,
            store,
            validator_id=agent_id,
            admitted_candidates=admitted_candidates,
            producer_authoritative_request_claims=authoritative_request_claims,
            validator_assessments=validator_assessments,
        )
        confirmed = validation.confirmed_findings
        assert validator_output_artifact is not None
        write_validation_artifacts(
            store,
            validation,
            validator_output=validator_output_artifact,
        )
        store.write_json(
            "findings.json", [finding.model_dump(mode="json") for finding in confirmed]
        )

        state.stage = "reporting"
        report = render_markdown_report(
            campaign,
            store.run_id,
            plan,
            results,
            confirmed,
            validation,
            execution_context=state.execution_context,
        )
        report_relative_path = store.write_text("report.md", report)
        state.stage = "finalization"
        self._write_terminal_state(
            store,
            state,
            status="completed",
            extra={"report": report_relative_path},
        )
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

    @staticmethod
    def _write_terminal_state(
        store: RunStore,
        state: _LocalExecutionState,
        *,
        status: str,
        extra: dict[str, object] | None = None,
    ) -> None:
        if state.ledger is not None:
            store.write_json("capabilities.json", state.ledger.snapshot())
        store.write_json("budget.json", state.budget.snapshot())
        store.write_json("rate-limits.json", state.rate_limits.snapshot())
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": status,
                "stage": state.stage,
                **state.execution_context.run_summary(),
                **(extra or {}),
            },
        )

    def _terminalize_failure(
        self,
        store: RunStore,
        state: _LocalExecutionState,
        *,
        status: str,
        error_type: str,
        cancellation_receipt: str | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "stage": state.stage,
            "errorType": error_type,
        }
        run_extra: dict[str, object] = {"errorType": error_type}
        if cancellation_receipt is not None:
            payload["cancellationReceipt"] = cancellation_receipt
            run_extra["cancellationReceipt"] = cancellation_receipt
        self._write_terminal_state(
            store,
            state,
            status=status,
            extra=run_extra,
        )
        store.append_event(f"campaign.{status}", payload)
        store.seal()
