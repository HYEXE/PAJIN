"""Policy-governed local supervisor for dynamic multi-agent campaign execution."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from pathlib import Path
from threading import Lock
from typing import TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from pajin.agents.base import (
    AgentReportNarrative,
    CandidateAwareValidatorRuntime,
    CandidateProducerRuntime,
    PlannerRuntime,
    ReporterRuntime,
    ValidatorRuntime,
)
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CapabilityGrant,
    Finding,
    ToolResult,
    ToolRiskTier,
)
from pajin.domain.orchestration import (
    AgentNode,
    AgentRole,
    AgentStatus,
    RunStatus,
    TaskGraph,
    TaskNode,
    TaskStatus,
)
from pajin.domain.validation import FindingValidationSet, ValidationReasonCode
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.policy.engine import PolicyEngine
from pajin.reporting import (
    escape_markdown_text,
    markdown_code_span,
    render_markdown_report,
)
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    ExecutionCancellationContext,
    KillSwitch,
)
from pajin.runtime.execution_context import (
    SIMULATED_EVIDENCE_LABEL,
    WorkerExecutionContext,
    worker_execution_context,
)
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunIntegrityError, RunStore, verify_run_integrity
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, RequestRateLimitLedger, ToolGateway
from pajin.workflow.cancellation import (
    ensure_cancellation_context,
    record_engine_cleanup,
    seal_executor_quiescence,
)
from pajin.workflow.multi_agent_execution import (
    InitializedExecution as _InitializedExecution,
)
from pajin.workflow.multi_agent_execution import (
    MultiAgentExecutionScheduler,
)
from pajin.workflow.multi_agent_projection import (
    MultiAgentResultProjector,
)
from pajin.workflow.multi_agent_projection import (
    MultiAgentRunState as _RunState,
)
from pajin.workflow.multi_agent_projection import (
    ReportingTerminal as _TerminalRun,
)
from pajin.workflow.validation_artifacts import write_validation_artifacts

T = TypeVar("T")
_MAX_LOCAL_PARALLEL_SPECIALISTS = 16
_MAX_AUDIT_TOKEN_CHARS = 80


def _audit_safe_token(value: object, *, fallback: str) -> str:
    """Normalize an untrusted label for one bounded, single-line audit field."""

    if not isinstance(value, str):
        return fallback
    normalized: list[str] = []
    separator_pending = False
    for character in value[: _MAX_AUDIT_TOKEN_CHARS * 4]:
        if character.isascii() and (character.isalnum() or character in "._-"):
            if separator_pending and normalized:
                normalized.append("-")
            normalized.append(character)
            separator_pending = False
        else:
            separator_pending = True
        if len(normalized) >= _MAX_AUDIT_TOKEN_CHARS:
            break
    token = "".join(normalized).strip("._-")[:_MAX_AUDIT_TOKEN_CHARS]
    return token or fallback


def _audit_safe_exception_type(exc: BaseException) -> str:
    try:
        exception_name = type(exc).__name__
    except BaseException:
        return "Exception"
    return _audit_safe_token(exception_name, fallback="Exception")


def _audit_safe_exception_diagnostic(
    exc: BaseException,
    *,
    stage: str,
    role: str,
) -> str:
    """Describe an exception without persisting its provider-controlled message."""

    safe_stage = _audit_safe_token(stage, fallback="unknown")
    safe_role = _audit_safe_token(role, fallback="unknown")
    return (
        f"exception_type={_audit_safe_exception_type(exc)}; "
        f"stage={safe_stage}; role={safe_role}; detail=omitted"
    )


class MultiAgentRunOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    run_id: str
    run_path: Path
    status: RunStatus
    plan: AgentPlan | None
    agents: list[AgentNode]
    task_graph: TaskGraph
    tool_results: list[ToolResult]
    findings: list[Finding]
    validation: FindingValidationSet
    report_path: Path
    cancellation_reason: str | None = None


class MultiAgentCampaignRunner:
    """Execute one Run at a time; an activated one-way KillSwitch survives reuse."""

    def __init__(
        self,
        *,
        planner: PlannerRuntime,
        validator: ValidatorRuntime,
        reporter: ReporterRuntime | None = None,
        tools: ToolRegistry,
        policy: PolicyEngine,
        worker: WorkerBackend,
        output_root: Path,
        candidate_producer: CandidateProducerRuntime | None = None,
        kill_switch: KillSwitch | None = None,
        kill_after_tool_calls: int | None = None,
        secrets: SecretBroker | None = None,
        max_parallel_specialists: int = 4,
    ) -> None:
        if kill_after_tool_calls is not None and kill_after_tool_calls < 1:
            raise ValueError("kill_after_tool_calls must be at least one")
        if not 1 <= max_parallel_specialists <= _MAX_LOCAL_PARALLEL_SPECIALISTS:
            raise ValueError(
                "max_parallel_specialists must be between one and "
                f"{_MAX_LOCAL_PARALLEL_SPECIALISTS}"
            )
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._execution_context = worker_execution_context(worker)
        self._output_root = output_root
        self._kill_switch = kill_switch or KillSwitch()
        self._kill_after_tool_calls = kill_after_tool_calls
        self._observed_tool_calls = 0
        self._secrets = secrets or SecretBroker()
        self._execution_cancellation: ExecutionCancellationContext | None = None
        self._run_guard = Lock()
        self._scheduler = MultiAgentExecutionScheduler(
            host=self,
            planner=planner,
            validator=validator,
            reporter=reporter,
            tools=tools,
            max_parallel_specialists=max_parallel_specialists,
            candidate_aware_validation=(
                candidate_producer is not None
                and isinstance(validator, CandidateAwareValidatorRuntime)
            ),
        )
        self._projector = MultiAgentResultProjector(
            host=self,
            scheduler=self._scheduler,
            validator=validator,
            reporter=reporter,
            candidate_producer=candidate_producer,
            execution_context=self._execution_context,
            safe_exception_type=_audit_safe_exception_type,
        )

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> MultiAgentRunOutcome:
        if not self._run_guard.acquire(blocking=False):
            raise RuntimeError("MultiAgentCampaignRunner does not allow concurrent runs")
        try:
            authoritative_campaign = CampaignManifest.model_validate(
                campaign.model_dump(mode="python", by_alias=True)
            )
            if budget is not None and budget.budgets != authoritative_campaign.spec.budgets:
                raise ValueError("shared budget does not match the Campaign budget contract")
            if cancellation is not None and cancellation.binding is not None:
                raise ValueError("execution cancellation context is already bound to another Run")
            return await self._run_once(
                authoritative_campaign,
                cancellation=cancellation,
                budget=budget or BudgetController(authoritative_campaign.spec.budgets),
                rate_limits=rate_limits or RequestRateLimitLedger(),
            )
        finally:
            self._execution_cancellation = None
            self._run_guard.release()

    async def _run_once(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        rate_limits: RequestRateLimitLedger,
    ) -> MultiAgentRunOutcome:
        store = RunStore.create(self._output_root, campaign.metadata.name)
        store.write_json(
            "execution-context.json",
            self._execution_context.model_dump(mode="json", by_alias=True),
        )
        self._execution_cancellation = cancellation
        if cancellation is not None:
            cancellation.bind_run(
                engine="multi-agent",
                run_id=store.run_id,
                path=store.path,
            )
        store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
        store.append_event(
            "campaign.started",
            {
                "campaign": campaign.metadata.name,
                "engine": "multi-agent",
                "workerBackend": self._execution_context.backend,
                "simulated": self._execution_context.simulated,
            },
        )
        ledger = CapabilityLedger(max_depth=campaign.spec.budgets.max_spawn_depth)
        try:
            return await self._run_initialized(
                campaign,
                store=store,
                cancellation=cancellation,
                budget=budget,
                rate_limits=rate_limits,
                ledger=ledger,
            )
        except BaseException as exc:
            try:
                verify_run_integrity(store.path)
            except RunIntegrityError:
                try:
                    store.append_event(
                        "campaign.failed",
                        {
                            "stage": "initialization-or-finalization",
                            "role": AgentRole.SUPERVISOR.value,
                            "errorType": _audit_safe_exception_type(exc),
                        },
                    )
                    store.write_json(
                        "run.json",
                        {
                            "runId": store.run_id,
                            "status": RunStatus.FAILED.value,
                            "stage": "initialization-or-finalization",
                            "role": AgentRole.SUPERVISOR.value,
                            "errorType": _audit_safe_exception_type(exc),
                            **self._execution_context.run_summary(),
                        },
                    )
                    store.write_json("capabilities.json", ledger.snapshot())
                    store.write_json("budget.json", budget.snapshot())
                    store.write_json("rate-limits.json", rate_limits.snapshot())
                    store.seal()
                except Exception as terminal_error:
                    exc.add_note(
                        "multi-agent Run terminalization failed: "
                        + _audit_safe_exception_diagnostic(
                            terminal_error,
                            stage="terminalization",
                            role=AgentRole.SUPERVISOR.value,
                        )
                    )
            raise

    async def _run_initialized(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        rate_limits: RequestRateLimitLedger,
        ledger: CapabilityLedger,
    ) -> MultiAgentRunOutcome:
        state = _RunState()
        self._observed_tool_calls = 0
        execution = self._initialize_execution(
            campaign,
            store=store,
            budget=budget,
            ledger=ledger,
            rate_limits=rate_limits,
            state=state,
        )
        try:
            terminal = await self._execute_campaign(
                campaign,
                store=store,
                cancellation=cancellation,
                budget=budget,
                ledger=ledger,
                state=state,
                execution=execution,
            )
        except asyncio.CancelledError:
            terminal = self._terminalize_caller_cancellation(
                campaign,
                store=store,
                cancellation=cancellation,
                budget=budget,
                ledger=ledger,
                state=state,
                execution=execution,
            )
        except (BudgetExceeded, CapabilityError) as exc:
            terminal = self._terminalize_control_stop(
                campaign,
                exc,
                store=store,
                cancellation=cancellation,
                budget=budget,
                ledger=ledger,
                state=state,
                execution=execution,
            )
        except Exception as exc:
            terminal = self._terminalize_failure(
                campaign,
                exc,
                store=store,
                cancellation=cancellation,
                budget=budget,
                ledger=ledger,
                state=state,
                execution=execution,
            )
        return self._finalize_run(
            store=store,
            budget=budget,
            rate_limits=rate_limits,
            ledger=ledger,
            state=state,
            terminal=terminal,
        )

    def _initialize_execution(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        budget: BudgetController,
        ledger: CapabilityLedger,
        rate_limits: RequestRateLimitLedger,
        state: _RunState,
    ) -> _InitializedExecution:
        supervisor_id = self._agent_id(AgentRole.SUPERVISOR)
        budget.reserve_agent(depth=0)
        model_endpoints = {access.endpoint for access in self._scheduler.reasoning_model_accesses()}
        root_grant = ledger.issue_root(
            campaign,
            subject=supervisor_id,
            tools=self._tools.tool_ids(),
            targets={target.endpoint for target in campaign.spec.targets} | model_endpoints,
        )
        supervisor = self._add_agent(
            store,
            state.agents,
            role=AgentRole.SUPERVISOR,
            agent_id=supervisor_id,
            parent_agent_id=None,
            grant=root_grant,
        )
        self._set_agent(store, supervisor, AgentStatus.RUNNING)
        gateway = ToolGateway(
            policy=self._policy,
            tools=self._tools,
            worker=self._worker,
            store=store,
            secrets=self._secrets,
            rate_limits=rate_limits,
        )
        return _InitializedExecution(
            root_grant=root_grant,
            supervisor=supervisor,
            gateway=gateway,
        )

    async def _execute_campaign(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: _RunState,
        execution: _InitializedExecution,
    ) -> _TerminalRun:
        plan_task = await self._scheduler.run_planning_phase(
            campaign,
            store=store,
            budget=budget,
            ledger=ledger,
            state=state,
            execution=execution,
        )
        tasks = self._scheduler.prepare_execution_tasks(
            campaign,
            plan_task=plan_task,
            store=store,
            budget=budget,
            ledger=ledger,
            state=state,
            execution=execution,
        )
        await self._scheduler.run_specialist_tasks(
            campaign,
            store,
            state.graph,
            budget,
            ledger,
            execution.gateway,
            tasks.specialist_tasks,
            tasks.specialist_agents,
            tasks.specialist_grants,
            tasks.specialist_parallel_contracts,
            state.results,
        )
        if self._check_control(budget, raise_on_cancel=False):
            raise BudgetExceeded(self._kill_switch.reason or "campaign cancelled")
        self._projector.ensure_candidate_production(
            campaign,
            store=store,
            state=state,
        )
        await self._projector.run_validation_phase(
            campaign,
            tasks=tasks,
            store=store,
            budget=budget,
            ledger=ledger,
            state=state,
            execution=execution,
        )
        return await self._projector.run_reporting_phase(
            campaign,
            tasks=tasks,
            store=store,
            cancellation=cancellation,
            budget=budget,
            ledger=ledger,
            state=state,
            execution=execution,
        )

    @staticmethod
    def _mark_phase_failed(
        store: RunStore,
        graph: TaskGraph,
        task: TaskNode,
        agent: AgentNode,
        exc: Exception,
        *,
        stage: str,
    ) -> None:
        error = _audit_safe_exception_diagnostic(
            exc,
            stage=stage,
            role=agent.role.value,
        )
        if task.status is TaskStatus.RUNNING:
            MultiAgentCampaignRunner._task_transition(
                store,
                graph,
                task.task_id,
                TaskStatus.FAILED,
                error=error,
            )
        if agent.status is AgentStatus.RUNNING:
            MultiAgentCampaignRunner._set_agent(
                store,
                agent,
                AgentStatus.FAILED,
                error=error,
            )

    def _terminalize_caller_cancellation(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: _RunState,
        execution: _InitializedExecution,
    ) -> _TerminalRun:
        context = ensure_cancellation_context(
            cancellation,
            engine="multi-agent",
            store=store,
        )
        self._execution_cancellation = context
        snapshot = context.snapshot()
        self._kill_switch.activate(snapshot.reason, source=snapshot.kind.value)
        self._projector.finalize_unvalidated_candidates(
            campaign,
            store=store,
            state=state,
            reason=ValidationReasonCode.VALIDATOR_CANCELLED,
        )
        return self._terminalize_stopped_run(
            campaign,
            store=store,
            status=RunStatus.CANCELLED,
            cancellation=context,
            budget=budget,
            ledger=ledger,
            state=state,
            execution=execution,
            propagate_cancel=True,
        )

    def _terminalize_control_stop(
        self,
        campaign: CampaignManifest,
        exc: Exception,
        *,
        store: RunStore,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: _RunState,
        execution: _InitializedExecution,
    ) -> _TerminalRun:
        self._kill_switch.activate(
            _audit_safe_exception_diagnostic(
                exc,
                stage="runtime-control",
                role=AgentRole.SUPERVISOR.value,
            ),
            source="runtime-control",
        )
        self._projector.finalize_unvalidated_candidates(
            campaign,
            store=store,
            state=state,
            reason=ValidationReasonCode.VALIDATOR_CANCELLED,
        )
        return self._terminalize_stopped_run(
            campaign,
            store=store,
            status=RunStatus.CANCELLED,
            cancellation=cancellation,
            budget=budget,
            ledger=ledger,
            state=state,
            execution=execution,
        )

    def _terminalize_failure(
        self,
        campaign: CampaignManifest,
        exc: Exception,
        *,
        store: RunStore,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: _RunState,
        execution: _InitializedExecution,
    ) -> _TerminalRun:
        failure_detail = _audit_safe_exception_diagnostic(
            exc,
            stage="campaign-execution",
            role=AgentRole.SUPERVISOR.value,
        )
        self._kill_switch.activate(
            failure_detail,
            source="supervisor",
        )
        self._projector.finalize_unvalidated_candidates(
            campaign,
            store=store,
            state=state,
            reason=ValidationReasonCode.VALIDATOR_UNAVAILABLE,
        )
        if execution.supervisor.status in {AgentStatus.SPAWNED, AgentStatus.RUNNING}:
            self._set_agent(
                store,
                execution.supervisor,
                AgentStatus.FAILED,
                error=failure_detail,
            )
        return self._terminalize_stopped_run(
            campaign,
            store=store,
            status=RunStatus.FAILED,
            cancellation=cancellation,
            budget=budget,
            ledger=ledger,
            state=state,
            execution=execution,
            failure_detail=failure_detail,
        )

    def _terminalize_stopped_run(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        status: RunStatus,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: _RunState,
        execution: _InitializedExecution,
        failure_detail: str | None = None,
        propagate_cancel: bool = False,
    ) -> _TerminalRun:
        if status not in {RunStatus.CANCELLED, RunStatus.FAILED}:
            raise ValueError("stopped Run must be cancelled or failed")
        if (status is RunStatus.FAILED) != (failure_detail is not None):
            raise ValueError("failed Run terminalization requires its causal exception")
        self._cancel_execution(
            store,
            state.graph,
            state.agents,
            ledger,
            execution.root_grant.grant_id,
        )
        report = self._render_cancelled_report(
            campaign,
            store.run_id,
            status,
            state.plan,
            state.results,
            state.findings,
            state.validation,
            state.agents,
            state.graph,
            budget,
        )
        report_relative = store.write_text("report.md", report)
        return _TerminalRun(
            status=status,
            report_relative=report_relative,
            cancellation=cancellation,
            event_kind="failed" if failure_detail is not None else "cancelled",
            failure_detail=failure_detail,
            propagate_cancel=propagate_cancel,
        )

    def _finalize_run(
        self,
        *,
        store: RunStore,
        budget: BudgetController,
        rate_limits: RequestRateLimitLedger,
        ledger: CapabilityLedger,
        state: _RunState,
        terminal: _TerminalRun,
    ) -> MultiAgentRunOutcome:
        write_validation_artifacts(
            store,
            state.validation,
            validator_output=state.validator_output,
        )
        store.write_json(
            "findings.json",
            [finding.model_dump(mode="json") for finding in state.findings],
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": terminal.status.value,
                "cancellationReason": self._kill_switch.reason,
                **self._execution_context.run_summary(),
            },
        )
        self._write_state(
            store,
            state.agents,
            state.graph,
            ledger,
            budget,
            rate_limits,
        )
        if terminal.cancellation is not None and terminal.cancellation.active:
            record_engine_cleanup(store, terminal.cancellation)
        self._append_terminal_event(store, terminal)
        store.seal()
        if terminal.cancellation is not None and terminal.cancellation.active:
            seal_executor_quiescence(terminal.cancellation)
        outcome = MultiAgentRunOutcome(
            run_id=store.run_id,
            run_path=store.path,
            status=terminal.status,
            plan=state.plan,
            agents=list(state.agents.values()),
            task_graph=state.graph,
            tool_results=state.results,
            findings=state.findings,
            validation=state.validation,
            report_path=store.path / terminal.report_relative,
            cancellation_reason=self._kill_switch.reason,
        )
        self._execution_cancellation = None
        if terminal.propagate_cancel:
            raise asyncio.CancelledError(outcome.cancellation_reason)
        return outcome

    def _append_terminal_event(self, store: RunStore, terminal: _TerminalRun) -> None:
        if terminal.event_kind == "completed":
            store.append_event(
                "campaign.completed",
                {
                    "status": terminal.status.value,
                    "report": terminal.report_relative,
                },
            )
            return
        if terminal.event_kind == "cancelled":
            store.append_event(
                "campaign.cancelled",
                {
                    "reason": self._kill_switch.reason,
                    "report": terminal.report_relative,
                },
            )
            return
        if terminal.failure_detail is None:
            raise ValueError("failed terminal event requires its causal exception")
        store.append_event(
            "campaign.failed",
            {
                "error": terminal.failure_detail,
                "report": terminal.report_relative,
            },
        )

    def _spawn_child(
        self,
        store: RunStore,
        agents: dict[str, AgentNode],
        budget: BudgetController,
        ledger: CapabilityLedger,
        *,
        parent: AgentNode,
        parent_grant: CapabilityGrant,
        role: AgentRole,
        tools: set[str],
        targets: set[str],
        max_calls: int,
        max_risk_tier: ToolRiskTier = ToolRiskTier.T0,
    ) -> AgentNode:
        depth = parent.depth + 1
        budget.reserve_agent(depth=depth)
        agent_id = self._agent_id(role)
        grant = ledger.delegate(
            parent_grant.grant_id,
            subject=agent_id,
            tools=tools,
            targets=targets,
            max_risk_tier=max_risk_tier,
            max_calls=max_calls,
        )
        return self._add_agent(
            store,
            agents,
            role=role,
            agent_id=agent_id,
            parent_agent_id=parent.agent_id,
            grant=grant,
        )

    @staticmethod
    def _add_agent(
        store: RunStore,
        agents: dict[str, AgentNode],
        *,
        role: AgentRole,
        agent_id: str,
        parent_agent_id: str | None,
        grant: CapabilityGrant,
    ) -> AgentNode:
        node = AgentNode(
            agent_id=agent_id,
            role=role,
            parent_agent_id=parent_agent_id,
            depth=grant.depth,
            capability_grant_id=grant.grant_id,
        )
        agents[node.agent_id] = node
        store.append_event(
            "agent.spawned",
            {
                "agentId": node.agent_id,
                "role": node.role.value,
                "parentAgentId": node.parent_agent_id,
                "depth": node.depth,
                "grantId": grant.grant_id,
            },
        )
        store.append_event("capability.issued", grant.model_dump(mode="json"))
        return node

    @staticmethod
    def _set_agent(
        store: RunStore,
        agent: AgentNode,
        status: AgentStatus,
        *,
        error: str | None = None,
    ) -> None:
        allowed = {
            AgentStatus.SPAWNED: {
                AgentStatus.RUNNING,
                AgentStatus.FAILED,
                AgentStatus.CANCELLED,
            },
            AgentStatus.RUNNING: {
                AgentStatus.COMPLETED,
                AgentStatus.FAILED,
                AgentStatus.CANCELLED,
            },
        }
        if status not in allowed.get(agent.status, set()):
            raise ValueError(f"invalid agent transition: {agent.status} -> {status}")
        store.append_event(
            f"agent.{status.value}",
            {"agentId": agent.agent_id, "role": agent.role.value, "error": error},
        )
        agent.status = status
        agent.error = error

    @staticmethod
    def _task_transition(
        store: RunStore,
        graph: TaskGraph,
        task_id: str,
        status: TaskStatus,
        *,
        error: str | None = None,
    ) -> None:
        graph.transition(task_id, status, error=error)
        store.append_event(
            f"task.{status.value}",
            {"taskId": task_id, "error": error},
        )

    async def _within_budget(
        self,
        operation: Awaitable[T],
        budget: BudgetController,
    ) -> T:
        operation_task = asyncio.ensure_future(operation)
        try:
            budget.check_duration()
        except BudgetExceeded:
            operation_task.cancel()
            await asyncio.gather(operation_task, return_exceptions=True)
            raise
        kill_task = asyncio.create_task(self._kill_switch.wait())
        cancellation_task = (
            asyncio.create_task(self._execution_cancellation.wait())
            if self._execution_cancellation is not None
            else None
        )
        wait_tasks = {operation_task, kill_task}
        if cancellation_task is not None:
            wait_tasks.add(cancellation_task)
        try:
            done, _ = await asyncio.wait(
                wait_tasks,
                timeout=budget.remaining_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            operation_task.cancel()
            kill_task.cancel()
            if cancellation_task is not None:
                cancellation_task.cancel()
            await asyncio.gather(*wait_tasks, return_exceptions=True)
            raise
        if cancellation_task is not None and cancellation_task in done:
            snapshot = cancellation_task.result()
            self._kill_switch.activate(snapshot.reason, source=snapshot.kind.value)
            operation_task.cancel()
            kill_task.cancel()
            await asyncio.gather(operation_task, kill_task, return_exceptions=True)
            raise BudgetExceeded(snapshot.reason)
        if kill_task in done:
            operation_task.cancel()
            if cancellation_task is not None:
                cancellation_task.cancel()
            await asyncio.gather(operation_task, return_exceptions=True)
            if cancellation_task is not None:
                await asyncio.gather(cancellation_task, return_exceptions=True)
            raise BudgetExceeded(kill_task.result())
        if operation_task in done:
            kill_task.cancel()
            if cancellation_task is not None:
                cancellation_task.cancel()
            await asyncio.gather(
                kill_task,
                *([cancellation_task] if cancellation_task is not None else []),
                return_exceptions=True,
            )
            return await operation_task
        self._kill_switch.activate("maximum campaign duration exceeded", source="budget")
        operation_task.cancel()
        kill_task.cancel()
        if cancellation_task is not None:
            cancellation_task.cancel()
        await asyncio.gather(*wait_tasks, return_exceptions=True)
        raise BudgetExceeded("maximum campaign duration exceeded")

    def _check_control(
        self,
        budget: BudgetController,
        *,
        raise_on_cancel: bool = True,
    ) -> bool:
        if self._execution_cancellation is not None and self._execution_cancellation.active:
            snapshot = self._execution_cancellation.snapshot()
            self._kill_switch.activate(snapshot.reason, source=snapshot.kind.value)
        self._kill_switch.poll()
        if self._kill_switch.active:
            if raise_on_cancel:
                raise BudgetExceeded(self._kill_switch.reason or "campaign cancelled")
            return True
        try:
            budget.check_duration()
        except BudgetExceeded as exc:
            self._kill_switch.activate(
                _audit_safe_exception_diagnostic(
                    exc,
                    stage="budget-control",
                    role=AgentRole.SUPERVISOR.value,
                ),
                source="budget",
            )
            if raise_on_cancel:
                raise
            return True
        return False

    def _evaluate_stop_conditions(
        self,
        campaign: CampaignManifest,
        outcome: GatewayOutcome,
    ) -> None:
        stop_on = campaign.spec.rules_of_engagement.stop_on
        if "out-of-scope-attempt" in stop_on and outcome.decision.policy in {
            "scope-allow",
            "scope-deny",
            "scope-invalid",
        }:
            self._kill_switch.activate(
                "rules of engagement stopOn triggered: out-of-scope-attempt",
                source="policy",
            )
        observed = outcome.result.data.get("stopCondition")
        if isinstance(observed, str) and observed in stop_on:
            self._kill_switch.activate(
                f"rules of engagement stopOn triggered: {observed}", source="tool-result"
            )
        if outcome.executed:
            self._observed_tool_calls += 1
        if (
            self._kill_after_tool_calls is not None
            and self._observed_tool_calls >= self._kill_after_tool_calls
        ):
            self._kill_switch.activate(
                "deterministic kill-after-tool-calls trigger", source="verification-hook"
            )

    def _cancel_execution(
        self,
        store: RunStore,
        graph: TaskGraph,
        agents: dict[str, AgentNode],
        ledger: CapabilityLedger,
        root_grant_id: str,
    ) -> None:
        reason = self._kill_switch.reason or "campaign cancelled"
        for task_id in graph.cancel_pending(reason):
            store.append_event("task.cancelled", {"taskId": task_id, "reason": reason})
        for agent in agents.values():
            if agent.status in {AgentStatus.SPAWNED, AgentStatus.RUNNING}:
                self._set_agent(store, agent, AgentStatus.CANCELLED, error=reason)
        self._revoke_execution_authority(
            store,
            ledger,
            root_grant_id,
            reason=reason,
        )

    def _revoke_execution_authority(
        self,
        store: RunStore,
        ledger: CapabilityLedger,
        root_grant_id: str,
        *,
        reason: str,
    ) -> None:
        self._revoke_capability_tree(
            store,
            ledger,
            root_grant_id,
            reason=reason,
        )
        secret_leases = self._secrets.revoke_scope(store.run_id, reason)
        if secret_leases:
            store.append_event(
                "secret.leases.revoked",
                {
                    "leaseIds": [lease.lease_id for lease in secret_leases],
                    "reason": reason,
                },
            )

    @staticmethod
    def _revoke_capability_tree(
        store: RunStore,
        ledger: CapabilityLedger,
        root_grant_id: str,
        *,
        reason: str,
    ) -> None:
        if not ledger.record(root_grant_id).revoked:
            revoked = ledger.revoke(root_grant_id, reason, cascade=True)
            store.append_event(
                "capability.revoked",
                {
                    "rootGrantId": root_grant_id,
                    "revokedGrantIds": revoked,
                    "reason": reason,
                },
            )

    def _write_state(
        self,
        store: RunStore,
        agents: dict[str, AgentNode],
        graph: TaskGraph,
        ledger: CapabilityLedger,
        budget: BudgetController,
        rate_limits: RequestRateLimitLedger,
    ) -> None:
        store.write_json(
            "agents.json", [agent.model_dump(mode="json") for agent in agents.values()]
        )
        store.write_json("task-graph.json", graph.model_dump(mode="json"))
        store.write_json("capabilities.json", ledger.snapshot())
        store.write_json("budget.json", budget.snapshot())
        store.write_json("rate-limits.json", rate_limits.snapshot())
        store.write_json("control.json", self._kill_switch.snapshot().model_dump(mode="json"))
        store.write_json("secrets.json", self._secrets.snapshot_scope(store.run_id))

    @staticmethod
    def _render_report(
        campaign: CampaignManifest,
        run_id: str,
        plan: AgentPlan,
        results: list[ToolResult],
        findings: list[Finding],
        agents: dict[str, AgentNode],
        graph: TaskGraph,
        budget: BudgetController,
        status: RunStatus,
        narrative: AgentReportNarrative | None = None,
        validation: FindingValidationSet | None = None,
        execution_context: WorkerExecutionContext | None = None,
    ) -> str:
        base = render_markdown_report(
            campaign,
            run_id,
            plan,
            results,
            findings,
            validation,
            execution_context=execution_context,
        ).rstrip()
        lines = [base, "", "## Multi-Agent Execution", ""]
        lines.extend(
            [
                f"- Run status: {markdown_code_span(status.value)}",
                f"- Agents spawned: {markdown_code_span(str(len(agents)))}",
                f"- Tool calls dispatched: {markdown_code_span(str(budget.tool_calls))}",
                "",
                "| Agent | Role | Parent | Depth | Status |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for agent in agents.values():
            lines.append(
                f"| {escape_markdown_text(agent.agent_id)} | "
                f"{escape_markdown_text(agent.role.value)} | "
                f"{escape_markdown_text(agent.parent_agent_id or '-')} | "
                f"{agent.depth} | {escape_markdown_text(agent.status.value)} |"
            )
        lines.extend(["", "### Task graph", ""])
        for task in graph.tasks.values():
            dependencies = ", ".join(sorted(task.depends_on)) or "none"
            lines.append(
                f"- {markdown_code_span(task.task_id)} — "
                f"**{escape_markdown_text(task.status.value)}** — "
                f"{escape_markdown_text(task.title)} "
                f"(depends on: {escape_markdown_text(dependencies)})"
            )
        if narrative is not None:
            lines.extend(
                [
                    "",
                    "## Model-generated Narrative",
                    "",
                    escape_markdown_text(narrative.summary),
                    "",
                    f"Risk overview: {escape_markdown_text(narrative.risk_overview)}",
                    "",
                    "### Recommendations",
                    "",
                    *[f"- {escape_markdown_text(item)}" for item in narrative.recommendations],
                    "",
                    "### Narrative limitations",
                    "",
                    *[f"- {escape_markdown_text(item)}" for item in narrative.limitations],
                ]
            )
        return "\n".join(lines) + "\n"

    def _render_cancelled_report(
        self,
        campaign: CampaignManifest,
        run_id: str,
        status: RunStatus,
        plan: AgentPlan | None,
        results: list[ToolResult],
        findings: list[Finding],
        validation: FindingValidationSet,
        agents: dict[str, AgentNode],
        graph: TaskGraph,
        budget: BudgetController,
    ) -> str:
        execution_context = getattr(self, "_execution_context", None)
        if execution_context is not None and not isinstance(
            execution_context, WorkerExecutionContext
        ):
            raise TypeError("multi-agent execution context has an invalid type")
        if plan is not None:
            return (
                self._render_report(
                    campaign,
                    run_id,
                    plan,
                    results,
                    findings,
                    agents,
                    graph,
                    budget,
                    status,
                    validation=validation,
                    execution_context=execution_context,
                )
                + "\nTermination reason: "
                + markdown_code_span(self._kill_switch.reason or "not provided")
                + "\n"
            )
        simulated_warning = (
            f"> **{SIMULATED_EVIDENCE_LABEL}.** "
            f"{escape_markdown_text(execution_context.warning or '')}\n\n"
            if execution_context is not None and execution_context.simulated
            else ""
        )
        execution_lines = (
            f"- Worker backend: {markdown_code_span(execution_context.backend)}\n"
            "- Evidence scope: "
            f"{markdown_code_span(execution_context.evidence_scope.value)}\n"
            if execution_context is not None
            else ""
        )
        return (
            f"# PAJIN Campaign Report: {escape_markdown_text(campaign.metadata.name)}\n\n"
            f"{simulated_warning}"
            f"- Run ID: {markdown_code_span(run_id)}\n"
            f"- Run status: {markdown_code_span(status.value)}\n"
            f"{execution_lines}"
            "- Termination reason: "
            f"{markdown_code_span(self._kill_switch.reason or 'not provided')}\n"
            f"- Agents spawned: {markdown_code_span(str(len(agents)))}\n"
            f"- Tasks created: {markdown_code_span(str(len(graph.tasks)))}\n"
        )

    @staticmethod
    def _agent_id(role: AgentRole) -> str:
        return f"agent:{role.value}:{uuid4().hex[:12]}"
