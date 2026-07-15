"""Policy-governed local supervisor for dynamic multi-agent campaign execution."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from pajin.agents.base import (
    AgentReportNarrative,
    CandidateProducerRuntime,
    ModelBoundRuntime,
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
from pajin.domain.validation import (
    CandidateFinding,
    FindingValidationSet,
    ValidationReasonCode,
)
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.policy.engine import PolicyEngine
from pajin.providers.models import ProviderRegistration
from pajin.providers.session import PolicyBoundProviderPort
from pajin.reporting.markdown import render_markdown_report
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    ExecutionCancellationContext,
    KillSwitch,
)
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunStore
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, RequestRateLimitLedger, ToolGateway
from pajin.workflow.cancellation import (
    ensure_cancellation_context,
    record_engine_cleanup,
    seal_executor_quiescence,
)
from pajin.workflow.validation import validate_findings
from pajin.workflow.validation_artifacts import write_validation_artifacts

T = TypeVar("T")
_MAX_LOCAL_PARALLEL_SPECIALISTS = 16


@dataclass(frozen=True)
class _ModelAccess:
    registration: ProviderRegistration
    tool_id: str
    endpoint: str
    max_attempts: int
    risk_tier: ToolRiskTier


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
    """Spawn bounded role agents and execute their task graph through one gateway."""

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
        self._planner = planner
        self._validator = validator
        self._reporter = reporter
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._output_root = output_root
        self._candidate_producer = candidate_producer
        self._kill_switch = kill_switch or KillSwitch()
        self._kill_after_tool_calls = kill_after_tool_calls
        self._observed_tool_calls = 0
        self._secrets = secrets or SecretBroker()
        self._max_parallel_specialists = max_parallel_specialists
        self._execution_cancellation: ExecutionCancellationContext | None = None

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> MultiAgentRunOutcome:
        store = RunStore.create(self._output_root, campaign.metadata.name)
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
            {"campaign": campaign.metadata.name, "engine": "multi-agent"},
        )
        if budget is not None and budget.budgets != campaign.spec.budgets:
            raise ValueError("shared budget does not match the Campaign budget contract")
        budget = budget or BudgetController(campaign.spec.budgets)
        rate_limits = rate_limits or RequestRateLimitLedger()
        ledger = CapabilityLedger(max_depth=campaign.spec.budgets.max_spawn_depth)
        graph = TaskGraph()
        agents: dict[str, AgentNode] = {}
        results: list[ToolResult] = []
        findings: list[Finding] = []
        validation = FindingValidationSet(
            candidates=[],
            decisions=[],
            confirmed_findings=[],
        )
        plan: AgentPlan | None = None
        admitted_candidates: list[CandidateFinding] = []
        authoritative_request_ids: set[str] = set()
        authoritative_claim_keys: set[tuple[str, str]] = set()
        candidate_production_attempted = False
        validation_snapshot_finalized = False
        validator_agent_id = "agent:validator:unavailable"
        self._observed_tool_calls = 0
        propagate_cancel = False

        supervisor_id = self._agent_id(AgentRole.SUPERVISOR)
        budget.reserve_agent(depth=0)
        model_endpoints = {
            access.endpoint
            for runtime in (self._planner, self._validator, self._reporter)
            if runtime is not None
            for access in [self._model_access(runtime)]
            if access is not None
        }
        root_grant = ledger.issue_root(
            campaign,
            subject=supervisor_id,
            tools=self._tools.tool_ids(),
            targets={target.endpoint for target in campaign.spec.targets} | model_endpoints,
        )
        supervisor = self._add_agent(
            store,
            agents,
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

        def ensure_candidate_production() -> None:
            nonlocal candidate_production_attempted
            nonlocal admitted_candidates
            nonlocal authoritative_request_ids
            nonlocal authoritative_claim_keys
            if candidate_production_attempted or self._candidate_producer is None or plan is None:
                return
            candidate_production_attempted = True
            try:
                production = self._candidate_producer.produce(campaign, plan, results)
            except Exception as exc:
                store.append_event(
                    "candidate-set.production-failed",
                    {
                        "producerId": self._candidate_producer.producer_id,
                        "errorType": type(exc).__name__,
                    },
                )
                raise
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

        def finalize_unvalidated_candidates(reason: ValidationReasonCode) -> None:
            nonlocal validation
            nonlocal findings
            nonlocal validation_snapshot_finalized
            if validation_snapshot_finalized:
                return
            try:
                ensure_candidate_production()
            except Exception:
                return
            if not admitted_candidates:
                return
            try:
                validation = validate_findings(
                    campaign,
                    results,
                    [],
                    store,
                    validator_id=validator_agent_id,
                    admitted_candidates=admitted_candidates,
                    producer_authoritative_request_ids=authoritative_request_ids,
                    producer_authoritative_claim_keys=authoritative_claim_keys,
                    validator_unavailable_reason=reason,
                )
            except Exception as exc:
                store.append_event(
                    "validation.snapshot.failed",
                    {"errorType": type(exc).__name__},
                )
                return
            findings = []
            validation_snapshot_finalized = True

        try:
            self._check_control(budget)
            planner_access = self._model_access(self._planner)
            planner_agent = self._spawn_child(
                store,
                agents,
                budget,
                ledger,
                parent=supervisor,
                parent_grant=root_grant,
                role=AgentRole.PLANNER,
                tools={planner_access.tool_id} if planner_access else set(),
                targets={planner_access.endpoint} if planner_access else set(),
                max_calls=planner_access.max_attempts if planner_access else 0,
                max_risk_tier=planner_access.risk_tier if planner_access else ToolRiskTier.T0,
            )
            if planner_access:
                self._bind_model_runtime(
                    self._planner,
                    planner_access,
                    campaign,
                    planner_agent,
                    ledger,
                    budget,
                    gateway,
                    store,
                )
            plan_task = TaskNode(
                title="Create authorized campaign plan",
                assigned_agent_id=planner_agent.agent_id,
            )
            graph.add(plan_task)
            self._task_transition(store, graph, plan_task.task_id, TaskStatus.RUNNING)
            self._set_agent(store, planner_agent, AgentStatus.RUNNING)
            proposed_plan = await self._within_budget(self._planner.plan(campaign), budget)
            plan = AgentPlan.model_validate(proposed_plan.model_dump())
            self._check_control(budget)
            self._validate_plan_boundary(campaign, plan)
            self._task_transition(store, graph, plan_task.task_id, TaskStatus.SUCCEEDED)
            self._set_agent(store, planner_agent, AgentStatus.COMPLETED)
            store.write_json("plan.json", plan.model_dump(mode="json"))
            store.append_event("agent.plan.created", {"steps": len(plan.steps)})

            required_agents = len(plan.steps) + 2
            if budget.agent_count + required_agents > campaign.spec.budgets.max_agents:
                raise BudgetExceeded("plan requires more agents than the campaign budget allows")

            specialist_risk_tiers: list[ToolRiskTier] = []
            specialist_parallel_safe: list[bool] = []
            for step in plan.steps:
                try:
                    spec = self._tools.spec(step.request.tool_id)
                except KeyError as exc:
                    raise CapabilityError(
                        f"planner requested unregistered tool: {step.request.tool_id}"
                    ) from exc
                specialist_risk_tiers.append(spec.risk_tier)
                specialist_parallel_safe.append(spec.parallel_safe)

            validator_access = self._model_access(self._validator)
            reporter_access = self._model_access(self._reporter) if self._reporter else None
            reserved_control_calls = sum(
                access.max_attempts
                for access in (validator_access, reporter_access)
                if access is not None
            )
            root_remaining_calls = ledger.record(root_grant.grant_id).remaining_calls
            specialist_call_capacity = root_remaining_calls - reserved_control_calls
            specialist_attempts = self._allocate_specialist_attempts(
                specialist_risk_tiers,
                available_calls=specialist_call_capacity,
            )
            store.append_event(
                "specialist.call-budget.allocated",
                {
                    "rootRemainingCalls": root_remaining_calls,
                    "reservedControlCalls": reserved_control_calls,
                    "unallocatedCalls": (specialist_call_capacity - sum(specialist_attempts)),
                    "allocations": [
                        {
                            "requestId": step.request.request_id,
                            "toolId": step.request.tool_id,
                            "target": step.request.target,
                            "maxAttempts": max_attempts,
                            "parallelSafe": parallel_safe,
                        }
                        for step, max_attempts, parallel_safe in zip(
                            plan.steps,
                            specialist_attempts,
                            specialist_parallel_safe,
                            strict=True,
                        )
                    ],
                },
            )

            specialist_tasks: list[TaskNode] = []
            specialist_agents: dict[str, AgentNode] = {}
            specialist_grants: dict[str, CapabilityGrant] = {}
            specialist_parallel_contracts: dict[str, bool] = {}
            for step, risk_tier, max_attempts, parallel_safe in zip(
                plan.steps,
                specialist_risk_tiers,
                specialist_attempts,
                specialist_parallel_safe,
                strict=True,
            ):
                specialist = self._spawn_child(
                    store,
                    agents,
                    budget,
                    ledger,
                    parent=supervisor,
                    parent_grant=root_grant,
                    role=AgentRole.SPECIALIST,
                    tools={step.request.tool_id},
                    targets={step.request.target},
                    max_calls=max_attempts,
                    max_risk_tier=risk_tier,
                )
                bound_request = step.request.model_copy(update={"agent_id": specialist.agent_id})
                task = TaskNode(
                    title=step.title,
                    assigned_agent_id=specialist.agent_id,
                    depends_on={plan_task.task_id},
                    request=bound_request,
                    max_attempts=max_attempts,
                )
                graph.add(task)
                specialist_tasks.append(task)
                specialist_agents[task.task_id] = specialist
                specialist_grants[task.task_id] = ledger.record(
                    specialist.capability_grant_id
                ).grant
                specialist_parallel_contracts[task.task_id] = parallel_safe

            validation_task = TaskNode(
                title="Independently validate candidate findings",
                depends_on={task.task_id for task in specialist_tasks},
            )
            graph.add(validation_task)
            report_task = TaskNode(
                title="Render campaign report",
                depends_on={validation_task.task_id},
            )
            graph.add(report_task)

            await self._run_specialist_tasks(
                campaign,
                store,
                graph,
                budget,
                ledger,
                gateway,
                specialist_tasks,
                specialist_agents,
                specialist_grants,
                specialist_parallel_contracts,
                results,
            )

            if self._check_control(budget, raise_on_cancel=False):
                raise BudgetExceeded(self._kill_switch.reason or "campaign cancelled")

            ensure_candidate_production()

            validator_agent = self._spawn_child(
                store,
                agents,
                budget,
                ledger,
                parent=supervisor,
                parent_grant=root_grant,
                role=AgentRole.VALIDATOR,
                tools={validator_access.tool_id} if validator_access else set(),
                targets={validator_access.endpoint} if validator_access else set(),
                max_calls=validator_access.max_attempts if validator_access else 0,
                max_risk_tier=(validator_access.risk_tier if validator_access else ToolRiskTier.T0),
            )
            if validator_access:
                self._bind_model_runtime(
                    self._validator,
                    validator_access,
                    campaign,
                    validator_agent,
                    ledger,
                    budget,
                    gateway,
                    store,
                )
            validation_task.assigned_agent_id = validator_agent.agent_id
            validator_agent_id = validator_agent.agent_id
            self._task_transition(store, graph, validation_task.task_id, TaskStatus.RUNNING)
            self._set_agent(store, validator_agent, AgentStatus.RUNNING)
            candidates = await self._within_budget(
                self._validator.validate(campaign, plan, results), budget
            )
            validation = validate_findings(
                campaign,
                results,
                candidates,
                store,
                validator_id=validator_agent.agent_id,
                admitted_candidates=admitted_candidates,
                producer_authoritative_request_ids=authoritative_request_ids,
                producer_authoritative_claim_keys=authoritative_claim_keys,
            )
            validation_snapshot_finalized = True
            findings = validation.confirmed_findings
            self._task_transition(store, graph, validation_task.task_id, TaskStatus.SUCCEEDED)
            self._set_agent(store, validator_agent, AgentStatus.COMPLETED)
            store.write_json(
                "findings.json", [finding.model_dump(mode="json") for finding in findings]
            )

            reporter_agent = self._spawn_child(
                store,
                agents,
                budget,
                ledger,
                parent=supervisor,
                parent_grant=root_grant,
                role=AgentRole.REPORTER,
                tools={reporter_access.tool_id} if reporter_access else set(),
                targets={reporter_access.endpoint} if reporter_access else set(),
                max_calls=reporter_access.max_attempts if reporter_access else 0,
                max_risk_tier=(reporter_access.risk_tier if reporter_access else ToolRiskTier.T0),
            )
            if reporter_access and self._reporter is not None:
                self._bind_model_runtime(
                    self._reporter,
                    reporter_access,
                    campaign,
                    reporter_agent,
                    ledger,
                    budget,
                    gateway,
                    store,
                )
            report_task.assigned_agent_id = reporter_agent.agent_id
            self._task_transition(store, graph, report_task.task_id, TaskStatus.RUNNING)
            self._set_agent(store, reporter_agent, AgentStatus.RUNNING)
            narrative: AgentReportNarrative | None = None
            if self._reporter is not None:
                narrative = await self._within_budget(
                    self._reporter.report(campaign, plan, results, findings),
                    budget,
                )
                store.write_json("model-narrative.json", narrative.model_dump(mode="json"))
            final_status = (
                RunStatus.FAILED
                if any(task.status is TaskStatus.FAILED for task in specialist_tasks)
                else RunStatus.COMPLETED
            )
            report_agents = {
                agent_id: agent.model_copy(deep=True) for agent_id, agent in agents.items()
            }
            report_agents[reporter_agent.agent_id].status = AgentStatus.COMPLETED
            report_agents[supervisor.agent_id].status = AgentStatus.COMPLETED
            report_graph = graph.model_copy(deep=True)
            report_graph.transition(report_task.task_id, TaskStatus.SUCCEEDED)
            report = self._render_report(
                campaign,
                store.run_id,
                plan,
                results,
                findings,
                report_agents,
                report_graph,
                budget,
                final_status,
                narrative=narrative,
                validation=validation,
            )
            report_relative = store.write_text("report.md", report)
            self._task_transition(store, graph, report_task.task_id, TaskStatus.SUCCEEDED)
            self._set_agent(store, reporter_agent, AgentStatus.COMPLETED)
            self._set_agent(store, supervisor, AgentStatus.COMPLETED)
            store.append_event(
                "campaign.completed",
                {"status": final_status.value, "report": report_relative},
            )
        except asyncio.CancelledError:
            context = ensure_cancellation_context(
                cancellation,
                engine="multi-agent",
                store=store,
            )
            cancellation = context
            self._execution_cancellation = context
            self._kill_switch.activate(
                context.snapshot().reason,
                source=context.snapshot().kind.value,
            )
            finalize_unvalidated_candidates(ValidationReasonCode.VALIDATOR_CANCELLED)
            self._cancel_execution(store, graph, agents, ledger, root_grant.grant_id)
            final_status = RunStatus.CANCELLED
            report = self._render_cancelled_report(
                campaign,
                store.run_id,
                final_status,
                plan,
                results,
                findings,
                validation,
                agents,
                graph,
                budget,
            )
            report_relative = store.write_text("report.md", report)
            store.append_event(
                "campaign.cancelled",
                {"reason": self._kill_switch.reason, "report": report_relative},
            )
            propagate_cancel = True
        except (BudgetExceeded, CapabilityError, TimeoutError) as exc:
            self._kill_switch.activate(str(exc), source="runtime-control")
            finalize_unvalidated_candidates(ValidationReasonCode.VALIDATOR_CANCELLED)
            self._cancel_execution(store, graph, agents, ledger, root_grant.grant_id)
            final_status = RunStatus.CANCELLED
            report = self._render_cancelled_report(
                campaign,
                store.run_id,
                final_status,
                plan,
                results,
                findings,
                validation,
                agents,
                graph,
                budget,
            )
            report_relative = store.write_text("report.md", report)
            store.append_event(
                "campaign.cancelled",
                {"reason": self._kill_switch.reason, "report": report_relative},
            )
        except Exception as exc:
            self._kill_switch.activate(
                f"unhandled orchestration failure: {type(exc).__name__}: {exc}",
                source="supervisor",
            )
            finalize_unvalidated_candidates(ValidationReasonCode.VALIDATOR_UNAVAILABLE)
            self._cancel_execution(store, graph, agents, ledger, root_grant.grant_id)
            self._set_agent(store, supervisor, AgentStatus.FAILED, error=str(exc))
            final_status = RunStatus.FAILED
            report = self._render_cancelled_report(
                campaign,
                store.run_id,
                final_status,
                plan,
                results,
                findings,
                validation,
                agents,
                graph,
                budget,
            )
            report_relative = store.write_text("report.md", report)
            store.append_event(
                "campaign.failed",
                {"error": str(exc), "report": report_relative},
            )

        write_validation_artifacts(store, validation)
        store.write_json("findings.json", [finding.model_dump(mode="json") for finding in findings])
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": final_status.value,
                "cancellationReason": self._kill_switch.reason,
            },
        )
        self._write_state(store, agents, graph, ledger, budget, rate_limits)
        if cancellation is not None and cancellation.active:
            record_engine_cleanup(store, cancellation)
        store.seal()
        if cancellation is not None and cancellation.active:
            seal_executor_quiescence(cancellation)
        outcome = MultiAgentRunOutcome(
            run_id=store.run_id,
            run_path=store.path,
            status=final_status,
            plan=plan,
            agents=list(agents.values()),
            task_graph=graph,
            tool_results=results,
            findings=findings,
            validation=validation,
            report_path=store.path / report_relative,
            cancellation_reason=self._kill_switch.reason,
        )
        self._execution_cancellation = None
        if propagate_cancel:
            raise asyncio.CancelledError(outcome.cancellation_reason)
        return outcome

    async def _run_specialist_tasks(
        self,
        campaign: CampaignManifest,
        store: RunStore,
        graph: TaskGraph,
        budget: BudgetController,
        ledger: CapabilityLedger,
        gateway: ToolGateway,
        tasks: list[TaskNode],
        agents: dict[str, AgentNode],
        grants: dict[str, CapabilityGrant],
        parallel_contracts: dict[str, bool],
        results: list[ToolResult],
    ) -> None:
        semaphore = asyncio.Semaphore(self._max_parallel_specialists)
        waves = self._specialist_execution_waves(tasks, parallel_contracts)
        for wave_index, wave in enumerate(waves, start=1):
            parallel_safe = all(parallel_contracts[task.task_id] for task in wave)
            store.append_event(
                "specialist.wave.started",
                {
                    "wave": wave_index,
                    "taskIds": [task.task_id for task in wave],
                    "parallelSafe": parallel_safe,
                    "maxConcurrency": (
                        min(len(wave), self._max_parallel_specialists) if parallel_safe else 1
                    ),
                },
            )
            task_results: dict[str, list[ToolResult]] = {task.task_id: [] for task in wave}

            async def execute(
                task: TaskNode,
                result_buffer: dict[str, list[ToolResult]],
            ) -> None:
                async with semaphore:
                    if self._check_control(budget, raise_on_cancel=False):
                        return
                    await self._run_specialist_task(
                        campaign,
                        store,
                        graph,
                        budget,
                        ledger,
                        gateway,
                        task,
                        agents[task.task_id],
                        grants[task.task_id],
                        result_buffer[task.task_id],
                    )

            outcomes = await asyncio.gather(
                *(execute(task, task_results) for task in wave),
                return_exceptions=True,
            )
            for task in wave:
                results.extend(task_results[task.task_id])
            for outcome in outcomes:
                if isinstance(outcome, BaseException):
                    raise outcome
            store.append_event(
                "specialist.wave.completed",
                {
                    "wave": wave_index,
                    "taskStatuses": {task.task_id: task.status.value for task in wave},
                },
            )

    @staticmethod
    def _specialist_execution_waves(
        tasks: list[TaskNode],
        parallel_contracts: dict[str, bool],
    ) -> list[list[TaskNode]]:
        waves: list[list[TaskNode]] = []
        parallel_wave: list[TaskNode] = []
        for task in tasks:
            if parallel_contracts[task.task_id]:
                parallel_wave.append(task)
                continue
            if parallel_wave:
                waves.append(parallel_wave)
                parallel_wave = []
            waves.append([task])
        if parallel_wave:
            waves.append(parallel_wave)
        return waves

    async def _run_specialist_task(
        self,
        campaign: CampaignManifest,
        store: RunStore,
        graph: TaskGraph,
        budget: BudgetController,
        ledger: CapabilityLedger,
        gateway: ToolGateway,
        task: TaskNode,
        agent: AgentNode,
        grant: CapabilityGrant,
        results: list[ToolResult],
    ) -> None:
        assert task.request is not None
        self._set_agent(store, agent, AgentStatus.RUNNING)
        while task.attempts < task.max_attempts:
            self._task_transition(store, graph, task.task_id, TaskStatus.RUNNING)
            task.attempts += 1
            budget.check_tool_call()
            if not ledger.can_consume(grant.grant_id):
                raise CapabilityError("specialist capability has no remaining call")
            request = task.request.model_copy(
                update={
                    "request_id": (
                        task.request.request_id
                        if task.attempts == 1
                        else f"{task.request.request_id}_attempt{task.attempts}"
                    )
                }
            )
            used_calls = grant.max_calls - ledger.record(grant.grant_id).remaining_calls
            outcome = await self._within_budget(
                gateway.execute(
                    campaign,
                    grant,
                    request,
                    used_calls=used_calls,
                ),
                budget,
            )
            results.append(outcome.result)
            if outcome.executed:
                ledger.consume(grant.grant_id)
                budget.record_tool_call()
            self._evaluate_stop_conditions(campaign, outcome)
            if outcome.result.success:
                self._task_transition(store, graph, task.task_id, TaskStatus.SUCCEEDED)
                self._set_agent(store, agent, AgentStatus.COMPLETED)
                return
            if not outcome.executed or task.attempts >= task.max_attempts:
                self._task_transition(
                    store,
                    graph,
                    task.task_id,
                    TaskStatus.FAILED,
                    error=outcome.result.error,
                )
                self._set_agent(
                    store,
                    agent,
                    AgentStatus.FAILED,
                    error=outcome.result.error,
                )
                return
            self._task_transition(store, graph, task.task_id, TaskStatus.WAITING)
            store.append_event(
                "task.retry_scheduled",
                {"taskId": task.task_id, "attempt": task.attempts + 1},
            )

    @staticmethod
    def _allocate_specialist_attempts(
        risk_tiers: list[ToolRiskTier],
        *,
        available_calls: int,
    ) -> list[int]:
        """Reserve one call per Specialist before assigning bounded retry slots."""

        if available_calls < len(risk_tiers):
            raise BudgetExceeded("plan requires more tool calls than the campaign budget allows")
        allocations = [1 for _ in risk_tiers]
        retry_slots = available_calls - len(allocations)
        for index, risk_tier in enumerate(risk_tiers):
            if retry_slots == 0:
                break
            if risk_tier.value <= ToolRiskTier.T1.value:
                allocations[index] += 1
                retry_slots -= 1
        return allocations

    def _model_access(self, runtime: object) -> _ModelAccess | None:
        if not isinstance(runtime, ModelBoundRuntime):
            return None
        registration = ProviderRegistration.model_validate(runtime.model_provider_registration)
        tool_id = f"provider.{registration.provider_id}.chat"
        endpoint = str(registration.endpoint)
        if runtime.model_provider_tool_id != tool_id:
            raise ValueError("model runtime tool ID differs from provider registration")
        if runtime.model_provider_endpoint != endpoint:
            raise ValueError("model runtime endpoint differs from provider registration")
        if not 1 <= runtime.model_max_attempts <= 3:
            raise ValueError("model runtime attempts must be between one and three")
        spec = self._tools.spec(tool_id)
        if "model-provider" not in spec.categories:
            raise ValueError("model runtime tool is not registered as a provider")
        return _ModelAccess(
            registration=registration,
            tool_id=tool_id,
            endpoint=endpoint,
            max_attempts=runtime.model_max_attempts,
            risk_tier=spec.risk_tier,
        )

    @staticmethod
    def _bind_model_runtime(
        runtime: object,
        access: _ModelAccess,
        campaign: CampaignManifest,
        agent: AgentNode,
        ledger: CapabilityLedger,
        budget: BudgetController,
        gateway: ToolGateway,
        store: RunStore,
    ) -> None:
        if not isinstance(runtime, ModelBoundRuntime):
            raise TypeError("runtime does not support a policy-bound model port")
        grant = ledger.record(agent.capability_grant_id).grant
        runtime.bind_model_port(
            PolicyBoundProviderPort(
                registration=access.registration,
                campaign=campaign,
                grant=grant,
                ledger=ledger,
                budget=budget,
                gateway=gateway,
                store=store,
            )
        )

    def _validate_plan_boundary(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
    ) -> None:
        declared_targets = {target.endpoint for target in campaign.spec.targets}
        for step in plan.steps:
            if step.request.target not in declared_targets:
                raise CapabilityError("planner selected an undeclared campaign target")
            try:
                spec = self._tools.spec(step.request.tool_id)
            except KeyError as exc:
                raise CapabilityError(
                    f"planner requested unregistered tool: {step.request.tool_id}"
                ) from exc
            if "model-provider" in spec.categories:
                raise CapabilityError("planner cannot assign the control-plane provider tool")

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
        agent.status = status
        agent.error = error
        store.append_event(
            f"agent.{status.value}",
            {"agentId": agent.agent_id, "role": agent.role.value, "error": error},
        )

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
            self._kill_switch.activate(str(exc), source="budget")
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
        revoked = ledger.revoke(root_grant_id, reason, cascade=True)
        store.append_event(
            "capability.revoked",
            {"rootGrantId": root_grant_id, "revokedGrantIds": revoked, "reason": reason},
        )
        secret_leases = self._secrets.revoke_all(reason)
        if secret_leases:
            store.append_event(
                "secret.leases.revoked",
                {
                    "leaseIds": [lease.lease_id for lease in secret_leases],
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
        store.write_json("secrets.json", self._secrets.snapshot())

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
    ) -> str:
        base = render_markdown_report(
            campaign,
            run_id,
            plan,
            results,
            findings,
            validation,
        ).rstrip()
        lines = [base, "", "## Multi-Agent Execution", ""]
        lines.extend(
            [
                f"- Run status: `{status.value}`",
                f"- Agents spawned: `{len(agents)}`",
                f"- Tool calls dispatched: `{budget.tool_calls}`",
                "",
                "| Agent | Role | Parent | Depth | Status |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for agent in agents.values():
            lines.append(
                f"| `{agent.agent_id}` | `{agent.role.value}` | "
                f"`{agent.parent_agent_id or '-'}` | {agent.depth} | `{agent.status.value}` |"
            )
        lines.extend(["", "### Task graph", ""])
        for task in graph.tasks.values():
            dependencies = ", ".join(sorted(task.depends_on)) or "none"
            lines.append(
                f"- `{task.task_id}` — **{task.status.value}** — {task.title} "
                f"(depends on: {dependencies})"
            )
        if narrative is not None:
            lines.extend(
                [
                    "",
                    "## Model-generated Narrative",
                    "",
                    narrative.summary,
                    "",
                    f"Risk overview: {narrative.risk_overview}",
                    "",
                    "### Recommendations",
                    "",
                    *[f"- {item}" for item in narrative.recommendations],
                    "",
                    "### Narrative limitations",
                    "",
                    *[f"- {item}" for item in narrative.limitations],
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
                )
                + f"\nTermination reason: `{self._kill_switch.reason}`\n"
            )
        return (
            f"# PAJIN Campaign Report: {campaign.metadata.name}\n\n"
            f"- Run ID: `{run_id}`\n"
            f"- Run status: `{status.value}`\n"
            f"- Termination reason: `{self._kill_switch.reason}`\n"
            f"- Agents spawned: `{len(agents)}`\n"
            f"- Tasks created: `{len(graph.tasks)}`\n"
        )

    @staticmethod
    def _agent_id(role: AgentRole) -> str:
        return f"agent:{role.value}:{uuid4().hex[:12]}"
