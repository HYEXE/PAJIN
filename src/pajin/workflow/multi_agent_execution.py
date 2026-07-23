"""Scheduling and specialist execution for the multi-agent workflow.

The public runner owns Run lifecycle, terminalization, validation, and reporting.
This collaborator owns the plan-to-task scheduling boundary: it validates model
and tool authority, allocates the finite call budget, builds the Task graph, and
executes Specialist waves without weakening deterministic result ordering.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Protocol, TypeVar

from pydantic import BaseModel

from pajin.agents.base import ModelBoundRuntime, PlannerRuntime, ReporterRuntime, ValidatorRuntime
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CapabilityGrant,
    ToolResult,
    ToolRiskTier,
)
from pajin.domain.orchestration import (
    AgentNode,
    AgentRole,
    AgentStatus,
    TaskGraph,
    TaskNode,
    TaskStatus,
)
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.providers.models import ProviderRegistration
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.control import BudgetController, BudgetExceeded, KillSwitch
from pajin.runtime.store import RunStore
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway

T = TypeVar("T")


@dataclass(frozen=True)
class ModelAccess:
    """Exact policy authority required by one model-backed runtime."""

    registration: ProviderRegistration
    tool_id: str
    endpoint: str
    max_attempts: int
    risk_tier: ToolRiskTier


@dataclass(frozen=True)
class InitializedExecution:
    """Supervisor authority and gateway shared by scheduled phases."""

    root_grant: CapabilityGrant
    supervisor: AgentNode
    gateway: ToolGateway


@dataclass(frozen=True)
class _SpecialistAllocation:
    risk_tiers: list[ToolRiskTier]
    parallel_contracts: list[bool]
    attempts: list[int]
    validator_access: ModelAccess | None
    reviewer_access: ModelAccess | None
    reporter_access: ModelAccess | None


@dataclass(frozen=True)
class ExecutionTasks:
    """Task graph nodes and their immutable execution authorities."""

    specialist_tasks: list[TaskNode]
    specialist_agents: dict[str, AgentNode]
    specialist_grants: dict[str, CapabilityGrant]
    specialist_parallel_contracts: dict[str, bool]
    validation_task: TaskNode
    review_task: TaskNode | None
    report_task: TaskNode
    validator_access: ModelAccess | None
    reviewer_access: ModelAccess | None
    reporter_access: ModelAccess | None


class SchedulingState(Protocol):
    """Minimal mutable Run state used while materializing the Task graph."""

    graph: TaskGraph
    agents: dict[str, AgentNode]
    results: list[ToolResult]
    plan: AgentPlan | None


class ExecutionHost(Protocol):
    """Cross-cutting lifecycle operations retained by the public runner."""

    _kill_switch: KillSwitch

    async def _within_budget(
        self,
        operation: Awaitable[T],
        budget: BudgetController,
    ) -> T: ...

    def _check_control(
        self,
        budget: BudgetController,
        *,
        raise_on_cancel: bool = True,
    ) -> bool: ...

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
    ) -> AgentNode: ...

    def _mark_phase_failed(
        self,
        store: RunStore,
        graph: TaskGraph,
        task: TaskNode,
        agent: AgentNode,
        exc: Exception,
        *,
        stage: str,
    ) -> None: ...

    def _evaluate_stop_conditions(
        self,
        campaign: CampaignManifest,
        outcome: GatewayOutcome,
    ) -> None: ...

    def _revoke_capability_tree(
        self,
        store: RunStore,
        ledger: CapabilityLedger,
        root_grant_id: str,
        *,
        reason: str,
    ) -> None: ...

    def _set_agent(
        self,
        store: RunStore,
        agent: AgentNode,
        status: AgentStatus,
        *,
        error: str | None = None,
    ) -> None: ...

    def _task_transition(
        self,
        store: RunStore,
        graph: TaskGraph,
        task_id: str,
        status: TaskStatus,
        *,
        error: str | None = None,
    ) -> None: ...


class MultiAgentExecutionScheduler:
    """Own planning, Task graph construction, and Specialist execution."""

    def __init__(
        self,
        *,
        host: ExecutionHost,
        planner: PlannerRuntime,
        validator: ValidatorRuntime,
        reporter: ReporterRuntime | None,
        tools: ToolRegistry,
        max_parallel_specialists: int,
        candidate_aware_validation: bool,
    ) -> None:
        self._host = host
        self._planner = planner
        self._validator = validator
        self._reporter = reporter
        self._tools = tools
        self._max_parallel_specialists = max_parallel_specialists
        self._candidate_aware_validation = candidate_aware_validation

    async def run_planning_phase(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: SchedulingState,
        execution: InitializedExecution,
    ) -> TaskNode:
        self._host._check_control(budget)
        planner_access = self._model_access(self._planner)
        planner_agent = self._host._spawn_child(
            store,
            state.agents,
            budget,
            ledger,
            parent=execution.supervisor,
            parent_grant=execution.root_grant,
            role=AgentRole.PLANNER,
            tools={planner_access.tool_id} if planner_access else set(),
            targets={planner_access.endpoint} if planner_access else set(),
            max_calls=planner_access.max_attempts if planner_access else 0,
            max_risk_tier=(planner_access.risk_tier if planner_access else ToolRiskTier.T0),
        )
        if planner_access:
            self.bind_model_runtime(
                self._planner,
                planner_access,
                campaign,
                planner_agent,
                ledger,
                budget,
                execution.gateway,
                store,
            )
        plan_task = TaskNode(
            title="Create authorized campaign plan",
            assigned_agent_id=planner_agent.agent_id,
        )
        state.graph.add(plan_task)
        self._host._task_transition(
            store,
            state.graph,
            plan_task.task_id,
            TaskStatus.RUNNING,
        )
        self._host._set_agent(store, planner_agent, AgentStatus.RUNNING)
        try:
            proposed_plan = await self._host._within_budget(
                self._planner.plan(_detached_model(campaign)),
                budget,
            )
            state.plan = AgentPlan.model_validate(proposed_plan.model_dump())
            self._host._check_control(budget)
            self._validate_plan_boundary(campaign, state.plan)
        except (BudgetExceeded, CapabilityError):
            raise
        except Exception as exc:
            try:
                self._host._mark_phase_failed(
                    store,
                    state.graph,
                    plan_task,
                    planner_agent,
                    exc,
                    stage="planner",
                )
            finally:
                self._host._revoke_capability_tree(
                    store,
                    ledger,
                    planner_agent.capability_grant_id,
                    reason="planner phase failed",
                )
            raise
        self._host._revoke_capability_tree(
            store,
            ledger,
            planner_agent.capability_grant_id,
            reason="planner phase completed",
        )
        self._host._task_transition(
            store,
            state.graph,
            plan_task.task_id,
            TaskStatus.SUCCEEDED,
        )
        self._host._set_agent(store, planner_agent, AgentStatus.COMPLETED)
        store.write_json("plan.json", state.plan.model_dump(mode="json"))
        store.append_event("agent.plan.created", {"steps": len(state.plan.steps)})
        return plan_task

    def prepare_execution_tasks(
        self,
        campaign: CampaignManifest,
        *,
        plan_task: TaskNode,
        store: RunStore,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: SchedulingState,
        execution: InitializedExecution,
    ) -> ExecutionTasks:
        plan = state.plan
        if plan is None:
            raise RuntimeError("planner phase completed without a validated plan")
        allocation = self._allocate_execution_contract(
            campaign,
            plan=plan,
            store=store,
            budget=budget,
            ledger=ledger,
            execution=execution,
        )

        specialist_tasks: list[TaskNode] = []
        specialist_agents: dict[str, AgentNode] = {}
        specialist_grants: dict[str, CapabilityGrant] = {}
        specialist_parallel_contracts: dict[str, bool] = {}
        for step, risk_tier, max_attempts, parallel_safe in zip(
            plan.steps,
            allocation.risk_tiers,
            allocation.attempts,
            allocation.parallel_contracts,
            strict=True,
        ):
            specialist = self._host._spawn_child(
                store,
                state.agents,
                budget,
                ledger,
                parent=execution.supervisor,
                parent_grant=execution.root_grant,
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
            state.graph.add(task)
            specialist_tasks.append(task)
            specialist_agents[task.task_id] = specialist
            specialist_grants[task.task_id] = ledger.record(specialist.capability_grant_id).grant
            specialist_parallel_contracts[task.task_id] = parallel_safe

        validation_task = TaskNode(
            title="Independently validate candidate findings",
            depends_on={task.task_id for task in specialist_tasks},
        )
        state.graph.add(validation_task)
        review_task = None
        if allocation.reviewer_access is not None:
            review_task = TaskNode(
                title="Blind-review evidence and derive severity with a diverse Provider/model",
                depends_on={task.task_id for task in specialist_tasks},
            )
            state.graph.add(review_task)
        report_dependencies = {validation_task.task_id}
        if review_task is not None:
            report_dependencies.add(review_task.task_id)
        report_task = TaskNode(
            title="Render campaign report",
            depends_on=report_dependencies,
        )
        state.graph.add(report_task)
        return ExecutionTasks(
            specialist_tasks=specialist_tasks,
            specialist_agents=specialist_agents,
            specialist_grants=specialist_grants,
            specialist_parallel_contracts=specialist_parallel_contracts,
            validation_task=validation_task,
            review_task=review_task,
            report_task=report_task,
            validator_access=allocation.validator_access,
            reviewer_access=allocation.reviewer_access,
            reporter_access=allocation.reporter_access,
        )

    def _allocate_execution_contract(
        self,
        campaign: CampaignManifest,
        *,
        plan: AgentPlan,
        store: RunStore,
        budget: BudgetController,
        ledger: CapabilityLedger,
        execution: InitializedExecution,
    ) -> _SpecialistAllocation:
        risk_tiers: list[ToolRiskTier] = []
        parallel_contracts: list[bool] = []
        for step in plan.steps:
            try:
                spec = self._tools.spec(step.request.tool_id)
            except KeyError as exc:
                raise CapabilityError(
                    f"planner requested unregistered tool: {step.request.tool_id}"
                ) from exc
            risk_tiers.append(spec.risk_tier)
            parallel_contracts.append(spec.parallel_safe)

        validator_access = self._model_access(
            self._validator,
            max_calls=(
                getattr(self._validator, "model_primary_validator_max_calls", None)
                if self._candidate_aware_validation
                else None
            ),
        )
        reviewer_access = (
            self._review_model_access(self._validator)
            if self._candidate_aware_validation
            else None
        )
        reporter_access = self._model_access(self._reporter) if self._reporter else None
        required_agents = len(plan.steps) + 2 + (1 if reviewer_access is not None else 0)
        if budget.agent_count + required_agents > campaign.spec.budgets.max_agents:
            raise BudgetExceeded("plan requires more agents than the campaign budget allows")
        reserved_control_calls = sum(
            access.max_attempts
            for access in (validator_access, reviewer_access, reporter_access)
            if access is not None
        )
        root_remaining_calls = ledger.record(execution.root_grant.grant_id).remaining_calls
        specialist_capacity = root_remaining_calls - reserved_control_calls
        attempts = self._allocate_specialist_attempts(
            risk_tiers,
            available_calls=specialist_capacity,
        )
        store.append_event(
            "specialist.call-budget.allocated",
            {
                "rootRemainingCalls": root_remaining_calls,
                "reservedControlCalls": reserved_control_calls,
                "unallocatedCalls": specialist_capacity - sum(attempts),
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
                        attempts,
                        parallel_contracts,
                        strict=True,
                    )
                ],
            },
        )
        return _SpecialistAllocation(
            risk_tiers=risk_tiers,
            parallel_contracts=parallel_contracts,
            attempts=attempts,
            validator_access=validator_access,
            reviewer_access=reviewer_access,
            reporter_access=reporter_access,
        )

    async def run_specialist_tasks(
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
                    if self._host._check_control(budget, raise_on_cancel=False):
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

            owned_tasks = [asyncio.create_task(execute(task, task_results)) for task in wave]
            try:
                done, pending = await asyncio.wait(
                    owned_tasks,
                    return_when=asyncio.FIRST_EXCEPTION,
                )
                failed = any(
                    not owned_task.cancelled() and owned_task.exception() is not None
                    for owned_task in done
                )
                if failed:
                    for owned_task in pending:
                        owned_task.cancel()
                outcomes = await asyncio.gather(
                    *owned_tasks,
                    return_exceptions=True,
                )
            except asyncio.CancelledError:
                for owned_task in owned_tasks:
                    if not owned_task.done():
                        owned_task.cancel()
                await asyncio.gather(*owned_tasks, return_exceptions=True)
                raise
            for task in wave:
                results.extend(task_results[task.task_id])
            for outcome in outcomes:
                if isinstance(outcome, BaseException) and not isinstance(
                    outcome,
                    asyncio.CancelledError,
                ):
                    raise outcome
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
        if task.request is None:
            raise RuntimeError("specialist task is missing its authorized request")
        self._host._set_agent(store, agent, AgentStatus.RUNNING)
        try:
            while task.attempts < task.max_attempts:
                self._host._task_transition(
                    store,
                    graph,
                    task.task_id,
                    TaskStatus.RUNNING,
                )
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
                gateway_outcome = await self._host._within_budget(
                    gateway.execute(
                        campaign,
                        grant,
                        request,
                        used_calls=used_calls,
                    ),
                    budget,
                )
                outcome = _detached_model(gateway_outcome)
                results.append(outcome.result)
                if outcome.executed:
                    ledger.consume(grant.grant_id)
                    budget.record_tool_call()
                self._host._evaluate_stop_conditions(campaign, outcome)
                if outcome.result.success:
                    self._host._task_transition(
                        store,
                        graph,
                        task.task_id,
                        TaskStatus.SUCCEEDED,
                    )
                    self._host._set_agent(store, agent, AgentStatus.COMPLETED)
                    self._host._revoke_capability_tree(
                        store,
                        ledger,
                        grant.grant_id,
                        reason="specialist task completed",
                    )
                    return
                if not outcome.executed or task.attempts >= task.max_attempts:
                    self._host._task_transition(
                        store,
                        graph,
                        task.task_id,
                        TaskStatus.FAILED,
                        error=outcome.result.error,
                    )
                    self._host._set_agent(
                        store,
                        agent,
                        AgentStatus.FAILED,
                        error=outcome.result.error,
                    )
                    self._host._revoke_capability_tree(
                        store,
                        ledger,
                        grant.grant_id,
                        reason="specialist task failed",
                    )
                    return
                self._host._task_transition(
                    store,
                    graph,
                    task.task_id,
                    TaskStatus.WAITING,
                )
                store.append_event(
                    "task.retry_scheduled",
                    {"taskId": task.task_id, "attempt": task.attempts + 1},
                )
        except (BudgetExceeded, CapabilityError, asyncio.CancelledError):
            raise
        except Exception as exc:
            try:
                self._host._mark_phase_failed(
                    store,
                    graph,
                    task,
                    agent,
                    exc,
                    stage="specialist",
                )
            finally:
                self._host._revoke_capability_tree(
                    store,
                    ledger,
                    grant.grant_id,
                    reason="specialist task failed",
                )
            raise

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

    def _model_access(
        self,
        runtime: object,
        *,
        max_calls: int | None = None,
    ) -> ModelAccess | None:
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
        role_max_calls = max_calls or runtime.model_max_attempts
        if not 1 <= role_max_calls <= 6:
            raise ValueError("model runtime role call budget must be between one and six")
        spec = self._tools.spec(tool_id)
        if "model-provider" not in spec.categories:
            raise ValueError("model runtime tool is not registered as a provider")
        return ModelAccess(
            registration=registration,
            tool_id=tool_id,
            endpoint=endpoint,
            max_attempts=role_max_calls,
            risk_tier=spec.risk_tier,
        )

    def _review_model_access(self, runtime: object) -> ModelAccess | None:
        raw_registration = getattr(runtime, "review_model_provider_registration", None)
        if raw_registration is None:
            return None
        registration = ProviderRegistration.model_validate(raw_registration)
        tool_id = f"provider.{registration.provider_id}.chat"
        endpoint = str(registration.endpoint)
        if getattr(runtime, "review_model_provider_tool_id", None) != tool_id:
            raise ValueError("review model runtime tool ID differs from its registration")
        if getattr(runtime, "review_model_provider_endpoint", None) != endpoint:
            raise ValueError("review model runtime endpoint differs from its registration")
        max_attempts = getattr(runtime, "review_model_max_attempts", None)
        if not isinstance(max_attempts, int) or not 1 <= max_attempts <= 3:
            raise ValueError("review model runtime attempts must be between one and three")
        spec = self._tools.spec(tool_id)
        if "model-provider" not in spec.categories:
            raise ValueError("review model runtime tool is not registered as a provider")
        return ModelAccess(
            registration=registration,
            tool_id=tool_id,
            endpoint=endpoint,
            max_attempts=max_attempts,
            risk_tier=spec.risk_tier,
        )

    def reasoning_model_accesses(self) -> tuple[ModelAccess, ...]:
        """Return the exact Provider authorities used by reasoning roles."""

        accesses: list[ModelAccess] = []
        for runtime in (self._planner, self._validator, self._reporter):
            if runtime is None:
                continue
            access = self._model_access(runtime)
            if access is not None:
                accesses.append(access)
        review_access = self._review_model_access(self._validator)
        if review_access is not None:
            accesses.append(review_access)
        return tuple(accesses)

    @staticmethod
    def bind_model_runtime(
        runtime: object,
        access: ModelAccess,
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

    @staticmethod
    def bind_review_model_runtime(
        runtime: object,
        access: ModelAccess,
        campaign: CampaignManifest,
        agent: AgentNode,
        ledger: CapabilityLedger,
        budget: BudgetController,
        gateway: ToolGateway,
        store: RunStore,
    ) -> None:
        binder = getattr(runtime, "bind_review_model_port", None)
        if not callable(binder):
            raise TypeError("runtime does not support a policy-bound review model port")
        actor_binder = getattr(runtime, "bind_review_actor_id", None)
        if callable(actor_binder):
            actor_binder(agent.agent_id)
        grant = ledger.record(agent.capability_grant_id).grant
        binder(
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
        control_plane_provider_tools = {
            access.tool_id for access in self.reasoning_model_accesses()
        }
        for step in plan.steps:
            if step.request.target not in declared_targets:
                raise CapabilityError("planner selected an undeclared campaign target")
            try:
                self._tools.spec(step.request.tool_id)
            except KeyError as exc:
                raise CapabilityError(
                    f"planner requested unregistered tool: {step.request.tool_id}"
                ) from exc
            if step.request.tool_id in control_plane_provider_tools:
                raise CapabilityError("planner cannot assign the control-plane provider tool")


def _detached_model[ModelT: BaseModel](model: ModelT) -> ModelT:
    """Give an in-process extension no alias to authoritative mutable state."""

    return model.model_copy(deep=True)
