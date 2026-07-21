"""Validation and report projection for the multi-agent workflow."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

from pydantic import BaseModel

from pajin.agents.base import (
    AgentReportNarrative,
    CandidateAuthority,
    CandidateAwareValidatorRuntime,
    CandidateProducerRuntime,
    ReporterRuntime,
    ValidatorRuntime,
)
from pajin.domain.models import AgentPlan, CampaignManifest, Finding, ToolResult, ToolRiskTier
from pajin.domain.orchestration import (
    AgentNode,
    AgentRole,
    AgentStatus,
    RunStatus,
    TaskGraph,
    TaskStatus,
)
from pajin.domain.validation import (
    CandidateFinding,
    FindingValidationSet,
    ValidationReasonCode,
    ValidatorOutputArtifact,
)
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    ExecutionCancellationContext,
)
from pajin.runtime.execution_context import WorkerExecutionContext
from pajin.runtime.store import RunStore
from pajin.workflow.multi_agent_execution import (
    ExecutionHost,
    ExecutionTasks,
    InitializedExecution,
    MultiAgentExecutionScheduler,
)
from pajin.workflow.validation import validate_findings


def _empty_validation_set() -> FindingValidationSet:
    return FindingValidationSet(
        candidates=[],
        decisions=[],
        confirmed_findings=[],
    )


@dataclass
class CandidateState:
    admitted: tuple[CandidateFinding, ...] = ()
    authoritative_request_claims: frozenset[CandidateAuthority] = frozenset()
    production_attempted: bool = False
    validation_snapshot_finalized: bool = False
    validator_agent_id: str = "agent:validator:unavailable"


@dataclass
class MultiAgentRunState:
    """Mutable state accumulated across one private Run execution."""

    graph: TaskGraph = field(default_factory=TaskGraph)
    agents: dict[str, AgentNode] = field(default_factory=dict)
    results: list[ToolResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    validation: FindingValidationSet = field(default_factory=_empty_validation_set)
    validator_output: ValidatorOutputArtifact | None = None
    plan: AgentPlan | None = None
    candidates: CandidateState = field(default_factory=CandidateState)


@dataclass(frozen=True)
class ReportingTerminal:
    status: RunStatus
    report_relative: str
    cancellation: ExecutionCancellationContext | None
    event_kind: Literal["completed", "cancelled", "failed"]
    failure_detail: str | None = None
    propagate_cancel: bool = False


class ProjectionHost(ExecutionHost, Protocol):
    """Lifecycle and compatibility hooks owned by the public runner."""

    def _revoke_execution_authority(
        self,
        store: RunStore,
        ledger: CapabilityLedger,
        root_grant_id: str,
        *,
        reason: str,
    ) -> None: ...

    def _render_report(
        self,
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
    ) -> str: ...


class MultiAgentResultProjector:
    """Own candidate admission, independent validation, and report projection."""

    def __init__(
        self,
        *,
        host: ProjectionHost,
        scheduler: MultiAgentExecutionScheduler,
        validator: ValidatorRuntime,
        reporter: ReporterRuntime | None,
        candidate_producer: CandidateProducerRuntime | None,
        execution_context: WorkerExecutionContext,
        safe_exception_type: Callable[[BaseException], str],
    ) -> None:
        self._host = host
        self._scheduler = scheduler
        self._validator = validator
        self._reporter = reporter
        self._candidate_producer = candidate_producer
        self._execution_context = execution_context
        self._safe_exception_type = safe_exception_type

    def ensure_candidate_production(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        state: MultiAgentRunState,
    ) -> None:
        candidates = state.candidates
        if candidates.production_attempted or self._candidate_producer is None:
            return
        if state.plan is None:
            return
        candidates.production_attempted = True
        producer_id = self._candidate_producer.producer_id
        try:
            production = self._candidate_producer.produce(
                _detached_model(campaign),
                _detached_model(state.plan),
                _detached_models(state.results),
            )
        except Exception as exc:
            store.append_event(
                "candidate-set.production-failed",
                {
                    "producerId": producer_id,
                    "stage": "candidate-production",
                    "role": "candidate-producer",
                    "errorType": self._safe_exception_type(exc),
                },
            )
            raise
        candidates.admitted = tuple(
            candidate.model_copy(deep=True) for candidate in production.candidates
        )
        candidates.authoritative_request_claims = frozenset(production.authoritative_request_claims)
        store.append_event(
            "candidate-set.produced",
            {
                "producerId": producer_id,
                "candidateCount": len(candidates.admitted),
                "authoritativeRequestCount": len(production.authoritative_request_ids),
                "authoritativeClaimCount": len(production.authoritative_claim_keys),
                "candidateIds": [item.candidate_id for item in candidates.admitted],
            },
        )

    async def run_validation_phase(
        self,
        campaign: CampaignManifest,
        *,
        tasks: ExecutionTasks,
        store: RunStore,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: MultiAgentRunState,
        execution: InitializedExecution,
    ) -> None:
        access = tasks.validator_access
        validator_agent = self._host._spawn_child(
            store,
            state.agents,
            budget,
            ledger,
            parent=execution.supervisor,
            parent_grant=execution.root_grant,
            role=AgentRole.VALIDATOR,
            tools={access.tool_id} if access else set(),
            targets={access.endpoint} if access else set(),
            max_calls=access.max_attempts if access else 0,
            max_risk_tier=access.risk_tier if access else ToolRiskTier.T0,
        )
        if access:
            self._scheduler.bind_model_runtime(
                self._validator,
                access,
                campaign,
                validator_agent,
                ledger,
                budget,
                execution.gateway,
                store,
            )
        tasks.validation_task.assigned_agent_id = validator_agent.agent_id
        state.candidates.validator_agent_id = validator_agent.agent_id
        self._host._task_transition(
            store,
            state.graph,
            tasks.validation_task.task_id,
            TaskStatus.RUNNING,
        )
        self._host._set_agent(store, validator_agent, AgentStatus.RUNNING)
        plan = state.plan
        if plan is None:
            raise RuntimeError("validation phase started without a validated plan")
        try:
            if isinstance(self._validator, CandidateAwareValidatorRuntime):
                validator_output = await self._host._within_budget(
                    self._validator.validate_candidates(
                        _detached_model(campaign),
                        _detached_model(plan),
                        _detached_models(state.results),
                        [
                            candidate.model_copy(deep=True)
                            for candidate in state.candidates.admitted
                        ],
                    ),
                    budget,
                )
                findings = _detached_models(validator_output.findings)
                assessments = _detached_models(validator_output.assessments)
            else:
                validator_findings = await self._host._within_budget(
                    self._validator.validate(
                        _detached_model(campaign),
                        _detached_model(plan),
                        _detached_models(state.results),
                    ),
                    budget,
                )
                findings = _detached_models(validator_findings)
                assessments = None
            validator_output_artifact = ValidatorOutputArtifact(
                sourceRunId=store.run_id,
                validatorId=validator_agent.agent_id,
                validationTaskId=tasks.validation_task.task_id,
                findings=_detached_models(findings),
                assessments=_detached_models(assessments or []),
            )
            validation = validate_findings(
                campaign,
                state.results,
                findings,
                store,
                validator_id=validator_agent.agent_id,
                admitted_candidates=list(state.candidates.admitted),
                producer_authoritative_request_claims=(
                    set(state.candidates.authoritative_request_claims)
                ),
                validator_assessments=assessments,
            )
        except (BudgetExceeded, CapabilityError):
            raise
        except Exception as exc:
            try:
                self._host._mark_phase_failed(
                    store,
                    state.graph,
                    tasks.validation_task,
                    validator_agent,
                    exc,
                    stage="validator",
                )
            finally:
                self._host._revoke_capability_tree(
                    store,
                    ledger,
                    validator_agent.capability_grant_id,
                    reason="validator phase failed",
                )
            raise
        self._host._revoke_capability_tree(
            store,
            ledger,
            validator_agent.capability_grant_id,
            reason="validator phase completed",
        )
        state.validation = validation
        state.validator_output = validator_output_artifact
        state.candidates.validation_snapshot_finalized = True
        state.findings = validation.confirmed_findings
        self._host._task_transition(
            store,
            state.graph,
            tasks.validation_task.task_id,
            TaskStatus.SUCCEEDED,
        )
        self._host._set_agent(store, validator_agent, AgentStatus.COMPLETED)
        store.write_json(
            "findings.json",
            [finding.model_dump(mode="json") for finding in state.findings],
        )

    async def run_reporting_phase(
        self,
        campaign: CampaignManifest,
        *,
        tasks: ExecutionTasks,
        store: RunStore,
        cancellation: ExecutionCancellationContext | None,
        budget: BudgetController,
        ledger: CapabilityLedger,
        state: MultiAgentRunState,
        execution: InitializedExecution,
    ) -> ReportingTerminal:
        access = tasks.reporter_access
        reporter_agent = self._host._spawn_child(
            store,
            state.agents,
            budget,
            ledger,
            parent=execution.supervisor,
            parent_grant=execution.root_grant,
            role=AgentRole.REPORTER,
            tools={access.tool_id} if access else set(),
            targets={access.endpoint} if access else set(),
            max_calls=access.max_attempts if access else 0,
            max_risk_tier=access.risk_tier if access else ToolRiskTier.T0,
        )
        if access and self._reporter is not None:
            self._scheduler.bind_model_runtime(
                self._reporter,
                access,
                campaign,
                reporter_agent,
                ledger,
                budget,
                execution.gateway,
                store,
            )
        tasks.report_task.assigned_agent_id = reporter_agent.agent_id
        self._host._task_transition(
            store,
            state.graph,
            tasks.report_task.task_id,
            TaskStatus.RUNNING,
        )
        self._host._set_agent(store, reporter_agent, AgentStatus.RUNNING)
        plan = state.plan
        if plan is None:
            raise RuntimeError("reporting phase started without a validated plan")
        narrative: AgentReportNarrative | None = None
        try:
            if self._reporter is not None:
                reported_narrative = await self._host._within_budget(
                    self._reporter.report(
                        _detached_model(campaign),
                        _detached_model(plan),
                        _detached_models(state.results),
                        _detached_models(state.findings),
                    ),
                    budget,
                )
                narrative = AgentReportNarrative.model_validate(
                    reported_narrative.model_dump(mode="python")
                )
                store.write_json(
                    "model-narrative.json",
                    narrative.model_dump(mode="json"),
                )
            final_status = (
                RunStatus.FAILED
                if any(task.status is TaskStatus.FAILED for task in tasks.specialist_tasks)
                else RunStatus.COMPLETED
            )
            report_agents = {
                agent_id: agent.model_copy(deep=True) for agent_id, agent in state.agents.items()
            }
            report_agents[reporter_agent.agent_id].status = AgentStatus.COMPLETED
            report_agents[execution.supervisor.agent_id].status = AgentStatus.COMPLETED
            report_graph = state.graph.model_copy(deep=True)
            report_graph.transition(tasks.report_task.task_id, TaskStatus.SUCCEEDED)
            report = self._host._render_report(
                campaign,
                store.run_id,
                plan,
                state.results,
                state.findings,
                report_agents,
                report_graph,
                budget,
                final_status,
                narrative=narrative,
                validation=state.validation,
                execution_context=self._execution_context,
            )
            report_relative = store.write_text("report.md", report)
            self._host._revoke_capability_tree(
                store,
                ledger,
                reporter_agent.capability_grant_id,
                reason="reporter phase completed",
            )
            self._host._revoke_execution_authority(
                store,
                ledger,
                execution.root_grant.grant_id,
                reason=(f"campaign execution reached terminal status: {final_status.value}"),
            )
        except (BudgetExceeded, CapabilityError):
            raise
        except Exception as exc:
            try:
                self._host._mark_phase_failed(
                    store,
                    state.graph,
                    tasks.report_task,
                    reporter_agent,
                    exc,
                    stage="reporter",
                )
            finally:
                self._host._revoke_capability_tree(
                    store,
                    ledger,
                    reporter_agent.capability_grant_id,
                    reason="reporter phase failed",
                )
            raise
        self._host._task_transition(
            store,
            state.graph,
            tasks.report_task.task_id,
            TaskStatus.SUCCEEDED,
        )
        self._host._set_agent(store, reporter_agent, AgentStatus.COMPLETED)
        self._host._set_agent(store, execution.supervisor, AgentStatus.COMPLETED)
        return ReportingTerminal(
            status=final_status,
            report_relative=report_relative,
            cancellation=cancellation,
            event_kind="completed",
        )

    def finalize_unvalidated_candidates(
        self,
        campaign: CampaignManifest,
        *,
        store: RunStore,
        state: MultiAgentRunState,
        reason: ValidationReasonCode,
    ) -> None:
        if state.candidates.validation_snapshot_finalized:
            return
        try:
            self.ensure_candidate_production(campaign, store=store, state=state)
        except Exception:
            return
        if not state.candidates.admitted:
            return
        try:
            state.validation = validate_findings(
                campaign,
                state.results,
                [],
                store,
                validator_id=state.candidates.validator_agent_id,
                admitted_candidates=list(state.candidates.admitted),
                producer_authoritative_request_claims=(
                    set(state.candidates.authoritative_request_claims)
                ),
                validator_unavailable_reason=reason,
            )
        except Exception as exc:
            store.append_event(
                "validation.snapshot.failed",
                {
                    "stage": "validation-snapshot",
                    "role": AgentRole.SUPERVISOR.value,
                    "errorType": self._safe_exception_type(exc),
                },
            )
            return
        state.findings = []
        state.candidates.validation_snapshot_finalized = True


def _detached_model[ModelT: BaseModel](model: ModelT) -> ModelT:
    """Give an in-process extension no alias to authoritative mutable state."""

    return model.model_copy(deep=True)


def _detached_models[ModelT: BaseModel](models: Sequence[ModelT]) -> list[ModelT]:
    return [_detached_model(model) for model in models]
