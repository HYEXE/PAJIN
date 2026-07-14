import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.base import AgentReportNarrative, CandidateProduction
from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.domain.orchestration import AgentRole, AgentStatus, RunStatus, TaskStatus
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    ValidationReasonCode,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import (
    CancellationKind,
    ExecutionCancellationContext,
    KillSwitch,
)
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


class RetryPlanner:
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        target = campaign.spec.targets[0].endpoint
        return AgentPlan(
            summary="Retry one bounded analysis task.",
            steps=[
                PlannedStep(
                    title="Retry transient analysis",
                    rationale="Verify bounded low-risk retry behavior.",
                    request=ToolRequest(
                        agent_id="untrusted-planner-id",
                        tool_id="test.retry-probe",
                        target=target,
                        method="POST",
                    ),
                )
            ],
        )


class TwoStepPlanner:
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        target = campaign.spec.targets[0]
        steps = [
            PlannedStep(
                title=f"Specialist probe {index}",
                rationale="Verify dynamic specialist fan-out.",
                request=ToolRequest(
                    agent_id="untrusted-planner-id",
                    tool_id="mock.agent-probe",
                    target=target.endpoint,
                    method="POST",
                    arguments={"simulation": target.simulation},
                ),
            )
            for index in (1, 2)
        ]
        return AgentPlan(summary="Fan out two specialist tasks.", steps=steps)


class TwoRetryStepPlanner:
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        target = campaign.spec.targets[0].endpoint
        return AgentPlan(
            summary="Reserve one call for each low-risk Specialist.",
            steps=[
                PlannedStep(
                    title=f"Bounded low-risk probe {index}",
                    rationale="Verify fair call allocation before retry assignment.",
                    request=ToolRequest(
                        agent_id="untrusted-planner-id",
                        tool_id="test.retry-probe",
                        target=target,
                        method="POST",
                    ),
                )
                for index in (1, 2)
            ],
        )


class RetryProbe(Tool):
    spec = ToolSpec(
        tool_id="test.retry-probe",
        version="1.0.0",
        description="Deterministic transient retry probe",
        risk_tier=ToolRiskTier.T0,
        categories={"analysis"},
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return WorkerJob(
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
            stdin=json.dumps({"target": request.target, "simulation": {}}),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=result.status is WorkerStatus.SUCCEEDED,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data={"target": request.target, "vulnerable": False},
            error=None if result.status is WorkerStatus.SUCCEEDED else result.stderr,
        )


class FlakyWorker:
    def __init__(self) -> None:
        self.calls = 0

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.calls += 1
        now = datetime.now(UTC)
        succeeded = self.calls > 1
        return WorkerResult(
            execution_id=job.execution_id,
            backend="flaky",
            status=WorkerStatus.SUCCEEDED if succeeded else WorkerStatus.FAILED,
            exit_code=0 if succeeded else 1,
            stdout='{"ok":true}' if succeeded else "",
            stderr="transient worker failure" if not succeeded else "",
            started_at=now,
            finished_at=now,
        )


class ConcurrencyTrackingWorker(SimulatedWorkerBackend):
    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0.01)
            return await super().run(job)
        finally:
            self.active -= 1


class CancellationBlockingWorker(SimulatedWorkerBackend):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("blocking orchestration Worker unexpectedly resumed")


class InventedEvidenceValidator:
    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        del plan, results
        return [
            Finding(
                title="Unsupported finding",
                severity=FindingSeverity.HIGH,
                threat_class="A02",
                target=campaign.spec.targets[0].endpoint,
                summary="This finding cites evidence that no specialist produced.",
                reproduction=["Invent evidence."],
                evidence=["evidence/invented.json"],
                confidence=1,
                validated=True,
            )
        ]


class UnconfirmedEvidenceValidator:
    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        del plan
        assert results
        return [
            Finding(
                finding_id="finding_multi_review",
                title="Multi-agent candidate pending review",
                severity=FindingSeverity.MEDIUM,
                threat_class="A02",
                target=campaign.spec.targets[0].endpoint,
                summary="Preserve this claim without publishing it as confirmed.",
                reproduction=["Review the same-Run evidence."],
                evidence=results[0].evidence,
                confidence=0.5,
                validated=False,
            )
        ]


class RecordingCandidateValidator(DeterministicAgentRuntime):
    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        assert self._calls == ["producer"]
        self._calls.append("validator")
        return await super().validate(campaign, plan, results)


class RecordingCandidateProducer:
    producer_id = "trusted-core:test-candidate-producer"

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def produce(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> CandidateProduction:
        assert results
        assert results[0].request_id in {step.request.request_id for step in plan.steps}
        self._calls.append("producer")
        result = results[0]
        candidate = CandidateFinding(
            candidate_id="candidate_test_trusted_observation",
            claim=Finding(
                finding_id="finding_test_trusted_observation",
                title="Trusted producer observation",
                severity=FindingSeverity.HIGH,
                threat_class="A02",
                target=campaign.spec.targets[0].endpoint,
                summary="A deterministic producer derived this candidate.",
                reproduction=["Review the same-Run evidence."],
                evidence=result.evidence,
                confidence=1,
                validated=False,
            ),
            source=self.producer_id,
            source_agent_id=self.producer_id,
            source_request_ids=[result.request_id],
            created_at=datetime.now(UTC),
        )
        return CandidateProduction(
            candidates=(candidate,),
            authoritative_request_ids=frozenset({result.request_id}),
            authoritative_claim_keys=frozenset(
                {(candidate.claim.target, candidate.claim.threat_class)}
            ),
        )


class FailingReporter:
    async def report(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        findings: list[Finding],
    ) -> AgentReportNarrative:
        del campaign, plan, results, findings
        raise RuntimeError("bounded reporter failure")


def _campaign() -> CampaignManifest:
    return load_manifest(Path("examples/multi-agent.yaml"))


def _runner(tmp_path: Path, *, kill_after: int | None = None) -> MultiAgentCampaignRunner:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    return MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
        kill_after_tool_calls=kill_after,
    )


@pytest.mark.parametrize("max_parallel_specialists", [0, 17])
def test_local_specialist_concurrency_limit_is_bounded(
    tmp_path: Path,
    max_parallel_specialists: int,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())

    with pytest.raises(ValueError, match="max_parallel_specialists"):
        MultiAgentCampaignRunner(
            planner=DeterministicAgentRuntime(),
            validator=DeterministicAgentRuntime(),
            tools=registry,
            policy=PolicyEngine(),
            worker=SimulatedWorkerBackend(),
            output_root=tmp_path,
            max_parallel_specialists=max_parallel_specialists,
        )


def test_dynamic_team_executes_with_attenuated_role_capabilities(tmp_path: Path) -> None:
    outcome = asyncio.run(_runner(tmp_path).run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.findings) == 1
    assert {agent.role for agent in outcome.agents} == set(AgentRole)
    assert all(agent.status is AgentStatus.COMPLETED for agent in outcome.agents)
    assert all(task.status is TaskStatus.SUCCEEDED for task in outcome.task_graph.tasks.values())

    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    records = {item["grant"]["subject"]: item for item in capabilities}
    supervisor = next(
        item for subject, item in records.items() if subject.startswith("agent:supervisor:")
    )
    specialist = next(
        item for subject, item in records.items() if subject.startswith("agent:specialist:")
    )
    assert supervisor["remaining_calls"] == 2
    assert specialist["grant"]["tools"] == ["mock.agent-probe"]
    assert specialist["grant"]["targets"] == ["https://staging.example.invalid/api/chat"]
    assert specialist["remaining_calls"] == 0

    evidence_path = next((outcome.run_path / "evidence").glob("*.json"))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    request_agent = evidence["request"]["agent_id"]
    assert request_agent.startswith("agent:specialist:")
    assert evidence["policyDecision"]["allowed"] is True


def test_multi_agent_runner_produces_candidates_before_validator_without_claim_event_data(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=RecordingCandidateValidator(calls),
        candidate_producer=RecordingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert calls == ["producer", "validator"]
    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.candidates[0].source == "trusted-core:test-candidate-producer"
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    produced = [event for event in events if event["event_type"] == "candidate-set.produced"]
    event_types = [event["event_type"] for event in events]
    assert event_types.index("candidate-set.produced") < event_types.index("validation.started")
    assert [event["payload"] for event in produced] == [
        {
            "producerId": "trusted-core:test-candidate-producer",
            "candidateCount": 1,
            "authoritativeRequestCount": 1,
            "authoritativeClaimCount": 1,
            "candidateIds": ["candidate_test_trusted_observation"],
        }
    ]


def test_kill_switch_cancels_pending_tasks_and_revokes_all_grants(tmp_path: Path) -> None:
    outcome = asyncio.run(_runner(tmp_path, kill_after=1).run(_campaign()))

    assert outcome.status is RunStatus.CANCELLED
    assert outcome.cancellation_reason == "deterministic kill-after-tool-calls trigger"
    assert not outcome.findings
    statuses = {task.status for task in outcome.task_graph.tasks.values()}
    assert TaskStatus.CANCELLED in statuses
    assert TaskStatus.SUCCEEDED in statuses
    assert any(agent.status is AgentStatus.CANCELLED for agent in outcome.agents)

    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    assert capabilities
    assert all(item["revoked"] is True for item in capabilities)
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"capability.revoked"' in events
    assert '"event_type":"campaign.cancelled"' in events
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    run_state = json.loads((outcome.run_path / "run.json").read_text(encoding="utf-8"))
    assert run_state["status"] == "cancelled"


def test_kill_after_tool_preserves_trusted_candidate_as_inconclusive(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        candidate_producer=RecordingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
        kill_after_tool_calls=1,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.CANCELLED
    assert calls == ["producer"]
    assert len(outcome.validation.candidates) == 1
    decision = outcome.validation.decisions[0]
    assert decision.disposition is FindingDisposition.INCONCLUSIVE
    assert decision.reason_codes == [ValidationReasonCode.VALIDATOR_CANCELLED]
    assert outcome.findings == []
    persisted = json.loads(
        (outcome.run_path / "candidate-findings.json").read_text(encoding="utf-8")
    )
    assert len(persisted) == 1
    assert verify_run_integrity(outcome.run_path).valid


@pytest.mark.asyncio
async def test_execution_context_cancels_multi_agent_stack_and_seals_quiescence(
    tmp_path: Path,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = CancellationBlockingWorker()
    cancellation = ExecutionCancellationContext(
        job_id="job_" + "1" * 32,
        control_plane_run_id="run_" + "2" * 32,
    )
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )
    execution = asyncio.create_task(runner.run(_campaign(), cancellation=cancellation))
    await asyncio.wait_for(worker.started.wait(), timeout=1)

    cancellation.cancel(CancellationKind.RUN_CANCELLED, "Control Plane fence observed")
    outcome = await asyncio.wait_for(execution, timeout=1)

    assert worker.cancelled
    assert outcome.status is RunStatus.CANCELLED
    assert outcome.cancellation_reason == "Control Plane fence observed"
    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text("utf-8"))
    assert capabilities
    assert all(item["revoked"] is True for item in capabilities)
    assert (outcome.run_path / "cancellation.json").is_file()
    assert (outcome.run_path / "quiescence.json").is_file()
    assert verify_run_integrity(outcome.run_path).seal_count == 2


def test_insufficient_agent_budget_fails_closed_before_specialist_spawn(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    budgets = campaign.spec.budgets.model_copy(update={"max_agents": 4})
    spec = campaign.spec.model_copy(update={"budgets": budgets})
    constrained = campaign.model_copy(update={"spec": spec})

    outcome = asyncio.run(_runner(tmp_path).run(constrained))

    assert outcome.status is RunStatus.CANCELLED
    assert outcome.cancellation_reason == (
        "plan requires more agents than the campaign budget allows"
    )
    assert not any(agent.role is AgentRole.SPECIALIST for agent in outcome.agents)


def test_low_risk_transient_failure_retries_with_same_attenuated_grant(
    tmp_path: Path,
) -> None:
    registry = ToolRegistry()
    registry.register(RetryProbe())
    worker = FlakyWorker()
    runner = MultiAgentCampaignRunner(
        planner=RetryPlanner(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert worker.calls == 2
    assert [result.success for result in outcome.tool_results] == [False, True]
    budget = json.loads((outcome.run_path / "budget.json").read_text(encoding="utf-8"))
    assert budget["toolCalls"] == 2
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"task.retry_scheduled"' in events


def test_supervisor_dynamically_fans_out_one_specialist_per_plan_step(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    budgets = campaign.spec.budgets.model_copy(update={"max_agents": 6, "max_tool_calls": 3})
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
    )
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = ConcurrencyTrackingWorker()
    runner = MultiAgentCampaignRunner(
        planner=TwoStepPlanner(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    specialists = [agent for agent in outcome.agents if agent.role is AgentRole.SPECIALIST]
    assert outcome.status is RunStatus.COMPLETED
    assert len(specialists) == 2
    assert len(outcome.tool_results) == 2
    assert len(outcome.findings) == 2
    assert worker.max_active == 1
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert events.count('"event_type":"specialist.wave.started"') == 2
    assert '"parallelSafe":false' in events


def test_specialist_call_budget_reserves_one_attempt_before_retries(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    budgets = campaign.spec.budgets.model_copy(update={"max_agents": 6, "max_tool_calls": 2})
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
    )
    registry = ToolRegistry()
    registry.register(RetryProbe())
    worker = FlakyWorker()
    runner = MultiAgentCampaignRunner(
        planner=TwoRetryStepPlanner(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.status is RunStatus.FAILED
    assert worker.calls == 2
    assert [result.success for result in outcome.tool_results] == [False, True]
    specialist_tasks = [
        task
        for task in outcome.task_graph.tasks.values()
        if task.request is not None and task.request.tool_id == "test.retry-probe"
    ]
    assert [task.max_attempts for task in specialist_tasks] == [1, 1]
    assert [task.status for task in specialist_tasks] == [
        TaskStatus.FAILED,
        TaskStatus.SUCCEEDED,
    ]
    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    specialist_grants = [
        item["grant"]
        for item in capabilities
        if item["grant"]["subject"].startswith("agent:specialist:")
    ]
    assert [grant["max_calls"] for grant in specialist_grants] == [1, 1]
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"specialist.call-budget.allocated"' in events
    assert '"reservedControlCalls":0' in events
    assert '"unallocatedCalls":0' in events


def test_specialist_call_budget_rejects_plan_before_partial_spawn(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    budgets = campaign.spec.budgets.model_copy(update={"max_agents": 6, "max_tool_calls": 1})
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
    )
    registry = ToolRegistry()
    registry.register(RetryProbe())
    runner = MultiAgentCampaignRunner(
        planner=TwoRetryStepPlanner(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.status is RunStatus.CANCELLED
    assert outcome.cancellation_reason == (
        "plan requires more tool calls than the campaign budget allows"
    )
    assert not any(agent.role is AgentRole.SPECIALIST for agent in outcome.agents)
    assert not outcome.tool_results


def test_signal_file_kill_switch_stops_before_child_spawn(tmp_path: Path) -> None:
    signal = tmp_path / "STOP"
    signal.write_text("operator requested immediate stop", encoding="utf-8")
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
        kill_switch=KillSwitch(signal),
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.CANCELLED
    assert outcome.cancellation_reason == "operator requested immediate stop"
    assert [agent.role for agent in outcome.agents] == [AgentRole.SUPERVISOR]
    assert outcome.agents[0].status is AgentStatus.CANCELLED


def test_validator_cannot_confirm_finding_with_invented_evidence(tmp_path: Path) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=InventedEvidenceValidator(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert not outcome.findings
    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.decisions[0].disposition is FindingDisposition.REJECTED_OBJECTIVE
    candidates = json.loads(
        (outcome.run_path / "candidate-findings.json").read_text(encoding="utf-8")
    )
    assert candidates[0]["claim"]["finding_id"] == outcome.validation.candidates[0].claim.finding_id
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"finding.rejected"' in events
    assert '"event_type":"validation.rejected-objective"' in events


def test_multi_agent_runner_preserves_unconfirmed_candidate_for_review(
    tmp_path: Path,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=UnconfirmedEvidenceValidator(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.findings == []
    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    index = json.loads((outcome.run_path / "validation-index.json").read_text(encoding="utf-8"))
    assert index["candidatesByDisposition"]["needs-review"] == [
        outcome.validation.candidates[0].candidate_id
    ]
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    report = outcome.report_path.read_text(encoding="utf-8")
    assert "Needs review: `1`" in report
    assert "Multi-agent candidate pending review" not in report
    assert verify_run_integrity(outcome.run_path).valid


def test_reporter_failure_keeps_completed_validation_consistent(
    tmp_path: Path,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        reporter=FailingReporter(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.FAILED
    assert len(outcome.findings) == 1
    assert outcome.validation.decisions[0].disposition is FindingDisposition.CONFIRMED
    persisted = json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in persisted] == [outcome.findings[0].finding_id]
    report = outcome.report_path.read_text(encoding="utf-8")
    assert "Run status: `failed`" in report
    assert "Confirmed findings: `1`" in report
    assert "Confirmed: `1`" in report
    assert outcome.findings[0].title in report
    assert verify_run_integrity(outcome.run_path).valid
