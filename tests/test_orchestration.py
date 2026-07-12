import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

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
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import KillSwitch
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
    runner = MultiAgentCampaignRunner(
        planner=TwoStepPlanner(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    specialists = [agent for agent in outcome.agents if agent.role is AgentRole.SPECIALIST]
    assert outcome.status is RunStatus.COMPLETED
    assert len(specialists) == 2
    assert len(outcome.tool_results) == 2
    assert len(outcome.findings) == 2


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
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"finding.rejected"' in events
