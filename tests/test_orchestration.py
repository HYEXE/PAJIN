import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.base import (
    AgentReportNarrative,
    CandidateAuthority,
    CandidateProduction,
    CandidateValidation,
    StructuredModelPort,
)
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
    CandidateAssessment,
    CandidateFinding,
    FindingDisposition,
    ValidationReasonCode,
    candidate_claim_digest,
)
from pajin.policy.capability import CapabilityError
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool, ProviderRegistration
from pajin.runtime.control import (
    CancellationKind,
    ExecutionCancellationContext,
    KillSwitch,
)
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerCleanupError,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome


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


class InputMutatingPlanner:
    def __init__(self) -> None:
        self.called = False

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        self.called = True
        target = campaign.spec.targets[0].model_copy(deep=True)
        campaign.metadata.name = "mutated-by-planner"
        campaign.spec.targets.clear()
        return AgentPlan(
            summary="Attempt to mutate the authoritative Campaign alias.",
            steps=[
                PlannedStep(
                    title="Detached planner probe",
                    rationale="The returned request still targets the original scope.",
                    request=ToolRequest(
                        agent_id="untrusted-planner-id",
                        tool_id="mock.agent-probe",
                        target=target.endpoint,
                        method="POST",
                        arguments={"simulation": target.simulation},
                    ),
                )
            ],
        )


class BlockingSnapshotPlanner:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        target = campaign.spec.targets[0].model_copy(deep=True)
        self.started.set()
        await self.release.wait()
        return AgentPlan(
            summary="Hold execution while the caller mutates its input object.",
            steps=[
                PlannedStep(
                    title="Caller-alias isolation probe",
                    rationale="Continue from the private Campaign snapshot.",
                    request=ToolRequest(
                        agent_id="untrusted-planner-id",
                        tool_id="mock.agent-probe",
                        target=target.endpoint,
                        method="POST",
                        arguments={"simulation": target.simulation},
                    ),
                )
            ],
        )


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


class MutatingCandidateValidator:
    """An untrusted Validator that tries to rewrite the Producer's admission set."""

    def __init__(self) -> None:
        self.received_candidates: list[CandidateFinding] | None = None

    async def validate_candidates(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        candidates: list[CandidateFinding],
    ) -> CandidateValidation:
        del campaign, plan, results
        self.received_candidates = candidates
        candidate_id = candidates[0].candidate_id
        claim_digest = candidate_claim_digest(candidates[0])
        candidates[0].claim.title = "Validator-mutated candidate"
        return CandidateValidation(
            findings=[],
            assessments=[
                CandidateAssessment(
                    candidate_id=candidate_id,
                    claim_digest=claim_digest,
                    supports_claim=False,
                    reason_code=ValidationReasonCode.VALIDATOR_DISAGREED,
                    rationale="Exercise the immutable admission boundary.",
                )
            ],
        )


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
            authoritative_request_claims=frozenset(
                {
                    CandidateAuthority(
                        request_id=result.request_id,
                        target=candidate.claim.target,
                        threat_class=candidate.claim.threat_class,
                    )
                }
            ),
        )


class InputMutatingCandidateProducer:
    producer_id = "trusted-core:input-mutating-producer"

    def __init__(self) -> None:
        self.called = False

    def produce(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> CandidateProduction:
        self.called = True
        self.producer_id = "mutated-by-producer"
        campaign.metadata.name = "mutated-by-producer"
        campaign.spec.targets.clear()
        plan.steps.clear()
        results[0].data["target"] = "https://mutated.invalid"
        results.clear()
        return CandidateProduction(candidates=())


class InputMutatingValidator:
    def __init__(self) -> None:
        self.called = False

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        self.called = True
        campaign.metadata.name = "mutated-by-validator"
        campaign.spec.targets.clear()
        plan.steps.clear()
        results[0].data["target"] = "https://mutated.invalid"
        results.clear()
        return []


class InputMutatingReporter:
    def __init__(self) -> None:
        self.called = False

    async def report(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        findings: list[Finding],
    ) -> AgentReportNarrative:
        self.called = True
        target = campaign.spec.targets[0].endpoint
        campaign.metadata.name = "mutated-by-reporter"
        campaign.spec.targets.clear()
        plan.steps.clear()
        results[0].data["target"] = "https://mutated.invalid"
        results.clear()
        findings.append(
            Finding(
                title="Reporter-invented authoritative finding",
                severity=FindingSeverity.CRITICAL,
                threat_class="A02",
                target=target,
                summary="This must remain confined to the Reporter input copy.",
                reproduction=["Mutate the aliased findings list."],
                evidence=[],
                confidence=1,
                validated=True,
            )
        )
        return AgentReportNarrative(
            summary="Detached Reporter input test.",
            risk_overview="No confirmed findings.",
            recommendations=["Preserve authoritative state aliases."],
            limitations=["Synthetic boundary test."],
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


class TimeoutReporter:
    async def report(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        findings: list[Finding],
    ) -> AgentReportNarrative:
        del campaign, plan, results, findings
        raise TimeoutError("report provider transport timed out: " + "x" * 1_000 + "\ud800")


class SensitiveExtensionFailure(RuntimeError):
    pass


SensitiveExtensionFailure.__name__ = "Provider\n**Failure**\x1b[31m"


class SensitiveFailingReporter:
    async def report(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        findings: list[Finding],
    ) -> AgentReportNarrative:
        del campaign, plan, results, findings
        raise SensitiveExtensionFailure("TOP_SECRET_PROVIDER_TOKEN\n# injected heading\x00\x1b[31m")


class CapturingModelRuntime(DeterministicAgentRuntime):
    def __init__(self, registration: ProviderRegistration) -> None:
        self.model_provider_registration = registration
        self.model_provider_tool_id = f"provider.{registration.provider_id}.chat"
        self.model_provider_endpoint = str(registration.endpoint)
        self.model_max_attempts = 1
        self.bound_ports: list[StructuredModelPort] = []
        self.phase_reuse_rejected = False

    def bind_model_port(self, port: StructuredModelPort) -> None:
        self.bound_ports.append(port)

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        try:
            await _reuse_captured_port(self.bound_ports[0])
        except CapabilityError:
            self.phase_reuse_rejected = True
        else:
            raise AssertionError("completed planner capability remained usable")
        return await super().validate(campaign, plan, results)


class SelfAssigningModelRuntime(CapturingModelRuntime):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        return AgentPlan(
            summary="Attempt to delegate the reasoning Provider to a Specialist.",
            steps=[
                PlannedStep(
                    title="Recursively call the reasoning Provider",
                    rationale="Exercise the control-plane Provider recursion boundary.",
                    request=ToolRequest(
                        agent_id="agent:untrusted-provider-planner",
                        tool_id=self.model_provider_tool_id,
                        target=campaign.spec.targets[0].endpoint,
                        method="POST",
                        arguments={"messages": [{"role": "user", "content": "recurse"}]},
                    ),
                )
            ],
        )


async def _reuse_captured_port(port: StructuredModelPort) -> object:
    return await port.complete(
        role="captured-authority-reuse",
        attempt=1,
        messages=[{"role": "user", "content": "reuse captured authority"}],
        schema_name="captured_authority_reuse",
        schema={
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        max_completion_tokens=128,
    )


class ParallelFailurePlanner:
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        target = campaign.spec.targets[0].endpoint
        return AgentPlan(
            summary="Exercise fail-fast parallel Specialist cleanup.",
            steps=[
                PlannedStep(
                    title="Blocking parallel Specialist",
                    rationale="Must be cancelled and drained when its sibling fails.",
                    request=ToolRequest(
                        agent_id="untrusted-planner-id",
                        tool_id="test.parallel-failure-probe",
                        target=target,
                        method="POST",
                        arguments={"behavior": "block"},
                    ),
                ),
                PlannedStep(
                    title="Failing parallel Specialist",
                    rationale="Raises a fatal isolation-cleanup failure.",
                    request=ToolRequest(
                        agent_id="untrusted-planner-id",
                        tool_id="test.parallel-failure-probe",
                        target=target,
                        method="POST",
                        arguments={"behavior": "fail"},
                    ),
                ),
            ],
        )


class ParallelFailureProbe(Tool):
    spec = ToolSpec(
        tool_id="test.parallel-failure-probe",
        version="1.0.0",
        description="Parallel Specialist fatal-cleanup regression probe",
        risk_tier=ToolRiskTier.T0,
        categories={"analysis"},
        parallel_safe=True,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return WorkerJob(
            image="pajin-worker:dev",
            command=["parallel-failure-probe"],
            stdin=json.dumps({"behavior": request.arguments["behavior"]}),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=result.status is WorkerStatus.SUCCEEDED,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data={"target": request.target},
            error=None if result.status is WorkerStatus.SUCCEEDED else result.stderr,
        )


class SyntheticWorkerCleanupError(WorkerCleanupError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "synthetic Worker cleanup could not be confirmed")


class ParallelCleanupFailureWorker:
    def __init__(self) -> None:
        self.blocker_started = asyncio.Event()
        self.blocker_cancelled = False

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        behavior = json.loads(job.stdin)["behavior"]
        if behavior == "block":
            self.blocker_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.blocker_cancelled = True
                raise
            raise AssertionError("blocking parallel Worker unexpectedly resumed")
        await asyncio.wait_for(self.blocker_started.wait(), timeout=1)
        raise SyntheticWorkerCleanupError


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
    assert outcome.findings == []
    assert outcome.validation.decisions[0].reason_codes == [
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
    ]
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


def _assert_authoritative_reasoning_inputs_remain_intact(
    outcome: object,
    campaign: CampaignManifest,
) -> None:
    assert isinstance(outcome, MultiAgentRunOutcome)
    target = campaign.spec.targets[0].endpoint
    assert campaign.metadata.name == "dynamic-multi-agent-validation"
    assert len(campaign.spec.targets) == 1
    assert outcome.status is RunStatus.COMPLETED
    assert outcome.plan is not None
    assert len(outcome.plan.steps) == 1
    assert len(outcome.tool_results) == 1
    assert outcome.tool_results[0].data["target"] == target
    assert outcome.findings == []
    persisted_campaign = json.loads(
        (outcome.run_path / "campaign.json").read_text(encoding="utf-8")
    )
    assert persisted_campaign["metadata"]["name"] == campaign.metadata.name
    assert persisted_campaign["spec"]["targets"][0]["endpoint"] == target
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    assert verify_run_integrity(outcome.run_path).valid


def test_planner_receives_a_detached_campaign_snapshot(tmp_path: Path) -> None:
    campaign = _campaign()
    planner = InputMutatingPlanner()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=planner,
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert planner.called
    _assert_authoritative_reasoning_inputs_remain_intact(outcome, campaign)


@pytest.mark.asyncio
async def test_caller_cannot_mutate_the_private_campaign_snapshot_mid_run(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    original_name = campaign.metadata.name
    original_target = campaign.spec.targets[0].endpoint
    planner = BlockingSnapshotPlanner()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=planner,
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    execution = asyncio.create_task(runner.run(campaign))
    await asyncio.wait_for(planner.started.wait(), timeout=1)

    campaign.metadata.name = "caller-mutated-mid-run"
    campaign.spec.targets.clear()
    planner.release.set()
    outcome = await asyncio.wait_for(execution, timeout=1)

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.plan is not None
    assert outcome.plan.steps[0].request.target == original_target
    assert outcome.tool_results[0].data["target"] == original_target
    persisted_campaign = json.loads(
        (outcome.run_path / "campaign.json").read_text(encoding="utf-8")
    )
    assert persisted_campaign["metadata"]["name"] == original_name
    assert persisted_campaign["spec"]["targets"][0]["endpoint"] == original_target
    assert verify_run_integrity(outcome.run_path).valid


def test_candidate_producer_receives_detached_authoritative_inputs(tmp_path: Path) -> None:
    campaign = _campaign()
    producer = InputMutatingCandidateProducer()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        candidate_producer=producer,
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert producer.called
    produced_event = next(
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if json.loads(line)["event_type"] == "candidate-set.produced"
    )
    assert produced_event["payload"]["producerId"] == ("trusted-core:input-mutating-producer")
    _assert_authoritative_reasoning_inputs_remain_intact(outcome, campaign)


def test_validator_receives_detached_authoritative_inputs(tmp_path: Path) -> None:
    campaign = _campaign()
    validator = InputMutatingValidator()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=validator,
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert validator.called
    _assert_authoritative_reasoning_inputs_remain_intact(outcome, campaign)


def test_reporter_receives_detached_authoritative_inputs(tmp_path: Path) -> None:
    campaign = _campaign()
    reporter = InputMutatingReporter()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        reporter=reporter,
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert reporter.called
    _assert_authoritative_reasoning_inputs_remain_intact(outcome, campaign)
    assert "Reporter-invented authoritative finding" not in outcome.report_path.read_text(
        encoding="utf-8"
    )


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


def test_candidate_aware_validator_cannot_mutate_the_producer_admission_snapshot(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    validator = MutatingCandidateValidator()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=validator,
        candidate_producer=RecordingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    assert outcome.status is RunStatus.COMPLETED
    assert calls == ["producer"]
    assert validator.received_candidates is not None
    assert validator.received_candidates[0].claim.title == "Validator-mutated candidate"
    assert len(outcome.validation.candidates) == 1
    admitted = outcome.validation.candidates[0]
    assert admitted.candidate_id == "candidate_test_trusted_observation"
    assert admitted.claim.title == "Trusted producer observation"
    assert outcome.validation.decisions[0].candidate_id == admitted.candidate_id
    assert verify_run_integrity(outcome.run_path).valid


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

    with pytest.raises(RuntimeError, match="does not allow concurrent runs"):
        await runner.run(_campaign())
    campaign_root = tmp_path / _campaign().metadata.name
    assert len(list(campaign_root.glob("run_*"))) == 1

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


def test_prebound_cancellation_is_rejected_before_creating_a_run_directory(
    tmp_path: Path,
) -> None:
    cancellation = ExecutionCancellationContext()
    cancellation.bind_run(
        engine="different-engine",
        run_id="run_" + "1" * 32,
        path=tmp_path / "different-run",
    )

    with pytest.raises(ValueError, match="already bound"):
        asyncio.run(_runner(tmp_path).run(_campaign(), cancellation=cancellation))

    campaign_root = tmp_path / _campaign().metadata.name
    assert not campaign_root.exists()


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
        "exception_type=BudgetExceeded; stage=runtime-control; role=supervisor; detail=omitted"
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
    assert outcome.findings == []
    assert all(
        decision.reason_codes == [ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING]
        for decision in outcome.validation.decisions
    )
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
        "exception_type=BudgetExceeded; stage=runtime-control; role=supervisor; detail=omitted"
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


def test_runner_reuse_is_serial_and_preserves_one_way_kill_switch_state(
    tmp_path: Path,
) -> None:
    reusable = _runner(tmp_path / "successful")

    first = asyncio.run(reusable.run(_campaign()))
    second = asyncio.run(reusable.run(_campaign()))

    assert first.status is RunStatus.COMPLETED
    assert second.status is RunStatus.COMPLETED
    assert first.run_id != second.run_id

    stopped = _runner(tmp_path / "stopped", kill_after=1)
    cancelled = asyncio.run(stopped.run(_campaign()))
    repeated = asyncio.run(stopped.run(_campaign()))

    assert cancelled.status is RunStatus.CANCELLED
    assert repeated.status is RunStatus.CANCELLED
    assert repeated.cancellation_reason == cancelled.cancellation_reason
    assert [agent.role for agent in repeated.agents] == [AgentRole.SUPERVISOR]
    assert verify_run_integrity(first.run_path).valid
    assert verify_run_integrity(second.run_path).valid
    assert verify_run_integrity(repeated.run_path).valid


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
    assert outcome.findings == []
    assert outcome.validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    assert outcome.validation.decisions[0].reason_codes == [
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
    ]
    persisted = json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8"))
    assert persisted == []
    report = outcome.report_path.read_text(encoding="utf-8")
    assert "Run status: `failed`" in report
    assert "Confirmed findings: `0`" in report
    assert "Confirmed: `0`" in report
    assert "Needs review: `1`" in report
    assert verify_run_integrity(outcome.run_path).valid


def test_report_render_failure_marks_the_causal_reporter_phase_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    render_report = runner._render_report
    render_attempts = 0

    def fail_render(*args: object, **kwargs: object) -> str:
        nonlocal render_attempts
        render_attempts += 1
        if render_attempts == 1:
            raise RuntimeError("synthetic canonical report rendering failure")
        return render_report(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner, "_render_report", fail_render)

    outcome = asyncio.run(runner.run(_campaign()))

    reporter = next(agent for agent in outcome.agents if agent.role is AgentRole.REPORTER)
    report_task = next(
        task
        for task in outcome.task_graph.tasks.values()
        if task.assigned_agent_id == reporter.agent_id
    )
    assert outcome.status is RunStatus.FAILED
    assert reporter.status is AgentStatus.FAILED
    assert report_task.status is TaskStatus.FAILED
    assert reporter.error == (
        "exception_type=RuntimeError; stage=reporter; role=reporter; detail=omitted"
    )
    assert verify_run_integrity(outcome.run_path).valid


def test_finalization_failure_emits_only_one_failed_terminal_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    def fail_state_write(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("synthetic final state persistence failure")

    monkeypatch.setattr(runner, "_write_state", fail_state_write)

    with pytest.raises(RuntimeError, match="synthetic final state persistence failure"):
        asyncio.run(runner.run(_campaign()))

    run_paths = list((tmp_path / _campaign().metadata.name).glob("run_*"))
    assert len(run_paths) == 1
    events = [
        json.loads(line)
        for line in (run_paths[0] / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    terminal_events = [
        event
        for event in events
        if event["event_type"] in {"campaign.completed", "campaign.cancelled", "campaign.failed"}
    ]
    assert [event["event_type"] for event in terminal_events] == ["campaign.failed"]
    assert terminal_events[0]["payload"]["stage"] == "initialization-or-finalization"
    assert verify_run_integrity(run_paths[0]).valid


def test_component_timeout_is_failed_not_misreported_as_campaign_cancellation(
    tmp_path: Path,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        reporter=TimeoutReporter(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    reporter = next(agent for agent in outcome.agents if agent.role is AgentRole.REPORTER)
    report_task = next(
        task
        for task in outcome.task_graph.tasks.values()
        if task.assigned_agent_id == reporter.agent_id
    )
    assert outcome.status is RunStatus.FAILED
    assert reporter.status is AgentStatus.FAILED
    assert report_task.status is TaskStatus.FAILED
    assert reporter.error == (
        "exception_type=TimeoutError; stage=reporter; role=reporter; detail=omitted"
    )
    terminal_error = (
        "exception_type=TimeoutError; stage=campaign-execution; role=supervisor; detail=omitted"
    )
    assert outcome.cancellation_reason == terminal_error
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    failure = next(event for event in events if event["event_type"] == "campaign.failed")
    assert failure["payload"]["error"] == terminal_error
    assert verify_run_integrity(outcome.run_path).valid


def test_extension_exception_details_are_omitted_from_every_sealed_artifact(
    tmp_path: Path,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        reporter=SensitiveFailingReporter(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(_campaign()))

    expected_phase_error = (
        "exception_type=Provider-Failure-31m; stage=reporter; role=reporter; detail=omitted"
    )
    expected_terminal_error = (
        "exception_type=Provider-Failure-31m; stage=campaign-execution; "
        "role=supervisor; detail=omitted"
    )
    reporter = next(agent for agent in outcome.agents if agent.role is AgentRole.REPORTER)
    report_task = next(
        task
        for task in outcome.task_graph.tasks.values()
        if task.assigned_agent_id == reporter.agent_id
    )
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    reporter_failure = next(
        event
        for event in events
        if event["event_type"] == "agent.failed"
        and event["payload"]["role"] == AgentRole.REPORTER.value
    )
    campaign_failure = next(event for event in events if event["event_type"] == "campaign.failed")

    assert outcome.status is RunStatus.FAILED
    assert reporter.error == expected_phase_error
    assert report_task.error == expected_phase_error
    assert reporter_failure["payload"]["error"] == expected_phase_error
    assert campaign_failure["payload"]["error"] == expected_terminal_error
    assert outcome.cancellation_reason == expected_terminal_error
    assert expected_terminal_error in outcome.report_path.read_text(encoding="utf-8")
    sealed_bytes = b"\n".join(
        path.read_bytes() for path in sorted(outcome.run_path.rglob("*")) if path.is_file()
    )
    for forbidden in (
        b"TOP_SECRET_PROVIDER_TOKEN",
        b"injected heading",
        b"**Failure**",
        b"\\u001b",
        b"\\u0000",
    ):
        assert forbidden not in sealed_bytes
    assert verify_run_integrity(outcome.run_path).valid


def test_plan_boundary_rejects_reasoning_provider_tool_reassignment(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/provider-openai-compatible-lab.yaml"))
    registration = ProviderRegistration.model_validate(
        {
            "provider_id": "reasoning-provider",
            "endpoint": campaign.spec.targets[0].endpoint,
            "model": "reasoning-model",
            "secret_ref": "provider/reasoning/api-key",
            "allow_private_networks": True,
        }
    )
    runtime = SelfAssigningModelRuntime(registration)
    registry = ToolRegistry()
    registry.register(OpenAICompatibleChatTool(registration))
    runner = MultiAgentCampaignRunner(
        planner=runtime,
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.status is RunStatus.CANCELLED
    assert outcome.plan is not None
    assert outcome.plan.steps[0].request.tool_id == runtime.model_provider_tool_id
    assert outcome.tool_results == []
    assert outcome.cancellation_reason == (
        "exception_type=CapabilityError; stage=runtime-control; role=supervisor; detail=omitted"
    )
    assert verify_run_integrity(outcome.run_path).valid


def test_terminal_run_revokes_every_captured_model_port_without_new_events(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    registration = ProviderRegistration.model_validate(
        {
            "provider_id": "captured-port",
            "endpoint": "https://provider.example/v1/chat/completions",
            "model": "captured-port-model",
            "secret_ref": "provider/captured-port/api-key",
        }
    )
    runtime = CapturingModelRuntime(registration)
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    registry.register(OpenAICompatibleChatTool(registration))
    runner = MultiAgentCampaignRunner(
        planner=runtime,
        validator=runtime,
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))
    events_before = (outcome.run_path / "events.jsonl").read_bytes()

    async def attempt_reuse() -> None:
        for port in runtime.bound_ports:
            with pytest.raises(CapabilityError, match="no remaining authorized call"):
                await _reuse_captured_port(port)

    asyncio.run(attempt_reuse())

    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    assert len(runtime.bound_ports) == 2
    assert runtime.phase_reuse_rejected
    assert all(record["revoked"] is True for record in capabilities)
    assert (outcome.run_path / "events.jsonl").read_bytes() == events_before
    assert verify_run_integrity(outcome.run_path).valid


def test_parallel_specialist_failure_cancels_and_drains_siblings_fail_fast(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    budgets = campaign.spec.budgets.model_copy(update={"max_agents": 6, "max_tool_calls": 2})
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
    )
    registry = ToolRegistry()
    registry.register(ParallelFailureProbe())
    worker = ParallelCleanupFailureWorker()
    runner = MultiAgentCampaignRunner(
        planner=ParallelFailurePlanner(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
        max_parallel_specialists=2,
    )

    outcome = asyncio.run(runner.run(campaign))

    specialist_tasks = [
        task for task in outcome.task_graph.tasks.values() if task.request is not None
    ]
    specialist_agents = {
        agent.agent_id: agent for agent in outcome.agents if agent.role is AgentRole.SPECIALIST
    }
    assert outcome.status is RunStatus.FAILED
    assert worker.blocker_cancelled
    assert [task.status for task in specialist_tasks] == [
        TaskStatus.CANCELLED,
        TaskStatus.FAILED,
    ]
    assigned_agent_ids = [task.assigned_agent_id for task in specialist_tasks]
    assert all(agent_id is not None for agent_id in assigned_agent_ids)
    assert [specialist_agents[str(agent_id)].status for agent_id in assigned_agent_ids] == [
        AgentStatus.CANCELLED,
        AgentStatus.FAILED,
    ]
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    event_types = [event["event_type"] for event in events]
    assert event_types.index("task.failed") < event_types.index("campaign.failed")
    assert verify_run_integrity(outcome.run_path).valid
