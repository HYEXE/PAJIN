import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.base import CandidateAuthority, CandidateProduction, CandidateValidation
from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
    ToolResult,
)
from pajin.domain.validation import (
    CandidateAssessment,
    CandidateFinding,
    FindingDisposition,
    ValidationReasonCode,
    candidate_claim_digest,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import (
    BudgetController,
    CancellationKind,
    ExecutionCancellationContext,
)
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerResult,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.local import LocalCampaignRunner, LocalToolExecutionError


class UnknownToolRuntime(DeterministicAgentRuntime):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        return AgentPlan(
            summary="Attempt an unregistered tool.",
            steps=[
                PlannedStep(
                    title="Unknown tool",
                    rationale="Exercise fail-closed behavior.",
                    request=ToolRequest(
                        agent_id=self.agent_id,
                        tool_id="invented.shell",
                        target=campaign.spec.targets[0].endpoint,
                    ),
                )
            ],
        )


class UntrustedPlanIdentityRuntime(DeterministicAgentRuntime):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        plan = await super().plan(campaign)
        return plan.model_copy(
            update={
                "steps": [
                    step.model_copy(
                        update={
                            "request": step.request.model_copy(
                                update={"agent_id": "agent:untrusted-plan-subject"}
                            )
                        }
                    )
                    for step in plan.steps
                ]
            }
        )


class MutatingPlannerRuntime(DeterministicAgentRuntime):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        plan = await super().plan(campaign)
        campaign.metadata.name = "planner-mutated-campaign"
        campaign.spec.scope.allow.clear()
        campaign.spec.targets.clear()
        campaign.spec.budgets.max_tool_calls = 0
        return plan


class UnconfirmedFindingRuntime(DeterministicAgentRuntime):
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
                finding_id="finding_needs_review",
                title="Sensitive unconfirmed candidate",
                severity=FindingSeverity.MEDIUM,
                threat_class="A02",
                target=campaign.spec.targets[0].endpoint,
                summary="This unconfirmed claim must remain internal to the ledger.",
                reproduction=["Review the preserved same-Run evidence."],
                evidence=results[0].evidence,
                confidence=0.5,
                validated=False,
            )
        ]


class RecordingCandidateRuntime(DeterministicAgentRuntime):
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


class BlockingValidationRuntime(DeterministicAgentRuntime):
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        del campaign, plan, results
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("blocking Validator unexpectedly resumed")


class FailingValidationRuntime(DeterministicAgentRuntime):
    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        del campaign, plan, results
        raise RuntimeError("validator unavailable")


class MutatingCandidateAwareRuntime(DeterministicAgentRuntime):
    async def validate_candidates(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        candidates: list[CandidateFinding],
    ) -> CandidateValidation:
        candidate = candidates[0].model_copy(deep=True)
        candidates[0].claim.title = "validator-mutated producer claim"
        candidates.clear()
        campaign.metadata.name = "validator-mutated-campaign"
        plan.steps.clear()
        results.clear()
        return CandidateValidation(
            findings=[],
            assessments=[
                CandidateAssessment(
                    candidate_id=candidate.candidate_id,
                    claim_digest=candidate_claim_digest(candidate),
                    supports_claim=False,
                    reason_code=ValidationReasonCode.VALIDATOR_OMITTED,
                    rationale="The mutation attempt deliberately omits semantic support.",
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


class MutatingCandidateProducer(RecordingCandidateProducer):
    def produce(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> CandidateProduction:
        production = super().produce(campaign, plan, results)
        campaign.metadata.name = "producer-mutated-campaign"
        campaign.spec.scope.allow.clear()
        plan.steps.clear()
        results[0].success = False
        results[0].evidence.clear()
        results.clear()
        return production


class BlockingWorker:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def run(
        self,
        _job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        assert not secrets
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("blocking Worker unexpectedly resumed")


@pytest.mark.asyncio
async def test_local_runner_seals_cleanup_receipt_on_cooperative_cancellation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = BlockingWorker()
    cancellation = ExecutionCancellationContext(
        job_id="job_" + "1" * 32,
        control_plane_run_id="run_" + "2" * 32,
    )
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )
    execution = asyncio.create_task(runner.run(sample_campaign, cancellation=cancellation))
    await asyncio.wait_for(worker.started.wait(), timeout=1)

    cancellation.cancel(CancellationKind.RUN_CANCELLED, "Control Plane fence observed")
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(execution, timeout=1)

    assert worker.cancelled
    binding = cancellation.binding
    assert binding is not None
    receipt = json.loads((binding.path / "cancellation.json").read_text(encoding="utf-8"))
    assert receipt["cancellation"]["kind"] == "run-cancelled"
    assert receipt["cancellation"]["cleanupStatus"] == "cleanup-completed"
    assert receipt["resourceCleanupAttested"] is False
    assert receipt["externalSideEffectsReverted"] is False
    events = (binding.path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"worker.cancelled"' in events
    assert '"event_type":"execution.cleanup-completed"' in events
    assert '"event_type":"campaign.cancelled"' in events
    assert verify_run_integrity(binding.path).valid


@pytest.mark.asyncio
async def test_pre_cancelled_context_blocks_local_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = BlockingWorker()
    cancellation = ExecutionCancellationContext()
    cancellation.cancel(CancellationKind.RUN_CANCELLED, "cancelled before dispatch")
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    with pytest.raises(asyncio.CancelledError):
        await runner.run(sample_campaign, cancellation=cancellation)

    assert not worker.started.is_set()
    binding = cancellation.binding
    assert binding is not None
    assert (binding.path / "cancellation.json").is_file()
    assert verify_run_integrity(binding.path).valid


@pytest.mark.asyncio
async def test_direct_task_cancellation_uses_caller_source(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = BlockingWorker()
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )
    execution = asyncio.create_task(runner.run(sample_campaign))
    await asyncio.wait_for(worker.started.wait(), timeout=1)

    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    receipt = json.loads((run_path / "cancellation.json").read_text(encoding="utf-8"))
    assert receipt["cancellation"]["kind"] == "caller-cancelled"
    assert verify_run_integrity(run_path).valid


@pytest.mark.asyncio
async def test_local_validator_cancellation_preserves_candidate_as_inconclusive(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    validator = BlockingValidationRuntime()
    cancellation = ExecutionCancellationContext()
    runner = LocalCampaignRunner(
        agents=validator,
        candidate_producer=RecordingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    execution = asyncio.create_task(runner.run(sample_campaign, cancellation=cancellation))
    await asyncio.wait_for(validator.started.wait(), timeout=1)

    cancellation.cancel(CancellationKind.RUN_CANCELLED, "cancel validator")
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(execution, timeout=1)

    binding = cancellation.binding
    assert binding is not None
    decisions = json.loads((binding.path / "validation-decisions.json").read_text(encoding="utf-8"))
    assert len(decisions) == 1
    assert decisions[0]["disposition"] == "inconclusive"
    assert decisions[0]["reason_codes"] == ["validator-cancelled"]
    assert calls == ["producer"]
    assert verify_run_integrity(binding.path).valid


def test_local_validator_failure_seals_inconclusive_candidate(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=FailingValidationRuntime(),
        candidate_producer=RecordingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="validator unavailable"):
        asyncio.run(runner.run(sample_campaign))

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    decisions = json.loads((run_path / "validation-decisions.json").read_text(encoding="utf-8"))
    assert decisions[0]["disposition"] == "inconclusive"
    assert decisions[0]["reason_codes"] == ["validator-unavailable"]
    run_state = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    assert run_state["status"] == "failed"
    assert calls == ["producer"]
    assert verify_run_integrity(run_path).valid


def test_local_vertical_slice_keeps_semantic_only_finding_out_of_confirmed_report(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert outcome.findings == []
    assert outcome.report_path.exists()
    report = outcome.report_path.read_text(encoding="utf-8")
    assert "Needs review: `1`" in report
    assert "Untrusted instruction triggered an unauthorized tool call" not in report

    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    event_types = {event["event_type"] for event in events}
    assert "tool.policy_evaluated" in event_types
    assert "findings.validated" in event_types
    assert "candidate.finding.created" in event_types
    assert "candidate-set.produced" not in event_types
    assert "validation.needs-review" in event_types
    assert "validation.confirmed" not in event_types
    assert "campaign.completed" in event_types
    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    assert outcome.validation.decisions[0].reason_codes == [
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
    ]
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    assert (outcome.run_path / "candidate-findings.json").is_file()
    assert (outcome.run_path / "validation-decisions.json").is_file()
    assert (outcome.run_path / "validation-index.json").is_file()


def test_local_runner_seals_shared_budget_and_rate_limit_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    budget = BudgetController(sample_campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign, budget=budget, rate_limits=rate_limits))

    sealed_budget = json.loads((outcome.run_path / "budget.json").read_text(encoding="utf-8"))
    current_budget = budget.snapshot()
    exact_fields = set(current_budget) - {"elapsedSeconds"}
    assert {key: sealed_budget[key] for key in exact_fields} == {
        key: current_budget[key] for key in exact_fields
    }
    assert current_budget["elapsedSeconds"] >= sealed_budget["elapsedSeconds"]
    assert sealed_budget["toolCalls"] == 1
    assert (
        json.loads((outcome.run_path / "rate-limits.json").read_text(encoding="utf-8"))
        == rate_limits.snapshot()
    )
    assert verify_run_integrity(outcome.run_path).valid


def test_local_runner_binds_untrusted_plan_identity_to_capability_subject(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runtime = UntrustedPlanIdentityRuntime()
    runner = LocalCampaignRunner(
        agents=runtime,
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    plan = json.loads((outcome.run_path / "plan.json").read_text(encoding="utf-8"))
    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    assert plan["steps"][0]["request"]["agent_id"] == runtime.agent_id
    assert capabilities[0]["grant"]["subject"] == runtime.agent_id
    assert capabilities[0]["remaining_calls"] == sample_campaign.spec.budgets.max_tool_calls - 1
    assert outcome.tool_results[0].success
    assert verify_run_integrity(outcome.run_path).valid


def test_planner_mutation_cannot_change_authoritative_campaign_snapshot(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    original_campaign = sample_campaign.model_copy(deep=True)
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=MutatingPlannerRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert sample_campaign == original_campaign
    assert outcome.tool_results[0].success
    sealed_campaign = CampaignManifest.model_validate_json(
        (outcome.run_path / "campaign.json").read_bytes()
    )
    assert sealed_campaign == original_campaign
    assert verify_run_integrity(outcome.run_path).valid


def test_local_runner_seals_completed_run_summary(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    summary = json.loads((outcome.run_path / "run.json").read_text(encoding="utf-8"))
    assert summary["runId"] == outcome.run_id
    assert summary["status"] == "completed"
    assert summary["report"] == "report.md"
    assert verify_run_integrity(outcome.run_path).valid


def test_local_runner_rejects_shared_budget_for_different_campaign_contract(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    mismatched = BudgetController(
        sample_campaign.spec.budgets.model_copy(
            update={"max_tool_calls": sample_campaign.spec.budgets.max_tool_calls + 1}
        )
    )

    with pytest.raises(ValueError, match="shared budget"):
        asyncio.run(runner.run(sample_campaign, budget=mismatched))

    assert not (tmp_path / sample_campaign.metadata.name).exists()


def test_local_runner_produces_candidates_before_validator_without_claim_event_data(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=RecordingCandidateRuntime(calls),
        candidate_producer=RecordingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

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


def test_candidate_aware_validator_cannot_mutate_producer_authority_snapshot(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=MutatingCandidateAwareRuntime(),
        candidate_producer=RecordingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.candidates[0].claim.title == "Trusted producer observation"
    assert len(outcome.tool_results) == 1
    sealed_campaign = json.loads((outcome.run_path / "campaign.json").read_text(encoding="utf-8"))
    assert sealed_campaign["metadata"]["name"] == sample_campaign.metadata.name
    assert verify_run_integrity(outcome.run_path).valid


def test_candidate_producer_mutation_cannot_change_plan_result_or_campaign_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    original_campaign = sample_campaign.model_copy(deep=True)
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=RecordingCandidateRuntime(calls),
        candidate_producer=MutatingCandidateProducer(calls),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert calls == ["producer", "validator"]
    assert sample_campaign == original_campaign
    assert len(outcome.tool_results) == 1
    assert outcome.tool_results[0].success
    assert outcome.tool_results[0].evidence
    plan = AgentPlan.model_validate_json((outcome.run_path / "plan.json").read_bytes())
    assert len(plan.steps) == 1
    assert len(outcome.validation.candidates) == 1
    assert verify_run_integrity(outcome.run_path).valid


def test_local_terminal_state_write_failure_emits_only_failed_terminal_event(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    real_write_json = RunStore.write_json
    injected = False

    def fail_completed_state_once(
        store: RunStore,
        relative_path: str,
        data: object,
    ) -> str:
        nonlocal injected
        if (
            relative_path == "run.json"
            and isinstance(data, dict)
            and data.get("status") == "completed"
            and not injected
        ):
            injected = True
            raise RuntimeError("injected completed state write failure")
        return real_write_json(store, relative_path, data)

    monkeypatch.setattr(RunStore, "write_json", fail_completed_state_once)
    with pytest.raises(RuntimeError, match="completed state write failure"):
        asyncio.run(runner.run(sample_campaign))

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    terminal_events = [
        json.loads(line)["event_type"]
        for line in (run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if json.loads(line)["event_type"]
        in {"campaign.completed", "campaign.failed", "campaign.cancelled"}
    ]
    assert injected
    assert terminal_events == ["campaign.failed"]
    assert json.loads((run_path / "run.json").read_text(encoding="utf-8"))["status"] == "failed"
    assert verify_run_integrity(run_path).valid


def test_local_runner_rejects_prebound_cancellation_before_creating_run(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    cancellation = ExecutionCancellationContext()
    cancellation.bind_run(
        engine="another-engine",
        run_id="run_existing",
        path=tmp_path,
    )
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    with pytest.raises(ValueError, match="already bound"):
        asyncio.run(runner.run(sample_campaign, cancellation=cancellation))

    assert not (tmp_path / sample_campaign.metadata.name).exists()


def test_local_runner_preserves_unconfirmed_candidate_for_review(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=UnconfirmedFindingRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert outcome.findings == []
    assert len(outcome.validation.candidates) == 1
    decision = outcome.validation.decisions[0]
    assert decision.disposition is FindingDisposition.NEEDS_REVIEW
    candidates = json.loads(
        (outcome.run_path / "candidate-findings.json").read_text(encoding="utf-8")
    )
    assert candidates[0]["claim"]["finding_id"] == "finding_needs_review"
    assert json.loads((outcome.run_path / "findings.json").read_text(encoding="utf-8")) == []
    report = outcome.report_path.read_text(encoding="utf-8")
    assert "Needs review: `1`" in report
    assert "Sensitive unconfirmed candidate" not in report
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"validation.needs-review"' in events
    assert verify_run_integrity(outcome.run_path).valid


def test_run_store_accepts_relative_output_root(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=Path(".pajin/runs"),
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert outcome.report_path.is_absolute()
    assert outcome.report_path.exists()


def test_unknown_model_generated_tool_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=UnknownToolRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    with pytest.raises(LocalToolExecutionError, match="failed 1 of 1"):
        asyncio.run(runner.run(sample_campaign))

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    events = (run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"policy":"tool-registry"' in events
    assert '"event_type":"tool.failed"' in events
    run_state = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    assert run_state["status"] == "failed"
    assert verify_run_integrity(run_path).valid
