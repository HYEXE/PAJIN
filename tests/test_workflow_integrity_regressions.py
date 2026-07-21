import asyncio
import json
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_finding_validation_gate import (
    _admitted_candidate,
    _candidate_authorities,
    _finding,
    _gateway_result,
)
from test_kisa_replay import TranscriptWorker, _trusted_docker_backend
from test_kisa_replay import _campaign as kisa_campaign
from test_orchestration import FailingReporter
from test_orchestration import _campaign as orchestration_campaign
from test_tool_loop import BlockingLoopWorker, LoopWorker, _binding, _registration
from test_tool_loop import _campaign as tool_loop_campaign
from test_tool_loop import _runner as tool_loop_runner

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.orchestration import AgentRole, RunStatus
from pajin.domain.validation import (
    CandidateAssessment,
    ValidationCheckStatus,
    ValidationReasonCode,
    candidate_claim_digest,
)
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.replay import KISAReplayBatchOutcome, KISAReplayCoordinator
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime, KISAValidatorRuntime
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    CancellationKind,
    ExecutionCancellationContext,
)
from pajin.runtime.secrets import SecretBroker, SecretLeaseStatus
from pajin.runtime.store import RunIntegrityError, RunStore, verify_run_integrity
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.tools.mock import MockAgentProbe
from pajin.workflow import confirmation as confirmation_module
from pajin.workflow.confirmation import (
    _render_confirmation_report,
    _semantic_supported,
    apply_confirmed_gate,
)
from pajin.workflow.local import LocalCampaignRunner
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopApproval,
    ToolLoopConfig,
    ToolLoopOutcome,
    ToolLoopStatus,
)
from pajin.workflow.validation import validate_findings


class _BlockingPlanner(DeterministicAgentRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.cancelled = False

    async def plan(self, campaign):
        del campaign
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("blocking planner unexpectedly resumed")


class _FailingPlanner(DeterministicAgentRuntime):
    async def plan(self, campaign):
        del campaign
        raise RuntimeError("planner failed")


def _local_runner(tmp_path: Path, agents: DeterministicAgentRuntime) -> LocalCampaignRunner:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    return LocalCampaignRunner(
        agents=agents,
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )


def _tool_loop_runner_with_shared_secrets(
    tmp_path: Path,
    worker: LoopWorker,
    secrets: SecretBroker,
) -> PolicyToolLoopRunner:
    registration = _registration()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    registry.register(OpenAICompatibleChatTool(registration))
    return PolicyToolLoopRunner(
        registration=registration,
        bindings=[_binding()],
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        secrets=secrets,
        output_root=tmp_path,
        config=ToolLoopConfig(max_turns=6),
    )


def _create_kisa_source_and_replays(
    tmp_path: Path,
) -> tuple[MultiAgentRunOutcome, KISAReplayBatchOutcome]:
    campaign = kisa_campaign()
    thresholds = EvaluationThresholds(repetitions=2)
    tools = ToolRegistry()
    tools.register(AIChatProbeTool())
    worker = TranscriptWorker([True] * 12)
    backend = _trusted_docker_backend(worker)
    policy = PolicyEngine()
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=policy,
        worker=backend,
        output_root=tmp_path / "candidate-runs",
    )
    coordinator = KISAReplayCoordinator(
        tools=tools,
        policy=policy,
        worker=backend,
        output_root=tmp_path / "replay-runs",
        repetitions=2,
        required_successes=2,
    )

    async def execute() -> tuple[MultiAgentRunOutcome, KISAReplayBatchOutcome]:
        source = await runner.run(campaign, budget=budget, rate_limits=rate_limits)
        batch = await coordinator.reproduce(
            campaign,
            source.run_path,
            budget=budget,
            rate_limits=rate_limits,
        )
        return source, batch

    return asyncio.run(execute())


def test_tool_loop_resume_rejects_same_name_campaign_policy_substitution(
    tmp_path: Path,
) -> None:
    worker = LoopWorker()
    runner, _secrets = tool_loop_runner(tmp_path, worker, high_risk=True)
    original = tool_loop_campaign(high_risk=False)
    widened = tool_loop_campaign(high_risk=True)
    assert original.metadata.name == widened.metadata.name

    waiting = asyncio.run(runner.run(original, prompt="Request the T3 probe."))
    assert waiting.status is ToolLoopStatus.AWAITING_APPROVAL
    assert waiting.pending_call is not None
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target=waiting.pending_call.target,
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )

    with pytest.raises(ValueError, match="Campaign digest"):
        asyncio.run(
            runner.resume(
                widened,
                checkpoint_path=waiting.checkpoint_path,
                approvals=[approval],
            )
        )

    assert worker.tool_calls == 0
    assert not waiting.checkpoint_path.with_suffix(
        waiting.checkpoint_path.suffix + ".claimed"
    ).exists()


def test_tool_loop_resume_rejects_changed_runner_context(tmp_path: Path) -> None:
    worker = LoopWorker()
    original_runner, _secrets = tool_loop_runner(tmp_path, worker, high_risk=True)
    campaign = tool_loop_campaign(high_risk=False)
    waiting = asyncio.run(original_runner.run(campaign, prompt="Request the T3 probe."))
    assert waiting.status is ToolLoopStatus.AWAITING_APPROVAL
    changed_runner, _changed_secrets = tool_loop_runner(
        tmp_path,
        worker,
        high_risk=True,
        max_turns=7,
    )

    with pytest.raises(ValueError, match="runner context"):
        asyncio.run(
            changed_runner.resume(
                campaign,
                checkpoint_path=waiting.checkpoint_path,
                approvals=[],
            )
        )


def test_concurrent_checkpoint_resume_claims_exactly_one_continuation_run(
    tmp_path: Path,
) -> None:
    campaign = tool_loop_campaign(high_risk=True)
    original, _original_secrets = tool_loop_runner(
        tmp_path,
        LoopWorker(),
        high_risk=True,
    )
    waiting = asyncio.run(original.run(campaign, prompt="Request the T3 probe."))
    assert waiting.pending_call is not None
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target=waiting.pending_call.target,
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )
    first_worker = LoopWorker()
    second_worker = LoopWorker()
    first, _first_secrets = tool_loop_runner(tmp_path, first_worker, high_risk=True)
    second, _second_secrets = tool_loop_runner(tmp_path, second_worker, high_risk=True)

    def resume(runner: PolicyToolLoopRunner) -> ToolLoopOutcome | ValueError:
        try:
            return asyncio.run(
                runner.resume(
                    campaign,
                    checkpoint_path=waiting.checkpoint_path,
                    approvals=[approval],
                )
            )
        except ValueError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        attempts = list(executor.map(resume, (first, second)))

    outcomes = [item for item in attempts if isinstance(item, ToolLoopOutcome)]
    rejections = [item for item in attempts if isinstance(item, ValueError)]
    assert len(outcomes) == 1
    assert len(rejections) == 1
    assert "already been claimed" in str(rejections[0])
    assert first_worker.tool_calls + second_worker.tool_calls == 1
    assert len(list(waiting.run_path.parent.glob("run_*"))) == 2
    assert len(list((waiting.run_path.parent / ".pajin-tool-loop-claims").glob("*.json"))) == 1
    assert verify_run_integrity(waiting.run_path).valid
    assert verify_run_integrity(outcomes[0].run_path).valid


def test_local_duration_budget_cancels_owned_planner_and_seals_run(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    campaign = campaign.model_copy(
        update={
            "spec": campaign.spec.model_copy(
                update={"budgets": campaign.spec.budgets.model_copy(update={"duration_seconds": 1})}
            )
        }
    )
    planner = _BlockingPlanner()

    with pytest.raises(BudgetExceeded, match="duration"):
        asyncio.run(_local_runner(tmp_path, planner).run(campaign))

    run_path = next((tmp_path / campaign.metadata.name).glob("run_*"))
    state = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    assert planner.cancelled
    assert state["status"] == "budget-exhausted"
    assert state["stage"] == "planning"
    assert verify_run_integrity(run_path).valid


def test_tool_loop_duration_budget_cancels_provider_and_seals_run(tmp_path: Path) -> None:
    worker = BlockingLoopWorker()
    runner, _secrets = tool_loop_runner(tmp_path, worker)
    base = tool_loop_campaign()
    campaign = base.model_copy(
        update={
            "spec": base.spec.model_copy(
                update={"budgets": base.spec.budgets.model_copy(update={"duration_seconds": 1})}
            )
        }
    )

    outcome = asyncio.run(runner.run(campaign, prompt="Block in provider."))

    assert worker.cancelled
    assert outcome.status is ToolLoopStatus.BUDGET_EXHAUSTED
    assert verify_run_integrity(outcome.run_path).valid


def test_shared_secret_broker_keeps_concurrent_tool_loop_runs_isolated(
    tmp_path: Path,
) -> None:
    async def execute() -> None:
        secrets = SecretBroker()
        secrets.register(_registration().secret_ref, "loop-provider-secret")
        first_worker = BlockingLoopWorker()
        first_runner = _tool_loop_runner_with_shared_secrets(
            tmp_path,
            first_worker,
            secrets,
        )
        second_runner = _tool_loop_runner_with_shared_secrets(
            tmp_path,
            LoopWorker(),
            secrets,
        )
        first_cancellation = ExecutionCancellationContext()
        first_execution = asyncio.create_task(
            first_runner.run(
                tool_loop_campaign(),
                prompt="Keep the first provider request in flight.",
                cancellation=first_cancellation,
            )
        )
        await asyncio.wait_for(first_worker.started.wait(), timeout=1)
        first_binding = first_cancellation.binding
        assert first_binding is not None
        first_scope = secrets.snapshot_scope(first_binding.run_id)
        assert len(first_scope) == 1
        assert first_scope[0]["status"] == SecretLeaseStatus.ACTIVE.value

        second_cancellation = ExecutionCancellationContext()
        second_cancellation.cancel(
            CancellationKind.RUN_CANCELLED,
            "Cancel only the second Run",
        )
        with pytest.raises(asyncio.CancelledError):
            await second_runner.run(
                tool_loop_campaign(),
                prompt="Do not dispatch the second provider request.",
                cancellation=second_cancellation,
            )

        second_binding = second_cancellation.binding
        assert second_binding is not None
        assert secrets.snapshot_scope(second_binding.run_id) == []
        assert json.loads((second_binding.path / "secrets.json").read_text(encoding="utf-8")) == []
        first_scope_after_second_cancel = secrets.snapshot_scope(first_binding.run_id)
        assert len(first_scope_after_second_cancel) == 1
        assert first_scope_after_second_cancel[0]["status"] == SecretLeaseStatus.ACTIVE.value
        assert verify_run_integrity(second_binding.path).valid

        first_cancellation.cancel(
            CancellationKind.RUN_CANCELLED,
            "Finish the first Run",
        )
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(first_execution, timeout=1)
        first_scope_after_own_cancel = secrets.snapshot_scope(first_binding.run_id)
        assert len(first_scope_after_own_cancel) == 1
        assert first_scope_after_own_cancel[0]["status"] == SecretLeaseStatus.REVOKED.value
        persisted_first = json.loads(
            (first_binding.path / "secrets.json").read_text(encoding="utf-8")
        )
        assert [item["lease_id"] for item in persisted_first] == [
            first_scope_after_own_cancel[0]["lease_id"]
        ]
        assert verify_run_integrity(first_binding.path).valid

    asyncio.run(execute())


def test_local_planner_failure_terminalizes_started_run(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))

    with pytest.raises(RuntimeError, match="planner failed"):
        asyncio.run(_local_runner(tmp_path, _FailingPlanner()).run(campaign))

    run_path = next((tmp_path / campaign.metadata.name).glob("run_*"))
    state = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    assert state["status"] == "failed"
    assert state["stage"] == "planning"
    assert verify_run_integrity(run_path).valid


def test_multi_agent_budget_preflight_does_not_create_run(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    mismatched = BudgetController(
        campaign.spec.budgets.model_copy(
            update={"max_tool_calls": campaign.spec.budgets.max_tool_calls + 1}
        )
    )

    with pytest.raises(ValueError, match="shared budget"):
        asyncio.run(runner.run(campaign, budget=mismatched))

    campaign_root = tmp_path / campaign.metadata.name
    assert not campaign_root.exists() or not list(campaign_root.glob("run_*"))


def test_reporter_failure_has_one_terminal_supervisor_transition(tmp_path: Path) -> None:
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

    outcome = asyncio.run(runner.run(orchestration_campaign()))
    supervisor = next(agent for agent in outcome.agents if agent.role is AgentRole.SUPERVISOR)
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    transitions = [
        event["event_type"]
        for event in events
        if event["payload"].get("agentId") == supervisor.agent_id
        and event["event_type"] in {"agent.cancelled", "agent.failed"}
    ]
    assert outcome.status is RunStatus.FAILED
    assert transitions == ["agent.failed"]


def test_typed_candidate_assessment_binds_exact_claim_not_legacy_similarity(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    target = campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(
        target=target,
        evidence=[evidence],
        finding_id="trusted_candidate",
        validated=False,
    ).model_copy(
        update={
            "title": "Exact trusted claim A",
            "summary": "Sensitive behavior A occurred.",
            "reproduction": ["Reproduce behavior A."],
        }
    )
    candidate = _admitted_candidate(claim)
    unrelated_legacy = claim.model_copy(
        update={
            "finding_id": "unrelated_validator_claim",
            "title": "Different claim B",
            "summary": "Different behavior B occurred.",
            "reproduction": ["Reproduce behavior B."],
            "validated": True,
        }
    )
    assessment = CandidateAssessment(
        candidate_id=candidate.candidate_id,
        claim_digest=candidate_claim_digest(candidate),
        supports_claim=True,
        reason_code=ValidationReasonCode.VALIDATOR_CONFIRMED,
        rationale="The exact Candidate claim was independently supported.",
        supporting_evidence=[evidence],
    )

    validation = validate_findings(
        campaign,
        [result],
        [unrelated_legacy],
        store,
        "agent:validator:1",
        admitted_candidates=[candidate],
        producer_authoritative_request_claims=_candidate_authorities([candidate]),
        validator_assessments=[assessment],
    )
    decision = validation.decisions[0]
    typed = next(
        check
        for check in decision.checks
        if check.check_id == "candidate-bound-validator-assessment"
    )
    assert typed.status is ValidationCheckStatus.PASS
    assert _semantic_supported(decision)

    legacy_store = RunStore.create(tmp_path, campaign.metadata.name)
    legacy_result, legacy_evidence = _gateway_result(legacy_store, target=target)
    legacy_candidate = _admitted_candidate(claim.model_copy(update={"evidence": [legacy_evidence]}))
    legacy_claim = unrelated_legacy.model_copy(update={"evidence": [legacy_evidence]})
    legacy_validation = validate_findings(
        campaign,
        [legacy_result],
        [legacy_claim],
        legacy_store,
        "agent:validator:1",
        admitted_candidates=[legacy_candidate],
        producer_authoritative_request_claims=_candidate_authorities([legacy_candidate]),
    )
    assert not _semantic_supported(legacy_validation.decisions[0])


def test_typed_candidate_assessment_rejects_wrong_claim_digest(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    target = campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(target=target, evidence=[evidence], validated=False)
    candidate = _admitted_candidate(claim)
    assessment = CandidateAssessment(
        candidate_id=candidate.candidate_id,
        claim_digest="0" * 64,
        supports_claim=True,
        reason_code=ValidationReasonCode.VALIDATOR_CONFIRMED,
        rationale="This digest does not belong to the Candidate.",
        supporting_evidence=[evidence],
    )

    with pytest.raises(ValueError, match="claim digest"):
        validate_findings(
            campaign,
            [result],
            [],
            store,
            "agent:validator:1",
            admitted_candidates=[candidate],
            producer_authoritative_request_claims=_candidate_authorities([candidate]),
            validator_assessments=[assessment],
        )


def test_confirmation_projection_recovers_after_event_append_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, batch = _create_kisa_source_and_replays(tmp_path)
    replay_paths = [result.run_path for result in batch.verified_results.values()]
    real_fsync_file = confirmation_module._fsync_file
    failure_injected = False

    def fail_after_confirmation_event(path: Path) -> None:
        nonlocal failure_injected
        if path.name == "events.jsonl" and not failure_injected:
            failure_injected = True
            raise RuntimeError("injected post-event confirmation crash")
        real_fsync_file(path)

    decided_at = datetime.now(UTC) + timedelta(seconds=1)
    monkeypatch.setattr(confirmation_module, "_fsync_file", fail_after_confirmation_event)
    with pytest.raises(RuntimeError, match="post-event"):
        apply_confirmed_gate(
            source_run_path=source.run_path,
            replay_run_paths=replay_paths,
            tickets=batch.tickets,
            decided_at=decided_at,
        )

    assert failure_injected
    assert (source.run_path / "validation/v1alpha1/transaction.json").is_file()
    with pytest.raises(RunIntegrityError, match="unsealed"):
        verify_run_integrity(source.run_path)

    monkeypatch.setattr(confirmation_module, "_fsync_file", real_fsync_file)
    recovered = apply_confirmed_gate(
        source_run_path=source.run_path,
        replay_run_paths=replay_paths,
        tickets=batch.tickets,
    )
    assert recovered.product_confirmed_findings == []
    assert all(
        decision.reason_codes == [ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING]
        for decision in recovered.validation.decisions
    )
    assert verify_run_integrity(source.run_path).valid

    repeated = apply_confirmed_gate(
        source_run_path=source.run_path,
        replay_run_paths=replay_paths,
        tickets=batch.tickets,
    )
    assert repeated == recovered


def test_confirmation_projection_serializes_concurrent_writers(tmp_path: Path) -> None:
    source, batch = _create_kisa_source_and_replays(tmp_path)
    replay_paths = [result.run_path for result in batch.verified_results.values()]
    decided_at = datetime.now(UTC) + timedelta(seconds=1)

    def apply_projection():
        return apply_confirmed_gate(
            source_run_path=source.run_path,
            replay_run_paths=replay_paths,
            tickets=batch.tickets,
            decided_at=decided_at,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        snapshots = list(executor.map(lambda _ordinal: apply_projection(), range(2)))

    assert snapshots[0] == snapshots[1]
    assert snapshots[0].product_confirmed_findings == []
    verification = verify_run_integrity(source.run_path)
    assert verification.valid
    events = [
        json.loads(line)
        for line in (source.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert (
        sum(event["event_type"] == "validation.confirmation-projection.created" for event in events)
        == 1
    )


def test_completed_confirmation_retry_requires_the_exact_replay_set(tmp_path: Path) -> None:
    source, batch = _create_kisa_source_and_replays(tmp_path)
    replay_paths = [result.run_path for result in batch.verified_results.values()]
    assert len(replay_paths) > 1
    apply_confirmed_gate(
        source_run_path=source.run_path,
        replay_run_paths=replay_paths,
        tickets=batch.tickets,
    )

    with pytest.raises(ValueError, match="different inputs"):
        apply_confirmed_gate(
            source_run_path=source.run_path,
            replay_run_paths=replay_paths[:-1],
            tickets=batch.tickets,
        )


def test_confirmation_projection_keeps_private_permissions_and_escapes_markdown(
    tmp_path: Path,
) -> None:
    source, batch = _create_kisa_source_and_replays(tmp_path)
    replay_paths = [result.run_path for result in batch.verified_results.values()]
    snapshot = apply_confirmed_gate(
        source_run_path=source.run_path,
        replay_run_paths=replay_paths,
        tickets=batch.tickets,
    )

    for directory in (
        source.run_path / "validation",
        source.run_path / "validation" / "v1alpha1",
        source.run_path.parent / ".pajin-confirmation-locks",
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for artifact in (
        source.run_path / "events.jsonl",
        source.run_path / "validation" / "v1alpha1" / "report.md",
        source.run_path / "validation" / "v1alpha1" / "transaction.json",
    ):
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600

    replayed_index = next(
        index
        for index, candidate in enumerate(snapshot.validation.candidates)
        if snapshot.validation.decisions[index].replay_lineage
    )
    candidate = snapshot.validation.candidates[replayed_index]
    injected_claim = candidate.claim.model_copy(
        update={"title": "trusted\ud800\n## forged <script>alert(1)</script>"}
    )
    candidates = list(snapshot.validation.candidates)
    candidates[replayed_index] = candidate.model_copy(update={"claim": injected_claim})
    report = _render_confirmation_report(
        snapshot.index,
        snapshot.validation.model_copy(update={"candidates": candidates}),
    )

    assert "\n## forged" not in report
    assert "&lt;script&gt;" in report
    assert "\ud800" not in report
