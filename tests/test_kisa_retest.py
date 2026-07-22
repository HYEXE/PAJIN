from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from kisa_control_plane_support import externally_attested_confirmation_fixture

import pajin.workflow.validation_artifacts as validation_artifacts
from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.orchestration import RunStatus
from pajin.domain.replay import ReplayOracleVerdict, ReplayPurpose
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.replay import (
    KISAReplayBatchOutcome,
    KISAReplayCoordinator,
    KISARetestReplayCoordinator,
)
from pajin.modes.ai_redteam.retest import (
    KISARetestService,
    RegressionStatus,
    RetestFindingResult,
    RetestFindingStatus,
)
from pajin.modes.ai_redteam.runtime import (
    KISAPlannerRuntime,
    KISARetestPlannerRuntime,
    KISAValidatorRuntime,
)
from pajin.modes.ai_redteam.service import KISAModePack
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController
from pajin.runtime.store import (
    RunIntegrityError,
    load_verified_run_snapshot,
    verify_run_integrity,
)
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.ai import (
    AI_CHAT_PROXY_RECEIPT_VERSION,
    AIChatProbeTool,
    AIChatRegressionTool,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.confirmation import apply_confirmed_gate
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


class ProfileAIWorker:
    """Return transcript-derived vulnerable, hardened, or mixed KISA observations."""

    def __init__(
        self,
        *,
        vulnerable: bool | list[bool],
        regression_passed: bool = True,
        regression_claimed: bool | None = None,
        regression_worker_failures: int = 0,
    ) -> None:
        self._vulnerable = vulnerable
        self._regression_passed = regression_passed
        self._regression_claimed = regression_claimed
        self._regression_worker_failures = regression_worker_failures
        self._regression_calls = 0
        self._attack_calls = 0

    def _attack_profile(self) -> bool:
        if isinstance(self._vulnerable, bool):
            return self._vulnerable
        value = self._vulnerable[self._attack_calls]
        self._attack_calls += 1
        return value

    async def run(self, job: WorkerJob) -> WorkerResult:
        started_at = datetime.now(UTC)
        assert job.command == ["ai-chat-probe"]
        assert job.network is NetworkMode.EGRESS_PROXY
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        purpose = probe.get("purpose", "attack")
        if purpose == "regression":
            self._regression_calls += 1
            if self._regression_calls <= self._regression_worker_failures:
                return WorkerResult(
                    execution_id=job.execution_id,
                    backend="profile-test",
                    status=WorkerStatus.FAILED,
                    exit_code=1,
                    stderr="profile-controlled transient failure",
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )
        attack_vulnerable = self._attack_profile() if purpose == "attack" else False
        checks_should_match = attack_vulnerable if purpose == "attack" else self._regression_passed
        reported_match = (
            self._regression_claimed
            if purpose == "regression" and self._regression_claimed is not None
            else checks_should_match
        )
        hardened_responses = {
            "kisa.model.system-prompt-disclosure": (
                ("I cannot reveal internal instructions.", True, "system-prompt-protection"),
            ),
            "kisa.model.jailbreak-policy-bypass": (
                ("The requested action is not allowed.", True, "policy-enforcement"),
            ),
            "kisa.agent.memory-poisoning-persistence": (
                (
                    "Untrusted content was not stored as trusted memory.",
                    True,
                    "untrusted-memory-write",
                ),
                ("No trusted directive is stored.", False, None),
            ),
        }
        turns = []
        for index, turn in enumerate(probe["turns"]):
            markers = [
                check["value"]
                for check in probe["checks"]
                if checks_should_match
                and check["turn"] == index
                and check["kind"] == "response-contains"
            ]
            hardened = purpose == "attack" and not attack_vulnerable
            if hardened:
                content, blocked, reason = hardened_responses[probe["scenario_id"]][index]
            else:
                content = " ".join(["safe normal response", *markers])
                blocked = False
                reason = None
            turns.append(
                {
                    "index": index,
                    "name": turn["name"],
                    "request": {
                        "sessionId": probe["session_id"],
                        "messages": turn["messages"],
                    },
                    "response": {
                        "sessionId": probe["session_id"],
                        "message": {"role": "assistant", "content": content},
                        "toolCalls": [],
                        "safety": {"blocked": blocked, "reason": reason},
                        "memoryWrites": [],
                        "model": "pajin-deterministic-lab-v1" if hardened else None,
                    },
                    "responseLatencySeconds": 0.01,
                }
            )
        checks = [
            {
                "checkId": check["check_id"],
                "kind": check["kind"],
                "turn": check["turn"],
                "matched": reported_match,
                "sensitive": check["sensitive"],
            }
            for check in probe["checks"]
        ]
        output = {
            "target": payload["target"],
            "scenarioId": probe["scenario_id"],
            "threatClass": probe["threat_class"],
            "sessionId": probe["session_id"],
            "purpose": purpose,
            "vulnerable": attack_vulnerable if purpose == "attack" else False,
            "observation": "profile-controlled test observation",
            "turns": turns,
            "checks": checks,
            "sensitiveExposureCount": sum(
                check["matched"] and check["sensitive"] for check in checks
            ),
            "meanResponseLatencySeconds": 0.01,
            "regressionPassed": (reported_match if purpose == "regression" else None),
            "networkPerformed": True,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="profile-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _proxy_receipt_log(job: WorkerJob, worker_result: WorkerResult) -> str:
    payload = json.loads(job.stdin)
    output = json.loads(worker_result.stdout)
    probe = payload["probe"]
    target_value = urlsplit(payload["target"])
    target = urlunsplit(
        (
            target_value.scheme,
            target_value.netloc,
            target_value.path,
            "<redacted>" if target_value.query else "",
            "",
        )
    )
    events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
    for index, (turn, observed) in enumerate(zip(probe["turns"], output["turns"], strict=True)):
        request_body = {
            "sessionId": probe["session_id"],
            "messages": turn["messages"],
            "metadata": {"scenarioId": probe["scenario_id"], "turn": index},
        }
        events.append(
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": index + 1,
                    "method": "POST",
                    "target": target,
                    "targetSha256": sha256(payload["target"].encode("utf-8")).hexdigest(),
                    "address": "172.17.0.1",
                    "status": 200,
                    "requestJsonSha256": _canonical_digest(request_body),
                    "responseBodySha256": _canonical_digest(observed["response"]),
                    "responseJsonSha256": _canonical_digest(observed["response"]),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events)


def _trusted_docker_backend(worker: ProfileAIWorker) -> DockerWorkerBackend:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})

    async def run(
        job: WorkerJob,
        *,
        secrets: object = None,
    ) -> WorkerResult:
        del secrets
        result = await worker.run(job)
        if result.status is not WorkerStatus.SUCCEEDED:
            return result.model_copy(update={"backend": "docker"})
        return result.model_copy(
            update={
                "backend": "docker",
                "network_log": _proxy_receipt_log(job, result),
            }
        )

    backend.run = run  # type: ignore[method-assign]
    return backend


def _campaign():
    return load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))


def _multi_target_campaign():
    campaign = _campaign()
    first = campaign.spec.targets[0]
    second_endpoint = "http://host.docker.internal:8766/v1/chat"
    second = first.model_copy(
        update={
            "id": "pajin-second-ai-lab",
            "endpoint": second_endpoint,
        }
    )
    scope = campaign.spec.scope.model_copy(
        update={"allow": [*campaign.spec.scope.allow, second_endpoint]}
    )
    budgets = campaign.spec.budgets.model_copy(update={"max_agents": 30, "max_tool_calls": 40})
    spec = campaign.spec.model_copy(
        update={
            "targets": [first, second],
            "scope": scope,
            "budgets": budgets,
        }
    )
    return campaign.model_copy(update={"spec": spec})


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(AIChatProbeTool())
    registry.register(AIChatRegressionTool())
    return registry


def _runner(*, planner, worker, output_root: Path, tools: ToolRegistry):
    return MultiAgentCampaignRunner(
        planner=planner,
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=PolicyEngine(),
        worker=worker,
        output_root=output_root,
    )


def _confirmed_baseline(tmp_path: Path, *, campaign=None):
    campaign = campaign or _campaign()
    thresholds = EvaluationThresholds(repetitions=2)
    tools = _registry()
    worker = ProfileAIWorker(vulnerable=True)
    execution_backend = _trusted_docker_backend(worker)
    policy = PolicyEngine()
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=policy,
        worker=execution_backend,
        output_root=tmp_path / "baseline",
    )
    coordinator = KISAReplayCoordinator(
        tools=tools,
        policy=policy,
        worker=execution_backend,
        output_root=tmp_path / "baseline-replay",
        repetitions=2,
        required_successes=2,
    )

    async def execute():
        outcome = await runner.run(campaign, budget=budget, rate_limits=rate_limits)
        batch = await coordinator.reproduce(
            campaign,
            outcome.run_path,
            budget=budget,
            rate_limits=rate_limits,
        )
        return outcome, batch

    outcome, batch = asyncio.run(execute())
    with externally_attested_confirmation_fixture():
        confirmation = apply_confirmed_gate(
            source_run_path=outcome.run_path,
            replay_run_paths=[result.run_path for result in batch.verified_results.values()],
            tickets=batch.tickets,
        )
    outcome = outcome.model_copy(
        update={
            "validation": confirmation.validation,
            "findings": confirmation.product_confirmed_findings,
        }
    )
    KISAModePack(thresholds=thresholds).evaluate(campaign, outcome, batch)
    return outcome


def _legacy_baseline(tmp_path: Path):
    campaign = _campaign()
    thresholds = EvaluationThresholds(repetitions=2)
    tools = _registry()
    outcome = asyncio.run(
        _runner(
            planner=KISAPlannerRuntime(thresholds=thresholds),
            worker=_trusted_docker_backend(ProfileAIWorker(vulnerable=True)),
            output_root=tmp_path / "legacy",
            tools=tools,
        ).run(campaign)
    )
    KISAModePack(thresholds=thresholds).evaluate(campaign, outcome)
    return outcome


def _parent_retest(
    tmp_path: Path,
    *,
    regression_passed: bool = True,
    regression_claimed: bool | None = None,
    regression_worker_failures: int = 0,
    raw_attack: bool = False,
    campaign=None,
    planner=None,
    trusted_receipts: bool = True,
):
    campaign = campaign or _campaign()
    thresholds = EvaluationThresholds(repetitions=2)
    tools = _registry()
    worker = ProfileAIWorker(
        vulnerable=False,
        regression_passed=regression_passed,
        regression_claimed=regression_claimed,
        regression_worker_failures=regression_worker_failures,
    )
    execution_backend = _trusted_docker_backend(worker) if trusted_receipts else worker
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    planner = planner or (
        KISAPlannerRuntime(thresholds=thresholds)
        if raw_attack
        else KISARetestPlannerRuntime(thresholds=thresholds)
    )
    outcome = asyncio.run(
        _runner(
            planner=planner,
            worker=execution_backend,
            output_root=tmp_path / "parent-retest",
            tools=tools,
        ).run(campaign, budget=budget, rate_limits=rate_limits)
    )
    return outcome, tools, budget, rate_limits


def _replay_retest(
    tmp_path: Path,
    *,
    baseline,
    retest,
    tools: ToolRegistry,
    budget: BudgetController,
    rate_limits: RequestRateLimitLedger,
    vulnerable: bool | list[bool],
    trusted_receipts: bool = True,
):
    service = KISARetestService()
    contexts = service.build_retest_contexts(baseline.run_path, retest.run_path)
    worker = ProfileAIWorker(vulnerable=vulnerable)
    execution_backend = _trusted_docker_backend(worker) if trusted_receipts else worker
    coordinator = KISARetestReplayCoordinator(
        tools=tools,
        policy=PolicyEngine(),
        worker=execution_backend,
        output_root=tmp_path / "retest-replay",
        repetitions=2,
    )
    return asyncio.run(
        coordinator.reproduce(
            _campaign(),
            baseline.run_path,
            retest.run_path,
            contexts=contexts,
            budget=budget,
            rate_limits=rate_limits,
        )
    )


def test_retest_planner_generates_only_normal_function_regression_tasks() -> None:
    plan = asyncio.run(KISARetestPlannerRuntime().plan(_campaign()))

    assert len(plan.steps) == 2
    assert all(step.request.tool_id == "ai.normal-probe" for step in plan.steps)
    assert all(step.scenario_id is None for step in plan.steps)


def test_retest_rejects_validation_from_an_intermediate_run_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    authority = load_verified_run_snapshot(baseline.run_path)
    phase_b_verification = authority.verification.model_copy(update={"root_digest": "0" * 64})
    original_artifact_load = validation_artifacts.load_verified_run_artifacts
    phase_b_initial_loads = 0

    def phase_b_initial(*args, **kwargs):
        nonlocal phase_b_initial_loads
        phase_b_initial_loads += 1
        return replace(authority, verification=phase_b_verification)

    def phase_b_artifacts(*args, **kwargs):
        snapshot = original_artifact_load(*args, **kwargs)
        return replace(snapshot, verification=phase_b_verification)

    monkeypatch.setattr(
        validation_artifacts,
        "load_verified_run_snapshot",
        phase_b_initial,
    )
    monkeypatch.setattr(
        validation_artifacts,
        "load_verified_run_artifacts",
        phase_b_artifacts,
    )

    with pytest.raises(ValueError, match="validation Run changed"):
        KISARetestService().create_remediation_plan(baseline.run_path)
    assert phase_b_initial_loads == 0
    assert not (baseline.run_path / "remediation-plan.json").exists()


def test_regression_uses_each_planned_tasks_terminal_retry_evidence(
    tmp_path: Path,
) -> None:
    retest, *_ = _parent_retest(tmp_path, regression_worker_failures=1)
    service = KISARetestService()
    snapshot = service._load_snapshot(retest.run_path)

    regression = service._regression_result(snapshot)

    assert regression.status is RegressionStatus.PASS
    assert sorted(item.attempt for item in regression.evidence) == [1, 2]
    assert len(regression.evidence) == 2
    assert all(item.trusted_passed for item in regression.evidence)
    assert any(item.request_id.endswith("_attempt2") for item in regression.evidence)


def test_regression_is_not_measured_when_parent_plan_omits_one_target(
    tmp_path: Path,
) -> None:
    campaign = _multi_target_campaign()

    class FirstTargetOnlyRetestPlanner(KISARetestPlannerRuntime):
        async def plan(self, campaign):
            plan = await super().plan(campaign)
            first_target = campaign.spec.targets[0].endpoint
            return plan.model_copy(
                update={
                    "steps": [step for step in plan.steps if step.request.target == first_target]
                }
            )

    baseline = _confirmed_baseline(tmp_path, campaign=campaign)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, *_ = _parent_retest(
        tmp_path,
        campaign=campaign,
        planner=FirstTargetOnlyRetestPlanner(thresholds=EvaluationThresholds(repetitions=2)),
    )

    result = service.compare(baseline.run_path, retest.run_path)

    assert result.assessment.regression.status is RegressionStatus.NOT_MEASURED
    assert result.assessment.regression.expected_targets == sorted(
        target.endpoint for target in campaign.spec.targets
    )
    assert {evidence.target for evidence in result.assessment.regression.evidence} == {
        campaign.spec.targets[0].endpoint
    }


def test_semantic_only_baseline_is_rejected_before_remediation_plan(tmp_path: Path) -> None:
    baseline = _legacy_baseline(tmp_path)

    with pytest.raises(ValueError, match="VERIFIED_INDEPENDENT_REPLAY"):
        KISARetestService().create_remediation_plan(baseline.run_path)


def test_confirmed_baseline_requires_remediation_plan_before_comparison(
    tmp_path: Path,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    retest, *_ = _parent_retest(tmp_path)

    with pytest.raises(ValueError, match="must be created before"):
        KISARetestService().compare(baseline.run_path, retest.run_path)


def test_raw_non_vulnerable_results_without_receipts_remain_inconclusive(
    tmp_path: Path,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, *_ = _parent_retest(tmp_path, raw_attack=True)

    result = service.compare(baseline.run_path, retest.run_path)

    assert result.assessment.summary.fixed == 0
    assert result.assessment.summary.inconclusive == 3
    assert all(
        item.status is RetestFindingStatus.INCONCLUSIVE
        and item.oracle_verdict is None
        and item.replay_lineage is None
        for item in result.assessment.finding_results
    )


def test_hardened_worker_replay_remains_inconclusive_without_external_attestation(
    tmp_path: Path,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    plan = service.create_remediation_plan(baseline.run_path)
    baseline_root = verify_run_integrity(baseline.run_path).root_digest
    retest, tools, budget, rate_limits = _parent_retest(tmp_path)
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=False,
    )
    rebuilt = KISAReplayBatchOutcome.from_verified_retest_results(
        baseline.run_path,
        retest.run_path,
        [result.run_path for result in batch.verified_results.values()],
        tickets=batch.tickets,
        contexts=batch.contexts,
    )
    assert rebuilt.records == batch.records

    result = service.compare(baseline.run_path, retest.run_path, rebuilt)

    assert len(plan.actions) == 3
    assert result.assessment.summary.fixed == 0
    assert result.assessment.summary.still_vulnerable == 0
    assert result.assessment.summary.inconclusive == 3
    assert result.assessment.summary.regression is RegressionStatus.PASS
    assert all(
        item.status is RetestFindingStatus.INCONCLUSIVE
        and item.oracle_verdict is ReplayOracleVerdict.INCONCLUSIVE
        and item.replay_context is not None
        and item.replay_lineage is not None
        and item.all_replay_attempts_succeeded
        for item in result.assessment.finding_results
    )
    forged_fixed = result.assessment.finding_results[0].model_dump(mode="python")
    forged_fixed.update(
        {
            "status": RetestFindingStatus.FIXED,
            "oracle_verdict": ReplayOracleVerdict.CONTRADICTS,
            "all_replay_attempts_succeeded": True,
        }
    )
    with pytest.raises(ValueError, match="independently verifiable remediation attestation"):
        RetestFindingResult.model_validate(forged_fixed)
    assert {
        "remediation-plan.json",
        "kisa-retest.json",
        "kisa-retest-index.json",
        "kisa-checklist-overlay.json",
        "kisa-retest-report.md",
    } <= {path.name for path in retest.run_path.iterdir()}
    report = result.report_path.read_text(encoding="utf-8")
    assert "Replay Run:" in report
    assert "Replay requests:" in report
    assert "OracleResult:" in report
    assert "ReplayOutcome:" in report
    assert "Verification receipt seal:" in report
    assert "New threat discovery: **not assessed**" in report
    assert "fresh `pajin kisa-run`" in report
    assert all(
        evidence.request_id and evidence.target
        for evidence in result.assessment.regression.evidence
    )
    verify_run_integrity(retest.run_path)
    assert verify_run_integrity(baseline.run_path).root_digest == baseline_root


def test_kisa_retest_report_neutralizes_heading_list_table_and_html_injection(
    tmp_path: Path,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, tools, budget, rate_limits = _parent_retest(tmp_path)
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=False,
    )
    assessment = service.compare(baseline.run_path, retest.run_path, batch).assessment
    injected = "Visible\n\n## Forged Retest Section\n| forged | row |\n<script>x</script>\n```"
    actions = [
        assessment.remediation_actions[0].model_copy(
            update={
                "title": injected,
                "controls": [injected],
                "acceptance_criteria": [injected],
                "owner": injected,
            }
        ),
        *assessment.remediation_actions[1:],
    ]
    finding_results = [
        assessment.finding_results[0].model_copy(update={"threat_class": injected}),
        *assessment.finding_results[1:],
    ]
    regression = assessment.regression.model_copy(
        update={
            "evidence": [
                assessment.regression.evidence[0].model_copy(update={"target": injected}),
                *assessment.regression.evidence[1:],
            ]
        }
    )
    overlay = assessment.checklist_overlay.model_copy(
        update={
            "items": [
                assessment.checklist_overlay.items[0].model_copy(
                    update={"item_id": injected, "rationale": injected}
                ),
                *assessment.checklist_overlay.items[1:],
            ]
        }
    )
    injected_assessment = assessment.model_copy(
        update={
            "remediation_actions": actions,
            "finding_results": finding_results,
            "regression": regression,
            "checklist_overlay": overlay,
        }
    )

    report = service._render_report(injected_assessment)

    assert report.count("\n## Finding outcomes\n") == 1
    assert report.count("\n## Checklist overlay\n") == 1
    assert "\n## Forged Retest Section" not in report
    assert "\n| forged |" not in report
    assert "\n```" not in report
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "\\|" in report


def test_worker_only_profiles_cannot_mark_fixed_or_regression_pass(tmp_path: Path) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, _tools, _budget, _rate_limits = _parent_retest(
        tmp_path,
        trusted_receipts=False,
    )

    assert retest.status is RunStatus.FAILED
    assert retest.findings == []
    assert retest.validation.candidates == []
    assert retest.tool_results
    assert all(result.success is False for result in retest.tool_results)


def test_supporting_replay_receipts_mark_findings_still_vulnerable(
    tmp_path: Path,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, tools, budget, rate_limits = _parent_retest(tmp_path)
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=True,
    )

    result = service.compare(baseline.run_path, retest.run_path, batch)

    assert result.assessment.summary.fixed == 0
    assert result.assessment.summary.still_vulnerable == 3
    assert all(
        item.oracle_verdict is ReplayOracleVerdict.SUPPORTS
        for item in result.assessment.finding_results
    )


def test_mixed_replay_receipts_are_inconclusive(tmp_path: Path) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, tools, budget, rate_limits = _parent_retest(tmp_path)
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=[True, False, True, False, True, False],
    )

    result = service.compare(baseline.run_path, retest.run_path, batch)

    assert result.assessment.summary.fixed == 0
    assert result.assessment.summary.still_vulnerable == 0
    assert result.assessment.summary.inconclusive == 3
    assert all(
        item.oracle_verdict is ReplayOracleVerdict.INCONCLUSIVE
        for item in result.assessment.finding_results
    )


def test_security_status_is_independent_from_normal_regression(tmp_path: Path) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, tools, budget, rate_limits = _parent_retest(
        tmp_path,
        regression_passed=False,
        regression_claimed=True,
    )
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=False,
    )

    result = service.compare(baseline.run_path, retest.run_path, batch)

    assert result.assessment.summary.fixed == 0
    assert result.assessment.summary.inconclusive == 3
    assert result.assessment.regression.status is RegressionStatus.FAIL
    assert all(
        evidence.trusted_passed is False for evidence in result.assessment.regression.evidence
    )


def test_foreign_retest_context_is_rejected_before_status_projection(
    tmp_path: Path,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, tools, budget, rate_limits = _parent_retest(tmp_path)
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=False,
    )
    contexts = dict(batch.contexts)
    candidate_id = next(iter(contexts))
    contexts[candidate_id] = contexts[candidate_id].model_copy(
        update={"retest_source_root_digest": "f" * 64}
    )
    forged = replace(batch, contexts=contexts)

    with pytest.raises(ValueError, match="exact retest context"):
        service.compare(baseline.run_path, retest.run_path, forged)


def test_tampered_replay_receipt_is_a_hard_integrity_failure(tmp_path: Path) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, tools, budget, rate_limits = _parent_retest(tmp_path)
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=False,
    )
    replay = next(iter(batch.verified_results.values()))
    (replay.run_path / "replay/verification-receipt.json").unlink()

    with pytest.raises(RunIntegrityError, match="sealed Run artifact is missing"):
        service.compare(baseline.run_path, retest.run_path, batch)


def test_retest_batch_preserves_remediation_purpose_and_exact_context(
    tmp_path: Path,
) -> None:
    baseline = _confirmed_baseline(tmp_path)
    service = KISARetestService()
    service.create_remediation_plan(baseline.run_path)
    retest, tools, budget, rate_limits = _parent_retest(tmp_path)
    contexts = service.build_retest_contexts(baseline.run_path, retest.run_path)
    batch = _replay_retest(
        tmp_path,
        baseline=baseline,
        retest=retest,
        tools=tools,
        budget=budget,
        rate_limits=rate_limits,
        vulnerable=False,
    )

    assert batch.purpose is ReplayPurpose.REMEDIATION_RETEST
    assert dict(batch.contexts) == contexts
    assert all(record.retest_context == contexts[record.candidate_id] for record in batch.records)
