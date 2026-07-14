from pathlib import Path

import pytest

import pajin.runtime.control as control_module
from pajin.domain.manifest import load_manifest
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    CancellationCleanupStatus,
    CancellationKind,
    ExecutionCancellationContext,
)


def test_execution_cancellation_is_one_way_and_records_monotonic_cleanup() -> None:
    cancellation = ExecutionCancellationContext(
        job_id="job_" + "1" * 32,
        control_plane_run_id="run_" + "2" * 32,
    )

    assert cancellation.cancel(CancellationKind.RUN_CANCELLED, "operator fence observed")
    assert not cancellation.cancel(CancellationKind.LEASE_LOST, "later lease failure")
    cancellation.mark_cleanup_completed()
    cancellation.mark_executor_drained()

    snapshot = cancellation.snapshot()
    assert snapshot.kind is CancellationKind.RUN_CANCELLED
    assert snapshot.reason == "operator fence observed"
    assert snapshot.cleanup_status is CancellationCleanupStatus.QUIESCED
    assert snapshot.cleanup_completed_at is not None
    assert snapshot.executor_drained_at is not None
    assert snapshot.forced_at is None


def test_agent_depth_and_cost_budgets_fail_closed() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budget = BudgetController(campaign.spec.budgets)

    budget.reserve_agent(depth=0)
    with pytest.raises(BudgetExceeded, match="spawn depth"):
        budget.reserve_agent(depth=2)
    with pytest.raises(BudgetExceeded, match="cost"):
        budget.record_cost(0.01)


def test_model_call_and_token_budgets_are_measured_separately() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budgets = campaign.spec.budgets.model_copy(
        update={"max_model_calls": 1, "max_model_tokens": 5, "max_cost_usd": 1}
    )
    budget = BudgetController(budgets)

    budget.record_model_call()
    budget.record_model_usage(prompt_tokens=2, completion_tokens=3, cost_usd=0.25)

    assert budget.snapshot()["modelTokens"] == 5
    with pytest.raises(BudgetExceeded, match="model-call"):
        budget.check_model_call()
    with pytest.raises(BudgetExceeded, match="model-token"):
        budget.record_model_usage(prompt_tokens=1, completion_tokens=0, cost_usd=0)


def test_elapsed_duration_budget_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    readings = iter((0.0, 121.0))
    monkeypatch.setattr(control_module, "monotonic", lambda: next(readings))
    budget = BudgetController(campaign.spec.budgets)

    with pytest.raises(BudgetExceeded, match="duration"):
        budget.check_duration()


def test_capability_ledger_rejects_delegation_beyond_depth() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    ledger = CapabilityLedger(max_depth=0)
    root = ledger.issue_root(
        campaign,
        subject="agent:supervisor",
        tools=set(),
        targets=set(),
    )

    with pytest.raises(CapabilityError, match="depth"):
        ledger.delegate(
            root.grant_id,
            subject="agent:planner",
            tools=set(),
            targets=set(),
            max_risk_tier=root.max_risk_tier,
            max_calls=0,
        )
