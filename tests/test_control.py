from pathlib import Path

import pytest

import pajin.runtime.control as control_module
from pajin.domain.manifest import load_manifest
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.runtime.control import BudgetController, BudgetExceeded


def test_agent_depth_and_cost_budgets_fail_closed() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budget = BudgetController(campaign.spec.budgets)

    budget.reserve_agent(depth=0)
    with pytest.raises(BudgetExceeded, match="spawn depth"):
        budget.reserve_agent(depth=2)
    with pytest.raises(BudgetExceeded, match="cost"):
        budget.record_cost(0.01)


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
