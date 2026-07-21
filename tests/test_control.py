import os
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


def test_model_usage_reservations_bound_concurrent_calls_and_settle_to_actual() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budgets = campaign.spec.budgets.model_copy(update={"max_model_tokens": 10, "max_cost_usd": 1})
    budget = BudgetController(budgets)

    first = budget.reserve_model_usage(prompt_tokens=2, completion_tokens=2, cost_usd=0.4)
    second = budget.reserve_model_usage(prompt_tokens=1, completion_tokens=1, cost_usd=0.1)

    in_flight_snapshot = budget.snapshot()
    assert in_flight_snapshot["toolCalls"] == 2
    assert in_flight_snapshot["modelCalls"] == 2
    assert in_flight_snapshot["modelTokens"] == 6
    assert in_flight_snapshot["costUsd"] == pytest.approx(0.5)
    with pytest.raises(BudgetExceeded, match="model-token"):
        budget.reserve_model_usage(prompt_tokens=3, completion_tokens=2, cost_usd=0.1)
    with pytest.raises(BudgetExceeded, match="cost"):
        budget.reserve_model_usage(prompt_tokens=0, completion_tokens=0, cost_usd=0.6)
    assert budget.snapshot()["toolCalls"] == 2
    assert budget.snapshot()["modelCalls"] == 2

    restored_in_flight = BudgetController(budgets)
    restored_in_flight.restore_usage(
        agent_count=0,
        tool_calls=int(in_flight_snapshot["toolCalls"]),
        model_calls=int(in_flight_snapshot["modelCalls"]),
        model_prompt_tokens=int(in_flight_snapshot["modelPromptTokens"]),
        model_completion_tokens=int(in_flight_snapshot["modelCompletionTokens"]),
        cost_usd=float(in_flight_snapshot["costUsd"]),
        elapsed_seconds=0,
    )
    assert restored_in_flight.snapshot()["modelTokens"] == 6
    with pytest.raises(BudgetExceeded, match="model-token"):
        restored_in_flight.reserve_model_usage(
            prompt_tokens=3,
            completion_tokens=2,
            cost_usd=0.1,
        )

    budget.settle_model_usage(
        first,
        prompt_tokens=1,
        completion_tokens=1,
        cost_usd=0.2,
    )
    budget.commit_model_usage_reservation(second)

    snapshot = budget.snapshot()
    assert snapshot["modelPromptTokens"] == 2
    assert snapshot["modelCompletionTokens"] == 2
    assert snapshot["modelTokens"] == 4
    assert snapshot["costUsd"] == pytest.approx(0.3)
    assert snapshot["toolCalls"] == 2
    assert snapshot["modelCalls"] == 2


def test_model_usage_reservation_keeps_bound_when_actual_exceeds_it() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budgets = campaign.spec.budgets.model_copy(update={"max_model_tokens": 10, "max_cost_usd": 1})
    budget = BudgetController(budgets)
    reservation = budget.reserve_model_usage(
        prompt_tokens=2,
        completion_tokens=2,
        cost_usd=0.4,
    )

    with pytest.raises(BudgetExceeded, match="reservation"):
        budget.settle_model_usage(
            reservation,
            prompt_tokens=3,
            completion_tokens=2,
            cost_usd=0.5,
        )

    assert budget.snapshot()["modelTokens"] == 4
    assert budget.snapshot()["costUsd"] == pytest.approx(0.4)
    assert budget.snapshot()["toolCalls"] == 1
    assert budget.snapshot()["modelCalls"] == 1
    with pytest.raises(ValueError, match="not active"):
        budget.release_model_usage_reservation(reservation)


def test_model_usage_reservation_releases_only_proven_unused_capacity() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budget = BudgetController(campaign.spec.budgets)
    reservation = budget.reserve_model_usage(
        prompt_tokens=20,
        completion_tokens=10,
        cost_usd=0,
    )

    budget.release_model_usage_reservation(reservation)

    assert budget.snapshot()["modelTokens"] == 0
    assert budget.snapshot()["costUsd"] == 0
    assert budget.snapshot()["toolCalls"] == 0
    assert budget.snapshot()["modelCalls"] == 0


@pytest.mark.parametrize("cost", [float("nan"), float("inf"), float("-inf")])
def test_budget_rejects_non_finite_costs_without_poisoning_state(cost: float) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budget = BudgetController(campaign.spec.budgets)

    with pytest.raises(ValueError, match="finite"):
        budget.record_cost(cost)
    with pytest.raises(ValueError, match="finite"):
        budget.reserve_model_usage(
            prompt_tokens=1,
            completion_tokens=1,
            cost_usd=cost,
        )

    assert budget.snapshot()["costUsd"] == 0
    assert budget.snapshot()["toolCalls"] == 0
    assert budget.snapshot()["modelCalls"] == 0


@pytest.mark.parametrize(
    ("budget_updates", "error"),
    [
        ({"max_tool_calls": 1, "max_model_calls": 2}, "tool-call"),
        ({"max_tool_calls": 2, "max_model_calls": 1}, "model-call"),
    ],
)
def test_model_usage_reservation_atomically_bounds_call_counts(
    budget_updates: dict[str, int],
    error: str,
) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budgets = campaign.spec.budgets.model_copy(
        update={**budget_updates, "max_model_tokens": 100, "max_cost_usd": 1}
    )
    budget = BudgetController(budgets)
    budget.reserve_model_usage(prompt_tokens=1, completion_tokens=1, cost_usd=0.1)

    with pytest.raises(BudgetExceeded, match=error):
        budget.reserve_model_usage(prompt_tokens=1, completion_tokens=1, cost_usd=0.1)

    assert budget.snapshot()["toolCalls"] == 1
    assert budget.snapshot()["modelCalls"] == 1
    assert budget.snapshot()["modelTokens"] == 2
    assert budget.snapshot()["costUsd"] == pytest.approx(0.1)


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


def test_kill_switch_reads_a_small_regular_signal_reason(tmp_path: Path) -> None:
    signal_path = tmp_path / "stop.signal"
    signal_path.write_text("operator requested shutdown\n", encoding="utf-8")

    kill_switch = control_module.KillSwitch(signal_path)

    assert kill_switch.poll()
    assert kill_switch.reason == "operator requested shutdown"
    assert kill_switch.snapshot().source == "signal-file"


def test_kill_switch_does_not_use_unbounded_path_read_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signal_path = tmp_path / "stop.signal"
    signal_path.write_text("stop", encoding="utf-8")
    kill_switch = control_module.KillSwitch(signal_path)

    def fail_unbounded_read(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("kill-switch must not use Path.read_text")

    monkeypatch.setattr(Path, "read_text", fail_unbounded_read)

    assert kill_switch.poll()


def test_kill_switch_does_not_disclose_symlink_target(tmp_path: Path) -> None:
    secret_path = tmp_path / "secret.txt"
    secret = "secret-token-that-must-not-become-a-cancellation-reason"
    secret_path.write_text(secret, encoding="utf-8")
    signal_path = tmp_path / "stop.signal"
    signal_path.symlink_to(secret_path)

    kill_switch = control_module.KillSwitch(signal_path)

    assert kill_switch.poll()
    assert kill_switch.reason == "kill-switch signal file detected"
    assert secret not in (kill_switch.reason or "")


def test_kill_switch_does_not_disclose_hard_link_target(tmp_path: Path) -> None:
    secret_path = tmp_path / "secret.txt"
    secret = "hard-linked-secret-that-must-not-be-disclosed"
    secret_path.write_text(secret, encoding="utf-8")
    signal_path = tmp_path / "stop.signal"
    try:
        os.link(secret_path, signal_path)
    except OSError as exc:  # pragma: no cover - platform/filesystem dependent
        pytest.skip(f"hard links are unavailable: {exc}")

    kill_switch = control_module.KillSwitch(signal_path)

    assert kill_switch.poll()
    assert kill_switch.reason == "kill-switch signal file detected"
    assert secret not in (kill_switch.reason or "")


def test_kill_switch_does_not_persist_oversized_signal_content(tmp_path: Path) -> None:
    signal_path = tmp_path / "stop.signal"
    signal_path.write_bytes(b"attacker-controlled-reason:" + (b"x" * 8_192))

    kill_switch = control_module.KillSwitch(signal_path)

    assert kill_switch.poll()
    assert kill_switch.reason == "kill-switch signal file detected"
