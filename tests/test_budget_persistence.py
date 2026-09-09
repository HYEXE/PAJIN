from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.domain.models import Budgets, ToolResult
from pajin.policy.engine import PolicyDecision
from pajin.runtime import budget_persistence
from pajin.runtime.budget_state import (
    BUDGET_SCHEMA_SQL,
    BudgetPersistenceError,
    parse_budget_checkpoint,
)
from pajin.runtime.budgeted_execution import budgeted_tool_call
from pajin.runtime.control import BudgetController, BudgetExceeded, DualModelUsageBudget
from pajin.supervision.invocation_journal import SupervisorInvocationJournal
from pajin.tools.gateway import GatewayOutcome

CAMPAIGN = "a" * 64
POLICY = "b" * 64
NOW = datetime(2026, 9, 8, tzinfo=UTC)


def _controllers(*, dedicated_limits: Budgets | None = None):
    limits = Budgets(
        durationSeconds=120,
        maxToolCalls=5,
        maxModelCalls=3,
        maxModelTokens=1000,
        maxCostUsd=2.0,
    )
    campaign = BudgetController(limits)
    dedicated = BudgetController(dedicated_limits or limits)
    return campaign, dedicated, DualModelUsageBudget(campaign, dedicated)


def _bind(journal, campaign, dedicated, *, policy=POLICY):
    journal.bind_budgets(
        campaign_digest=CAMPAIGN,
        policy_digest=policy,
        campaign=campaign,
        dedicated=dedicated,
    )


def _saved(path: Path):
    with sqlite3.connect(path) as connection:
        payloads = connection.execute(
            "SELECT payload FROM supervisor_budget_checkpoints ORDER BY scope_id, revision"
        ).fetchall()
    return [parse_budget_checkpoint(payload) for (payload,) in payloads]


def _counts(budget: BudgetController):
    return (
        budget.agent_count,
        budget.tool_calls,
        budget.model_calls,
        budget.model_prompt_tokens,
        budget.model_completion_tokens,
        budget.cost_usd,
    )


def test_restart_retains_all_campaign_usage_and_uncertain_dual_and_tool_reservations(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, dual = _controllers()
    campaign.reserve_agent(depth=0)
    campaign.record_tool_call()
    campaign.record_cost(0.125)
    journal = SupervisorInvocationJournal(path, clock=lambda: NOW)
    _bind(journal, campaign, dedicated)
    model = dual.reserve_model_usage(prompt_tokens=100, completion_tokens=200, cost_usd=0.75)
    tool = campaign.reserve_tool_usage()

    restored_campaign, restored_dedicated, restored_dual = _controllers()
    reopened = SupervisorInvocationJournal(path, clock=lambda: NOW + timedelta(seconds=5))
    _bind(reopened, restored_campaign, restored_dedicated)

    assert _counts(restored_campaign) == (1, 3, 1, 100, 200, 0.875)
    assert _counts(restored_dedicated) == (0, 1, 1, 100, 200, 0.75)
    assert restored_campaign.elapsed_seconds >= 5
    assert restored_dedicated.elapsed_seconds >= 5
    with pytest.raises(ValueError, match="not active"):
        restored_campaign.release_tool_usage_reservation(tool)
    with pytest.raises(ValueError, match="not active"):
        restored_dual.release_model_usage_reservation(model)
    assert _counts(restored_campaign) == (1, 3, 1, 100, 200, 0.875)
    with pytest.raises(BudgetPersistenceError, match="superseded"):
        dual.release_model_usage_reservation(model)
    with pytest.raises(BudgetPersistenceError):
        campaign.reserve_tool_usage()


def test_rebinding_same_pair_is_read_only_but_checks_new_owner(tmp_path: Path) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, _ = _controllers()
    journal = SupervisorInvocationJournal(path, clock=lambda: NOW)
    _bind(journal, campaign, dedicated)
    before = _saved(path)
    _bind(journal, campaign, dedicated)
    assert _saved(path) == before
    replacement_campaign, replacement_dedicated, _ = _controllers()
    _bind(
        SupervisorInvocationJournal(path, clock=lambda: NOW),
        replacement_campaign,
        replacement_dedicated,
    )
    with pytest.raises(BudgetPersistenceError, match="superseded"):
        _bind(journal, campaign, dedicated)


def test_dedicated_denial_rolls_back_both_live_and_recovered_counts(tmp_path: Path) -> None:
    limited = Budgets(maxModelCalls=0)
    campaign, dedicated, dual = _controllers(dedicated_limits=limited)
    path = tmp_path / "invocations.sqlite3"
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)

    with pytest.raises(BudgetExceeded, match="model-call"):
        dual.reserve_model_usage(prompt_tokens=100, completion_tokens=200, cost_usd=0.75)

    assert _counts(campaign) == _counts(dedicated) == (0, 0, 0, 0, 0, 0.0)
    restored_campaign, restored_dedicated, _ = _controllers(dedicated_limits=limited)
    _bind(
        SupervisorInvocationJournal(path, clock=lambda: NOW), restored_campaign, restored_dedicated
    )
    assert _counts(restored_campaign) == _counts(restored_dedicated) == (0, 0, 0, 0, 0, 0.0)


@pytest.mark.parametrize("other_journal", [False, True])
def test_dual_mutation_rejects_an_unbound_or_foreign_journal_participant(
    tmp_path: Path, other_journal: bool
) -> None:
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(tmp_path / "one.sqlite3"), campaign, dedicated)
    other_campaign, other_dedicated, _ = _controllers()
    if other_journal:
        _bind(
            SupervisorInvocationJournal(tmp_path / "two.sqlite3"), other_campaign, other_dedicated
        )
    mixed = DualModelUsageBudget(campaign, other_dedicated)

    with pytest.raises(BudgetPersistenceError, match="unbound participant"):
        mixed.reserve_model_usage(prompt_tokens=10, completion_tokens=20, cost_usd=0.25)

    assert _counts(campaign) == _counts(other_dedicated) == (0, 0, 0, 0, 0, 0.0)


def test_second_scope_write_failure_rolls_back_database_and_fences_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, dual = _controllers()
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)
    before = _saved(path)
    original_insert = budget_persistence._insert
    writes = 0

    def fail_second(connection, checkpoint):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise sqlite3.OperationalError("simulated journal write failure")
        original_insert(connection, checkpoint)

    with monkeypatch.context() as patch:
        patch.setattr(budget_persistence, "_insert", fail_second)
        with pytest.raises(sqlite3.OperationalError, match="simulated"):
            dual.reserve_model_usage(prompt_tokens=100, completion_tokens=200, cost_usd=0.75)
    assert _saved(path) == before
    for budget in (campaign, dedicated):
        with pytest.raises(BudgetPersistenceError):
            budget.reserve_tool_usage()
    restored_campaign, restored_dedicated, _ = _controllers()
    _bind(
        SupervisorInvocationJournal(path, clock=lambda: NOW), restored_campaign, restored_dedicated
    )
    assert _counts(restored_campaign) == _counts(restored_dedicated) == (0, 0, 0, 0, 0, 0.0)


def test_lost_commit_acknowledgement_keeps_both_charges_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, dual = _controllers()
    journal = SupervisorInvocationJournal(path, clock=lambda: NOW)
    _bind(journal, campaign, dedicated)
    original_transaction = journal._budget_ledger._transaction

    @contextmanager
    def lose_commit_ack():
        with original_transaction() as connection:
            yield connection
        raise OSError("simulated interruption after durable commit")

    monkeypatch.setattr(journal._budget_ledger, "_transaction", lose_commit_ack)
    with pytest.raises(OSError, match="after durable commit"):
        dual.reserve_model_usage(prompt_tokens=100, completion_tokens=200, cost_usd=0.75)
    with pytest.raises(BudgetPersistenceError):
        campaign.reserve_tool_usage()
    restored_campaign, restored_dedicated, _ = _controllers()
    _bind(
        SupervisorInvocationJournal(path, clock=lambda: NOW), restored_campaign, restored_dedicated
    )
    assert _counts(restored_campaign) == _counts(restored_dedicated) == (0, 1, 1, 100, 200, 0.75)


def test_interrupted_recovery_cannot_leave_either_controller_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, dual = _controllers()
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)
    dual.reserve_model_usage(prompt_tokens=100, completion_tokens=200, cost_usd=0.75)
    restored_campaign, restored_dedicated, _ = _controllers()
    original_restore = budget_persistence._restore
    restores = 0

    def fail_final_restore(controller, usage, *, elapsed):
        nonlocal restores
        restores += 1
        if restores == 4:
            raise BudgetExceeded("simulated expiry after commit")
        original_restore(controller, usage, elapsed=elapsed)

    with monkeypatch.context() as patch:
        patch.setattr(budget_persistence, "_restore", fail_final_restore)
        with pytest.raises(BudgetExceeded, match="after commit"):
            _bind(
                SupervisorInvocationJournal(path, clock=lambda: NOW),
                restored_campaign,
                restored_dedicated,
            )
    for controller in (campaign, dedicated, restored_campaign, restored_dedicated):
        with pytest.raises(BudgetPersistenceError):
            controller.reserve_tool_usage()
    recovered_campaign, recovered_dedicated, _ = _controllers()
    _bind(
        SupervisorInvocationJournal(path, clock=lambda: NOW),
        recovered_campaign,
        recovered_dedicated,
    )
    assert _counts(recovered_campaign) == _counts(recovered_dedicated) == (0, 1, 1, 100, 200, 0.75)


@pytest.mark.parametrize("change", ["limits", "policy", "used-controller", "clock", "expired"])
def test_recovery_rejects_changed_authority_usage_or_deadline(tmp_path: Path, change: str) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)
    before = _saved(path)
    restored_campaign, restored_dedicated, _ = _controllers()
    if change == "limits":
        restored_campaign.budgets.max_tool_calls += 1
    if change == "used-controller":
        restored_campaign.record_tool_call()
    when = NOW
    if change == "clock":
        when -= timedelta(seconds=1)
    if change == "expired":
        when += timedelta(seconds=121)

    with pytest.raises((BudgetPersistenceError, BudgetExceeded)):
        _bind(
            SupervisorInvocationJournal(path, clock=lambda: when),
            restored_campaign,
            restored_dedicated,
            policy="c" * 64 if change == "policy" else POLICY,
        )
    assert _saved(path) == before
    for controller in (restored_campaign, restored_dedicated):
        with pytest.raises(BudgetPersistenceError):
            controller.reserve_tool_usage()


def test_bound_controller_cannot_reset_usage_or_change_limits(tmp_path: Path) -> None:
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(tmp_path / "invocations.sqlite3"), campaign, dedicated)
    with pytest.raises(BudgetPersistenceError, match="caller-restored"):
        campaign.restore_usage(
            agent_count=0,
            tool_calls=0,
            model_calls=0,
            model_prompt_tokens=0,
            model_completion_tokens=0,
            cost_usd=0.0,
            elapsed_seconds=0.0,
        )
    campaign.budgets.max_tool_calls += 1
    with pytest.raises(BudgetPersistenceError, match="configuration has changed"):
        campaign.reserve_tool_usage()


def test_settlement_persists_only_verified_actual_usage_and_unknown_bound(tmp_path: Path) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)
    known = campaign.reserve_model_usage(prompt_tokens=100, completion_tokens=200, cost_usd=0.75)
    campaign.settle_model_usage(known, prompt_tokens=50, completion_tokens=80, cost_usd=0.25)
    unknown = campaign.reserve_model_usage(prompt_tokens=100, completion_tokens=200, cost_usd=0.75)
    with pytest.raises(BudgetExceeded, match="conservative reservation"):
        campaign.settle_model_usage(unknown, prompt_tokens=101, completion_tokens=100, cost_usd=0.5)
    with pytest.raises(ValueError, match="not active"):
        campaign.release_model_usage_reservation(unknown)
    restored_campaign, restored_dedicated, _ = _controllers()
    _bind(
        SupervisorInvocationJournal(path, clock=lambda: NOW), restored_campaign, restored_dedicated
    )
    assert _counts(restored_campaign) == (0, 2, 2, 150, 280, 1.0)
    assert _counts(restored_dedicated) == (0, 0, 0, 0, 0, 0.0)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE supervisor_budget_checkpoints SET revision=revision+1",
        "DELETE FROM supervisor_budget_checkpoints",
        "INSERT OR REPLACE INTO supervisor_budget_checkpoints "
        "SELECT * FROM supervisor_budget_checkpoints",
        "INSERT OR REPLACE INTO supervisor_budget_checkpoints "
        "(rowid, scope_id, revision, checkpoint_digest, payload) "
        "SELECT rowid, scope_id, revision+1, printf('%064d', 1), payload "
        "FROM supervisor_budget_checkpoints",
    ],
)
def test_budget_history_cannot_be_updated_deleted_or_replaced(
    tmp_path: Path, statement: str
) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)
    before = _saved(path)
    with sqlite3.connect(path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(statement)
    assert _saved(path) == before


@pytest.mark.parametrize("damage", ["missing-side", "gap", "middle-payload"])
def test_recovery_verifies_complete_history_and_both_scopes(tmp_path: Path, damage: str) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)
    campaign.record_tool_call()
    campaign.record_tool_call()
    with sqlite3.connect(path) as connection:
        if damage == "middle-payload":
            connection.execute("DROP TRIGGER supervisor_budget_checkpoints_no_update")
            connection.execute(
                "UPDATE supervisor_budget_checkpoints SET payload='{}' WHERE revision=2"
            )
            guard = "supervisor_budget_checkpoints_no_update"
        else:
            connection.execute("DROP TRIGGER supervisor_budget_checkpoints_no_delete")
            if damage == "gap":
                connection.execute("DELETE FROM supervisor_budget_checkpoints WHERE revision=2")
            else:
                connection.execute(
                    "DELETE FROM supervisor_budget_checkpoints WHERE scope_id=?",
                    (dedicated._persistence.checkpoint.scope.scope_id,),
                )
            guard = "supervisor_budget_checkpoints_no_delete"
        connection.execute(BUDGET_SCHEMA_SQL[("trigger", guard)])
    restored_campaign, restored_dedicated, _ = _controllers()
    with pytest.raises(BudgetPersistenceError):
        _bind(
            SupervisorInvocationJournal(path, clock=lambda: NOW),
            restored_campaign,
            restored_dedicated,
        )


def test_fresh_process_crash_keeps_reservation_without_live_handles(tmp_path: Path) -> None:
    path = tmp_path / "invocations.sqlite3"
    script = """
import os, sys
from pajin.domain.models import Budgets
from pajin.runtime.control import BudgetController, DualModelUsageBudget
from pajin.supervision.invocation_journal import SupervisorInvocationJournal
campaign, dedicated = BudgetController(Budgets()), BudgetController(Budgets())
journal = SupervisorInvocationJournal(sys.argv[1])
journal.bind_budgets(
    campaign_digest='a'*64, policy_digest='b'*64, campaign=campaign, dedicated=dedicated,
)
DualModelUsageBudget(campaign, dedicated).reserve_model_usage(
    prompt_tokens=100, completion_tokens=200, cost_usd=0.75,
)
os._exit(23)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)], capture_output=True, timeout=20
    )
    assert result.returncode == 23, result.stderr.decode()
    campaign, dedicated = BudgetController(Budgets()), BudgetController(Budgets())
    _bind(SupervisorInvocationJournal(path), campaign, dedicated)
    assert _counts(campaign) == _counts(dedicated) == (0, 1, 1, 100, 200, 0.75)
    assert not campaign._model_usage_reservations
    assert not dedicated._model_usage_reservations


def _outcome(*, executed: bool) -> GatewayOutcome:
    return GatewayOutcome(
        decision=PolicyDecision(allowed=executed, reason="bounded test outcome", policy="test"),
        result=ToolResult(
            request_id="request-budget",
            tool_id="mock.agent-probe",
            success=executed,
            started_at=NOW,
            finished_at=NOW,
        ),
        executed=executed,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("result", ["executed", "denied", "error", "cancelled"])
async def test_tool_call_records_before_dispatch_and_refunds_only_proven_nonexecution(
    tmp_path: Path,
    result: str,
) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(path, clock=lambda: NOW), campaign, dedicated)

    async def operation():
        assert campaign.tool_calls == 1
        current = [entry for entry in _saved(path) if entry.scope.role == "campaign"][-1]
        assert current.usage.tool_calls == 1
        if result == "error":
            raise RuntimeError("simulated uncertain execution")
        if result == "cancelled":
            raise asyncio.CancelledError
        return _outcome(executed=result == "executed")

    if result in {"executed", "denied"}:
        outcome = await budgeted_tool_call(campaign, operation)
        assert outcome.executed is (result == "executed")
    else:
        error = RuntimeError if result == "error" else asyncio.CancelledError
        with pytest.raises(error):
            await budgeted_tool_call(campaign, operation)
    restored_campaign, restored_dedicated, _ = _controllers()
    _bind(
        SupervisorInvocationJournal(path, clock=lambda: NOW), restored_campaign, restored_dedicated
    )
    assert restored_campaign.tool_calls == (0 if result == "denied" else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_accounting_failure_does_not_replace_execution_error_or_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cancelled: bool,
) -> None:
    path = tmp_path / "invocations.sqlite3"
    campaign, dedicated, _ = _controllers()
    _bind(SupervisorInvocationJournal(path), campaign, dedicated)
    original_error = asyncio.CancelledError() if cancelled else RuntimeError("execution stopped")

    def fail_terminal_write(connection, checkpoint):
        raise sqlite3.OperationalError("simulated accounting outage")

    async def operation():
        monkeypatch.setattr(budget_persistence, "_insert", fail_terminal_write)
        raise original_error

    with pytest.raises(type(original_error)) as caught:
        await budgeted_tool_call(campaign, operation)

    assert caught.value is original_error
    assert "budget accounting failed" in caught.value.__notes__[0]
    assert campaign.tool_calls == 1
    with pytest.raises(BudgetPersistenceError):
        campaign.reserve_tool_usage()
    assert [entry for entry in _saved(path) if entry.scope.role == "campaign"][
        -1
    ].usage.tool_calls == 1


@pytest.mark.asyncio
async def test_concurrent_tools_cannot_enter_gateway_beyond_call_limit(tmp_path: Path) -> None:
    campaign, dedicated, _ = _controllers()
    campaign.budgets.max_tool_calls = 1
    _bind(SupervisorInvocationJournal(tmp_path / "invocations.sqlite3"), campaign, dedicated)
    entered, finish = asyncio.Event(), asyncio.Event()
    calls = 0

    async def operation():
        nonlocal calls
        calls += 1
        entered.set()
        await finish.wait()
        return _outcome(executed=True)

    first = asyncio.create_task(budgeted_tool_call(campaign, operation))
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        with pytest.raises(BudgetExceeded, match="tool-call"):
            await budgeted_tool_call(campaign, operation)
    finally:
        finish.set()
        await first
    assert calls == campaign.tool_calls == 1
