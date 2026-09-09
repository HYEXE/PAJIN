from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from pajin.control_plane import worker_main
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.client import ControlPlaneClient
from pajin.control_plane.executors import (
    ApprovalCheckpointExecution,
    CampaignJobExecutor,
    CampaignJobInput,
    CompletedExecution,
    ToolLoopJobExecutor,
    ToolLoopJobInput,
)
from pajin.control_plane.models import (
    JobState,
    JobView,
    Principal,
    PrincipalRole,
    replay_execution_component_digest,
)
from pajin.control_plane.run_budgets import RunBudgetError, RunBudgetRegistry, run_budgeted_action
from pajin.domain.manifest import load_manifest
from pajin.runtime.budget_state import BudgetPersistenceError, parse_budget_checkpoint
from pajin.runtime.control import BudgetController, BudgetExceeded
from pajin.runtime.host_gate import HostActivityError, enroll_host_gate, host_quiescence
from pajin.runtime.inventory import RuntimeInventory, fingerprint_component, host_root_digest
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.supervision.invocation_journal import (
    SupervisorInvocationJournal,
    SupervisorInvocationJournalError,
)
from pajin.supervision.run_binding import SupervisorRunBinding


def _job(*, kind: str = "campaign", run: str = "first-run", attempts: int = 1) -> JobView:
    now = datetime.now(UTC)
    return JobView(
        job_id="job_" + "1" * 32, run_id=run, kind=kind, state=JobState.LEASED, payload={},
        priority=0, attempts=attempts, max_attempts=3, available_at=now,
        lease_owner="isolated-worker", lease_expires_at=now + timedelta(seconds=30),
        heartbeat_at=now, result=None, error=None, created_at=now, updated_at=now,
    )


def _campaign():
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    campaign.spec.targets[0].simulation = {"seconds": 0.1}
    return campaign


def _saved(root: Path):
    paths = list(root.glob("*.sqlite3"))
    assert len(paths) == 1
    with sqlite3.connect(paths[0]) as connection:
        return [parse_budget_checkpoint(row[0]) for row in connection.execute(
            "SELECT payload FROM supervisor_budget_checkpoints ORDER BY revision",
        )]


def _binding(campaign, *, run: str = "first-run", mode: str = "campaign-only"):
    return SupervisorRunBinding(
        controlPlaneRunId=run, campaignDigest=replay_execution_component_digest(campaign),
        inputDigest="a" * 64, budgetMode=mode,
    )


def test_first_work_binding_retains_usage_and_fences_old_controller(tmp_path: Path) -> None:
    campaign = _campaign()
    campaign.spec.budgets.max_cost_usd = 1
    registry = RunBudgetRegistry(tmp_path)
    before = registry.bind(_job(), campaign, original_input={"purpose": "isolated"})
    before.reserve_agent(depth=0)
    before.reserve_tool_usage()
    before.record_cost(0.125)
    after = RunBudgetRegistry(tmp_path).bind(
        _job(attempts=2), campaign, original_input={"purpose": "isolated"},
    )
    assert (after.agent_count, after.tool_calls, after.cost_usd) == (1, 1, 0.125)
    assert after.elapsed_seconds >= before.elapsed_seconds - 0.01
    with pytest.raises(BudgetPersistenceError):
        before.reserve_tool_usage()
    histories = _saved(tmp_path)
    assert histories[0].usage.tool_calls == 0
    assert histories[-1].usage.tool_calls == 1
    with sqlite3.connect(next(tmp_path.glob("*.sqlite3"))) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (3,)


def test_different_runs_with_same_campaign_have_separate_bound_allowances(tmp_path: Path) -> None:
    campaign = _campaign()
    registry = RunBudgetRegistry(tmp_path)
    first = registry.bind(_job(), campaign, original_input={})
    first.record_tool_call()
    second = registry.bind(_job(run="second-run"), campaign, original_input={})
    assert first.tool_calls == 1 and second.tool_calls == 0
    assert len(list(tmp_path.glob("*.sqlite3"))) == 2


@pytest.mark.parametrize("changed", ["input", "campaign", "journal-run"])
def test_reopen_rejects_input_campaign_and_foreign_run_journal(
    tmp_path: Path, changed: str,
) -> None:
    campaign = _campaign()
    registry = RunBudgetRegistry(tmp_path / "one")
    registry.bind(_job(), campaign, original_input={})
    if changed == "journal-run":
        other_root = tmp_path / "two"
        other = RunBudgetRegistry(other_root)
        other.bind(_job(run="second-run"), campaign, original_input={})
        shutil.copyfile(next(registry._root.glob("*.sqlite3")), next(other_root.glob("*.sqlite3")))
        with pytest.raises(RunBudgetError):
            other.bind(_job(run="second-run", attempts=2), campaign, original_input={})
    else:
        altered = campaign.model_copy(deep=True)
        if changed == "campaign":
            altered.spec.budgets.max_tool_calls += 1
        with pytest.raises(RunBudgetError):
            registry.bind(
                _job(attempts=2), altered, original_input={"changed": True} if changed == "input"
                else {},
            )


@pytest.mark.parametrize(("attempts", "resuming"), [(2, False), (1, True), (0, False)])
def test_missing_budget_cannot_bootstrap_on_retry_resume_or_unclaimed_job(
    tmp_path: Path, attempts: int, resuming: bool,
) -> None:
    root = tmp_path / "uncreated"
    with pytest.raises(RunBudgetError):
        RunBudgetRegistry(root).bind(
            _job(attempts=attempts), _campaign(), original_input={}, resuming=resuming,
        )
    assert not root.exists()


def test_run_path_and_bound_metadata_cannot_be_retargeted(tmp_path: Path) -> None:
    registry = RunBudgetRegistry(tmp_path / "journals")
    with pytest.raises(RunBudgetError):
        registry.bind(
            _job().model_copy(update={"run_id": "../outside"}), _campaign(), original_input={},
        )
    assert not registry._root.exists()
    campaign = _campaign()
    path = tmp_path / "journal.sqlite3"
    binding = _binding(campaign)
    SupervisorInvocationJournal(path, run_binding=binding)
    with pytest.raises(ValueError):
        SupervisorInvocationJournal(path)
    with sqlite3.connect(path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE supervisor_invocation_metadata SET value = '{}' WHERE key = 'run_binding'",
        )


@pytest.mark.parametrize("operation", ["reopen", "reserve"])
def test_missing_required_journal_during_open_is_not_recreated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    registry = RunBudgetRegistry(tmp_path)
    budget = registry.bind(_job(), _campaign(), original_input={})
    path = next(tmp_path.glob("*.sqlite3"))
    original_connect = sqlite3.connect

    def removed_before_connect(*args, **kwargs):
        path.unlink()
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", removed_before_connect)
    if operation == "reopen":
        with pytest.raises(RunBudgetError):
            registry.bind(_job(attempts=2), _campaign(), original_input={})
    else:
        with pytest.raises((SupervisorInvocationJournalError, sqlite3.OperationalError)):
            budget.reserve_tool_usage()
    assert not path.exists()


def test_nonempty_legacy_journal_cannot_be_rebound_as_fresh_run(tmp_path: Path) -> None:
    campaign = _campaign()
    path = tmp_path / "legacy.sqlite3"
    journal = SupervisorInvocationJournal(path)
    journal.bind_budgets(
        campaign_digest=replay_execution_component_digest(campaign), policy_digest="b" * 64,
        campaign=BudgetController(campaign.spec.budgets),
        dedicated=BudgetController(campaign.spec.budgets),
    )
    before = path.read_bytes()
    with pytest.raises(SupervisorInvocationJournalError, match="cannot be enrolled"):
        SupervisorInvocationJournal(path, run_binding=_binding(campaign))
    assert path.read_bytes() == before


def test_run_bound_dual_mode_preserves_original_pair_without_single_account_downgrade(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    binding = _binding(campaign, mode="campaign-and-supervisor")
    journal = SupervisorInvocationJournal(tmp_path / "dual.sqlite3", run_binding=binding)
    first = BudgetController(campaign.spec.budgets)
    dedicated = BudgetController(campaign.spec.budgets)
    journal.bind_budgets(
        campaign_digest=binding.campaign_digest, policy_digest="b" * 64,
        campaign=first, dedicated=dedicated,
    )
    with pytest.raises(SupervisorInvocationJournalError, match="budget differs"):
        journal.bind_campaign_budget(campaign_digest=binding.campaign_digest, campaign=first)
    with pytest.raises(ValueError):
        SupervisorInvocationJournal(
            journal.path, run_binding=_binding(campaign, mode="campaign-only"),
        )


@pytest.mark.asyncio
async def test_actual_local_executor_records_budget_before_work_and_retains_exhaustion(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    campaign.spec.budgets.max_tool_calls = 1
    job_input = CampaignJobInput(manifest=campaign)
    job = _job().model_copy(update={"payload": {"input": job_input.model_dump(mode="json")}})
    registry = RunBudgetRegistry(tmp_path / "budgets")
    executor = CampaignJobExecutor(output_root=tmp_path / "runs", budget_registry=registry)
    result = await executor.execute(job)
    assert result.result["toolCalls"] == 1
    assert _saved(registry._root)[-1].usage.tool_calls == 1
    reopened = registry.bind(
        job.model_copy(update={"attempts": 2}), campaign, original_input=job_input,
    )
    with pytest.raises(BudgetExceeded):
        reopened.reserve_tool_usage()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["executed", "duplicate", "unknown"])
async def test_action_reservation_precedes_dispatch_and_refunds_only_proven_duplicate(
    tmp_path: Path, outcome: str,
) -> None:
    registry = RunBudgetRegistry(tmp_path)
    budget = registry.bind(_job(), _campaign(), original_input={})

    async def operation() -> bool:
        assert _saved(tmp_path)[-1].usage.tool_calls == 1
        if outcome == "unknown":
            raise asyncio.CancelledError()
        return outcome == "executed"

    if outcome == "unknown":
        with pytest.raises(asyncio.CancelledError):
            await run_budgeted_action(budget, operation, dispatched=lambda result: result)
    else:
        await run_budgeted_action(budget, operation, dispatched=lambda result: result)
    assert _saved(tmp_path)[-1].usage.tool_calls == (0 if outcome == "duplicate" else 1)


@pytest.mark.asyncio
async def test_tool_loop_approval_continuation_reuses_journal_in_replacement_executor(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/tool-loop-approval-lab.yaml"))
    registry = RunBudgetRegistry(tmp_path / "budgets")
    executor = ToolLoopJobExecutor(output_root=tmp_path / "runs", budget_registry=registry)
    job_input = ToolLoopJobInput(manifest=campaign, prompt="Request the approval-gated mock probe.")
    job = _job(kind="tool-loop").model_copy(update={
        "payload": {"input": job_input.model_dump(mode="json")},
    })
    first = await executor.execute(job)
    assert isinstance(first, ApprovalCheckpointExecution)
    before = _saved(registry._root)[-1]
    now = datetime.now(UTC)
    continuation = _job(kind="tool-loop").model_copy(update={
        "job_id": "job_" + "2" * 32,
        "payload": {
            "resumeFromCheckpointId": "checkpoint_" + "2" * 32,
            "state": first.state, "approvalId": "approval_" + "2" * 32,
            "approval": {
                "callFingerprint": first.pending_intent.call_fingerprint,
                "toolId": first.pending_intent.tool_id, "target": first.pending_intent.target,
                "riskTier": int(first.pending_intent.risk_tier), "approvedBy": "security-owner",
                "approvedAt": now.isoformat(),
                "expiresAt": first.pending_intent.expires_at.isoformat(),
            },
        },
    })
    completed = await ToolLoopJobExecutor(
        output_root=tmp_path / "runs", budget_registry=RunBudgetRegistry(registry._root),
    ).execute(continuation)
    assert isinstance(completed, CompletedExecution)
    after = _saved(registry._root)[-1]
    assert after.origin_at == before.origin_at
    assert after.usage.tool_calls > before.usage.tool_calls
    assert after.usage.model_calls >= before.usage.model_calls


def test_abrupt_new_process_retains_unacknowledged_reservation(tmp_path: Path) -> None:
    campaign = _campaign()
    job = _job()
    inputs = tmp_path / "input.json"
    inputs.write_text(json.dumps({
        "job": job.model_dump(mode="json"), "campaign": campaign.model_dump(mode="json"),
    }))
    root = tmp_path / "budgets"
    script = """
import json, os, sys
from pathlib import Path
from pajin.control_plane.models import JobView
from pajin.control_plane.run_budgets import RunBudgetRegistry
from pajin.domain.models import CampaignManifest
value = json.loads(Path(sys.argv[1]).read_text())
budget = RunBudgetRegistry(Path(sys.argv[2])).bind(
    JobView.model_validate(value['job']), CampaignManifest.model_validate(value['campaign']),
    original_input={},
)
budget.reserve_tool_usage()
os._exit(23)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(inputs), str(root)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 23, result.stderr
    restored = RunBudgetRegistry(root).bind(
        job.model_copy(update={"attempts": 2}), campaign, original_input={},
    )
    assert restored.tool_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(("host_enrolled", "recovery"), [
    (False, False),
    pytest.param(True, False, marks=pytest.mark.skipif(os.name != "posix", reason="POSIX gate")),
    pytest.param(True, True, marks=pytest.mark.skipif(os.name != "posix", reason="POSIX gate")),
])
async def test_default_worker_inventory_to_authenticated_claim_dispatch_and_durable_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host_enrolled: bool, recovery: bool,
) -> None:
    from hashlib import sha256

    token = "isolated-run-budget-worker-token-32-bytes"
    operator = "isolated-run-budget-operator-token-32-bytes"
    settings = ControlPlaneSettings(
        database_url=f"sqlite:///{tmp_path / 'cp.sqlite3'}",
        credentials={
            token: Principal(subject="worker", roles=frozenset({PrincipalRole.WORKER})),
            operator: Principal(subject="operator", roles=frozenset({PrincipalRole.OPERATOR})),
        },
        checkpoint_keys={"v1": b"isolated-run-budget-checkpoint-key-32-bytes"},
    )
    app = create_app(settings)
    stop = asyncio.Event()
    runs = tmp_path / "host/state/runs" if recovery else tmp_path / "runs"
    budget_root = runs / "_control-plane-budgets"
    observed = []
    original_run = SimulatedWorkerBackend.run

    async def inspect_before_work(self, *args, **kwargs):
        if host_enrolled:
            with pytest.raises(HostActivityError), host_quiescence(
                host_root, inventory_path=path, inventory_sha256=digest,
            ):
                pytest.fail("Tool dispatch is outside host activity")
        latest = _saved(budget_root)[-1]
        assert latest.usage.tool_calls == 1
        observed.append(latest.checkpoint_digest)
        return await original_run(self, *args, **kwargs)

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            response = await httpx.ASGITransport(app=app).handle_async_request(request)
            if request.url.path.endswith("/complete") and response.status_code == 200:
                stop.set()
            return response

    def client(**kwargs):
        return ControlPlaneClient(**kwargs, transport=Transport())

    for name, value in {
        "PAJIN_CP_URL": "http://127.0.0.1:8090",
        "PAJIN_CP_WORKER_TOKEN": token,
        "PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB": "true",
        "PAJIN_DAEMON_OUTPUT_ROOT": str(runs),
        "PAJIN_DAEMON_STATUS_PATH": str(tmp_path / "status.json"),
        "PAJIN_DAEMON_LONG_POLL_SECONDS": "0",
        "PAJIN_DAEMON_HEARTBEAT_SECONDS": "0.1",
        "PAJIN_DAEMON_LEASE_SECONDS": "5",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(SimulatedWorkerBackend, "run", inspect_before_work)
    monkeypatch.setattr(worker_main, "ControlPlaneClient", client)
    monkeypatch.setattr(worker_main, "install_stop_event", lambda: stop)
    campaign = _campaign()
    with TestClient(app) as http:
        host_root = tmp_path / "host"
        if host_enrolled:
            monkeypatch.setenv("PAJIN_HOST_RUNTIME_ROOT", str(host_root))
        inventory = RuntimeInventory(
            apiVersion=(
                "pajin.dev/runtime-inventory/v3" if recovery else
                "pajin.dev/runtime-inventory/v2"
                if host_enrolled else "pajin.dev/runtime-inventory/v1"
            ), inventoryId="isolated-host",
            recoveryPolicy="closed-local-sqlite-v1" if recovery else None,
            hostRootSha256=host_root_digest(host_root) if host_enrolled else None,
            components=(fingerprint_component("worker"),),
        )
        path = tmp_path / "inventory.json"
        path.write_text(inventory.model_dump_json(by_alias=True))
        digest = sha256(path.read_bytes()).hexdigest()
        monkeypatch.setenv("PAJIN_RUNTIME_INVENTORY_PATH", str(path))
        monkeypatch.setenv("PAJIN_RUNTIME_INVENTORY_SHA256", digest)
        if host_enrolled:
            enroll_host_gate(host_root, inventory_path=path, inventory_sha256=digest)
        submitted = http.post(
            "/v1/runs", headers={"Authorization": f"Bearer {operator}"}, json={
                "campaign_name": campaign.metadata.name, "idempotency_key": "first-budget-work",
                "input": {"manifest": campaign.model_dump(mode="json", by_alias=True)},
            },
        )
        assert submitted.status_code == 200, submitted.text
        await asyncio.wait_for(worker_main.run_from_env(), timeout=15)
        run_id = submitted.json()["run"]["run_id"]
        stored = http.get(f"/v1/runs/{run_id}", headers={"Authorization": f"Bearer {operator}"})
        assert stored.status_code == 200
        assert stored.json()["state"] == "completed"
    assert len(observed) == 1
    assert _saved(budget_root)[-1].usage.tool_calls == 1
    if host_enrolled:
        with host_quiescence(host_root, inventory_path=path, inventory_sha256=digest) as lease:
            if recovery:
                from pajin.runtime.host_recovery import inspect_recovery_inventory

                registered = inspect_recovery_inventory(lease, require_complete=True)
                assert {item.kind for item in registered.registrations} == {
                    "supervisor-sqlite", "run-store",
                }
                journals = [item for item in registered.registrations if item.run_binding]
                assert len(journals) == 1
                assert journals[0].run_binding.control_plane_run_id == run_id
