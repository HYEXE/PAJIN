from __future__ import annotations

import asyncio
import os
import sqlite3
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient
from test_control_plane_checkpoint_recovery import _checkpoint, _settings
from test_control_plane_run_budgets import _binding, _campaign
from test_host_activity import _enroll, _quiescence
from test_host_checkpoint import _create, _restore

from pajin.control_plane.api import create_app
from pajin.control_plane.executors import CampaignJobInput
from pajin.control_plane.models import replay_execution_component_digest
from pajin.control_plane.worker_main import run_from_env
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime.control import BudgetController
from pajin.runtime.host_gate import enroll_host_gate, runtime_activity
from pajin.runtime.host_recovery import RecoveryEnrollmentError, inspect_recovery_inventory
from pajin.runtime.inventory import RuntimeInventory, fingerprint_component, host_root_digest
from pajin.runtime.registered_checkpoint import build_registered_checkpoint_plan
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.supervision.invocation_journal import SupervisorInvocationJournal
from pajin.supervision.run_binding import SupervisorRunBinding

pytestmark = pytest.mark.skipif(os.name != "posix", reason="host recovery uses POSIX local locking")


def _inspect(enrolled, **kwargs):
    with _quiescence(enrolled) as lease:
        return inspect_recovery_inventory(lease, **kwargs)


def test_v3_index_is_enrolled_once_and_cannot_be_repaired_by_gate_enroll(tmp_path, monkeypatch):
    enrolled = _enroll(tmp_path, monkeypatch, recovery=True)
    root, path, digest, _ = enrolled
    index = root / "recovery-index.sqlite3"
    before = index.read_bytes()
    with pytest.raises(FileExistsError):
        enroll_host_gate(root, inventory_path=path, inventory_sha256=digest)
    assert index.read_bytes() == before
    index.unlink()
    with pytest.raises(FileExistsError):
        enroll_host_gate(root, inventory_path=path, inventory_sha256=digest)
    assert not index.exists()
    with pytest.raises(FileNotFoundError), runtime_activity("worker"):
        pytest.fail("missing index admitted a new runtime")
    assert not index.exists()


def test_default_control_plane_registers_before_serving_and_keeps_identity_on_restart(
    tmp_path,
    monkeypatch,
):
    settings = _settings(tmp_path / "host/state/control-plane.db")
    enrolled = _enroll(
        tmp_path, monkeypatch, role="control-plane", configuration=settings, recovery=True
    )
    for _ in range(2):
        with TestClient(create_app(settings)) as client:
            assert client.get("/healthz").status_code == 200
    inventory = _inspect(enrolled, require_complete=True)
    assert [item.component_id for item in inventory.components] == ["control-plane"]
    assert [(item.path, item.kind) for item in inventory.registrations] == [
        ("control-plane.db", "control-plane-sqlite"),
    ]
    path = tmp_path / "host/state/control-plane.db"
    path.unlink()
    with pytest.raises(RecoveryEnrollmentError, match="missing"):
        create_app(settings)
    assert not path.exists()


def test_control_plane_cannot_recreate_state_lost_between_factory_and_lifespan(
    tmp_path, monkeypatch
):
    settings = _settings(tmp_path / "host/state/control-plane.db")
    _enroll(tmp_path, monkeypatch, role="control-plane", configuration=settings, recovery=True)
    with TestClient(create_app(settings)):
        pass
    application = create_app(settings)
    path = tmp_path / "host/state/control-plane.db"
    path.unlink()
    with pytest.raises(RecoveryEnrollmentError, match="missing"), TestClient(application):
        pytest.fail("missing registered CP state was recreated by lifespan initialization")
    assert not path.exists()


def test_graph_budget_and_run_store_are_registered_before_returning_to_the_caller(
    tmp_path, monkeypatch
):
    enrolled = _enroll(tmp_path, monkeypatch, recovery=True)
    state = enrolled[0] / "state"
    campaign = _campaign()
    binding = _binding(campaign)
    with runtime_activity("worker"):
        SQLiteGraphStore(state / "graph.sqlite3", campaign_id="isolated-campaign")
        journal = SupervisorInvocationJournal(state / "budget.sqlite3", run_binding=binding)
        budget = BudgetController(campaign.spec.budgets)
        journal.bind_campaign_budget(campaign_digest=binding.campaign_digest, campaign=budget)
        budget.reserve_tool_usage()
        run = RunStore.create(state / "runs", "isolated-campaign")
        run.append_event("test.started")
        run.write_text("result.txt", "bounded evidence")
        run.seal()
    registrations = _inspect(enrolled).registrations
    assert [item.kind for item in registrations] == [
        "supervisor-sqlite",
        "graph-sqlite",
        "run-store",
    ]
    assert registrations[0].run_binding == binding
    assert registrations[2].run_id == run.run_id
    with runtime_activity("worker"):
        reopened = SupervisorInvocationJournal(state / "budget.sqlite3", run_binding=binding)
        restored_budget = BudgetController(campaign.spec.budgets)
        reopened.bind_campaign_budget(
            campaign_digest=binding.campaign_digest, campaign=restored_budget
        )
        assert restored_budget.tool_calls == 1
    assert _inspect(enrolled).registrations == registrations


@pytest.mark.parametrize("change", ["missing", "other-run", "unbound", "outside", "preexisting"])
def test_journal_first_use_rejects_missing_or_unregistered_binding(tmp_path, monkeypatch, change):
    enrolled = _enroll(tmp_path, monkeypatch, recovery=True)
    path = enrolled[0] / "state/budget.sqlite3"
    binding = _binding(_campaign())
    with runtime_activity("worker"):
        SupervisorInvocationJournal(path, run_binding=binding)
    if change == "missing":
        path.unlink()
    elif change == "other-run":
        binding = binding.model_copy(update={"control_plane_run_id": "another-run"})
    elif change == "unbound":
        binding = None
    elif change == "outside":
        path = tmp_path / "outside.sqlite3"
    else:
        path = enrolled[0] / "state/unregistered.sqlite3"
        path.write_bytes(b"existing state must never be silently imported")
    before = path.read_bytes() if path.exists() else None
    with runtime_activity("worker"), pytest.raises((RecoveryEnrollmentError, ValueError)):
        SupervisorInvocationJournal(path, run_binding=binding)
    assert (path.read_bytes() if path.exists() else None) == before


def test_default_worker_checks_output_location_before_claiming_a_job(tmp_path, monkeypatch):
    monkeypatch.setenv("PAJIN_DAEMON_OUTPUT_ROOT", str(tmp_path / "outside"))
    _enroll(tmp_path, monkeypatch, recovery=True)
    with pytest.raises(RecoveryEnrollmentError, match="host state directory"):
        asyncio.run(run_from_env())
    assert not (tmp_path / "outside").exists()


def test_registration_index_is_immutable_and_checked_before_any_store_work(tmp_path, monkeypatch):
    enrolled = _enroll(tmp_path, monkeypatch, recovery=True)
    with runtime_activity("worker"):
        SQLiteGraphStore(enrolled[0] / "state/graph.sqlite3", campaign_id="isolated-campaign")
    index = enrolled[0] / "recovery-index.sqlite3"
    with sqlite3.connect(index) as connection:
        for sql in (
            "DELETE FROM recovery_registrations",
            "UPDATE recovery_components SET digest = 'changed'",
            "INSERT OR REPLACE INTO recovery_metadata(key, value) VALUES ('gate', 'changed')",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(sql)
        connection.execute("DROP TRIGGER recovery_registrations_no_delete")
    with pytest.raises(RecoveryEnrollmentError, match="schema"), runtime_activity("worker"):
        pytest.fail("damaged enrollment admitted activity")


def test_checkpoint_requires_every_component_from_the_original_pinned_runtime_inventory(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "host"
    monkeypatch.setenv("PAJIN_HOST_RUNTIME_ROOT", str(root))
    components = (fingerprint_component("worker"), fingerprint_component("replay-worker"))
    inventory = RuntimeInventory(
        apiVersion="pajin.dev/runtime-inventory/v3",
        inventoryId="two-components",
        hostRootSha256=host_root_digest(root),
        recoveryPolicy="closed-local-sqlite-v1",
        components=components,
    )
    path = tmp_path / "inventory.json"
    path.write_text(inventory.model_dump_json(by_alias=True))
    digest = sha256(path.read_bytes()).hexdigest()
    monkeypatch.setenv("PAJIN_RUNTIME_INVENTORY_PATH", str(path))
    monkeypatch.setenv("PAJIN_RUNTIME_INVENTORY_SHA256", digest)
    gate = enroll_host_gate(root, inventory_path=path, inventory_sha256=digest)
    enrolled = root, path, digest, gate
    with runtime_activity("worker"):
        pass
    with pytest.raises(RecoveryEnrollmentError, match="every configured runtime"):
        _inspect(enrolled, require_complete=True)
    with runtime_activity("replay-worker"):
        pass
    assert len(_inspect(enrolled, require_complete=True).components) == 2


@pytest.mark.parametrize("changed_binding", [None, "input_digest", "campaign_digest"])
def test_registered_stores_generate_and_restore_one_complete_checkpoint(
    tmp_path, monkeypatch, changed_binding,
):
    settings = _settings(tmp_path / "host/state/control-plane.db")
    enrolled = _enroll(
        tmp_path, monkeypatch, role="control-plane", configuration=settings, recovery=True
    )
    campaign = _campaign()
    with TestClient(create_app(settings)) as client:
        checkpoint_id, _ = _checkpoint(client, "enrolled", campaign=campaign)
    with sqlite3.connect(tmp_path / "host/state/control-plane.db") as connection:
        run_id = connection.execute(
            "SELECT run_id FROM cp_checkpoints WHERE checkpoint_id = ?",
            (checkpoint_id,),
        ).fetchone()[0]
    state = enrolled[0] / "state"
    with runtime_activity("control-plane", configuration=settings):
        binding = SupervisorRunBinding(
            controlPlaneRunId=run_id,
            campaignDigest=replay_execution_component_digest(campaign),
            inputDigest=replay_execution_component_digest({
                "kind": "campaign", "input": CampaignJobInput(manifest=campaign),
            }),
            budgetMode="campaign-only",
        )
        if changed_binding is not None:
            binding = binding.model_copy(update={changed_binding: "e" * 64})
        journal = SupervisorInvocationJournal(state / "budget.sqlite3", run_binding=binding)
        budget = BudgetController(campaign.spec.budgets)
        journal.bind_campaign_budget(campaign_digest=binding.campaign_digest, campaign=budget)
        budget.reserve_tool_usage()
        SQLiteGraphStore(state / "graph.sqlite3", campaign_id="isolated-campaign")
        run = RunStore.create(state / "runs", "isolated-campaign")
        run.append_event("test.started")
        run.write_text("result.txt", "bounded sealed evidence")
        seal = run.seal()
    with _quiescence(enrolled) as lease:
        registered = inspect_recovery_inventory(lease, require_complete=True)
        plan = build_registered_checkpoint_plan(
            lease,
            runtime_inventory_path=enrolled[1],
            expected_enrollment_sha256=registered.digest,
            recovery_set_id="registered-host",
        )
    assert plan.enrollment == registered
    if changed_binding is not None:
        with pytest.raises(ValueError, match="original"):
            _create(tmp_path, enrolled, plan)
        assert not (tmp_path / "retained.checkpoint").exists()
        return
    manifest = _create(tmp_path, enrolled, plan)
    restored = _restore(tmp_path, manifest)
    assert restored.statement.plan.enrollment == registered
    assert (
        verify_run_integrity(
            tmp_path / "restored/state" / run.path.relative_to(state),
        ).root_digest
        == seal.root_digest
    )
    omitted = plan.model_copy(
        update={
            "api_version": "pajin.dev/host-checkpoint-plan/v1",
            "enrollment": None,
        }
    )
    with pytest.raises(RuntimeError, match="first-use enrollment"):
        _create(tmp_path, enrolled, omitted, destination=tmp_path / "omitted.checkpoint")
