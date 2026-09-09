from __future__ import annotations

import asyncio
import json
import os
import selectors
import subprocess
import sys
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient
from test_control_plane import _settings

from pajin.control_plane import api as cp_api
from pajin.runtime import host_gate
from pajin.runtime.host_gate import (
    HostActivityError,
    enroll_host_gate,
    host_quiescence,
    host_work,
    runtime_activity,
)
from pajin.runtime.inventory import (
    RuntimeInventory,
    RuntimeInventoryError,
    fingerprint_component,
    host_root_digest,
)
from pajin.supervision.invocation_journal import SupervisorInvocationJournal

pytestmark = pytest.mark.skipif(os.name != "posix", reason="enrolled local host uses POSIX flock")


def _enroll(tmp_path, monkeypatch, *, role="worker", configuration=None, recovery=False):
    root = tmp_path / "host"
    monkeypatch.setenv(host_gate.HOST_ROOT_ENV, str(root))
    inventory = RuntimeInventory(
        apiVersion=(
            "pajin.dev/runtime-inventory/v3" if recovery else "pajin.dev/runtime-inventory/v2"
        ),
        inventoryId="isolated-host",
        hostRootSha256=host_root_digest(root),
        recoveryPolicy="closed-local-sqlite-v1" if recovery else None,
        components=(fingerprint_component(role, configuration=configuration),),
    )
    path = tmp_path / "runtime-inventory.json"
    path.write_text(inventory.model_dump_json(by_alias=True))
    digest = sha256(path.read_bytes()).hexdigest()
    monkeypatch.setenv("PAJIN_RUNTIME_INVENTORY_PATH", str(path))
    monkeypatch.setenv("PAJIN_RUNTIME_INVENTORY_SHA256", digest)
    identity = enroll_host_gate(root, inventory_path=path, inventory_sha256=digest)
    return root, path, digest, identity


def _quiescence(enrolled):
    root, path, digest, _ = enrolled
    return host_quiescence(root, inventory_path=path, inventory_sha256=digest)


def test_shared_activity_excludes_quiescence_until_every_participant_releases(
    tmp_path, monkeypatch,
):
    enrolled = _enroll(tmp_path, monkeypatch)
    with runtime_activity("worker") as outer:
        with runtime_activity("worker") as inner:
            with host_work(), pytest.raises(HostActivityError), _quiescence(enrolled):
                pytest.fail("exclusive checkpoint entered during activity")
            assert inner is not None and outer is not None
        with pytest.raises(HostActivityError), _quiescence(enrolled):
            pytest.fail("remaining activity was ignored")
    with _quiescence(enrolled) as exclusive:
        exclusive.require_active(exclusive=True)
        with pytest.raises(HostActivityError), runtime_activity("worker"):
            pytest.fail("new activity entered during checkpoint")
    for expired in (inner, outer, exclusive):
        with pytest.raises(HostActivityError):
            expired.require_active()


def test_enrollment_never_overwrites_or_repairs_existing_gate(tmp_path, monkeypatch):
    enrolled = _enroll(tmp_path, monkeypatch)
    root, path, digest, _ = enrolled
    before = (root / "runtime-gate.json").read_bytes()
    with pytest.raises(FileExistsError):
        enroll_host_gate(root, inventory_path=path, inventory_sha256=digest)
    assert (root / "runtime-gate.json").read_bytes() == before
    (root / "runtime-gate.json").write_bytes(b"")
    with pytest.raises(HostActivityError), runtime_activity("worker"):
        pytest.fail("incomplete enrollment admitted")
    assert (root / "runtime-gate.json").read_bytes() == b""


def test_copied_gate_cannot_claim_quiescence_for_another_location(tmp_path, monkeypatch):
    root, path, digest, _ = _enroll(tmp_path, monkeypatch)
    copied = tmp_path / "copied"
    copied.mkdir(mode=0o700)
    gate = copied / "runtime-gate.json"
    gate.write_bytes((root / "runtime-gate.json").read_bytes())
    gate.chmod(0o600)
    with pytest.raises(HostActivityError), host_quiescence(
        copied, inventory_path=path, inventory_sha256=digest,
    ):
        pytest.fail("copied gate was treated as original host quiescence")


def test_active_context_cannot_drop_its_gate_configuration(tmp_path, monkeypatch):
    _enroll(tmp_path, monkeypatch)
    with runtime_activity("worker"):
        monkeypatch.delenv(host_gate.HOST_ROOT_ENV)
        with pytest.raises(HostActivityError, match="remove"), host_work():
            pytest.fail("live context became unenrolled")


@pytest.mark.parametrize("change", ["absent", "different"])
def test_enrolled_inventory_cannot_start_a_participant_without_its_common_root(
    tmp_path, monkeypatch, change,
):
    _enroll(tmp_path, monkeypatch)
    if change == "absent":
        monkeypatch.delenv(host_gate.HOST_ROOT_ENV)
    else:
        monkeypatch.setenv(host_gate.HOST_ROOT_ENV, str(tmp_path / "different"))
    with (
        pytest.raises(RuntimeInventoryError, match="enrolled host root"),
        runtime_activity("worker"),
    ):
        pytest.fail("partial host enrollment admitted")


def test_v1_inventory_wire_stays_unenrolled_and_cannot_create_a_host_gate(tmp_path, monkeypatch):
    inventory = RuntimeInventory(
        apiVersion="pajin.dev/runtime-inventory/v1", inventoryId="isolated-host",
        components=(fingerprint_component("worker"),),
    )
    assert set(inventory.model_dump(mode="json", by_alias=True)) == {
        "apiVersion", "inventoryId", "components",
    }
    path = tmp_path / "v1.json"
    path.write_text(inventory.model_dump_json(by_alias=True))
    digest = sha256(path.read_bytes()).hexdigest()
    with pytest.raises(HostActivityError, match="v2"):
        enroll_host_gate(tmp_path / "host", inventory_path=path, inventory_sha256=digest)
    assert not (tmp_path / "host").exists()


@pytest.mark.parametrize("change", ["digest", "extra", "symlink", "hardlink", "permission"])
def test_gate_substitution_rejects_before_entering_activity(tmp_path, monkeypatch, change):
    root, _, _, _ = _enroll(tmp_path, monkeypatch)
    path = root / "runtime-gate.json"
    if change in {"digest", "extra"}:
        value = json.loads(path.read_bytes())
        value["inventorySha256" if change == "digest" else "unknown"] = "b" * 64
        path.write_text(json.dumps(value))
    elif change == "symlink":
        saved = tmp_path / "other-gate.json"
        path.rename(saved)
        path.symlink_to(saved)
    elif change == "hardlink":
        os.link(path, tmp_path / "other-gate.json")
    else:
        path.chmod(0o644)
    with pytest.raises(HostActivityError), runtime_activity("worker"):
        pytest.fail("invalid gate admitted")


def test_activity_requires_pinned_inventory_and_existing_gate(tmp_path, monkeypatch):
    monkeypatch.setenv(host_gate.HOST_ROOT_ENV, str(tmp_path / "absent"))
    with pytest.raises(HostActivityError, match="pinned"), runtime_activity("worker"):
        pytest.fail("unenrolled activity admitted")
    assert not (tmp_path / "absent").exists()
    root, _, _, _ = _enroll(tmp_path, monkeypatch)
    (root / "runtime-gate.json").unlink()
    with pytest.raises(HostActivityError), runtime_activity("worker"):
        pytest.fail("missing gate admitted")
    assert not (root / "runtime-gate.json").exists()


def test_embedded_journal_requires_context_and_cannot_write_after_it_ends(tmp_path, monkeypatch):
    enrolled = _enroll(tmp_path, monkeypatch)
    path = tmp_path / "supervisor.sqlite3"
    with pytest.raises(HostActivityError, match="admitted runtime context"):
        SupervisorInvocationJournal(path)
    assert not path.exists()
    with runtime_activity("worker"):
        journal = SupervisorInvocationJournal(path)
        assert journal.checkpoint_entry("a" * 64) is None
    with pytest.raises(HostActivityError, match="admitted runtime context"):
        journal.checkpoint_entry("a" * 64)
    with _quiescence(enrolled):
        assert path.is_file()


def test_exception_releases_activity_without_masking_original_failure(tmp_path, monkeypatch):
    enrolled = _enroll(tmp_path, monkeypatch)
    with (
        pytest.raises(LookupError, match="isolated failure"),
        runtime_activity("worker"), host_work(),
    ):
        raise LookupError("isolated failure")
    with _quiescence(enrolled):
        pass


@pytest.mark.asyncio
async def test_child_operation_retains_its_own_lock_until_drained(tmp_path, monkeypatch):
    enrolled = _enroll(tmp_path, monkeypatch)
    started, release = asyncio.Event(), asyncio.Event()

    async def child():
        with host_work():
            started.set()
            await release.wait()

    with runtime_activity("worker"):
        task = asyncio.create_task(child())
        await asyncio.wait_for(started.wait(), timeout=2)
    try:
        with pytest.raises(HostActivityError), _quiescence(enrolled):
            pytest.fail("undrained operation was ignored")
    finally:
        release.set()
        await asyncio.wait_for(task, timeout=2)
    with _quiescence(enrolled):
        pass


def test_default_cp_holds_gate_through_repository_close(tmp_path, monkeypatch):
    settings = _settings(tmp_path / "cp.sqlite3")
    enrolled = _enroll(tmp_path, monkeypatch, role="control-plane", configuration=settings)
    original_close = cp_api.ControlPlaneRepository.close
    observed = []

    def close(repository):
        with pytest.raises(HostActivityError), _quiescence(enrolled):
            pytest.fail("repository closed outside activity")
        observed.append(True)
        return original_close(repository)

    monkeypatch.setattr(cp_api.ControlPlaneRepository, "close", close)
    app = cp_api.create_app(settings)
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        with pytest.raises(HostActivityError), _quiescence(enrolled):
            pytest.fail("serving CP was not excluded")
    assert observed == [True]
    with _quiescence(enrolled):
        pass


def test_default_cp_rejects_exclusive_gate_before_repository_construction(tmp_path, monkeypatch):
    settings = _settings(tmp_path / "uncreated.sqlite3")
    enrolled = _enroll(tmp_path, monkeypatch, role="control-plane", configuration=settings)

    def forbidden(*args, **kwargs):
        pytest.fail("stateful factory reached during checkpoint")

    monkeypatch.setattr(cp_api, "_build_application_context", forbidden)
    with _quiescence(enrolled), pytest.raises(HostActivityError):
        cp_api.create_app(settings)
    assert not (tmp_path / "uncreated.sqlite3").exists()


def test_default_cp_reacquires_gate_before_lifespan_initialization(tmp_path, monkeypatch):
    settings = _settings(tmp_path / "uncreated.sqlite3")
    enrolled = _enroll(tmp_path, monkeypatch, role="control-plane", configuration=settings)
    app = cp_api.create_app(settings)
    with _quiescence(enrolled), pytest.raises(HostActivityError), TestClient(app):
        pytest.fail("lifespan initialized during checkpoint")
    assert not (tmp_path / "uncreated.sqlite3").exists()


def test_actual_supervisor_invocation_and_receipt_are_inside_host_activity(
    tmp_path, monkeypatch, sample_campaign,
):
    from test_supervisor_checkpoint_scheduler import (
        _campaign,
        _graph,
        _invocation_environment,
        _policy,
        _runtime,
        _schedule,
    )

    from pajin.runtime.store import verify_run_integrity
    from pajin.supervision.checkpoint_scheduler import SupervisorCheckpointScheduler

    campaign = _campaign(sample_campaign)
    graph, _, _, collaboration = _graph(campaign)
    runtime = _runtime(campaign, graph, collaboration)
    snapshot, binding, provider, configuration = runtime
    policy = _policy()
    scheduled = _schedule(
        SupervisorCheckpointScheduler(output_root=tmp_path / "schedules", budget_policy=policy),
        runtime, campaign, collaboration, graph,
    )
    enrolled = _enroll(tmp_path, monkeypatch)
    with runtime_activity("worker"):
        invoker, journal, authorities, worker, campaign_budget, dedicated_budget = (
            _invocation_environment(
                tmp_path, campaign, provider, policy, snapshot, binding, configuration,
                collaboration, graph,
            )
        )
    with pytest.raises(HostActivityError):
        asyncio.run(invoker.invoke(scheduled, authorities))
    assert worker.calls == 0
    original_run = worker.run

    async def during_work(*args, **kwargs):
        with pytest.raises(HostActivityError), _quiescence(enrolled):
            pytest.fail("Supervisor Worker entered without activity exclusion")
        return await original_run(*args, **kwargs)

    monkeypatch.setattr(worker, "run", during_work)
    with runtime_activity("worker"):
        first = asyncio.run(invoker.invoke(scheduled, authorities))
        second = asyncio.run(invoker.invoke(scheduled, authorities))
        assert journal.inspect(first.publication.journal_entry.intent.intent_id).state == (
            "terminal-success"
        )
    assert first == second and worker.calls == 1
    assert campaign_budget.model_calls == dedicated_budget.model_calls == 1
    assert verify_run_integrity(first.publication.run_path).seal_count == 2
    with _quiescence(enrolled):
        pass


def test_actual_urgent_producer_applies_cancellation_inside_host_activity(
    tmp_path, monkeypatch, sample_campaign,
):
    from datetime import timedelta

    from test_collaboration_urgent_observation import NOW, _scenario
    from test_urgent_stop_runtime import _alerts, _deployment, _runtime, _submit

    settings, body, digest = _deployment(tmp_path, sample_campaign)
    scenario = _scenario(tmp_path, sample_campaign)
    with TestClient(cp_api.create_app(settings)) as client:
        run_id = _submit(client, body)
        runtime, observation = _runtime(client, sample_campaign, digest, run_id, scenario)
        enrolled = _enroll(tmp_path, monkeypatch)
        with pytest.raises(HostActivityError):
            runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
        assert _alerts(client)["items"] == []
        apply = runtime._service._apply_verified

        def apply_inside_activity(*args, **kwargs):
            with pytest.raises(HostActivityError), _quiescence(enrolled):
                pytest.fail("cancellation committed outside activity exclusion")
            return apply(*args, **kwargs)

        monkeypatch.setattr(runtime._service, "_apply_verified", apply_inside_activity)
        with runtime_activity("worker"):
            first = runtime.admit(observation=observation, decided_at=NOW + timedelta(seconds=6))
            assert runtime.admit(
                observation=observation, decided_at=NOW + timedelta(seconds=7),
            ) == first
        assert first.state == "control-plane-cancelled"
        assert len(_alerts(client)["items"]) == 1
        with _quiescence(enrolled):
            pass


def test_process_exit_releases_kernel_activity_without_stale_pid_recovery(tmp_path):
    script = """
import os, sys
from hashlib import sha256
from pathlib import Path
from pajin.runtime.inventory import RuntimeInventory, fingerprint_component, host_root_digest
from pajin.runtime.host_gate import enroll_host_gate, runtime_activity
base = Path(sys.argv[1])
root, path = base / 'host', base / 'inventory.json'
os.environ['PAJIN_HOST_RUNTIME_ROOT'] = str(root)
inventory = RuntimeInventory(apiVersion='pajin.dev/runtime-inventory/v2',
    hostRootSha256=host_root_digest(root),
    inventoryId='isolated-child', components=(fingerprint_component('worker'),))
path.write_text(inventory.model_dump_json(by_alias=True))
digest = sha256(path.read_bytes()).hexdigest()
os.environ['PAJIN_RUNTIME_INVENTORY_PATH'] = str(path)
os.environ['PAJIN_RUNTIME_INVENTORY_SHA256'] = digest
enroll_host_gate(root, inventory_path=path, inventory_sha256=digest)
with runtime_activity('worker'):
    print(digest, flush=True)
    sys.stdin.readline()
    os._exit(23)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert process.stdout is not None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=15), "child did not acquire its gate"
        digest = process.stdout.readline().strip()
        assert len(digest) == 64
        values = (tmp_path / "host", tmp_path / "inventory.json", digest, None)
        with pytest.raises(HostActivityError), _quiescence(values):
            pytest.fail("another process's shared activity was ignored")
        _, error = process.communicate("exit\n", timeout=10)
        assert process.returncode == 23, error
        with _quiescence(values):
            pass
    finally:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=10)
