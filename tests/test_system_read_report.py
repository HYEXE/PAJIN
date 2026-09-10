"""Independent trust, tamper and unknown-cleanup regressions; no live success is synthesized."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

import pajin.system_read.report as reporting
from pajin.runtime.store import RunIntegrityError
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.system_read.models import SystemRunReference
from pajin.system_read.report import SystemReportTrust, compare_system_runs, read_system_run
from pajin.system_read.runtime import SystemGateway, dispatch_system_action
from pajin.system_read.tool import SystemReadTool
from tests.sys_002_support import fixture_action
from tests.test_system_read import deployment


class FailedBackend:
    """Synthetic failure only; cannot prove authenticated execution or resource absence."""

    name = "docker"

    async def run(self, job, *, secrets=()):
        assert len(secrets) == 1
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend=self.name,
            status=WorkerStatus.FAILED,
            exit_code=70,
            stderr="synthetic failure",
            started_at=now,
            finished_at=now,
        )


@pytest.mark.asyncio
async def test_unknown_cleanup_failure_and_independent_pins(tmp_path, monkeypatch):
    tool = SystemReadTool(deployment())
    action, authority, graph, store = fixture_action(tmp_path, tool, tool.deployment.value)
    gateway = SystemGateway(tool, store, "{}")
    gateway._worker = FailedBackend()
    monkeypatch.setattr(reporting, "observe_worker_absence", lambda result: "unknown")
    outcome = await dispatch_system_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    assert outcome is not None and not outcome.result.success
    policy, keys, releases = authority.activation.lifecycle.verification_material()
    trust = SystemReportTrust(
        deployment=tool.deployment,
        operator_public_key=authority.public_key.hex(),
        operator_id=authority.operator_id,
        policy=policy,
        keys=keys,
        releases=releases,
        release=authority.activation.release,
    )
    reference = reporting.seal_system_execution(store, outcome, trust)
    root = store.path.parent.parent
    result = read_system_run(root, reference, trust)
    assert result["cleanup"] == "unknown" and result["complete"] is False
    assert result["findingAuthority"] is False and result["distribution"] is None
    with pytest.raises(ValueError, match="separately sealed"):
        compare_system_runs(root, reference, reference, trust)
    with pytest.raises(ValueError, match="pinned root"):
        read_system_run(
            root, SystemRunReference(run_id=reference.run_id, root_digest="0" * 64), trust
        )
    with pytest.raises(ValueError, match="independent deployment trust"):
        read_system_run(root, reference, trust.model_copy(update={"operator_public_key": "a" * 64}))
    evidence = store.path / "evidence" / (action.request.request_id + ".json")
    original = evidence.read_text()
    evidence.write_text(original.replace('"exit_code": 70', '"exit_code": 0'))
    assert evidence.read_text() != original
    with pytest.raises(RunIntegrityError):
        read_system_run(root, reference, trust)


@pytest.mark.parametrize("network_status,expected", [(0, "absent"), (1, "unknown"), (2, "present")])
def test_cleanup_observes_proxy_network_separately(monkeypatch, network_status, expected):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[1:3] == ["network", "ls"]:
            return subprocess.CompletedProcess(
                command, int(network_status == 1), b"network" if network_status == 2 else b"", b""
            )
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(reporting.subprocess, "run", run)
    result = SimpleNamespace(backend="docker", execution_id="exec_sys002")
    assert reporting.observe_worker_absence(result) == expected
    assert len(calls) == 2
    assert all("label=pajin.execution-id=exec_sys002" in call for call in calls)
