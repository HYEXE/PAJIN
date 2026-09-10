from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

import pajin.application_elf.report as report_module
from pajin.application_elf.models import ELFRunReference
from pajin.application_elf.report import ELFReportTrust, compare_elf_runs, read_elf_run
from pajin.application_elf.runtime import dispatch_elf_action
from pajin.runtime.store import RunIntegrityError
from tests.test_application_elf import setup_action


@pytest.mark.asyncio
async def test_unknown_cleanup_is_not_success_and_reader_requires_independent_pins(
    tmp_path,
    monkeypatch,
):
    action, authority, graph, store, gateway, worker = setup_action(tmp_path)
    # This is a synthetic failure receipt for reader unit coverage. Only the separate real-Docker
    # suite can supply live success/confinement evidence; no success is injected here.
    worker.name = "docker"
    monkeypatch.setattr(report_module, "observe_worker_absence", lambda result: "unknown")
    outcome = await dispatch_elf_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    policy, keys, releases = authority.activation.lifecycle.verification_material()
    trust = ELFReportTrust(
        image_id=authority.tool.image_id,
        parser_sha256=authority.tool.parser_sha256,
        operator_public_key=authority.public_key.hex(),
        operator_id=authority.operator_id,
        policy=policy,
        keys=keys,
        releases=releases,
        release=authority.activation.release,
    )
    reference = report_module.seal_elf_execution(store, outcome, trust)
    root = store.path.parent.parent
    result = read_elf_run(root, reference, trust)
    assert result["cleanup"] == "unknown" and result["complete"] is False
    assert result["findingAuthority"] is False and result["header"] is None
    with pytest.raises(ValueError, match="separately sealed"):
        compare_elf_runs(root, reference, reference, trust)
    with pytest.raises(ValueError, match="pinned root"):
        read_elf_run(root, ELFRunReference(run_id=reference.run_id, root_digest="0" * 64), trust)
    changed_trust = ELFReportTrust.model_validate(
        {**trust.model_dump(), "operator_public_key": "f" * 64}
    )
    with pytest.raises(ValueError, match="independent deployment trust"):
        read_elf_run(root, reference, changed_trust)
    evidence = store.path / "evidence" / (action.request.request_id + ".json")
    original = evidence.read_text()
    evidence.write_text(original.replace('"exit_code": 2', '"exit_code": 0'))
    assert evidence.read_text() != original
    with pytest.raises(RunIntegrityError):
        read_elf_run(root, reference, trust)


@pytest.mark.parametrize(
    "returncode,stdout,expected",
    (
        (0, b"", "absent"),
        (0, b"aabbcc\n", "present"),
        (1, b"", "unknown"),
    ),
)
def test_cleanup_observation_does_not_confuse_failure_with_absence(
    monkeypatch,
    returncode,
    stdout,
    expected,
):
    observed = []

    def run(command, **kwargs):
        observed.append(command)
        return subprocess.CompletedProcess(command, returncode, stdout, b"")

    monkeypatch.setattr(report_module.subprocess, "run", run)
    assert (
        report_module.observe_worker_absence(
            SimpleNamespace(backend="docker", execution_id="exec_app002")
        )
        == expected
    )
    assert observed[0][1:3] == ["ps", "--all"]
    assert "label=pajin.execution-id=exec_app002" in observed[0]


def test_unavailable_cleanup_observer_and_uncreated_worker_are_distinct(monkeypatch):
    def failed(*args, **kwargs):
        raise subprocess.TimeoutExpired("docker", 15)

    monkeypatch.setattr(report_module.subprocess, "run", failed)
    assert (
        report_module.observe_worker_absence(
            SimpleNamespace(backend="docker", execution_id="exec_app002")
        )
        == "unknown"
    )
    assert report_module.observe_worker_absence(None) == "not-created"
