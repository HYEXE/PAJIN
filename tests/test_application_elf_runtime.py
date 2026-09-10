from __future__ import annotations

import importlib.util
import os
from types import SimpleNamespace

import pytest

from pajin.application_elf.models import ELFRuntimeObservation
from pajin.application_elf.runtime import ELFGateway, dispatch_elf_action, prepare_elf_action
from pajin.application_elf.tool import ELFHeaderTool
from pajin.graph import ActionApprovalError
from pajin.runtime.store import RunStore
from tests.app_002_support import private_custody, seeded_elf
from tests.test_application_elf import setup_action


@pytest.fixture
def runtime_files(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "app_002_entry", "containers/application-elf/entry.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for directory in (
        "proc/self",
        "proc/net",
        "sys/class/net/lo",
        "sys/class/net/dormant-test-link",
    ):
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)
    (tmp_path / "proc/self/status").write_text("CapEff:\t0000000000000000\nNoNewPrivs:\t1\n")
    (tmp_path / "proc/net/route").write_text("Iface\tDestination\tGateway\n")
    (tmp_path / "proc/net/ipv6_route").write_text("0000 00 0000 lo\n")
    (tmp_path / "sys/class/net/lo/flags").write_text("0x9\n")
    (tmp_path / "sys/class/net/dormant-test-link/flags").write_text("0x80\n")
    (tmp_path / "sys/class/net/non-interface-metadata").write_text("")
    (tmp_path / "proc/mounts").write_text(
        "tmpfs /workspace tmpfs rw,noexec,nosuid,nodev 0 0\n"
        "tmpfs /tmp tmpfs rw,noexec,nosuid,nodev 0 0\n"
    )
    monkeypatch.setattr(module, "Path", lambda path: tmp_path / path.removeprefix("/"))
    monkeypatch.setattr(module.os, "statvfs", lambda path: SimpleNamespace(f_flag=os.ST_RDONLY))
    return module, tmp_path


def test_inactive_links_are_observed_without_confusing_them_with_active_network(runtime_files):
    entry, _ = runtime_files
    observed = entry.observe_runtime()
    assert observed["activeInterfaces"] == ["lo"]
    assert observed["inactiveInterfaceCount"] == 1 and observed["nonLoopbackRoutes"] == 0
    ELFRuntimeObservation.model_validate(observed)


@pytest.mark.parametrize(
    "case",
    (
        "active-link",
        "ipv4-route",
        "ipv6-route",
        "capability",
        "privileges",
        "exec-mount",
        "writable-root",
    ),
)
def test_observed_confinement_failure_is_rejected(runtime_files, monkeypatch, case):
    entry, root = runtime_files
    if case == "active-link":
        (root / "sys/class/net/dormant-test-link/flags").write_text("0x81\n")
    elif case == "ipv4-route":
        (root / "proc/net/route").write_text("Iface Destination Gateway\ndormant-test-link 0 0\n")
    elif case == "ipv6-route":
        (root / "proc/net/ipv6_route").write_text("0000 00 0000 dormant-test-link\n")
    elif case == "capability":
        (root / "proc/self/status").write_text("CapEff:\t0000000000001000\nNoNewPrivs:\t1\n")
    elif case == "privileges":
        (root / "proc/self/status").write_text("CapEff:\t0000000000000000\nNoNewPrivs:\t0\n")
    elif case == "exec-mount":
        (root / "proc/mounts").write_text(
            "tmpfs /workspace tmpfs rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n"
        )
    else:
        monkeypatch.setattr(entry.os, "statvfs", lambda path: SimpleNamespace(f_flag=0))
    with pytest.raises(ValueError, match="confinement"):
        entry.observe_runtime()


@pytest.mark.parametrize(
    "field,value",
    (
        ("rootReadOnly", 1),
        ("effectiveCapabilities", False),
        ("noNewPrivileges", True),
        ("nonLoopbackRoutes", False),
    ),
)
def test_runtime_output_does_not_coerce_boolean_or_numeric_claims(runtime_files, field, value):
    raw = {**runtime_files[0].observe_runtime(), field: value}
    with pytest.raises(ValueError):
        ELFRuntimeObservation.model_validate(raw)


def test_fifo_substitution_does_not_block_or_read_an_unbounded_stream(tmp_path):
    custody, value = private_custody(tmp_path / "custody", seeded_elf())
    path = custody.directory / (value.artifact_sha256 + ".elf")
    path.rename(tmp_path / "retained-original.elf")
    os.mkfifo(path, 0o600)
    with pytest.raises(ValueError, match="byte contract"):
        custody.read(value)


def test_a_run_cannot_prepare_a_second_independent_budget_envelope(tmp_path):
    action, authority, graph, store, *_ = setup_action(tmp_path)
    with pytest.raises((FileExistsError, ValueError)):
        prepare_elf_action(
            activation=authority.activation,
            tool=authority.tool,
            value=authority.tool.validate_request(action.request),
            campaign=authority.campaign,
            grant=authority.grant,
            graph=graph,
            store=store,
        )
    assert len(graph.snapshot_store.snapshots()) == 1
    assert graph.permit_store.permits() == ()


@pytest.mark.parametrize("field", ("image_id", "parser_sha256"))
def test_replacement_tool_context_is_rejected_before_preparing_intent(tmp_path, field):
    action, authority, graph, *_ = setup_action(tmp_path)
    replacement = ELFHeaderTool(
        authority.tool.custody,
        image_id=authority.tool.image_id,
        parser_sha256=authority.tool.parser_sha256,
    )
    setattr(replacement, field, "sha256:" + "d" * 64 if field == "image_id" else "d" * 64)
    store = RunStore.create(tmp_path / "other-runs", authority.campaign.metadata.name)
    with pytest.raises(ValueError, match=r"ELF Tool.*activated"):
        prepare_elf_action(
            activation=authority.activation,
            tool=replacement,
            value=replacement.validate_request(action.request),
            campaign=authority.campaign,
            grant=authority.grant,
            graph=graph,
            store=store,
        )
    assert not (store.path / "app-002-plan-reservation.json").exists()
    assert len(graph.snapshot_store.snapshots()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ("image_id", "parser_sha256"))
async def test_replacement_tool_context_is_rejected_before_permit_and_worker(tmp_path, field):
    action, authority, graph, store, _, worker = setup_action(tmp_path)
    replacement = ELFHeaderTool(
        authority.tool.custody,
        image_id=authority.tool.image_id,
        parser_sha256=authority.tool.parser_sha256,
    )
    setattr(replacement, field, "sha256:" + "d" * 64 if field == "image_id" else "d" * 64)
    authority.tool = replacement
    gateway = ELFGateway(replacement, store)
    gateway._worker = worker
    with pytest.raises(ActionApprovalError, match="input authority rejected") as caught:
        await dispatch_elf_action(
            action=action, authority=authority, graph=graph, gateway=gateway, store=store
        )
    assert isinstance(caught.value.__cause__, ValueError)
    assert "ELF Tool differs from the activated code authority" in str(caught.value.__cause__)
    assert worker.calls == 0 and graph.permit_store.permits() == ()
    assert not (store.path / "authorization.json").exists()
