"""SYS-004 authority and parser regressions; real agent checks live in its explicit probe."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.domain.models import ToolRequest
from pajin.graph.approval import ActionApprovalError
from pajin.graph.authority import ActionPermitError
from pajin.system_aslr.models import (
    TOOL_ID,
    AslrAgentRead,
    AslrDeployment,
    AslrInput,
    aslr_metadata,
)
from pajin.system_aslr.runtime import AslrGateway, dispatch_aslr_action, prepare_aslr_action
from pajin.system_aslr.tool import AslrReadTool
from tests.sys_004_support import fixture_action


def deployment() -> AslrDeployment:
    return AslrDeployment(
        value=AslrInput(target="https://127.0.0.1:8443/v1/aslr", instance="owned-fixture"),
        image_id="sha256:" + "1" * 64,
        proxy_image_id="sha256:" + "2" * 64,
        ca_sha256="3" * 64,
        server_cert_sha256="4" * 64,
        client_cert_sha256="5" * 64,
        agent_sha256="6" * 64,
        client_sha256="7" * 64,
    )


@pytest.mark.parametrize("mode", [0, 1, 2])
def test_aslr_reads_only_the_three_exact_kernel_values(mode):
    assert aslr_metadata(f"{mode}\n".encode()) == {"randomizeVaSpace": mode}


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"2", b"3\n", b"-1\n", b"02\n", b"2\r\n", b" 2\n", b"2\n0\n",
        b"True\n", b"2\x00", b"\xff\n", b"x" * 8193,
    ],
)
def test_invalid_aslr_never_becomes_success(content):
    with pytest.raises(ValueError):
        aslr_metadata(content)


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8443/v1/aslr",
        "https://u:p@host:8443/v1/aslr",
        "https://host:8443/etc/passwd",
        "https://host:8443/v1/aslr?path=/etc/passwd",
        "https://host/v1/aslr",
        "https://host:8443/v1/aslr#fragment",
    ],
)
def test_agent_endpoint_does_not_accept_arbitrary_command_or_path(target):
    with pytest.raises(ValueError):
        AslrInput(target=target, instance="owned")


def test_tool_prepares_only_exact_pinned_agent_and_bounded_lease():
    config = deployment()
    tool = AslrReadTool(config)
    request = ToolRequest(
        agent_id="planner",
        tool_id=TOOL_ID,
        target=config.value.target,
        arguments=config.value.model_dump(),
    )
    job = tool.prepare(request)
    assert job.command == ["system-aslr"] and job.network.value == "none"
    assert len(job.secret_requests) == 1 and job.secret_requests[0].ttl_seconds == 30
    assert "key" not in job.stdin and "certificate" not in job.stdin
    with pytest.raises(ValueError, match="pinned deployment"):
        tool.prepare(request.model_copy(update={"target": "https://outside:8443/v1/aslr"}))


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["signature", "expired", "scope", "agent-pin"])
async def test_current_authority_denies_before_any_worker(tmp_path, change):
    tool = AslrReadTool(deployment())
    action, authority, graph, store = fixture_action(tmp_path, tool, tool.deployment.value)
    gateway = AslrGateway(tool, store, "{}")
    if change == "signature":
        authority.signed.signature = "0" * 128
    elif change == "expired":
        authority.clock = lambda: datetime.now(UTC) + timedelta(days=1)
    elif change == "scope":
        authority.campaign.spec.scope.allow = [tool.deployment.value.target]
    else:
        tool.deployment = tool.deployment.model_copy(update={"agent_sha256": "a" * 64})
    with pytest.raises((ValueError, ActionApprovalError, ActionPermitError)):
        await dispatch_aslr_action(
            action=action, authority=authority, graph=graph, gateway=gateway, store=store
        )
    assert not (store.path / "authorization.json").exists()
    assert not list((store.path / "evidence").glob("*.json"))


def test_preparation_requires_explicit_connect_scope(tmp_path):
    tool = AslrReadTool(deployment())
    action, authority, graph, store = fixture_action(tmp_path, tool, tool.deployment.value)
    authority.campaign.spec.scope.allow = [tool.deployment.value.target]
    with pytest.raises(ValueError, match="explicit exact Scope"):
        prepare_aslr_action(
            activation=authority.activation,
            tool=tool,
            value=tool.deployment.value,
            campaign=authority.campaign,
            grant=authority.grant,
            graph=graph,
            store=store,
        )
    assert action.request.tool_id == TOOL_ID


@pytest.mark.asyncio
async def test_os_release_approval_domain_cannot_authorize_aslr(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from pajin.system_read.runtime import approval_message as old_approval_message

    key = Ed25519PrivateKey.generate()
    tool = AslrReadTool(deployment())
    action, authority, graph, store = fixture_action(
        tmp_path, tool, tool.deployment.value, operator=key
    )
    authority.signed.signature = key.sign(old_approval_message(authority.signed.approval)).hex()
    with pytest.raises((ValueError, ActionApprovalError, ActionPermitError)):
        await dispatch_aslr_action(
            action=action, authority=authority, graph=graph,
            gateway=AslrGateway(tool, store, "{}"), store=store,
        )
    assert not (store.path / "authorization.json").exists()


@pytest.mark.parametrize("change", ["source", "schema", "digest", "base64", "size", "boolean"])
def test_receipt_cannot_alias_os_release_or_uncommitted_bytes(change):
    content = b"2\n"
    value = {
        "schema": "pajin.sys-004.agent-read/v1", "instance": "owned-fixture",
        "requestId": "tool_" + "1" * 32, "agentSha256": "2" * 64,
        "fileSha256": sha256(content).hexdigest(), "fileBytes": 2,
        "fileBase64": base64.b64encode(content).decode(),
        "source": "/proc/sys/kernel/randomize_va_space",
    }
    assert AslrAgentRead.model_validate(value).content() == content
    if change == "source":
        value["source"] = "/usr/lib/os-release"
    elif change == "schema":
        value["schema"] = "pajin.sys-002.agent-read/v1"
    elif change == "digest":
        value["fileSha256"] = "0" * 64
    elif change == "base64":
        value["fileBase64"] += "="
    elif change == "size":
        value["fileBytes"] = 3
    else:
        value["fileBytes"] = True
    with pytest.raises(ValueError):
        AslrAgentRead.model_validate(value).content()


@pytest.mark.parametrize("content", [b"2\n", b"9\n", b"2\n0", b"", b"2"])
def test_agent_uses_only_fixed_read_only_bounded_descriptor(tmp_path, monkeypatch, content):
    spec = importlib.util.spec_from_file_location(
        "pajin_test_aslr_agent", Path("containers/system-aslr/agent.py")
    )
    assert spec is not None and spec.loader is not None
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    fixture = tmp_path / "kernel-fixture"
    fixture.write_bytes(content)
    real_open = os.open
    descriptors = []

    def controlled_open(path, flags):
        assert path == "/proc/sys/kernel/randomize_va_space"
        assert flags == os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptor = real_open(fixture, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(agent.os, "open", controlled_open)
    if content == b"2\n":
        assert agent.read_aslr() == content
    else:
        with pytest.raises(ValueError):
            agent.read_aslr()
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_agent_rejects_a_valid_mode_that_changes_between_reads(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "pajin_test_changing_aslr_agent", Path("containers/system-aslr/agent.py")
    )
    assert spec is not None and spec.loader is not None
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    fixture = tmp_path / "changing-kernel-fixture"
    fixture.write_bytes(b"2\n")
    real_open, real_seek = os.open, os.lseek
    descriptors = []

    def controlled_open(path, flags):
        assert path == "/proc/sys/kernel/randomize_va_space"
        descriptor = real_open(fixture, flags)
        descriptors.append(descriptor)
        return descriptor

    def change_before_second_read(descriptor, offset, whence):
        fixture.write_bytes(b"1\n")
        return real_seek(descriptor, offset, whence)

    monkeypatch.setattr(agent.os, "open", controlled_open)
    monkeypatch.setattr(agent.os, "lseek", change_before_second_read)
    with pytest.raises(ValueError, match="changing ASLR"):
        agent.read_aslr()
    assert fixture.read_bytes() == b"1\n" and len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.parametrize("executions,residue", [(0, False), (4, True), (4, False)])
def test_probe_exit_requires_observed_worker_cleanup(tmp_path, monkeypatch, executions, residue):
    from scripts import operational_system_aslr as probe

    output = tmp_path / "probe"
    image, proxy = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    monkeypatch.setattr(probe.sys, "argv", [
        "probe", "--image-id", image, "--proxy-image-id", proxy, "--output", str(output),
    ])
    monkeypatch.setattr(probe, "inventory", lambda: {"fixture.py": "3" * 64})

    def docker(*args):
        if args[:2] == ("image", "inspect"):
            return args[2]
        return "remaining" if residue and any(
            arg.startswith("label=pajin.execution-id=") for arg in args
        ) else ""

    def run(*args, **kwargs):
        for index in range(executions):
            (output / f"{index}-outcome.json").write_text(json.dumps({
                "worker_result": {"execution_id": str(index)},
            }))
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(probe, "docker", docker)
    monkeypatch.setattr(probe.subprocess, "run", run)
    expected = executions == 4 and not residue
    assert probe.main() == (0 if expected else 1)
    assert json.loads((output / "report.json").read_text())["complete"] is expected
