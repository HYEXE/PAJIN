"""SYS-002 authority and parser regressions; real agent checks live in its explicit probe."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pajin.domain.models import ToolRequest
from pajin.graph.approval import ActionApprovalError
from pajin.graph.authority import ActionPermitError
from pajin.system_read.models import (
    TOOL_ID,
    SystemDeployment,
    SystemInput,
    distribution_metadata,
)
from pajin.system_read.runtime import SystemGateway, dispatch_system_action, prepare_system_action
from pajin.system_read.tool import SystemReadTool
from tests.sys_002_support import fixture_action


def deployment() -> SystemDeployment:
    return SystemDeployment(
        value=SystemInput(target="https://127.0.0.1:8443/v1/os-release", instance="owned-fixture"),
        image_id="sha256:" + "1" * 64,
        proxy_image_id="sha256:" + "2" * 64,
        ca_sha256="3" * 64,
        server_cert_sha256="4" * 64,
        client_cert_sha256="5" * 64,
        agent_sha256="6" * 64,
        client_sha256="7" * 64,
    )


def test_distribution_uses_actual_assignments_without_shell_evaluation():
    assert distribution_metadata(b'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian Linux"\n') == {
        "ID": "debian",
        "VERSION_ID": "13",
        "PRETTY_NAME": "Debian Linux",
    }
    assert (
        distribution_metadata(b'ID=test\nVERSION_ID=1\nPRETTY_NAME="$(do-not-execute)"\n')[
            "PRETTY_NAME"
        ]
        == "$(do-not-execute)"
    )


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"x" * 8193,
        b"ID=one\nID=two\n",
        b"ID=two words\n",
        b"ID=\xff\n",
        b"ID=x\x00\n",
        b'ID=test\nVERSION_ID=1\nPRETTY_NAME="unterminated\n',
    ],
)
def test_invalid_distribution_never_becomes_success(content):
    with pytest.raises(ValueError):
        distribution_metadata(content)


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8443/v1/os-release",
        "https://u:p@host:8443/v1/os-release",
        "https://host:8443/etc/passwd",
        "https://host:8443/v1/os-release?path=/etc/passwd",
        "https://host/v1/os-release",
        "https://host:8443/v1/os-release#fragment",
    ],
)
def test_agent_endpoint_does_not_accept_arbitrary_command_or_path(target):
    with pytest.raises(ValueError):
        SystemInput(target=target, instance="owned")


def test_tool_prepares_only_exact_pinned_agent_and_bounded_lease():
    config = deployment()
    tool = SystemReadTool(config)
    request = ToolRequest(
        agent_id="planner",
        tool_id=TOOL_ID,
        target=config.value.target,
        arguments=config.value.model_dump(),
    )
    job = tool.prepare(request)
    assert job.command == ["system-os-release"] and job.network.value == "none"
    assert len(job.secret_requests) == 1 and job.secret_requests[0].ttl_seconds == 30
    assert "key" not in job.stdin and "certificate" not in job.stdin
    with pytest.raises(ValueError, match="pinned deployment"):
        tool.prepare(request.model_copy(update={"target": "https://outside:8443/v1/os-release"}))


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["signature", "expired", "scope", "agent-pin"])
async def test_current_authority_denies_before_any_worker(tmp_path, change):
    tool = SystemReadTool(deployment())
    action, authority, graph, store = fixture_action(tmp_path, tool, tool.deployment.value)
    gateway = SystemGateway(tool, store, "{}")
    if change == "signature":
        authority.signed.signature = "0" * 128
    elif change == "expired":
        authority.clock = lambda: datetime.now(UTC) + timedelta(days=1)
    elif change == "scope":
        authority.campaign.spec.scope.allow = [tool.deployment.value.target]
    else:
        tool.deployment = tool.deployment.model_copy(update={"agent_sha256": "a" * 64})
    with pytest.raises((ValueError, ActionApprovalError, ActionPermitError)):
        await dispatch_system_action(
            action=action, authority=authority, graph=graph, gateway=gateway, store=store
        )
    assert not (store.path / "authorization.json").exists()
    assert not list((store.path / "evidence").glob("*.json"))


def test_preparation_requires_explicit_connect_scope(tmp_path):
    tool = SystemReadTool(deployment())
    action, authority, graph, store = fixture_action(tmp_path, tool, tool.deployment.value)
    authority.campaign.spec.scope.allow = [tool.deployment.value.target]
    with pytest.raises(ValueError, match="explicit exact Scope"):
        prepare_system_action(
            activation=authority.activation,
            tool=tool,
            value=tool.deployment.value,
            campaign=authority.campaign,
            grant=authority.grant,
            graph=graph,
            store=store,
        )
    assert action.request.tool_id == TOOL_ID
