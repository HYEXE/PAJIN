import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.discovery import (
    DiscoveryAdapterRegistry,
    MCPBoundarySurfaceAdapter,
    RegisteredMCPBoundaryReconPlanner,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import demo_mcp_discovery_tool


def _request(campaign: CampaignManifest) -> ToolRequest:
    tool = demo_mcp_discovery_tool()
    return (
        RegisteredMCPBoundaryReconPlanner(
            tool=tool,
            target_id=campaign.spec.targets[0].id,
        )
        .plan(campaign)
        .request
    )


def _result(campaign: CampaignManifest) -> ToolResult:
    tool = demo_mcp_discovery_tool()
    request = _request(campaign)
    worker_result = asyncio.run(SimulatedWorkerBackend().run(tool.prepare(request)))
    result = tool.interpret(request, worker_result)
    assert result.success
    return result


def test_mcp_boundary_adapter_emits_only_non_executable_locators(
    sample_campaign: CampaignManifest,
) -> None:
    tool = demo_mcp_discovery_tool()
    request = _request(sample_campaign)
    result = _result(sample_campaign)
    adapter = MCPBoundarySurfaceAdapter(tool=tool)

    candidates = adapter.extract_surfaces(request, result)
    locator_payloads = [candidate.locator.model_dump(mode="json") for candidate in candidates]
    serialized = json.dumps(locator_payloads, sort_keys=True)

    assert [payload["kind"] for payload in locator_payloads] == [
        "mcp-server",
        "mcp-tool",
        "mcp-tool",
        "mcp-url-tool",
        "mcp-resource",
        "mcp-resource-template",
        "mcp-prompt",
    ]
    assert locator_payloads[0] == {
        "kind": "mcp-server",
        "server_id": "demo-security",
        "protocol_version": "2025-06-18",
        "capabilities": ["prompts", "resources", "tools"],
    }
    assert locator_payloads[3]["tool_name"] == "inspect_url"
    assert locator_payloads[3]["url_arguments"] == [{"name": "url", "required": True}]
    assert locator_payloads[-1]["arguments"] == [{"name": "text", "required": True}]
    assert "pajin://policy" not in serialized
    assert "pajin://guidance/{topic}" not in serialized
    assert "inputSchema" not in serialized
    assert "description" not in serialized.lower()
    assert "command" not in serialized.lower()


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-server",
        "raw-resource-uri",
        "raw-description",
        "unsorted-capabilities",
        "duplicate-tool",
        "capability-contradiction",
        "url-value",
        "url-argument-coercion",
    ],
)
def test_mcp_boundary_adapter_rejects_forged_or_noncanonical_data(
    sample_campaign: CampaignManifest,
    mutation: str,
) -> None:
    tool = demo_mcp_discovery_tool()
    request = _request(sample_campaign)
    result = _result(sample_campaign)
    data = json.loads(json.dumps(result.data))
    if mutation == "wrong-server":
        data["mcpServerId"] = "other-server"
    elif mutation == "raw-resource-uri":
        data["resources"][0]["uri"] = "pajin://policy"
    elif mutation == "raw-description":
        data["tools"][0]["description"] = "untrusted annotation"
    elif mutation == "unsorted-capabilities":
        data["capabilities"] = ["tools", "resources", "prompts"]
    elif mutation == "duplicate-tool":
        data["tools"].append(dict(data["tools"][0]))
    elif mutation == "url-value":
        data["tools"][1]["urlArguments"][0]["value"] = "http://internal.invalid"  # type: ignore[index]
    elif mutation == "url-argument-coercion":
        data["tools"][1]["urlArguments"][0]["required"] = 1  # type: ignore[index]
    else:
        data["capabilities"] = ["prompts", "resources"]
    now = datetime.now(UTC)
    forged = ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        data=data,
    )

    with pytest.raises(ValueError):
        MCPBoundarySurfaceAdapter(tool=tool).extract_surfaces(request, forged)


def test_mcp_boundary_adapter_registration_binds_all_surface_kinds(
    sample_campaign: CampaignManifest,
) -> None:
    del sample_campaign
    tool = demo_mcp_discovery_tool()
    tools = ToolRegistry()
    tools.register(tool)
    adapter = MCPBoundarySurfaceAdapter(tool=tool)
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])

    definition = registry.definitions()[0]

    assert definition.supported_surface_kinds == (
        "mcp-prompt",
        "mcp-resource",
        "mcp-resource-template",
        "mcp-server",
        "mcp-tool",
        "mcp-url-tool",
    )
    context = adapter.stable_execution_context()
    assert context["serverId"] == "demo-security"
    assert context["retainsRawResourceUris"] is False
    assert context["retainsRawSchemas"] is False
    assert context["retainsURLArgumentNames"] is True
    assert context["retainsDescriptions"] is False
    assert context["retainsPromptValues"] is False


def test_mcp_boundary_recon_seals_admits_and_projects_all_interfaces(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    tool = demo_mcp_discovery_tool()
    tools = ToolRegistry()
    tools.register(tool)
    adapter = MCPBoundarySurfaceAdapter(tool=tool)
    adapter_registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=adapter_registry,
        adapter_references=[
            definition.reference() for definition in adapter_registry.definitions()
        ],
    )
    runner = SingleReconWaveRunner(
        planner=RegisteredMCPBoundaryReconPlanner(
            tool=tool,
            target_id=sample_campaign.spec.targets[0].id,
        ),
        producer=producer,
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert verify_run_integrity(outcome.source_run_path).valid
    assert verify_run_integrity(outcome.projection_run_path).valid
    assert sorted(surface.locator.kind for surface in outcome.surface_set.surfaces) == [
        "mcp-prompt",
        "mcp-resource",
        "mcp-resource-template",
        "mcp-server",
        "mcp-tool",
        "mcp-tool",
        "mcp-url-tool",
    ]
    evidence = json.loads(
        next((outcome.source_run_path / "evidence").glob("*.json")).read_text(encoding="utf-8")
    )
    evidence_text = json.dumps(evidence, sort_keys=True)
    assert evidence["workerJob"]["command"] == ["mcp-discover"]
    assert "stdin" not in evidence["workerJob"]
    assert len(evidence["workerJob"]["stdinSha256"]) == 64
    assert evidence["request"]["arguments"] == {}
    assert evidence["result"]["data"]["mcpServerId"] == "demo-security"
    assert "pajin://policy" not in evidence_text
    assert "pajin://guidance/{topic}" not in evidence_text
