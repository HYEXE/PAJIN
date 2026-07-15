import asyncio
import json
from pathlib import Path

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import ToolRequest
from pajin.domain.validation import FindingDisposition, ValidationReasonCode
from pajin.policy.engine import PolicyEngine
from pajin.runtime.worker import NetworkMode, SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import demo_mcp_tool
from pajin.workflow.local import LocalCampaignRunner


def test_registered_mcp_tool_exposes_only_catalog_identifiers_to_worker() -> None:
    tool = demo_mcp_tool()
    request = ToolRequest(
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://mcp.internal/demo-security/inspect-text",
        method="POST",
        arguments={"text": "test"},
    )

    job = tool.prepare(request)
    payload = json.loads(job.stdin)

    assert job.command == ["mcp-call"]
    assert job.network is NetworkMode.NONE
    assert payload == {
        "serverId": "demo-security",
        "toolName": "inspect_text",
        "arguments": {"text": "test"},
    }
    assert "demo_mcp_server.py" not in job.stdin
    assert "/usr/local/bin/python" not in job.stdin


def test_registered_mcp_workflow_preserves_candidate_without_confirming_it(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/mcp-tool.yaml"))
    registry = ToolRegistry()
    registry.register(demo_mcp_tool())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.findings == []
    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    assert outcome.validation.decisions[0].reason_codes == [
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
    ]
    evidence = json.loads(
        next((outcome.run_path / "evidence").glob("*.json")).read_text(encoding="utf-8")
    )
    assert evidence["workerJob"]["command"] == ["mcp-call"]
    assert evidence["workerJob"]["network"] == "none"
