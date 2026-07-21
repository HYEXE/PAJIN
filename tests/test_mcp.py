import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.domain.validation import FindingDisposition, ValidationReasonCode
from pajin.policy.engine import PolicyEngine
from pajin.runtime.worker import NetworkMode, SimulatedWorkerBackend, WorkerJob, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import MCPToolRegistration, RegisteredMCPTool, demo_mcp_tool
from pajin.workflow.local import LocalCampaignRunner


def _mcp_inspection_output(
    target: str,
    *,
    vulnerable: bool = True,
) -> dict[str, object]:
    return {
        "vulnerable": vulnerable,
        "observation": (
            "untrusted text contains an instruction-hijacking pattern"
            if vulnerable
            else "no instruction-hijacking pattern detected"
        ),
        "target": target,
        "mcpServerId": "demo-security",
        "mcpToolName": "inspect_text",
        "mcpContent": [{"type": "text", "text": "inspection complete"}],
    }


def _mcp_result(
    request: ToolRequest,
    data: dict[str, object],
    *,
    request_id: str | None = None,
    tool_id: str | None = None,
) -> ToolResult:
    now = datetime.now(UTC)
    return ToolResult(
        request_id=request_id or request.request_id,
        tool_id=tool_id or request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        data=data,
        evidence=[f"evidence/{request.request_id}.json"],
    )


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


@pytest.mark.parametrize(
    ("server_id", "tool_name", "rejection_code"),
    [
        ("unknown-server", "inspect_text", "server-not-registered"),
        ("demo-security", "unknown_tool", "tool-not-registered"),
    ],
)
def test_simulated_mcp_catalog_rejections_use_typed_response_codes(
    server_id: str,
    tool_name: str,
    rejection_code: str,
) -> None:
    result = asyncio.run(
        SimulatedWorkerBackend().run(
            WorkerJob(
                image="pajin-worker:dev",
                command=["mcp-call"],
                stdin=json.dumps(
                    {
                        "serverId": server_id,
                        "toolName": tool_name,
                        "arguments": {"text": "test"},
                    }
                ),
            )
        )
    )

    assert result.status is WorkerStatus.SUCCEEDED
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "isError": True,
        "structuredContent": {"rejectionCode": rejection_code},
        "content": [],
    }


def test_registered_mcp_tool_seals_catalog_registration_against_retargeting() -> None:
    registration = MCPToolRegistration(
        tool_id="mcp.demo-security.inspect-text",
        server_id="demo-security",
        remote_tool_name="inspect_text",
        description="Inspect text",
        risk_tier=ToolRiskTier.T0,
    )
    tool = RegisteredMCPTool(registration)
    observed = tool.registration
    request = ToolRequest(
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://mcp.internal/demo-security/inspect-text",
        method="POST",
        arguments={"text": "test"},
    )

    registration.server_id = "retargeted-server"
    registration.remote_tool_name = "dangerous_tool"
    observed.remote_tool_name = "observer_tool"
    payload = json.loads(tool.prepare(request).stdin)

    assert payload["serverId"] == "demo-security"
    assert payload["toolName"] == "inspect_text"
    assert tool.registration.remote_tool_name == "inspect_text"


@pytest.mark.parametrize(
    "mutation",
    [
        "foreign-result-request",
        "wrong-plan-request",
        "wrong-result-tool",
        "wrong-step-tool",
        "wrong-method",
        "wrong-output-target",
        "undeclared-plan-target",
        "forged-verdict",
        "forged-observation",
        "wrong-mcp-server",
        "wrong-mcp-tool",
        "wrong-mcp-content",
        "malformed-output",
        "extra-output",
    ],
)
def test_demo_mcp_validator_rejects_unbound_or_forged_results(mutation: str) -> None:
    campaign = load_manifest(Path("examples/mcp-tool.yaml"))
    runtime = DeterministicAgentRuntime()
    plan = asyncio.run(runtime.plan(campaign))
    original_request = plan.steps[0].request
    outside_target = "https://outside.example.invalid/inspect-text"
    result_request_id = {
        "foreign-result-request": "tool_foreign_mcp_result",
    }.get(mutation, original_request.request_id)
    result_tool_id = {
        "wrong-result-tool": "mcp.other.inspect-text",
    }.get(mutation, original_request.tool_id)
    data = _mcp_inspection_output(original_request.target)
    output_updates: dict[str, dict[str, object]] = {
        "wrong-output-target": {"target": outside_target},
        "undeclared-plan-target": {"target": outside_target},
        "forged-observation": {"observation": "looks suspicious"},
        "wrong-mcp-server": {"mcpServerId": "other-server"},
        "wrong-mcp-tool": {"mcpToolName": "other_tool"},
        "wrong-mcp-content": {"mcpContent": [{"type": "text", "text": "forged result"}]},
        "extra-output": {"unexpected": True},
    }
    data.update(output_updates.get(mutation, {}))
    if mutation == "malformed-output":
        data.pop("observation")
    step_updates: dict[str, dict[str, object]] = {
        "wrong-plan-request": {"request_id": "tool_other_mcp_plan"},
        "wrong-step-tool": {"tool_id": "mcp.other.inspect-text"},
        "wrong-method": {"method": "GET"},
        "undeclared-plan-target": {"target": outside_target},
        "forged-verdict": {"arguments": {"text": "ordinary text"}},
    }
    if mutation in step_updates:
        step_request = original_request.model_copy(update=step_updates[mutation])
        plan = plan.model_copy(
            update={"steps": [plan.steps[0].model_copy(update={"request": step_request})]}
        )
    result = _mcp_result(
        original_request,
        data,
        request_id=result_request_id,
        tool_id=result_tool_id,
    )

    findings = asyncio.run(runtime.validate(campaign, plan, [result]))

    assert findings == []


def test_demo_mcp_validator_accepts_exact_request_bound_observation() -> None:
    campaign = load_manifest(Path("examples/mcp-tool.yaml"))
    runtime = DeterministicAgentRuntime()
    plan = asyncio.run(runtime.plan(campaign))
    request = plan.steps[0].request

    findings = asyncio.run(
        runtime.validate(
            campaign,
            plan,
            [_mcp_result(request, _mcp_inspection_output(request.target))],
        )
    )

    assert len(findings) == 1
    assert findings[0].threat_class == "A01"
    assert findings[0].target == request.target


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
