import asyncio
import json
from pathlib import Path

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.models import AgentPlan, CampaignManifest, PlannedStep, ToolRequest
from pajin.policy.engine import PolicyEngine
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.local import LocalCampaignRunner


class UnknownToolRuntime(DeterministicAgentRuntime):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        return AgentPlan(
            summary="Attempt an unregistered tool.",
            steps=[
                PlannedStep(
                    title="Unknown tool",
                    rationale="Exercise fail-closed behavior.",
                    request=ToolRequest(
                        agent_id=self.agent_id,
                        tool_id="invented.shell",
                        target=campaign.spec.targets[0].endpoint,
                    ),
                )
            ],
        )


def test_local_vertical_slice_creates_validated_finding_and_report(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert len(outcome.findings) == 1
    assert outcome.findings[0].validated
    assert outcome.report_path.exists()
    report = outcome.report_path.read_text(encoding="utf-8")
    assert "Untrusted instruction triggered an unauthorized tool call" in report

    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    event_types = {event["event_type"] for event in events}
    assert "tool.policy_evaluated" in event_types
    assert "findings.validated" in event_types
    assert "campaign.completed" in event_types


def test_run_store_accepts_relative_output_root(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=Path(".pajin/runs"),
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert outcome.report_path.is_absolute()
    assert outcome.report_path.exists()


def test_unknown_model_generated_tool_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = LocalCampaignRunner(
        agents=UnknownToolRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(sample_campaign))

    assert not outcome.findings
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"policy":"tool-registry"' in events
    assert '"event_type":"tool.failed"' in events
