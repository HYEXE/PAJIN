import asyncio
import json
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.models import AgentPlan, CampaignManifest, PlannedStep, ToolRequest
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import CancellationKind, ExecutionCancellationContext
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerResult,
)
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


class BlockingWorker:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def run(
        self,
        _job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        assert not secrets
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("blocking Worker unexpectedly resumed")


@pytest.mark.asyncio
async def test_local_runner_seals_cleanup_receipt_on_cooperative_cancellation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = BlockingWorker()
    cancellation = ExecutionCancellationContext(
        job_id="job_" + "1" * 32,
        control_plane_run_id="run_" + "2" * 32,
    )
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )
    execution = asyncio.create_task(
        runner.run(sample_campaign, cancellation=cancellation)
    )
    await asyncio.wait_for(worker.started.wait(), timeout=1)

    cancellation.cancel(CancellationKind.RUN_CANCELLED, "Control Plane fence observed")
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(execution, timeout=1)

    assert worker.cancelled
    binding = cancellation.binding
    assert binding is not None
    receipt = json.loads((binding.path / "cancellation.json").read_text(encoding="utf-8"))
    assert receipt["cancellation"]["kind"] == "run-cancelled"
    assert receipt["cancellation"]["cleanupStatus"] == "cleanup-completed"
    assert receipt["resourceCleanupAttested"] is False
    assert receipt["externalSideEffectsReverted"] is False
    events = (binding.path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"worker.cancelled"' in events
    assert '"event_type":"execution.cleanup-completed"' in events
    assert '"event_type":"campaign.cancelled"' in events
    assert verify_run_integrity(binding.path).valid


@pytest.mark.asyncio
async def test_pre_cancelled_context_blocks_local_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = BlockingWorker()
    cancellation = ExecutionCancellationContext()
    cancellation.cancel(CancellationKind.RUN_CANCELLED, "cancelled before dispatch")
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    with pytest.raises(asyncio.CancelledError):
        await runner.run(sample_campaign, cancellation=cancellation)

    assert not worker.started.is_set()
    binding = cancellation.binding
    assert binding is not None
    assert (binding.path / "cancellation.json").is_file()
    assert verify_run_integrity(binding.path).valid


@pytest.mark.asyncio
async def test_direct_task_cancellation_uses_caller_source(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    worker = BlockingWorker()
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )
    execution = asyncio.create_task(runner.run(sample_campaign))
    await asyncio.wait_for(worker.started.wait(), timeout=1)

    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    receipt = json.loads((run_path / "cancellation.json").read_text(encoding="utf-8"))
    assert receipt["cancellation"]["kind"] == "caller-cancelled"
    assert verify_run_integrity(run_path).valid


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
