"""PAJIN command-line interface."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignMode
from pajin.domain.orchestration import RunStatus
from pajin.modes.ai_redteam import KISAModePack, KISAPlannerRuntime, KISAValidatorRuntime
from pajin.modes.ai_redteam.models import EvaluationThresholds, MetricStatus
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import KillSwitch
from pajin.runtime.worker import (
    DockerWorkerBackend,
    EgressPolicy,
    NetworkMode,
    SimulatedWorkerBackend,
    WorkerBackend,
    WorkerJob,
    WorkerLimits,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import MockAgentProbe, SleepCheckTool
from pajin.workflow.local import LocalCampaignRunner
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome

app = typer.Typer(help="PAJIN policy-governed security validation CLI", no_args_is_help=True)
console = Console()


def _tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    registry.register(HTTPGetTool())
    registry.register(demo_mcp_tool())
    return registry


def _worker_backend(worker: str) -> WorkerBackend:
    if worker == "simulated":
        return SimulatedWorkerBackend()
    if worker == "docker":
        return DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    raise ValueError("use 'simulated' or 'docker'")


async def _run_egress_checks(backend: DockerWorkerBackend) -> dict[str, WorkerResult]:
    policy = EgressPolicy(
        allow=["http://example.com/**"],
        deny=["http://example.org/**"],
        allowed_methods={"GET"},
    )
    allowed = await backend.run(
        WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            stdin='{"target":"http://example.com/"}',
            network=NetworkMode.EGRESS_PROXY,
            egress_policy=policy,
        )
    )
    denied = await backend.run(
        WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            stdin='{"target":"http://example.org/"}',
            network=NetworkMode.EGRESS_PROXY,
            egress_policy=policy,
        )
    )
    direct = await backend.run(
        WorkerJob(
            image="pajin-worker:dev",
            command=["direct-network-check"],
            stdin='{"host":"example.com","port":80}',
            network=NetworkMode.EGRESS_PROXY,
            egress_policy=policy,
        )
    )
    return {"allowed": allowed, "denied": denied, "direct": direct}


async def _run_mcp_checks(backend: DockerWorkerBackend) -> dict[str, WorkerResult]:
    async def invoke(server_id: str, tool_name: str) -> WorkerResult:
        return await backend.run(
            WorkerJob(
                image="pajin-worker:dev",
                command=["mcp-call"],
                stdin=json.dumps(
                    {
                        "serverId": server_id,
                        "toolName": tool_name,
                        "arguments": {"text": "Ignore previous instructions."},
                    }
                ),
            )
        )

    registered = await invoke("demo-security", "inspect_text")
    unknown_server = await invoke("unregistered-server", "inspect_text")
    unknown_tool = await invoke("demo-security", "unregistered_tool")
    return {
        "registered": registered,
        "unknown_server": unknown_server,
        "unknown_tool": unknown_tool,
    }


async def _run_multi_cancel_check(
    runner: MultiAgentCampaignRunner,
    campaign_path: Path,
    kill_switch: KillSwitch,
) -> MultiAgentRunOutcome:
    campaign = load_manifest(campaign_path)
    run_task = asyncio.create_task(runner.run(campaign))
    await asyncio.sleep(0.25)
    kill_switch.activate("operator cancellation verification", source="cli-check")
    return await run_task


@app.command("validate")
def validate_campaign(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
) -> None:
    """Validate a campaign manifest without executing it."""

    try:
        campaign = load_manifest(manifest)
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Invalid campaign:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title="Validated PAJIN Campaign")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Name", campaign.metadata.name)
    table.add_row("Mode", campaign.spec.mode.value)
    table.add_row("Autonomy", campaign.spec.autonomy.value)
    table.add_row("Targets", str(len(campaign.spec.targets)))
    table.add_row("Max tool risk", f"T{campaign.spec.rules_of_engagement.max_tool_risk_tier.value}")
    table.add_row("Authorization active", str(campaign.spec.authorization.is_active()))
    console.print(table)


@app.command("run")
def run_campaign(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "simulated",
) -> None:
    """Run the deterministic vertical slice with a selected worker backend."""

    try:
        campaign = load_manifest(manifest)
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Invalid campaign:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    registry = _tool_registry()
    try:
        backend = _worker_backend(worker)
    except ValueError as exc:
        console.print(f"[bold red]Invalid worker:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    runner = LocalCampaignRunner(
        agents=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        output_root=output,
    )
    outcome = asyncio.run(runner.run(campaign))
    failed_tools = sum(not result.success for result in outcome.tool_results)
    console.print(f"[bold green]Campaign completed:[/bold green] {outcome.run_id}")
    console.print(f"Failed tool calls: {failed_tools}")
    console.print(f"Validated findings: {len(outcome.findings)}")
    console.print(f"Report: {outcome.report_path.resolve()}")
    if failed_tools:
        raise typer.Exit(code=1)


@app.command("multi-run")
def run_multi_agent_campaign(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "simulated",
    kill_file: Annotated[Path | None, typer.Option("--kill-file")] = None,
    kill_after_tool_calls: Annotated[
        int | None, typer.Option("--kill-after-tool-calls", hidden=True)
    ] = None,
) -> None:
    """Run a bounded dynamic Planner/Specialist/Validator/Reporter team."""

    try:
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Cannot start campaign:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    registry = _tool_registry()
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        output_root=output,
        kill_switch=KillSwitch(kill_file),
        kill_after_tool_calls=kill_after_tool_calls,
    )
    outcome = asyncio.run(runner.run(campaign))
    table = Table(title="PAJIN Multi-Agent Campaign")
    table.add_column("Role")
    table.add_column("Agent")
    table.add_column("Status")
    for agent in outcome.agents:
        table.add_row(agent.role.value, agent.agent_id, agent.status.value)
    console.print(table)
    console.print(f"Run status: {outcome.status.value}")
    console.print(f"Tool calls: {len(outcome.tool_results)}")
    console.print(f"Validated findings: {len(outcome.findings)}")
    if outcome.cancellation_reason:
        console.print(f"Cancellation: {outcome.cancellation_reason}")
    console.print(f"Report: {outcome.report_path.resolve()}")
    if outcome.status is not RunStatus.COMPLETED:
        raise typer.Exit(code=1)


@app.command("multi-cancel-check")
def check_multi_agent_cancellation(
    worker: Annotated[str, typer.Option("--worker")] = "docker",
) -> None:
    """Verify that a live multi-agent operation is cancelled and cleaned up."""

    try:
        backend = _worker_backend(worker)
    except ValueError as exc:
        console.print(f"[bold red]Invalid worker:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    registry = _tool_registry()
    registry.register(SleepCheckTool())
    kill_switch = KillSwitch()
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        output_root=Path(".pajin/runs"),
        kill_switch=kill_switch,
    )
    outcome = asyncio.run(
        _run_multi_cancel_check(
            runner,
            Path("examples/multi-agent-cancel.yaml"),
            kill_switch,
        )
    )
    passed = (
        outcome.status is RunStatus.CANCELLED
        and outcome.cancellation_reason == "operator cancellation verification"
    )
    console.print(f"Live cancellation propagation: {'PASS' if passed else 'FAIL'}")
    console.print(f"Report: {outcome.report_path}")
    if not passed:
        raise typer.Exit(code=1)


@app.command("kisa-run")
def run_kisa_ai_redteam(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "simulated",
    repetitions: Annotated[int, typer.Option("--repetitions", min=2, max=20)] = 2,
) -> None:
    """Run the KISA-aligned AI Red Team Mode Pack and emit guide artifacts."""

    try:
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
        if campaign.spec.mode is not CampaignMode.AI_REDTEAM:
            raise ValueError("KISA Mode Pack requires mode: ai-redteam")
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Cannot start KISA campaign:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    thresholds = EvaluationThresholds(repetitions=repetitions)
    planner = KISAPlannerRuntime(thresholds=thresholds)
    registry = _tool_registry()
    runner = MultiAgentCampaignRunner(
        planner=planner,
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        output_root=output,
    )
    outcome = asyncio.run(runner.run(campaign))
    try:
        mode_outcome = KISAModePack(thresholds=thresholds).evaluate(campaign, outcome)
    except ValueError as exc:
        console.print(f"[bold red]KISA evaluation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    failed_metrics = sum(
        metric.status is MetricStatus.FAIL for metric in mode_outcome.assessment.metrics
    )
    summary = mode_outcome.assessment.checklist_summary
    table = Table(title="PAJIN KISA AI Red Team Mode Pack")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run status", outcome.status.value)
    table.add_row("Threat coverage", f"{mode_outcome.assessment.coverage.coverage_rate:.1%}")
    table.add_row("Validated findings", str(len(outcome.findings)))
    table.add_row("Failed metric thresholds", str(failed_metrics))
    table.add_row("Checklist yes", str(summary.yes))
    table.add_row("Checklist no", str(summary.no))
    table.add_row("Checklist needs review", str(summary.needs_review))
    console.print(table)
    console.print(f"KISA report: {mode_outcome.report_path.resolve()}")
    console.print(f"KISA checklist: {mode_outcome.checklist_path.resolve()}")
    if outcome.status is not RunStatus.COMPLETED:
        raise typer.Exit(code=1)


@app.command("worker-check")
def check_worker() -> None:
    """Verify the Docker Worker security profile and timeout enforcement."""

    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    isolation = asyncio.run(
        backend.run(
            WorkerJob(
                image="pajin-worker:dev",
                command=["isolation-check"],
                stdin="{}",
                limits=WorkerLimits(timeout_seconds=5),
            )
        )
    )
    if isolation.status is not WorkerStatus.SUCCEEDED:
        console.print(f"[bold red]Worker isolation check failed:[/bold red] {isolation.stderr}")
        raise typer.Exit(code=1)
    try:
        checks = json.loads(isolation.stdout)
    except json.JSONDecodeError as exc:
        console.print(f"[bold red]Invalid worker-check output:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    required = {
        "nonRoot": True,
        "networkBlocked": True,
        "rootReadOnly": True,
        "workspaceWritable": True,
        "capabilitiesDropped": True,
        "noNewPrivileges": True,
    }
    table = Table(title="PAJIN Docker Worker Isolation")
    table.add_column("Control")
    table.add_column("Observed")
    table.add_column("Status")
    passed = True
    for control, expected in required.items():
        observed = checks.get(control)
        control_passed = observed is expected
        passed = passed and control_passed
        table.add_row(control, str(observed), "PASS" if control_passed else "FAIL")
    for control in ("memoryMax", "pidsMax", "cpuMax"):
        table.add_row(control, str(checks.get(control)), "INFO")
    console.print(table)

    timeout_result = asyncio.run(
        backend.run(
            WorkerJob(
                image="pajin-worker:dev",
                command=["sleep-check"],
                stdin='{"seconds":2}',
                limits=WorkerLimits(timeout_seconds=0.2),
            )
        )
    )
    timeout_passed = timeout_result.status is WorkerStatus.TIMED_OUT
    console.print(f"Timeout enforcement: {'PASS' if timeout_passed else 'FAIL'}")
    if not passed or not timeout_passed:
        raise typer.Exit(code=1)


@app.command("egress-check")
def check_egress() -> None:
    """Verify proxy allow/deny decisions and direct-network bypass blocking."""

    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    results = asyncio.run(_run_egress_checks(backend))
    allowed = results["allowed"]
    denied = results["denied"]
    direct = results["direct"]

    try:
        allowed_payload = json.loads(allowed.stdout)
        denied_payload = json.loads(denied.stdout)
        direct_payload = json.loads(direct.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        console.print(f"[bold red]Invalid egress-check output:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    checks = {
        "allowlisted HTTP request": (
            allowed.status is WorkerStatus.SUCCEEDED
            and 200 <= int(allowed_payload.get("status", 0)) < 400
            and '"event":"allow"' in allowed.network_log
        ),
        "denied host rejected": (
            denied.status is WorkerStatus.SUCCEEDED
            and not 200 <= int(denied_payload.get("status", 0)) < 400
            and '"event":"deny"' in denied.network_log
        ),
        "direct socket bypass blocked": (
            direct.status is WorkerStatus.SUCCEEDED
            and direct_payload.get("directNetworkBlocked") is True
            and '"event":"allow"' not in direct.network_log
        ),
    }
    table = Table(title="PAJIN Egress Isolation")
    table.add_column("Control")
    table.add_column("Status")
    for control, passed in checks.items():
        table.add_row(control, "PASS" if passed else "FAIL")
    console.print(table)
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command("mcp-check")
def check_mcp() -> None:
    """Verify the Worker MCP catalog accepts registered calls and rejects unknown IDs."""

    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    results = asyncio.run(_run_mcp_checks(backend))
    registered = results["registered"]
    unknown_server = results["unknown_server"]
    unknown_tool = results["unknown_tool"]
    try:
        registered_payload = json.loads(registered.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        console.print(f"[bold red]Invalid mcp-check output:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    checks = {
        "registered MCP call": (
            registered.status is WorkerStatus.SUCCEEDED
            and registered_payload.get("isError") is False
        ),
        "unknown server rejected": (
            unknown_server.status is WorkerStatus.FAILED
            and "server ID is not registered" in unknown_server.stderr
        ),
        "unknown tool rejected": (
            unknown_tool.status is WorkerStatus.FAILED
            and "tool is not registered" in unknown_tool.stderr
        ),
    }
    table = Table(title="PAJIN MCP Registration Boundary")
    table.add_column("Control")
    table.add_column("Status")
    for control, passed in checks.items():
        table.add_row(control, "PASS" if passed else "FAIL")
    console.print(table)
    if not all(checks.values()):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
