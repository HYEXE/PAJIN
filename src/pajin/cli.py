"""PAJIN command-line interface."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.agents.provider import ModelToolDescriptor, ProviderAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.domain.orchestration import RunStatus
from pajin.modes.ai_redteam import (
    KISAModePack,
    KISAPlannerRuntime,
    KISARetestPlannerRuntime,
    KISARetestService,
    KISAValidatorRuntime,
)
from pajin.modes.ai_redteam.models import EvaluationThresholds, MetricStatus
from pajin.modes.ai_redteam.retest import RegressionStatus
from pajin.modes.bug_bounty import (
    BugBountyPlannerRuntime,
    BugBountyReportService,
    BugBountyScopeApproval,
    BugBountyScopeService,
    BugBountyValidatorRuntime,
    load_bug_bounty_finding_index,
    load_bug_bounty_program,
)
from pajin.modes.ctf import (
    CTFCategory,
    CTFChallengeService,
    CTFFlagValidatorRuntime,
    CTFModePack,
    CTFSolveStatus,
    CTFSuiteModePack,
    CTFTriagePlannerRuntime,
    load_ctf_challenge,
)
from pajin.policy.engine import PolicyEngine
from pajin.providers import (
    OpenAICompatibleChatTool,
    ProviderRegistration,
    ProviderValidationPlanner,
)
from pajin.runtime.control import KillSwitch
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunIntegrityError, verify_run_integrity
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
from pajin.tools.ai import AIChatProbeTool, AIChatRegressionTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import ApprovalCheckTool, MockAgentProbe, SleepCheckTool
from pajin.workflow.local import LocalCampaignRunner
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopApproval,
    ToolLoopBinding,
    ToolLoopConfig,
    ToolLoopOutcome,
    ToolLoopStatus,
)

app = typer.Typer(help="PAJIN policy-governed security validation CLI", no_args_is_help=True)
console = Console()


def _tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    registry.register(ApprovalCheckTool())
    registry.register(AIChatProbeTool())
    registry.register(AIChatRegressionTool())
    registry.register(BooleanSQLiProbeTool())
    registry.register(CTFWebBackupProbeTool())
    registry.register(CTFCryptoXORTool())
    registry.register(HTTPGetTool())
    registry.register(demo_mcp_tool())
    return registry


def _worker_backend(worker: str) -> WorkerBackend:
    if worker == "simulated":
        return SimulatedWorkerBackend()
    if worker == "docker":
        return DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    raise ValueError("use 'simulated' or 'docker'")


def _parse_aware_datetime(value: str, *, option: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{option} must be an ISO 8601 datetime") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{option} must include a UTC offset or Z")
    return parsed


def _provider_checks(
    outcome: MultiAgentRunOutcome,
    *,
    credential: str,
) -> dict[str, bool]:
    results = outcome.tool_results
    leases = json.loads((outcome.run_path / "secrets.json").read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    tool_calls = results[2].data.get("tool_calls", []) if len(results) > 2 else []
    call = tool_calls[0] if isinstance(tool_calls, list) and tool_calls else {}
    arguments = call.get("arguments", {}) if isinstance(call, dict) else {}
    credential_bytes = credential.encode()
    leaked_paths = [
        path
        for path in outcome.run_path.rglob("*")
        if path.is_file() and credential_bytes in path.read_bytes()
    ]
    event_types = [event.get("event_type") for event in events]
    return {
        "campaign completed": outcome.status is RunStatus.COMPLETED,
        "four provider calls succeeded": (
            len(results) == 4 and all(result.success for result in results)
        ),
        "non-stream response normalized": (
            len(results) > 0
            and results[0].data.get("content") == "provider gateway non-stream response"
            and results[0].data.get("streamed") is False
        ),
        "SSE response normalized": (
            len(results) > 1
            and results[1].data.get("content") == "provider gateway stream response"
            and results[1].data.get("streamed") is True
            and int(results[1].data.get("chunks", 0)) >= 2
        ),
        "function tool call normalized": (
            isinstance(call, dict)
            and call.get("name") == "get_weather"
            and call.get("arguments_valid") is True
            and isinstance(arguments, dict)
            and arguments.get("location") == "Seoul"
        ),
        "provider output secret redacted": (
            len(results) > 3 and results[3].data.get("content") == "<redacted-secret>"
        ),
        "all secret leases revoked": (
            len(leases) == 4
            and all(
                lease.get("status") == "revoked" and lease.get("remaining_uses") == 0
                for lease in leases
            )
        ),
        "lease lifecycle audited": (
            event_types.count("secret.lease.issued") == 4
            and event_types.count("secret.lease.revoked") == 4
        ),
        "credential absent from run artifacts": not leaked_paths,
    }


def _provider_agent_checks(
    outcome: MultiAgentRunOutcome,
    *,
    credential: str,
) -> dict[str, bool]:
    events = [
        json.loads(line)
        for line in (outcome.run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    event_types = [event.get("event_type") for event in events]
    budget = json.loads((outcome.run_path / "budget.json").read_text(encoding="utf-8"))
    leases = json.loads((outcome.run_path / "secrets.json").read_text(encoding="utf-8"))
    narrative_path = outcome.run_path / "model-narrative.json"
    credential_bytes = credential.encode()
    leaked_paths = [
        path
        for path in outcome.run_path.rglob("*")
        if path.is_file() and credential_bytes in path.read_bytes()
    ]
    return {
        "campaign completed": outcome.status is RunStatus.COMPLETED,
        "provider planner produced bounded plan": (
            outcome.plan is not None
            and len(outcome.plan.steps) == 1
            and outcome.plan.steps[0].request.tool_id == "ai.chat-probe"
            and outcome.plan.steps[0].scenario_id == "kisa.model.system-prompt-disclosure"
        ),
        "provider validator confirmed same-run evidence": (
            len(outcome.findings) == 1
            and outcome.findings[0].threat_class == "M03"
            and outcome.findings[0].validated
        ),
        "provider reporter narrative persisted": narrative_path.is_file(),
        "three role model calls audited": (
            event_types.count("model.call.completed") == 3
            and event_types.count("model.fallback.activated") == 0
        ),
        "model token and call budgets measured": (
            budget.get("modelCalls") == 3
            and budget.get("modelPromptTokens") == 30
            and budget.get("modelCompletionTokens") == 15
            and budget.get("modelTokens") == 45
        ),
        "three provider secret leases revoked": (
            len(leases) == 3
            and all(
                lease.get("status") == "revoked" and lease.get("remaining_uses") == 0
                for lease in leases
            )
        ),
        "credential absent from run artifacts": not leaked_paths,
    }


def _tool_loop_checks(
    outcome: ToolLoopOutcome,
    *,
    credential: str,
) -> dict[str, bool]:
    state = json.loads((outcome.run_path / "tool-loop.json").read_text(encoding="utf-8"))
    budget = json.loads((outcome.run_path / "budget.json").read_text(encoding="utf-8"))
    leases = json.loads((outcome.run_path / "secrets.json").read_text(encoding="utf-8"))
    credential_bytes = credential.encode()
    leaked_paths = [
        path
        for path in outcome.run_path.rglob("*")
        if path.is_file() and credential_bytes in path.read_bytes()
    ]
    messages = state.get("messages", [])
    return {
        "tool loop completed": outcome.status is ToolLoopStatus.COMPLETED,
        "provider requested one registered function": (
            len(messages) >= 3
            and messages[2].get("role") == "assistant"
            and len(messages[2].get("tool_calls", [])) == 1
            and messages[2]["tool_calls"][0]["function"]["name"] == "probe_mock_agent"
        ),
        "specialist executed through gateway": (
            len(outcome.tool_results) == 1
            and outcome.tool_results[0].success
            and outcome.tool_results[0].tool_id == "mock.agent-probe"
        ),
        "tool result returned with matching call ID": (
            len(messages) >= 4
            and messages[3].get("role") == "tool"
            and messages[3].get("tool_call_id") == "call_pajin_probe"
        ),
        "provider returned final response": (
            outcome.final_content == "Authorized specialist result was received and summarized."
        ),
        "turn tool model and agent budgets measured": (
            state.get("turn") == 2
            and budget.get("toolCalls") == 3
            and budget.get("modelCalls") == 2
            and budget.get("modelTokens") == 30
            and budget.get("agentCount") == 3
        ),
        "provider secret leases revoked": (
            len(leases) == 2
            and all(
                lease.get("status") == "revoked" and lease.get("remaining_uses") == 0
                for lease in leases
            )
        ),
        "resumable checkpoint persisted": outcome.checkpoint_path.is_file(),
        "credential absent from run artifacts": not leaked_paths,
    }


def _tool_loop_approval_checks(
    waiting: ToolLoopOutcome,
    resumed: ToolLoopOutcome,
    *,
    approval_id: str,
    credential: str,
) -> dict[str, bool]:
    resumed_state = json.loads((resumed.run_path / "tool-loop.json").read_text(encoding="utf-8"))
    budget = json.loads((resumed.run_path / "budget.json").read_text(encoding="utf-8"))
    leases = json.loads((resumed.run_path / "secrets.json").read_text(encoding="utf-8"))
    leaked_paths = [
        path
        for root in (waiting.run_path, resumed.run_path)
        for path in root.rglob("*")
        if path.is_file() and credential.encode() in path.read_bytes()
    ]
    return {
        "T3 intent paused before Worker dispatch": (
            waiting.status is ToolLoopStatus.AWAITING_APPROVAL
            and waiting.pending_call is not None
            and waiting.pending_call.risk_tier is ToolRiskTier.T3
            and not waiting.tool_results
        ),
        "exact approval resumed a continuation run": (
            resumed.status is ToolLoopStatus.COMPLETED
            and resumed.run_id != waiting.run_id
            and resumed_state.get("resumed_from_run_id") == waiting.run_id
        ),
        "approval identity audited": resumed_state.get("approval_ids") == [approval_id],
        "approved Specialist executed once": (
            len(resumed.tool_results) == 1
            and resumed.tool_results[0].tool_id == "mock.approval-probe"
            and resumed.tool_results[0].success
        ),
        "cumulative budgets restored": (
            budget.get("agentCount") == 5
            and budget.get("toolCalls") == 3
            and budget.get("modelCalls") == 2
            and budget.get("modelTokens") == 30
        ),
        "cross-run Provider leases revoked": (
            len(leases) == 2 and all(lease.get("status") == "revoked" for lease in leases)
        ),
        "credential absent from both runs": not leaked_paths,
    }


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


@app.command("provider-check")
def check_openai_compatible_provider(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    provider_id: Annotated[str, typer.Option("--provider-id")] = "local-openai",
    model: Annotated[str, typer.Option("--model")] = "pajin-provider-lab",
    secret_env: Annotated[str, typer.Option("--secret-env")] = "PAJIN_PROVIDER_API_KEY",
) -> None:
    """Validate one registered OpenAI-compatible provider through bounded Secret Leases."""

    try:
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
        credential = os.environ.get(secret_env)
        if not credential:
            raise ValueError(f"provider credential environment variable is unset: {secret_env}")
        registration = ProviderRegistration.model_validate(
            {
                "provider_id": provider_id,
                "endpoint": campaign.spec.targets[0].endpoint,
                "model": model,
                "secret_ref": f"provider/{provider_id}/api-key",
                "allowed_function_tools": {"get_weather"},
            }
        )
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Cannot start provider check:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    secrets = SecretBroker()
    secrets.register(registration.secret_ref, credential)
    registry = _tool_registry()
    registry.register(OpenAICompatibleChatTool(registration))
    runner = MultiAgentCampaignRunner(
        planner=ProviderValidationPlanner(registration),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        output_root=output,
        secrets=secrets,
    )
    outcome = asyncio.run(runner.run(campaign))
    checks = _provider_checks(outcome, credential=credential)
    table = Table(title="PAJIN OpenAI-Compatible Provider Gateway")
    table.add_column("Control")
    table.add_column("Status")
    for control, passed in checks.items():
        table.add_row(control, "PASS" if passed else "FAIL")
    console.print(table)
    console.print(f"Run: {outcome.run_id}")
    console.print(f"Report: {outcome.report_path.resolve()}")
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command("provider-agent-run")
def run_provider_backed_agents(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    provider_endpoint: Annotated[str, typer.Option("--provider-endpoint")] = (
        "http://host.docker.internal:8765/v1/chat/completions"
    ),
    provider_id: Annotated[str, typer.Option("--provider-id")] = "local-openai",
    model: Annotated[str, typer.Option("--model")] = "pajin-provider-lab",
    secret_env: Annotated[str, typer.Option("--secret-env")] = "PAJIN_PROVIDER_API_KEY",
    allow_private_provider: Annotated[bool, typer.Option("--allow-private-provider")] = False,
    input_cost_per_million: Annotated[float, typer.Option("--input-cost-per-million", min=0)] = 0,
    output_cost_per_million: Annotated[float, typer.Option("--output-cost-per-million", min=0)] = 0,
) -> None:
    """Run Planner, Validator, and Reporter through a policy-bound model provider."""

    try:
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
        credential = os.environ.get(secret_env)
        if not credential:
            raise ValueError(f"provider credential environment variable is unset: {secret_env}")
        registration = ProviderRegistration.model_validate(
            {
                "provider_id": provider_id,
                "endpoint": provider_endpoint,
                "model": model,
                "secret_ref": f"provider/{provider_id}/api-key",
                "allow_private_networks": allow_private_provider,
                "input_cost_per_million_usd": input_cost_per_million,
                "output_cost_per_million_usd": output_cost_per_million,
            }
        )
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Cannot start provider-backed agents:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    secrets = SecretBroker()
    secrets.register(registration.secret_ref, credential)
    registry = _tool_registry()
    registry.register(OpenAICompatibleChatTool(registration))
    fallback = DeterministicAgentRuntime()
    runtime = ProviderAgentRuntime(
        registration,
        tools=[
            ModelToolDescriptor(
                tool_id="ai.chat-probe",
                description="Execute a bounded provider-neutral AI chat security probe.",
                allowed_methods=["POST"],
            )
        ],
        fallback_planner=KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=1)),
        fallback_validator=KISAValidatorRuntime(fallback),
    )
    runner = MultiAgentCampaignRunner(
        planner=runtime,
        validator=runtime,
        reporter=runtime,
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        output_root=output,
        secrets=secrets,
    )
    outcome = asyncio.run(runner.run(campaign))
    checks = _provider_agent_checks(outcome, credential=credential)
    table = Table(title="PAJIN Provider-Backed Multi-Agent Runtime")
    table.add_column("Control")
    table.add_column("Status")
    for control, passed in checks.items():
        table.add_row(control, "PASS" if passed else "FAIL")
    console.print(table)
    console.print(f"Run: {outcome.run_id}")
    console.print(f"Report: {outcome.report_path.resolve()}")
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command("tool-loop-run")
def run_policy_tool_loop(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    prompt: Annotated[str, typer.Option("--prompt")] = (
        "Inspect the declared mock agent target exactly once and summarize the result."
    ),
    max_turns: Annotated[int, typer.Option("--max-turns", min=1, max=50)] = 6,
    provider_endpoint: Annotated[str, typer.Option("--provider-endpoint")] = (
        "http://host.docker.internal:8765/v1/chat/completions"
    ),
    provider_id: Annotated[str, typer.Option("--provider-id")] = "local-openai",
    model: Annotated[str, typer.Option("--model")] = "pajin-provider-lab",
    secret_env: Annotated[str, typer.Option("--secret-env")] = "PAJIN_PROVIDER_API_KEY",
    allow_private_provider: Annotated[bool, typer.Option("--allow-private-provider")] = False,
    input_cost_per_million: Annotated[float, typer.Option("--input-cost-per-million", min=0)] = 0,
    output_cost_per_million: Annotated[float, typer.Option("--output-cost-per-million", min=0)] = 0,
) -> None:
    """Run a bounded Provider function-call loop with policy re-entry."""

    try:
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
        credential = os.environ.get(secret_env)
        if not credential:
            raise ValueError(f"provider credential environment variable is unset: {secret_env}")
        registration = ProviderRegistration.model_validate(
            {
                "provider_id": provider_id,
                "endpoint": provider_endpoint,
                "model": model,
                "secret_ref": f"provider/{provider_id}/api-key",
                "allowed_function_tools": {"probe_mock_agent"},
                "allow_private_networks": allow_private_provider,
                "input_cost_per_million_usd": input_cost_per_million,
                "output_cost_per_million_usd": output_cost_per_million,
            }
        )
        target = campaign.spec.targets[0]
        if target.type != "mock-agent":
            raise ValueError("the current tool-loop CLI lab requires a mock-agent target")
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Cannot start tool loop:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    secrets = SecretBroker()
    secrets.register(registration.secret_ref, credential)
    registry = _tool_registry()
    registry.register(OpenAICompatibleChatTool(registration))
    binding = ToolLoopBinding(
        function_name="probe_mock_agent",
        description="Probe the declared mock agent for unauthorized tool execution.",
        parameters={
            "type": "object",
            "properties": {
                "simulation": {
                    "type": "object",
                    "properties": {"unauthorizedToolCall": {"type": "boolean"}},
                    "required": ["unauthorizedToolCall"],
                    "additionalProperties": False,
                }
            },
            "required": ["simulation"],
            "additionalProperties": False,
        },
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
    )
    runner = PolicyToolLoopRunner(
        registration=registration,
        bindings=[binding],
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        secrets=secrets,
        output_root=output,
        config=ToolLoopConfig(max_turns=max_turns),
    )
    outcome = asyncio.run(runner.run(campaign, prompt=prompt))
    checks = _tool_loop_checks(outcome, credential=credential)
    table = Table(title="PAJIN Policy-Governed Agent Tool Loop")
    table.add_column("Control")
    table.add_column("Status")
    for control, passed in checks.items():
        table.add_row(control, "PASS" if passed else "FAIL")
    console.print(table)
    console.print(f"Run: {outcome.run_id}")
    console.print(f"Checkpoint: {outcome.checkpoint_path.resolve()}")
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command("tool-loop-approval-check")
def check_tool_loop_approval_resume(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    approved_by: Annotated[str, typer.Option("--approved-by")] = "local-security-owner",
    approval_ttl_seconds: Annotated[
        int, typer.Option("--approval-ttl-seconds", min=1, max=300)
    ] = 60,
    provider_endpoint: Annotated[str, typer.Option("--provider-endpoint")] = (
        "http://host.docker.internal:8765/v1/chat/completions"
    ),
    provider_id: Annotated[str, typer.Option("--provider-id")] = "local-openai",
    model: Annotated[str, typer.Option("--model")] = "pajin-provider-lab",
    secret_env: Annotated[str, typer.Option("--secret-env")] = "PAJIN_PROVIDER_API_KEY",
    allow_private_provider: Annotated[bool, typer.Option("--allow-private-provider")] = False,
) -> None:
    """Verify T3 pause, exact approval binding, checkpoint resume, and completion."""

    try:
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
        credential = os.environ.get(secret_env)
        if not credential:
            raise ValueError(f"provider credential environment variable is unset: {secret_env}")
        registration = ProviderRegistration.model_validate(
            {
                "provider_id": provider_id,
                "endpoint": provider_endpoint,
                "model": model,
                "secret_ref": f"provider/{provider_id}/api-key",
                "allowed_function_tools": {"probe_mock_agent"},
                "allow_private_networks": allow_private_provider,
            }
        )
        target = campaign.spec.targets[0]
        if target.type != "mock-agent":
            raise ValueError("approval check requires a mock-agent target")
        if campaign.spec.rules_of_engagement.max_tool_risk_tier < ToolRiskTier.T3:
            raise ValueError("approval check campaign must permit T3 for the lab fixture")
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Cannot start approval check:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    secrets = SecretBroker()
    secrets.register(registration.secret_ref, credential)
    registry = _tool_registry()
    registry.register(OpenAICompatibleChatTool(registration))
    binding = ToolLoopBinding(
        function_name="probe_mock_agent",
        description="Run the approval-gated mock probe against the declared target.",
        parameters={
            "type": "object",
            "properties": {
                "simulation": {
                    "type": "object",
                    "properties": {"unauthorizedToolCall": {"type": "boolean"}},
                    "required": ["unauthorizedToolCall"],
                    "additionalProperties": False,
                }
            },
            "required": ["simulation"],
            "additionalProperties": False,
        },
        tool_id="mock.approval-probe",
        target=target.endpoint,
        method="POST",
    )
    runner = PolicyToolLoopRunner(
        registration=registration,
        bindings=[binding],
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        secrets=secrets,
        output_root=output,
    )
    waiting = asyncio.run(
        runner.run(campaign, prompt="Request the approval-gated mock probe exactly once.")
    )
    if waiting.pending_call is None:
        console.print("[bold red]Approval check failed:[/bold red] no pending call was produced")
        raise typer.Exit(code=1)
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target=waiting.pending_call.target,
        approved_by=approved_by,
        approved_at=now,
        expires_at=now + timedelta(seconds=approval_ttl_seconds),
    )
    resumed = asyncio.run(
        runner.resume(
            campaign,
            checkpoint_path=waiting.checkpoint_path,
            approvals=[approval],
        )
    )
    checks = _tool_loop_approval_checks(
        waiting,
        resumed,
        approval_id=approval.approval_id,
        credential=credential,
    )
    table = Table(title="PAJIN T3 Tool Loop Approval & Resume")
    table.add_column("Control")
    table.add_column("Status")
    for control, passed in checks.items():
        table.add_row(control, "PASS" if passed else "FAIL")
    console.print(table)
    console.print(f"Waiting run: {waiting.run_id}")
    console.print(f"Continuation run: {resumed.run_id}")
    console.print(f"Approval: {approval.approval_id}")
    if not all(checks.values()):
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


@app.command("kisa-retest")
def run_kisa_retest(
    baseline_run: Annotated[Path, typer.Argument(exists=True, readable=True, file_okay=False)],
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    repetitions: Annotated[int, typer.Option("--repetitions", min=2, max=20)] = 2,
    normal_prompt: Annotated[str, typer.Option("--normal-prompt")] = (
        "Provide the normal lab service response."
    ),
    expected_contains: Annotated[str, typer.Option("--expected-contains")] = (
        "Request processed without exposing protected state."
    ),
) -> None:
    """Rerun KISA attacks plus normal behavior and compare with a baseline run."""

    try:
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
        if campaign.spec.mode is not CampaignMode.AI_REDTEAM:
            raise ValueError("KISA retest requires mode: ai-redteam")
    except (ValidationError, ValueError) as exc:
        console.print(f"[bold red]Cannot start KISA retest:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    retest_service = KISARetestService()
    try:
        remediation_plan = retest_service.create_remediation_plan(baseline_run)
    except ValueError as exc:
        console.print(f"[bold red]Cannot create remediation plan:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    thresholds = EvaluationThresholds(repetitions=repetitions)
    runner = MultiAgentCampaignRunner(
        planner=KISARetestPlannerRuntime(
            thresholds=thresholds,
            normal_prompt=normal_prompt,
            expected_contains=expected_contains,
        ),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        tools=_tool_registry(),
        policy=PolicyEngine(),
        worker=backend,
        output_root=output,
    )
    outcome = asyncio.run(runner.run(campaign))
    if outcome.status is not RunStatus.COMPLETED:
        console.print(f"[bold red]Retest run failed:[/bold red] {outcome.run_id}")
        console.print(f"Report: {outcome.report_path.resolve()}")
        raise typer.Exit(code=1)
    try:
        KISAModePack(thresholds=thresholds).evaluate(campaign, outcome)
        retest = retest_service.compare(baseline_run, outcome.run_path)
    except ValueError as exc:
        console.print(f"[bold red]KISA retest comparison failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = retest.assessment.summary
    table = Table(title="PAJIN KISA Remediation & Retest")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Retest run", outcome.run_id)
    table.add_row("Fixed", str(summary.fixed))
    table.add_row("Still vulnerable", str(summary.still_vulnerable))
    table.add_row("Inconclusive", str(summary.inconclusive))
    table.add_row("New findings", str(summary.new_findings))
    table.add_row("Normal-function regression", summary.regression.value)
    console.print(table)
    console.print(f"Retest report: {retest.report_path.resolve()}")
    console.print(f"Baseline remediation plan: {remediation_plan.path.resolve()}")
    console.print(f"Retest remediation copy: {retest.remediation_plan_path.resolve()}")
    console.print(f"Checklist overlay: {retest.checklist_overlay_path.resolve()}")
    acceptance_failed = (
        summary.still_vulnerable > 0
        or summary.inconclusive > 0
        or summary.new_findings > 0
        or summary.regression is not RegressionStatus.PASS
    )
    if acceptance_failed:
        raise typer.Exit(code=1)


@app.command("kisa-plan-remediation")
def plan_kisa_remediation(
    baseline_run: Annotated[Path, typer.Argument(exists=True, readable=True, file_okay=False)],
) -> None:
    """Create a threat-specific remediation plan from a completed KISA baseline run."""

    try:
        outcome = KISARetestService().create_remediation_plan(baseline_run)
    except ValueError as exc:
        console.print(f"[bold red]Cannot create remediation plan:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    table = Table(title="PAJIN KISA Remediation Plan")
    table.add_column("Threat")
    table.add_column("Finding")
    table.add_column("Controls")
    table.add_column("Assignment")
    for action in outcome.actions:
        table.add_row(
            action.threat_class,
            action.baseline_finding_id,
            str(len(action.controls)),
            "needs-review" if action.requires_human_assignment else "assigned",
        )
    console.print(table)
    console.print(f"Remediation plan: {outcome.path.resolve()}")


@app.command("bug-bounty-review")
def review_bug_bounty_scope(
    program_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/programs"),
) -> None:
    """Normalize a Bug Bounty program policy and emit a digest-bound scope review."""

    try:
        program = load_bug_bounty_program(program_path)
        artifacts = BugBountyScopeService().write_review(program, output)
    except (ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]Cannot review Bug Bounty scope:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    review = artifacts.review
    table = Table(title="PAJIN Bug Bounty Scope Review")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Program", program.metadata.display_name)
    table.add_row("In-scope rules", str(len(review.allow)))
    table.add_row("Out-of-scope rules", str(len(review.deny)))
    table.add_row("Entry points", str(len(review.entry_points)))
    table.add_row("Warnings", str(len(review.warnings)))
    console.print(table)
    console.print(f"Scope digest: {review.scope_digest}")
    console.print(f"Scope review: {artifacts.review_markdown_path.resolve()}")
    console.print("Campaign compilation requires explicit approval of the displayed digest.")


@app.command("bug-bounty-compile")
def compile_bug_bounty_campaign(
    program_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    scope_digest: Annotated[str, typer.Option("--scope-digest")],
    approved_by: Annotated[str, typer.Option("--approved-by")],
    approved_at: Annotated[str, typer.Option("--approved-at")],
    expires_at: Annotated[str, typer.Option("--expires-at")],
    evidence: Annotated[str, typer.Option("--evidence")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/campaigns"),
) -> None:
    """Compile a reviewed Bug Bounty policy into an executable Campaign manifest."""

    try:
        program = load_bug_bounty_program(program_path)
        approval = BugBountyScopeApproval(
            scope_digest=scope_digest,
            approved_by=approved_by,
            approved_at=_parse_aware_datetime(approved_at, option="--approved-at"),
            expires_at=_parse_aware_datetime(expires_at, option="--expires-at"),
            evidence=evidence,
        )
        artifact = BugBountyScopeService().write_campaign(
            program,
            approval,
            output / f"{program.metadata.name}.yaml",
        )
    except (ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]Cannot compile Bug Bounty campaign:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    campaign = artifact.campaign
    table = Table(title="Compiled PAJIN Bug Bounty Campaign")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Campaign", campaign.metadata.name)
    table.add_row("Targets", str(len(campaign.spec.targets)))
    table.add_row("Max risk", f"T{campaign.spec.rules_of_engagement.max_tool_risk_tier.value}")
    table.add_row(
        "Rate limit",
        f"{campaign.spec.rules_of_engagement.max_requests_per_minute}/minute",
    )
    console.print(table)
    console.print(f"Campaign manifest: {artifact.path.resolve()}")


@app.command("bug-bounty-report")
def report_bug_bounty_findings(
    program_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True, file_okay=False)],
    known_findings: Annotated[
        Path | None,
        typer.Option("--known-findings", exists=True, readable=True, dir_okay=False),
    ] = None,
) -> None:
    """Deduplicate validated findings and emit evidence-bound submission drafts."""

    try:
        program = load_bug_bounty_program(program_path)
        finding_index = (
            load_bug_bounty_finding_index(known_findings) if known_findings is not None else None
        )
        artifacts = BugBountyReportService().report_run(
            program,
            run_path,
            known_findings=finding_index,
        )
    except (ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]Cannot create Bug Bounty report:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    summary = artifacts.report.summary
    table = Table(title="PAJIN Bug Bounty Finding Triage")
    table.add_column("Disposition")
    table.add_column("Count")
    table.add_row("Ready", str(summary.ready))
    table.add_row("Needs review", str(summary.needs_review))
    table.add_row("Known duplicates", str(summary.known_duplicates))
    table.add_row("Same-run duplicates", str(summary.run_duplicates))
    console.print(table)
    console.print(f"Triage report: {artifacts.report_path.resolve()}")
    console.print(f"Submission drafts: {len(artifacts.submission_paths)}")
    if summary.needs_review:
        console.print(
            "[yellow]Potential duplicates or incomplete required fields need "
            "operator review.[/yellow]"
        )


@app.command("bug-bounty-run")
def run_bug_bounty_campaign(
    program_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    known_findings: Annotated[
        Path | None,
        typer.Option("--known-findings", exists=True, readable=True, dir_okay=False),
    ] = None,
) -> None:
    """Run the fixed Bug Bounty lab probe with Docker and create triage drafts."""

    try:
        program = load_bug_bounty_program(program_path)
        campaign = load_manifest(manifest)
        finding_index = (
            load_bug_bounty_finding_index(known_findings) if known_findings is not None else None
        )
        report_service = BugBountyReportService()
        report_service.validate_campaign(program, campaign)
    except (ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]Cannot start Bug Bounty campaign:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    runner = MultiAgentCampaignRunner(
        planner=BugBountyPlannerRuntime(),
        validator=BugBountyValidatorRuntime(),
        tools=_tool_registry(),
        policy=PolicyEngine(),
        worker=_worker_backend("docker"),
        output_root=output,
    )
    outcome = asyncio.run(runner.run(campaign))
    if outcome.status is not RunStatus.COMPLETED:
        console.print(f"[bold red]Bug Bounty run failed:[/bold red] {outcome.run_id}")
        if outcome.cancellation_reason:
            console.print(f"Reason: {outcome.cancellation_reason}")
        console.print(f"Run report: {outcome.report_path.resolve()}")
        raise typer.Exit(code=1)

    try:
        artifacts = report_service.report_run(
            program,
            outcome.run_path,
            known_findings=finding_index,
        )
    except (ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]Bug Bounty triage failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = artifacts.report.summary
    table = Table(title="PAJIN Bug Bounty Multi-Agent Run")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run status", outcome.status.value)
    table.add_row("Tool calls", str(len(outcome.tool_results)))
    table.add_row("Validated findings", str(len(outcome.findings)))
    table.add_row("Ready drafts", str(summary.ready))
    table.add_row("Needs review", str(summary.needs_review))
    table.add_row("Known duplicates", str(summary.known_duplicates))
    table.add_row("Same-run duplicates", str(summary.run_duplicates))
    console.print(table)
    console.print(f"Run report: {outcome.report_path.resolve()}")
    console.print(f"Triage report: {artifacts.report_path.resolve()}")
    console.print(f"Submission drafts: {len(artifacts.submission_paths)}")
    console.print("No external submission was performed.")


def _execute_ctf_challenge(
    challenge_path: Path,
    output: Path,
    *,
    required_category: CTFCategory | None = None,
) -> None:
    try:
        challenge = load_ctf_challenge(challenge_path)
        if required_category is not None and challenge.spec.category is not required_category:
            raise ValueError(
                f"this command accepts only the {required_category.value} CTF category"
            )
        campaign = CTFChallengeService().compile_campaign(challenge)
    except (ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]Cannot start CTF challenge:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    runner = MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
        tools=_tool_registry(),
        policy=PolicyEngine(),
        worker=_worker_backend("docker"),
        output_root=output,
    )
    outcome = asyncio.run(runner.run(campaign))
    if outcome.status is not RunStatus.COMPLETED:
        console.print(f"[bold red]CTF run failed:[/bold red] {outcome.run_id}")
        if outcome.cancellation_reason:
            console.print(f"Reason: {outcome.cancellation_reason}")
        console.print(f"Run report: {outcome.report_path.resolve()}")
        raise typer.Exit(code=1)

    try:
        artifacts = CTFModePack().finalize(challenge, outcome)
    except (RunIntegrityError, ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]CTF finalization failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    result = artifacts.result
    table = Table(title=f"PAJIN CTF {result.category.value.title()} Multi-Agent Run")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run status", outcome.status.value)
    table.add_row("Solve status", result.status.value)
    table.add_row("Agents", str(len(outcome.agents)))
    table.add_row("Tool calls", str(len(outcome.tool_results)))
    table.add_row("Independent validations", str(len(outcome.findings)))
    console.print(table)
    if result.status is CTFSolveStatus.SOLVED:
        console.print(f"Verified flag: {result.candidate_flag}")
    console.print(f"CTF result: {artifacts.result_path.resolve()}")
    console.print(f"CTF write-up: {artifacts.writeup_path.resolve()}")
    console.print("No external scoreboard submission was performed.")
    if result.status is not CTFSolveStatus.SOLVED:
        raise typer.Exit(code=1)


@app.command("ctf-run")
def run_ctf_challenge(
    challenge_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
) -> None:
    """Run one supported local CTF category without external submission."""

    _execute_ctf_challenge(challenge_path, output)


@app.command("ctf-web-run")
def run_ctf_web_challenge(
    challenge_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
) -> None:
    """Backward-compatible alias restricted to the local CTF Web category."""

    _execute_ctf_challenge(
        challenge_path,
        output,
        required_category=CTFCategory.WEB,
    )


@app.command("ctf-suite-run")
def run_ctf_suite(
    suite_name: Annotated[str, typer.Argument()],
    challenge_paths: Annotated[
        list[Path],
        typer.Argument(exists=True, readable=True, dir_okay=False),
    ],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
) -> None:
    """Run one bounded Web/Crypto Suite without external submission."""

    try:
        challenges = [load_ctf_challenge(path) for path in challenge_paths]
        campaign = CTFChallengeService().compile_suite(suite_name, challenges)
    except (ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]Cannot start CTF Suite:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    runner = MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
        tools=_tool_registry(),
        policy=PolicyEngine(),
        worker=_worker_backend("docker"),
        output_root=output,
    )
    outcome = asyncio.run(runner.run(campaign))
    if outcome.status is not RunStatus.COMPLETED:
        console.print(f"[bold red]CTF Suite run failed:[/bold red] {outcome.run_id}")
        if outcome.cancellation_reason:
            console.print(f"Reason: {outcome.cancellation_reason}")
        console.print(f"Run report: {outcome.report_path.resolve()}")
        raise typer.Exit(code=1)

    try:
        artifacts = CTFSuiteModePack().finalize(suite_name, challenges, outcome)
    except (RunIntegrityError, ValidationError, ValueError, OSError) as exc:
        console.print(f"[bold red]CTF Suite finalization failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    summary = artifacts.result.summary
    table = Table(title="PAJIN CTF Suite Multi-Agent Run")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run status", outcome.status.value)
    table.add_row("Challenges", str(len(artifacts.result.items)))
    table.add_row("Agents", str(len(outcome.agents)))
    table.add_row("Tool calls", str(len(outcome.tool_results)))
    table.add_row("Solved", str(summary.solved))
    table.add_row("Unsolved", str(summary.unsolved))
    table.add_row("Invalid flags", str(summary.invalid_flag))
    console.print(table)
    for item in artifacts.result.items:
        if item.status is CTFSolveStatus.SOLVED:
            console.print(f"Verified flag ({item.challenge_id}): {item.candidate_flag}")
    console.print(f"CTF Suite result: {artifacts.result_path.resolve()}")
    console.print(f"CTF Suite write-up: {artifacts.writeup_path.resolve()}")
    console.print("No external scoreboard submission was performed.")
    if summary.solved != len(artifacts.result.items):
        raise typer.Exit(code=1)


@app.command("evidence-verify")
def verify_run_evidence(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True, file_okay=False)],
) -> None:
    """Verify a Run's Audit Event chain and sealed artifact digest chain."""

    try:
        verification = verify_run_integrity(run_path)
    except (RunIntegrityError, OSError) as exc:
        console.print(f"[bold red]Run integrity verification failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="PAJIN Run Evidence Integrity")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run", verification.run_id)
    table.add_row("Seals", str(verification.seal_count))
    table.add_row("Artifacts", str(verification.artifact_count))
    table.add_row("Audit events", str(verification.event_count))
    table.add_row("Root digest", f"{verification.root_digest[:16]}...")
    table.add_row("Integrity", "VALID")
    console.print(table)
    console.print(f"Root digest: {verification.root_digest}")


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
