"""PAJIN command-line interface."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.agents.provider import ModelToolDescriptor, ProviderAgentRuntime
from pajin.capabilities.scaffold import (
    generate_capability_scaffold,
    load_capability_scaffold_spec,
    write_capability_scaffold,
)
from pajin.cli_support.check_contracts import (
    mcp_registered_call_matches as _mcp_registered_call_matches,
)
from pajin.cli_support.check_contracts import (
    mcp_registered_discovery_matches as _mcp_registered_discovery_matches,
)
from pajin.cli_support.check_contracts import (
    mcp_rejection_matches as _mcp_rejection_matches,
)
from pajin.cli_support.check_contracts import (
    multi_cancel_checks as _multi_cancel_checks,
)
from pajin.cli_support.check_contracts import (
    run_egress_checks as _run_egress_checks,
)
from pajin.cli_support.check_contracts import (
    run_mcp_checks as _run_mcp_checks,
)
from pajin.cli_support.check_contracts import (
    run_multi_cancel_check as _run_multi_cancel_check,
)
from pajin.cli_support.common import (
    cli_error_boundary as _cli_error_boundary,
)
from pajin.cli_support.common import (
    cli_json_integer as _cli_json_integer,
)
from pajin.cli_support.common import (
    console,
)
from pajin.cli_support.common import (
    disposition_count as _disposition_count,
)
from pajin.cli_support.common import (
    parse_aware_datetime as _parse_aware_datetime,
)
from pajin.cli_support.common import (
    plain_cli_value as _plain_cli_value,
)
from pajin.cli_support.common import (
    print_check_table as _print_check_table,
)
from pajin.cli_support.common import (
    print_cli_error as _print_cli_error,
)
from pajin.cli_support.common import (
    print_cli_field as _print_cli_field,
)
from pajin.cli_support.common import (
    print_cli_status_failure as _print_cli_status_failure,
)
from pajin.cli_support.common import (
    print_worker_execution_context as _print_worker_execution_context,
)
from pajin.cli_support.common import (
    safe_cli_value as _safe_cli_value,
)
from pajin.cli_support.common import (
    tool_registry as _tool_registry,
)
from pajin.cli_support.common import (
    worker_backend as _worker_backend,
)
from pajin.cli_support.provider_contracts import (
    provider_agent_checks as _provider_agent_checks,
)
from pajin.cli_support.provider_contracts import (
    provider_checks as _provider_checks,
)
from pajin.cli_support.tool_loop_contracts import (
    tool_loop_approval_checks,
    tool_loop_checks,
)
from pajin.control_plane.attestation import (
    load_portable_replay_attestation_file,
    load_replay_attestation_trust_anchor,
    verify_portable_replay_attestation,
)
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest, CampaignMode, ToolRiskTier
from pajin.domain.orchestration import RunStatus
from pajin.domain.validation import (
    FindingDisposition,
)
from pajin.modes.ai_redteam import (
    KISACandidateProducer,
    KISALocalAgentRuntime,
    KISALocalReplayOrchestrator,
    KISALocalReplayOutcome,
    KISAModePack,
    KISAPlannerRuntime,
    KISARemediationPlanOutcome,
    KISAReplayBatchOutcome,
    KISAReplayCoordinator,
    KISARetestOutcome,
    KISARetestPlannerRuntime,
    KISARetestService,
    KISAValidationControlBatchOutcome,
    KISAValidationControlCoordinator,
    KISAValidatorRuntime,
    required_kisa_replay_calls,
    required_kisa_validation_control_calls,
)
from pajin.modes.ai_redteam.models import EvaluationThresholds, MetricStatus
from pajin.modes.ai_redteam.replay import KISARetestReplayCoordinator
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
from pajin.replay.runtime import load_verified_replay_result
from pajin.replay.sqlite_tickets import (
    SQLiteReplayExecutionAuthority,
    SQLiteReplayTicketFinalizationVerifier,
)
from pajin.reporting.sarif import (
    load_verified_sarif_export,
    write_verified_sarif_export,
)
from pajin.runtime.control import (
    BudgetController,
    ExecutionCancellationContext,
    KillSwitch,
)
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import (
    load_verified_run_artifacts,
    verify_run_integrity,
)
from pajin.runtime.worker import (
    DockerWorkerBackend,
    WorkerBackend,
    WorkerJob,
    WorkerLimits,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry, decode_strict_worker_json_object
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.tools.mock import SleepCheckTool
from pajin.workflow.campaign_builder import (
    CampaignBuilderError,
    CampaignBuilderSource,
    CampaignProfileScopeDraft,
    build_campaign_profile_scope_draft,
    load_campaign_profile_scope_draft,
    write_campaign_profile_scope_draft,
)
from pajin.workflow.confirmation import apply_confirmed_gate
from pajin.workflow.local import LocalCampaignRunner, RunOutcome
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopApproval,
    ToolLoopBinding,
    ToolLoopConfig,
    ToolLoopOutcome,
)

app = typer.Typer(help="PAJIN policy-governed security validation CLI", no_args_is_help=True)


def _tool_loop_checks(
    outcome: ToolLoopOutcome,
    *,
    credential: str,
) -> dict[str, bool]:
    return tool_loop_checks(
        outcome,
        credential=credential,
        artifact_loader=load_verified_run_artifacts,
    )


def _tool_loop_approval_checks(
    waiting: ToolLoopOutcome,
    resumed: ToolLoopOutcome,
    *,
    approval_id: str,
    credential: str,
) -> dict[str, bool]:
    return tool_loop_approval_checks(
        waiting,
        resumed,
        approval_id=approval_id,
        credential=credential,
        artifact_loader=load_verified_run_artifacts,
    )


def _prepare_kisa_replay_planner(
    campaign: CampaignManifest,
    *,
    repetitions: int,
    mode_error: str,
    budget_error: str,
    validation_controls: bool = False,
) -> KISAPlannerRuntime:
    if campaign.spec.mode is not CampaignMode.AI_REDTEAM:
        raise ValueError(mode_error)
    planner = KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=repetitions))
    preflight_plan = asyncio.run(planner.plan(campaign))
    required_calls = len(preflight_plan.steps) + required_kisa_replay_calls(
        preflight_plan,
        repetitions=repetitions,
    )
    if validation_controls:
        required_calls += required_kisa_validation_control_calls(preflight_plan)
    if required_calls > campaign.spec.budgets.max_tool_calls:
        raise ValueError(f"{budget_error} (requires at least {required_calls})")
    return planner


def _print_local_campaign_success(outcome: RunOutcome, backend: WorkerBackend) -> None:
    _print_worker_execution_context(backend)
    _print_cli_field("Campaign completed", outcome.run_id, label_style="bold green")
    console.print("Failed tool calls: 0")
    console.print(f"Confirmed findings: {len(outcome.findings)}")
    console.print(
        f"Needs review: {_disposition_count(outcome.validation, FindingDisposition.NEEDS_REVIEW)}"
    )
    _print_cli_field("Report", outcome.report_path.resolve())


def _run_local_campaign(
    campaign: CampaignManifest,
    *,
    registry: ToolRegistry,
    backend: WorkerBackend,
    output: Path,
) -> None:
    with _cli_error_boundary("Local campaign execution failed", exit_code=1):
        runner = LocalCampaignRunner(
            agents=DeterministicAgentRuntime(),
            tools=registry,
            policy=PolicyEngine(),
            worker=backend,
            output_root=output,
        )
        outcome = asyncio.run(runner.run(campaign))

    failed_tools = sum(not result.success for result in outcome.tool_results)
    if failed_tools:
        _print_cli_status_failure(
            "Local campaign failed",
            f"{failed_tools} tool call(s) failed",
        )
        _print_cli_field("Report", outcome.report_path.resolve())
        raise typer.Exit(code=1)
    _print_local_campaign_success(outcome, backend)


def _run_local_kisa_replay(
    campaign: CampaignManifest,
    *,
    planner: KISAPlannerRuntime,
    registry: ToolRegistry,
    backend: WorkerBackend,
    output: Path,
    repetitions: int,
) -> None:
    policy = PolicyEngine()
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    cancellation = ExecutionCancellationContext()
    with _cli_error_boundary("Local KISA replay failed", exit_code=1):
        orchestrator = KISALocalReplayOrchestrator(
            agents=KISALocalAgentRuntime(
                planner=planner,
                validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
            ),
            tools=registry,
            policy=policy,
            worker=backend,
            output_root=output,
            repetitions=repetitions,
            ticket_authority_factory=lambda: SQLiteReplayExecutionAuthority(
                output / "local-replay" / "replay-tickets.sqlite3"
            ),
        )
        local_replay: KISALocalReplayOutcome = asyncio.run(
            orchestrator.run(
                campaign,
                cancellation=cancellation,
                budget=budget,
                rate_limits=rate_limits,
            )
        )

    failed_tools = sum(not result.success for result in local_replay.outcome.tool_results)
    replay_execution_failed = any(
        record.execution_status != "succeeded" for record in local_replay.batch.records
    )
    if replay_execution_failed or failed_tools:
        detail = (
            "one or more replay records did not succeed"
            if replay_execution_failed
            else f"{failed_tools} source tool call(s) failed"
        )
        _print_cli_status_failure("Local KISA replay failed", detail)
        _print_cli_field("Report", local_replay.outcome.report_path.resolve())
        raise typer.Exit(code=1)

    outcome = local_replay.outcome
    _print_worker_execution_context(backend)
    _print_cli_field("Campaign completed", outcome.run_id, label_style="bold green")
    console.print("Failed tool calls: 0")
    console.print(f"Confirmed findings: {len(outcome.findings)}")
    console.print(f"Replay records: {len(local_replay.batch.records)}")
    _print_cli_field("Final report", outcome.report_path.resolve())


@app.command("capability-scaffold")
def scaffold_capability(
    spec: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
) -> None:
    """Generate one inert, digest-bound Capability authoring scaffold."""

    with _cli_error_boundary("Capability scaffold generation failed", exit_code=2):
        scaffold_spec = load_capability_scaffold_spec(spec)
        scaffold = generate_capability_scaffold(scaffold_spec)
        destination = write_capability_scaffold(scaffold, output)

    _print_cli_field("Capability scaffold", scaffold.scaffold_id, label_style="bold green")
    _print_cli_field("Capability", scaffold.capability.capability_id)
    _print_cli_field("Output", destination.resolve())


@app.command("validate")
def validate_campaign(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
) -> None:
    """Validate a campaign manifest without executing it."""

    with _cli_error_boundary("Invalid campaign", exit_code=2):
        campaign = load_manifest(manifest)

    table = Table(title="Validated PAJIN Campaign")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Name", _plain_cli_value(campaign.metadata.name))
    table.add_row("Mode", campaign.spec.mode.value)
    table.add_row("Autonomy", campaign.spec.autonomy.value)
    table.add_row("Targets", str(len(campaign.spec.targets)))
    table.add_row("Max tool risk", f"T{campaign.spec.rules_of_engagement.max_tool_risk_tier.value}")
    table.add_row("Authorization active", str(campaign.spec.authorization.is_active()))
    console.print(table)


@app.command("run")
def run_campaign(
    ctx: typer.Context,
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    kisa_replay: Annotated[bool, typer.Option("--kisa-replay")] = False,
    repetitions: Annotated[int, typer.Option("--repetitions", min=2, max=20)] = 2,
) -> None:
    """Run locally, optionally opting in to exact KISA replay confirmation."""

    repetitions_source = ctx.get_parameter_source("repetitions")
    if (
        not kisa_replay
        and repetitions_source is not None
        and repetitions_source.name == "COMMANDLINE"
    ):
        console.print(
            "[bold red]Invalid replay options:[/bold red] --repetitions requires --kisa-replay"
        )
        raise typer.Exit(code=2)

    with _cli_error_boundary("Invalid campaign", exit_code=2):
        campaign = load_manifest(manifest)

    planner: KISAPlannerRuntime | None = None
    if kisa_replay:
        with _cli_error_boundary("Cannot start Local KISA replay", exit_code=2):
            planner = _prepare_kisa_replay_planner(
                campaign,
                repetitions=repetitions,
                mode_error="Local KISA replay requires mode: ai-redteam",
                budget_error=(
                    "maxToolCalls must reserve the Local KISA source plan and every replay attempt"
                ),
            )

    with _cli_error_boundary("Invalid worker", exit_code=2):
        backend = _worker_backend(worker)

    with _cli_error_boundary("Campaign setup failed", exit_code=1):
        registry = _tool_registry()
    if kisa_replay:
        if planner is None:
            _print_cli_error(
                "Local KISA replay failed",
                RuntimeError("replay planner was not initialized"),
            )
            raise typer.Exit(code=1)
        _run_local_kisa_replay(
            campaign,
            planner=planner,
            registry=registry,
            backend=backend,
            output=output,
            repetitions=repetitions,
        )
        return

    _run_local_campaign(
        campaign,
        registry=registry,
        backend=backend,
        output=output,
    )


@app.command("multi-run")
def run_multi_agent_campaign(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    kill_file: Annotated[Path | None, typer.Option("--kill-file")] = None,
    kill_after_tool_calls: Annotated[
        int | None, typer.Option("--kill-after-tool-calls", hidden=True)
    ] = None,
) -> None:
    """Run a bounded dynamic Planner/Specialist/Validator/Reporter team."""

    with _cli_error_boundary("Cannot start campaign", exit_code=2):
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
    with _cli_error_boundary("Campaign execution failed", exit_code=1):
        runner = MultiAgentCampaignRunner(
            planner=DeterministicAgentRuntime(),
            validator=DeterministicAgentRuntime(),
            tools=_tool_registry(),
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
        table.add_row(
            _plain_cli_value(agent.role.value),
            _plain_cli_value(agent.agent_id),
            _plain_cli_value(agent.status.value),
        )
    console.print(table)
    _print_worker_execution_context(backend)
    console.print(f"Run status: {outcome.status.value}")
    console.print(f"Tool calls: {len(outcome.tool_results)}")
    console.print(f"Confirmed findings: {len(outcome.findings)}")
    _print_cli_field(
        "Needs review",
        _disposition_count(outcome.validation, FindingDisposition.NEEDS_REVIEW),
    )
    if outcome.cancellation_reason:
        _print_cli_field("Cancellation", outcome.cancellation_reason)
    _print_cli_field("Report", outcome.report_path.resolve())
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

    with _cli_error_boundary("Cannot start provider check", exit_code=2):
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
                "allow_private_networks": (
                    campaign.spec.rules_of_engagement.allow_private_networks
                ),
            }
        )
    with _cli_error_boundary("Provider check failed", exit_code=1):
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
    _print_check_table("PAJIN OpenAI-Compatible Provider Gateway", checks)
    _print_cli_field("Run", outcome.run_id)
    _print_cli_field("Report", outcome.report_path.resolve())
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
    review_provider_endpoint: Annotated[
        str | None,
        typer.Option("--review-provider-endpoint"),
    ] = None,
    review_provider_id: Annotated[
        str | None,
        typer.Option("--review-provider-id"),
    ] = None,
    review_model: Annotated[str | None, typer.Option("--review-model")] = None,
    review_secret_env: Annotated[
        str | None,
        typer.Option("--review-secret-env"),
    ] = None,
    allow_private_review_provider: Annotated[
        bool,
        typer.Option("--allow-private-review-provider"),
    ] = False,
    input_cost_per_million: Annotated[float, typer.Option("--input-cost-per-million", min=0)] = 0,
    output_cost_per_million: Annotated[float, typer.Option("--output-cost-per-million", min=0)] = 0,
) -> None:
    """Run policy-bound roles with optional diverse review Provider/model authority."""

    with _cli_error_boundary("Cannot start provider-backed agents", exit_code=2):
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
        review_values = (
            review_provider_endpoint,
            review_provider_id,
            review_model,
            review_secret_env,
        )
        if any(value is not None for value in review_values) and not all(
            value is not None for value in review_values
        ):
            raise ValueError(
                "diverse review requires endpoint, provider ID, model, and secret environment"
            )
        review_registration = None
        review_credential = None
        if all(value is not None for value in review_values):
            assert review_provider_endpoint is not None
            assert review_provider_id is not None
            assert review_model is not None
            assert review_secret_env is not None
            review_credential = os.environ.get(review_secret_env)
            if not review_credential:
                raise ValueError(
                    f"review provider credential environment variable is unset: {review_secret_env}"
                )
            review_registration = ProviderRegistration.model_validate(
                {
                    "provider_id": review_provider_id,
                    "endpoint": review_provider_endpoint,
                    "model": review_model,
                    "secret_ref": f"provider/{review_provider_id}/api-key",
                    "allow_private_networks": allow_private_review_provider,
                }
            )
    with _cli_error_boundary("Provider-backed agent run failed", exit_code=1):
        secrets = SecretBroker()
        secrets.register(registration.secret_ref, credential)
        if review_registration is not None and review_credential is not None:
            secrets.register(review_registration.secret_ref, review_credential)
        registry = _tool_registry()
        registry.register(OpenAICompatibleChatTool(registration))
        if review_registration is not None:
            registry.register(OpenAICompatibleChatTool(review_registration))
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
            review_registration=review_registration,
        )
        runner = MultiAgentCampaignRunner(
            planner=runtime,
            validator=runtime,
            reporter=runtime,
            candidate_producer=KISACandidateProducer(),
            tools=registry,
            policy=PolicyEngine(),
            worker=backend,
            output_root=output,
            secrets=secrets,
        )
        outcome = asyncio.run(runner.run(campaign))
        checks = _provider_agent_checks(
            outcome,
            credential=credential,
            additional_credentials=((review_credential,) if review_credential is not None else ()),
        )
    _print_check_table("PAJIN Provider-Backed Multi-Agent Runtime", checks)
    _print_cli_field("Run", outcome.run_id)
    _print_cli_field("Report", outcome.report_path.resolve())
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

    with _cli_error_boundary("Cannot start tool loop", exit_code=2):
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
    with _cli_error_boundary("Tool loop execution failed", exit_code=1):
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
    _print_check_table("PAJIN Policy-Governed Agent Tool Loop", checks)
    _print_cli_field("Run", outcome.run_id)
    _print_cli_field("Checkpoint", outcome.checkpoint_path.resolve())
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

    with _cli_error_boundary("Cannot start approval check", exit_code=2):
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
    with _cli_error_boundary("Approval check execution failed", exit_code=1):
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
    with _cli_error_boundary("Approval continuation failed", exit_code=1):
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
    _print_check_table("PAJIN T3 Tool Loop Approval & Resume", checks)
    _print_cli_field("Waiting run", waiting.run_id)
    _print_cli_field("Continuation run", resumed.run_id)
    _print_cli_field("Approval", approval.approval_id)
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command("multi-cancel-check")
def check_multi_agent_cancellation(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
) -> None:
    """Verify live cancellation and sealed owned-stack cleanup receipts."""

    with _cli_error_boundary("Cannot start cancellation check", exit_code=2):
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
    with _cli_error_boundary("Cancellation check failed", exit_code=1):
        registry = _tool_registry()
        registry.register(SleepCheckTool())
        kill_switch = KillSwitch()
        cancellation = ExecutionCancellationContext()
        runner = MultiAgentCampaignRunner(
            planner=DeterministicAgentRuntime(),
            validator=DeterministicAgentRuntime(),
            tools=registry,
            policy=PolicyEngine(),
            worker=backend,
            output_root=output,
            kill_switch=kill_switch,
        )
        outcome = asyncio.run(
            _run_multi_cancel_check(
                runner,
                campaign,
                cancellation,
            )
        )
        checks = _multi_cancel_checks(outcome, backend=backend)
    _print_worker_execution_context(backend)
    _print_check_table("PAJIN Live Cancellation & Owned-Stack Quiescence", checks)
    console.print(
        "Physical resource cleanup: NOT ATTESTED by the local receipt; "
        "backend cleanup failures still fail the command."
    )
    _print_cli_field("Report", outcome.report_path)
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command("kisa-run")
def run_kisa_ai_redteam(
    manifest: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/runs"),
    worker: Annotated[str, typer.Option("--worker")] = "docker",
    repetitions: Annotated[int, typer.Option("--repetitions", min=2, max=20)] = 2,
    validation_controls: Annotated[
        bool,
        typer.Option(
            "--validation-controls",
            help=(
                "Run information-only fresh-capability M03, M06, and A04 Baseline, "
                "Negative Control, and Counterfactual checks."
            ),
        ),
    ] = False,
) -> None:
    """Run the KISA-aligned AI Red Team Mode Pack and emit guide artifacts."""

    with _cli_error_boundary("Cannot start KISA campaign", exit_code=2):
        campaign = load_manifest(manifest)
        backend = _worker_backend(worker)
        planner = _prepare_kisa_replay_planner(
            campaign,
            repetitions=repetitions,
            mode_error="KISA Mode Pack requires mode: ai-redteam",
            budget_error=(
                (
                    "maxToolCalls must reserve the original KISA plan and every automatic "
                    "replay attempt and opted-in validation Control"
                )
                if validation_controls
                else (
                    "maxToolCalls must reserve the original KISA plan and every automatic "
                    "replay attempt"
                )
            ),
            validation_controls=validation_controls,
        )
        thresholds = planner.thresholds
    with _cli_error_boundary("KISA campaign setup failed", exit_code=1):
        registry = _tool_registry()
        policy = PolicyEngine()
        budget = BudgetController(campaign.spec.budgets)
        rate_limits = RequestRateLimitLedger()
        runner = MultiAgentCampaignRunner(
            planner=planner,
            validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
            candidate_producer=KISACandidateProducer(),
            tools=registry,
            policy=policy,
            worker=backend,
            output_root=output,
        )
        coordinator = KISAReplayCoordinator(
            tools=registry,
            policy=policy,
            worker=backend,
            output_root=output / "replay",
            repetitions=repetitions,
            required_successes=repetitions,
            ticket_authority_factory=lambda: SQLiteReplayExecutionAuthority(
                output / "replay" / "replay-tickets.sqlite3"
            ),
        )
        control_coordinator = (
            KISAValidationControlCoordinator(
                tools=registry,
                policy=policy,
                worker=backend,
                output_root=output / "validation-controls",
            )
            if validation_controls
            else None
        )

    async def execute_kisa() -> tuple[
        MultiAgentRunOutcome,
        KISAReplayBatchOutcome | None,
        KISAValidationControlBatchOutcome | None,
    ]:
        outcome = await runner.run(
            campaign,
            budget=budget,
            rate_limits=rate_limits,
        )
        replay_batch = None
        control_batch = None
        if outcome.status is RunStatus.COMPLETED:
            replay_batch = await coordinator.reproduce(
                campaign,
                outcome.run_path,
                budget=budget,
                rate_limits=rate_limits,
            )
            confirmation_results = getattr(
                replay_batch,
                "confirmation_results",
                replay_batch.verified_results,
            )
            if confirmation_results:
                confirmation = apply_confirmed_gate(
                    source_run_path=outcome.run_path,
                    replay_run_paths=[result.run_path for result in confirmation_results.values()],
                    tickets=replay_batch.tickets,
                )
                outcome = outcome.model_copy(
                    update={
                        "validation": confirmation.validation,
                        "findings": confirmation.product_confirmed_findings,
                    }
                )
            if control_coordinator is not None:
                control_batch = await control_coordinator.execute(
                    campaign,
                    outcome.run_path,
                    budget=budget,
                    rate_limits=rate_limits,
                )
        return outcome, replay_batch, control_batch

    with _cli_error_boundary("KISA evaluation failed", exit_code=1):
        outcome, replay_batch, control_batch = asyncio.run(execute_kisa())
        mode_outcome = KISAModePack(thresholds=thresholds).evaluate(
            campaign,
            outcome,
            replay_batch,
        )
    failed_metrics = sum(
        metric.status is MetricStatus.FAIL for metric in mode_outcome.assessment.metrics
    )
    summary = mode_outcome.assessment.checklist_summary
    _print_worker_execution_context(backend)
    table = Table(title="PAJIN KISA AI Red Team Mode Pack")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run status", outcome.status.value)
    table.add_row("Threat coverage", f"{mode_outcome.assessment.coverage.coverage_rate:.1%}")
    table.add_row("Confirmed findings", str(len(outcome.findings)))
    table.add_row(
        "Replay Oracle supports",
        str(
            sum(record.supports_claim for record in replay_batch.records)
            if replay_batch is not None
            else 0
        ),
    )
    table.add_row(
        "Validation Control runs",
        str(len(control_batch.records) if control_batch is not None else 0),
    )
    table.add_row(
        "Validation Control authority",
        "information-only (cannot confirm)",
    )
    table.add_row(
        "Finding needs review",
        str(_disposition_count(outcome.validation, FindingDisposition.NEEDS_REVIEW)),
    )
    table.add_row("Failed metric thresholds", str(failed_metrics))
    table.add_row("Checklist yes", str(summary.yes))
    table.add_row("Checklist no", str(summary.no))
    table.add_row("Checklist needs review", str(summary.needs_review))
    console.print(table)
    _print_cli_field("KISA report", mode_outcome.report_path.resolve())
    _print_cli_field("KISA checklist", mode_outcome.checklist_path.resolve())
    replay_execution_failed = replay_batch is not None and any(
        record.execution_status != "succeeded" for record in replay_batch.records
    )
    if outcome.status is not RunStatus.COMPLETED or replay_execution_failed or failed_metrics:
        raise typer.Exit(code=1)


@dataclass(frozen=True, slots=True)
class _KISARetestSetup:
    campaign: CampaignManifest
    backend: WorkerBackend
    remediation_plan: KISARemediationPlanOutcome
    planner: KISARetestPlannerRuntime


def _prepare_kisa_retest(
    *,
    baseline_run: Path,
    manifest: Path,
    worker: str,
    repetitions: int,
    normal_prompt: str,
    expected_contains: str,
    retest_service: KISARetestService,
) -> _KISARetestSetup:
    campaign = load_manifest(manifest)
    backend = _worker_backend(worker)
    if campaign.spec.mode is not CampaignMode.AI_REDTEAM:
        raise ValueError("KISA retest requires mode: ai-redteam")
    remediation_plan = retest_service.create_remediation_plan(baseline_run)
    planner = KISARetestPlannerRuntime(
        thresholds=EvaluationThresholds(repetitions=repetitions),
        normal_prompt=normal_prompt,
        expected_contains=expected_contains,
    )
    preflight_plan = asyncio.run(planner.plan(campaign))
    # Normal probes are T1 operations and may consume one bounded retry each.
    # Reserve their worst-case calls before sharing the Campaign budget with
    # the baseline-bound negative replay coordinator.
    required_calls = 2 * len(preflight_plan.steps) + len(remediation_plan.actions) * repetitions
    if required_calls > campaign.spec.budgets.max_tool_calls:
        raise ValueError(
            "maxToolCalls must reserve every normal-function probe retry and "
            "baseline-bound negative replay attempt "
            f"(requires at least {required_calls})"
        )
    return _KISARetestSetup(
        campaign=campaign,
        backend=backend,
        remediation_plan=remediation_plan,
        planner=planner,
    )


async def _execute_kisa_retest(
    *,
    setup: _KISARetestSetup,
    baseline_run: Path,
    retest_service: KISARetestService,
    runner: MultiAgentCampaignRunner,
    coordinator: KISARetestReplayCoordinator,
    budget: BudgetController,
    rate_limits: RequestRateLimitLedger,
) -> tuple[MultiAgentRunOutcome, KISAReplayBatchOutcome | None]:
    outcome = await runner.run(
        setup.campaign,
        budget=budget,
        rate_limits=rate_limits,
    )
    if outcome.status is not RunStatus.COMPLETED:
        return outcome, None

    # The parent Run intentionally contains only normal-function probes. Do not
    # project an attack-scenario Mode Pack assessment onto that evidence; bind
    # the sealed parent Run directly into every negative replay context.
    contexts = retest_service.build_retest_contexts(baseline_run, outcome.run_path)
    replay_batch = await coordinator.reproduce(
        setup.campaign,
        baseline_run,
        outcome.run_path,
        contexts=contexts,
        budget=budget,
        rate_limits=rate_limits,
    )
    return outcome, replay_batch


def _require_completed_retest(
    outcome: MultiAgentRunOutcome,
    replay_batch: KISAReplayBatchOutcome | None,
) -> KISAReplayBatchOutcome:
    if outcome.status is not RunStatus.COMPLETED:
        _print_cli_error("Retest run failed", RuntimeError(outcome.run_id))
        _print_cli_field("Report", outcome.report_path.resolve())
        raise typer.Exit(code=1)
    if replay_batch is None:
        _print_cli_error(
            "KISA retest failed",
            RuntimeError("replay did not produce a sealed batch"),
        )
        raise typer.Exit(code=1)
    return replay_batch


def _print_kisa_retest_result(
    *,
    outcome: MultiAgentRunOutcome,
    replay_batch: KISAReplayBatchOutcome,
    retest: KISARetestOutcome,
    remediation_plan: KISARemediationPlanOutcome,
) -> None:
    summary = retest.assessment.summary
    table = Table(title="PAJIN KISA Remediation & Retest")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Retest run", _plain_cli_value(outcome.run_id))
    table.add_row("Fixed", str(summary.fixed))
    table.add_row("Still vulnerable", str(summary.still_vulnerable))
    table.add_row("Inconclusive", str(summary.inconclusive))
    table.add_row("New threat discovery", "Not assessed — run fresh `pajin kisa-run`")
    if summary.new_findings:
        table.add_row("Unexpected new confirmed findings observed", str(summary.new_findings))
    table.add_row("Verified negative replay receipts", str(len(replay_batch.verified_results)))
    table.add_row("Normal-function regression", summary.regression.value)
    console.print(table)
    _print_cli_field("Retest report", retest.report_path.resolve())
    _print_cli_field("Baseline remediation plan", remediation_plan.path.resolve())
    _print_cli_field("Retest remediation copy", retest.remediation_plan_path.resolve())
    _print_cli_field("Checklist overlay", retest.checklist_overlay_path.resolve())
    console.print(
        "[yellow]Scope note:[/yellow] this command closes the supplied baseline findings; "
        "it is not a full re-scan for newly introduced threat classes. Run a fresh "
        "`pajin kisa-run` as a separate discovery gate for currently supported scenarios."
    )


def _kisa_retest_acceptance_failed(
    retest: KISARetestOutcome,
    remediation_plan: KISARemediationPlanOutcome,
) -> bool:
    summary = retest.assessment.summary
    return (
        summary.fixed != len(remediation_plan.actions)
        or summary.still_vulnerable > 0
        or summary.inconclusive > 0
        or summary.new_findings > 0
        or summary.regression is not RegressionStatus.PASS
    )


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
    """Verify remediation with baseline-bound replays and normal regression probes."""

    retest_service = KISARetestService()
    with _cli_error_boundary("Cannot start KISA retest", exit_code=2):
        setup = _prepare_kisa_retest(
            baseline_run=baseline_run,
            manifest=manifest,
            worker=worker,
            repetitions=repetitions,
            normal_prompt=normal_prompt,
            expected_contains=expected_contains,
            retest_service=retest_service,
        )

    with _cli_error_boundary("KISA retest setup failed", exit_code=1):
        registry = _tool_registry()
        policy = PolicyEngine()
        budget = BudgetController(setup.campaign.spec.budgets)
        rate_limits = RequestRateLimitLedger()
        runner = MultiAgentCampaignRunner(
            planner=setup.planner,
            validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
            candidate_producer=KISACandidateProducer(),
            tools=registry,
            policy=policy,
            worker=setup.backend,
            output_root=output,
        )
        coordinator = KISARetestReplayCoordinator(
            tools=registry,
            policy=policy,
            worker=setup.backend,
            output_root=output / "retest-replay",
            repetitions=repetitions,
            ticket_authority_factory=lambda: SQLiteReplayExecutionAuthority(
                output / "retest-replay" / "replay-tickets.sqlite3"
            ),
        )

    with _cli_error_boundary("KISA retest execution failed", exit_code=1):
        outcome, replay_batch = asyncio.run(
            _execute_kisa_retest(
                setup=setup,
                baseline_run=baseline_run,
                retest_service=retest_service,
                runner=runner,
                coordinator=coordinator,
                budget=budget,
                rate_limits=rate_limits,
            )
        )
    verified_batch = _require_completed_retest(outcome, replay_batch)
    with _cli_error_boundary("KISA retest comparison failed", exit_code=1):
        retest = retest_service.compare(
            baseline_run,
            outcome.run_path,
            replay_batch=verified_batch,
        )
    _print_worker_execution_context(setup.backend)
    _print_kisa_retest_result(
        outcome=outcome,
        replay_batch=verified_batch,
        retest=retest,
        remediation_plan=setup.remediation_plan,
    )
    if _kisa_retest_acceptance_failed(retest, setup.remediation_plan):
        raise typer.Exit(code=1)


@app.command("kisa-plan-remediation")
def plan_kisa_remediation(
    baseline_run: Annotated[Path, typer.Argument(exists=True, readable=True, file_okay=False)],
) -> None:
    """Create a threat-specific remediation plan from a completed KISA baseline run."""

    with _cli_error_boundary("Cannot create remediation plan", exit_code=2):
        outcome = KISARetestService().create_remediation_plan(baseline_run)
    table = Table(title="PAJIN KISA Remediation Plan")
    table.add_column("Threat")
    table.add_column("Finding")
    table.add_column("Controls")
    table.add_column("Assignment")
    for action in outcome.actions:
        table.add_row(
            _plain_cli_value(action.threat_class),
            _plain_cli_value(action.baseline_finding_id),
            str(len(action.controls)),
            "needs-review" if action.requires_human_assignment else "assigned",
        )
    console.print(table)
    _print_cli_field("Remediation plan", outcome.path.resolve())


def _load_campaign_builder_source(
    source_path: Path,
    *,
    profile_id: str,
) -> CampaignBuilderSource:
    if profile_id == "pajin.profile.bug-hunt":
        return load_bug_bounty_program(source_path)
    if profile_id == "pajin.profile.ctf":
        return load_ctf_challenge(source_path)
    raise CampaignBuilderError(
        "Campaign draft CLI supports only pajin.profile.bug-hunt or pajin.profile.ctf"
    )


def _print_campaign_builder_draft(draft: CampaignProfileScopeDraft) -> None:
    table = Table(title="PAJIN Campaign Builder Draft")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Draft ID", _plain_cli_value(draft.draft_id))
    table.add_row("Source kind", draft.source_kind.value)
    table.add_row(
        "Profile",
        _plain_cli_value(
            f"{draft.selected_profile.profile_id}@{draft.selected_profile.profile_version}"
        ),
    )
    table.add_row("Target inputs", str(len(draft.scope_preview.target_inputs)))
    table.add_row("Review-only sources", str(len(draft.scope_preview.review_only_source_ids)))
    table.add_row("Draft state", draft.draft_state)
    table.add_row("Execution authorized", "false")
    console.print(table)


@app.command("campaign-draft-create")
def create_campaign_builder_draft(
    source_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    profile_id: Annotated[str, typer.Option("--profile-id")],
    profile_version: Annotated[str, typer.Option("--profile-version")] = "1.0.0",
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/drafts"),
) -> None:
    """Create a content-addressed local draft without compiling a Campaign."""

    with _cli_error_boundary("Cannot create Campaign Builder draft", exit_code=2):
        source = _load_campaign_builder_source(source_path, profile_id=profile_id)
        draft = build_campaign_profile_scope_draft(
            source,
            profile_id=profile_id,
            profile_version=profile_version,
        )
        artifact = write_campaign_profile_scope_draft(draft, output)
    _print_campaign_builder_draft(artifact.draft)
    _print_cli_field("Draft artifact", artifact.path.resolve())
    console.print("No Campaign, approval, Capability, Permit, or execution authority was created.")


@app.command("campaign-draft-inspect")
def inspect_campaign_builder_draft(
    draft_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
) -> None:
    """Inspect a fully revalidated local Campaign Builder draft artifact."""

    with _cli_error_boundary("Cannot inspect Campaign Builder draft", exit_code=2):
        draft = load_campaign_profile_scope_draft(draft_path)
    _print_campaign_builder_draft(draft)
    _print_cli_field("Draft artifact", draft_path.resolve())
    console.print("This draft is not a compiler input or execution authorization.")


@app.command("bug-bounty-review")
def review_bug_bounty_scope(
    program_path: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".pajin/programs"),
) -> None:
    """Normalize a Bug Bounty program policy and emit a digest-bound scope review."""

    with _cli_error_boundary("Cannot review Bug Bounty scope", exit_code=2):
        program = load_bug_bounty_program(program_path)
        artifacts = BugBountyScopeService().write_review(program, output)

    review = artifacts.review
    table = Table(title="PAJIN Bug Bounty Scope Review")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Program", _plain_cli_value(program.metadata.display_name))
    table.add_row("In-scope rules", str(len(review.allow)))
    table.add_row("Out-of-scope rules", str(len(review.deny)))
    table.add_row("Entry points", str(len(review.entry_points)))
    table.add_row("Warnings", str(len(review.warnings)))
    console.print(table)
    _print_cli_field("Scope digest", review.scope_digest)
    _print_cli_field("Scope review", artifacts.review_markdown_path.resolve())
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

    with _cli_error_boundary("Cannot compile Bug Bounty campaign", exit_code=2):
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

    campaign = artifact.campaign
    table = Table(title="Compiled PAJIN Bug Bounty Campaign")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Campaign", _plain_cli_value(campaign.metadata.name))
    table.add_row("Targets", str(len(campaign.spec.targets)))
    table.add_row("Max risk", f"T{campaign.spec.rules_of_engagement.max_tool_risk_tier.value}")
    table.add_row(
        "Rate limit",
        f"{campaign.spec.rules_of_engagement.max_requests_per_minute}/minute",
    )
    console.print(table)
    _print_cli_field("Campaign manifest", artifact.path.resolve())


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

    with _cli_error_boundary("Cannot create Bug Bounty report", exit_code=2):
        program = load_bug_bounty_program(program_path)
        finding_index = (
            load_bug_bounty_finding_index(known_findings) if known_findings is not None else None
        )
        artifacts = BugBountyReportService().report_run(
            program,
            run_path,
            known_findings=finding_index,
        )

    summary = artifacts.report.summary
    table = Table(title="PAJIN Bug Bounty Finding Triage")
    table.add_column("Disposition")
    table.add_column("Count")
    table.add_row("Ready", str(summary.ready))
    table.add_row("Needs review", str(summary.needs_review))
    table.add_row("Known duplicates", str(summary.known_duplicates))
    table.add_row("Same-run duplicates", str(summary.run_duplicates))
    console.print(table)
    _print_cli_field("Triage report", artifacts.report_path.resolve())
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

    with _cli_error_boundary("Cannot start Bug Bounty campaign", exit_code=2):
        program = load_bug_bounty_program(program_path)
        campaign = load_manifest(manifest)
        finding_index = (
            load_bug_bounty_finding_index(known_findings) if known_findings is not None else None
        )
        report_service = BugBountyReportService()
        report_service.validate_campaign(program, campaign)
    with _cli_error_boundary("Bug Bounty execution failed", exit_code=1):
        runner = MultiAgentCampaignRunner(
            planner=BugBountyPlannerRuntime(),
            validator=BugBountyValidatorRuntime(),
            tools=_tool_registry(),
            policy=PolicyEngine(),
            worker=_worker_backend("docker"),
            output_root=output,
        )
        outcome = asyncio.run(runner.run(campaign))
    failed_tools = sum(not result.success for result in outcome.tool_results)
    if outcome.status is not RunStatus.COMPLETED or failed_tools:
        _print_cli_error(
            "Bug Bounty run failed",
            RuntimeError(
                outcome.cancellation_reason
                or (f"{failed_tools} tool call(s) failed" if failed_tools else outcome.run_id)
            ),
        )
        if outcome.cancellation_reason:
            _print_cli_field("Reason", outcome.cancellation_reason)
        _print_cli_field("Run report", outcome.report_path.resolve())
        raise typer.Exit(code=1)

    with _cli_error_boundary("Bug Bounty triage failed", exit_code=1):
        artifacts = report_service.report_run(
            program,
            outcome.run_path,
            known_findings=finding_index,
        )

    summary = artifacts.report.summary
    table = Table(title="PAJIN Bug Bounty Multi-Agent Run")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run status", outcome.status.value)
    table.add_row("Tool calls", str(len(outcome.tool_results)))
    table.add_row("Confirmed findings", str(len(outcome.findings)))
    table.add_row(
        "Candidate needs review",
        str(_disposition_count(outcome.validation, FindingDisposition.NEEDS_REVIEW)),
    )
    table.add_row("Ready drafts", str(summary.ready))
    table.add_row("Triage needs review", str(summary.needs_review))
    table.add_row("Known duplicates", str(summary.known_duplicates))
    table.add_row("Same-run duplicates", str(summary.run_duplicates))
    console.print(table)
    _print_cli_field("Run report", outcome.report_path.resolve())
    _print_cli_field("Triage report", artifacts.report_path.resolve())
    console.print(f"Submission drafts: {len(artifacts.submission_paths)}")
    console.print("No external submission was performed.")


def _ctf_runner(output: Path) -> MultiAgentCampaignRunner:
    return MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
        tools=_tool_registry(),
        policy=PolicyEngine(),
        worker=_worker_backend("docker"),
        output_root=output,
    )


def _execute_ctf_challenge(
    challenge_path: Path,
    output: Path,
    *,
    required_category: CTFCategory | None = None,
) -> None:
    with _cli_error_boundary("Cannot start CTF challenge", exit_code=2):
        challenge = load_ctf_challenge(challenge_path)
        if required_category is not None and challenge.spec.category is not required_category:
            raise ValueError(
                f"this command accepts only the {required_category.value} CTF category"
            )
        campaign = CTFChallengeService().compile_campaign(challenge)
    with _cli_error_boundary("CTF execution failed", exit_code=1):
        outcome = asyncio.run(_ctf_runner(output).run(campaign))
    failed_tools = sum(not result.success for result in outcome.tool_results)
    if outcome.status is not RunStatus.COMPLETED or failed_tools:
        _print_cli_error(
            "CTF run failed",
            RuntimeError(
                outcome.cancellation_reason
                or (f"{failed_tools} tool call(s) failed" if failed_tools else outcome.run_id)
            ),
        )
        if outcome.cancellation_reason:
            _print_cli_field("Reason", outcome.cancellation_reason)
        _print_cli_field("Run report", outcome.report_path.resolve())
        raise typer.Exit(code=1)

    with _cli_error_boundary("CTF finalization failed", exit_code=1):
        artifacts = CTFModePack().finalize(challenge, outcome)

    result = artifacts.result
    table = Table(title=f"PAJIN CTF {result.category.value.title()} Multi-Agent Run")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run status", outcome.status.value)
    table.add_row("Solve status", result.status.value)
    table.add_row("Agents", str(len(outcome.agents)))
    table.add_row("Tool calls", str(len(outcome.tool_results)))
    # The CTF digest verifier owns ``result.status``. Generic Finding confirmation
    # is a separate replay/attestation boundary and must not be presented as the
    # number of independent flag validations.
    table.add_row("Confirmed findings", str(len(outcome.findings)))
    console.print(table)
    if result.status is CTFSolveStatus.SOLVED:
        _print_cli_field("Verified flag", result.candidate_flag)
    _print_cli_field("CTF result", artifacts.result_path.resolve())
    _print_cli_field("CTF write-up", artifacts.writeup_path.resolve())
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

    with _cli_error_boundary("Cannot start CTF Suite", exit_code=2):
        challenges = [load_ctf_challenge(path) for path in challenge_paths]
        campaign = CTFChallengeService().compile_suite(suite_name, challenges)
    with _cli_error_boundary("CTF Suite execution failed", exit_code=1):
        outcome = asyncio.run(_ctf_runner(output).run(campaign))
    failed_tools = sum(not result.success for result in outcome.tool_results)
    if outcome.status is not RunStatus.COMPLETED or failed_tools:
        _print_cli_error(
            "CTF Suite run failed",
            RuntimeError(
                outcome.cancellation_reason
                or (f"{failed_tools} tool call(s) failed" if failed_tools else outcome.run_id)
            ),
        )
        if outcome.cancellation_reason:
            _print_cli_field("Reason", outcome.cancellation_reason)
        _print_cli_field("Run report", outcome.report_path.resolve())
        raise typer.Exit(code=1)

    with _cli_error_boundary("CTF Suite finalization failed", exit_code=1):
        artifacts = CTFSuiteModePack().finalize(suite_name, challenges, outcome)

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
            label = f"Verified flag ({_safe_cli_value(item.challenge_id)})"
            _print_cli_field(label, item.candidate_flag)
    _print_cli_field("CTF Suite result", artifacts.result_path.resolve())
    _print_cli_field("CTF Suite write-up", artifacts.writeup_path.resolve())
    console.print("No external scoreboard submission was performed.")
    if summary.solved != len(artifacts.result.items):
        raise typer.Exit(code=1)


@app.command("evidence-verify")
def verify_run_evidence(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True, file_okay=False)],
) -> None:
    """Verify a Run's Audit Event chain and sealed artifact digest chain."""

    with _cli_error_boundary("Run integrity verification failed", exit_code=1):
        verification = verify_run_integrity(run_path)

    table = Table(title="PAJIN Run Evidence Integrity")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Run", _plain_cli_value(verification.run_id))
    table.add_row("Seals", str(verification.seal_count))
    table.add_row("Artifacts", str(verification.artifact_count))
    table.add_row("Audit events", str(verification.event_count))
    table.add_row("Root digest", f"{verification.root_digest[:16]}...")
    table.add_row("Integrity", "VALID")
    console.print(table)
    _print_cli_field("Root digest", verification.root_digest)


@app.command("sarif-export")
def export_sarif(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True, file_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o", dir_okay=False)],
    expected_run_id: Annotated[str, typer.Option("--expected-run-id")],
    expected_root_digest: Annotated[str, typer.Option("--expected-root-digest")],
) -> None:
    """Export replay-confirmed Findings from one exact sealed Run as local SARIF 2.1.0."""

    with _cli_error_boundary("SARIF export failed", exit_code=1):
        exported = load_verified_sarif_export(
            run_path,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
        )
        persisted = write_verified_sarif_export(exported, output)

    table = Table(title="PAJIN Verified Finding SARIF Export")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Source Run", _plain_cli_value(exported.source_run_id))
    table.add_row("Confirmed Findings", str(exported.finding_count))
    table.add_row("Source root", _plain_cli_value(exported.source_root_digest))
    table.add_row("Finding set digest", _plain_cli_value(exported.finding_set_digest))
    table.add_row("SARIF digest", _plain_cli_value(exported.sarif_digest))
    table.add_row("External delivery", "NOT PERFORMED")
    console.print(table)
    _print_cli_field("SARIF artifact", persisted)


@app.command("replay-verify")
def verify_replay_ticket(
    replay_run: Annotated[Path, typer.Argument()],
    ledger: Annotated[Path, typer.Option("--ledger", dir_okay=False)],
) -> None:
    """Verify a sealed replay Run against a durable read-only ticket ledger."""

    with _cli_error_boundary("Replay verification failed", exit_code=1):
        if not replay_run.is_dir():
            raise ValueError("replay Run directory does not exist")
        tickets = SQLiteReplayTicketFinalizationVerifier(ledger)
        verified = load_verified_replay_result(replay_run, tickets=tickets)

    table = Table(title="PAJIN Durable Replay Ticket Verification")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Replay run", _plain_cli_value(verified.verification.run_id))
    table.add_row("Ticket", _plain_cli_value(verified.receipt.ticket_id))
    table.add_row("Source root", _plain_cli_value(verified.receipt.candidate_source_root_digest))
    table.add_row("Receipt seal root", _plain_cli_value(verified.receipt_seal_root_digest))
    table.add_row("Ledger", _plain_cli_value(ledger.resolve()))
    table.add_row("Verification", "VALID")
    console.print(table)
    _print_cli_field("Root digest", verified.receipt_seal_root_digest)


@app.command("replay-attestation-verify")
def verify_replay_attestation(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True, dir_okay=False)],
    trust_anchor: Annotated[
        Path,
        typer.Option("--trust-anchor", exists=True, readable=True, dir_okay=False),
    ],
) -> None:
    """Verify a portable Claim receipt bundle against explicit out-of-band trust."""

    with _cli_error_boundary("Replay attestation verification failed", exit_code=1):
        parsed_bundle = load_portable_replay_attestation_file(bundle)
        parsed_anchor = load_replay_attestation_trust_anchor(trust_anchor)
        verified = verify_portable_replay_attestation(
            parsed_bundle,
            trust_anchor=parsed_anchor,
        )

    table = Table(title="PAJIN Portable Replay Attestation")
    table.add_column("Measure")
    table.add_column("Value")
    table.add_row("Batch", _plain_cli_value(verified.batch_id))
    table.add_row("Signing key", _plain_cli_value(verified.key_id))
    table.add_row("Key state", verified.key_state.value)
    table.add_row("Claim receipts", str(verified.receipt_count))
    table.add_row("Verification", "VALID")
    console.print(table)
    _print_cli_field("Input authority digest", verified.input_authority_digest)
    _print_cli_field("Trust anchor digest", verified.trust_anchor_digest)


@app.command("worker-check")
def check_worker() -> None:
    """Verify the Docker Worker security profile and timeout enforcement."""

    with _cli_error_boundary("Worker isolation check failed", exit_code=1):
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
        _print_cli_error("Worker isolation check failed", RuntimeError(isolation.stderr))
        raise typer.Exit(code=1)
    with _cli_error_boundary("Invalid worker-check output", exit_code=1):
        checks = decode_strict_worker_json_object(
            isolation,
            label="worker isolation result",
        )

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

    with _cli_error_boundary("Worker timeout check failed", exit_code=1):
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

    with _cli_error_boundary("Egress check failed", exit_code=1):
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        results = asyncio.run(_run_egress_checks(backend))
        allowed = results["allowed"]
        denied = results["denied"]
        direct = results["direct"]
        allowed_payload = decode_strict_worker_json_object(
            allowed,
            label="allowed egress result",
        )
        denied_payload = decode_strict_worker_json_object(
            denied,
            label="denied egress result",
        )
        direct_payload = decode_strict_worker_json_object(
            direct,
            label="direct-network result",
        )
        allowed_status = _cli_json_integer(
            allowed_payload.get("status", 0),
            label="allowed egress status",
        )
        denied_status = _cli_json_integer(
            denied_payload.get("status", 0),
            label="denied egress status",
        )
        checks = {
            "allowlisted HTTP request": (
                allowed.status is WorkerStatus.SUCCEEDED
                and 200 <= allowed_status < 400
                and '"event":"allow"' in allowed.network_log
            ),
            "denied host rejected": (
                denied.status is WorkerStatus.SUCCEEDED
                and not 200 <= denied_status < 400
                and '"event":"deny"' in denied.network_log
            ),
            "direct socket bypass blocked": (
                direct.status is WorkerStatus.SUCCEEDED
                and direct_payload.get("directNetworkBlocked") is True
                and direct_payload.get("failureKind") == "network-unreachable"
                and '"event":"allow"' not in direct.network_log
            ),
        }
    _print_check_table("PAJIN Egress Isolation", checks)
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command("mcp-check")
def check_mcp() -> None:
    """Verify the Worker MCP catalog accepts registered calls and rejects unknown IDs."""

    with _cli_error_boundary("MCP check failed", exit_code=1):
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        results = asyncio.run(_run_mcp_checks(backend))
        registered = results["registered"]
        registered_discovery = results["registered_discovery"]
        unknown_server = results["unknown_server"]
        unknown_tool = results["unknown_tool"]
        checks = {
            "registered MCP call": _mcp_registered_call_matches(registered),
            "registered MCP boundary discovery": _mcp_registered_discovery_matches(
                registered_discovery
            ),
            "unknown server rejected with typed code": _mcp_rejection_matches(
                unknown_server,
                expected_code="server-not-registered",
            ),
            "unknown tool rejected with typed code": _mcp_rejection_matches(
                unknown_tool,
                expected_code="tool-not-registered",
            ),
        }
    _print_check_table("PAJIN MCP Registration Boundary", checks)
    if not all(checks.values()):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
