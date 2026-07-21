"""Sealed checkpoint and budget contracts for Tool Loop CLI commands."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pajin.domain.models import CampaignManifest, ToolRiskTier
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import VerifiedRunSnapshot
from pajin.workflow.tool_loop import ToolLoopCheckpoint, ToolLoopOutcome, ToolLoopStatus

from .common import (
    MAX_CLI_RUN_ARTIFACT_BYTES,
    cli_json_integer,
    cli_json_object,
    cli_json_object_list,
    verified_cli_run_contains_secret,
)


class ArtifactLoader(Protocol):
    def __call__(
        self,
        run_path: Path,
        *,
        requests: Mapping[str, int],
        expected_run_id: str | None = None,
    ) -> VerifiedRunSnapshot: ...


@dataclass(frozen=True, slots=True)
class _VerifiedToolLoopRun:
    campaign: CampaignManifest
    state: ToolLoopCheckpoint
    checkpoint: ToolLoopCheckpoint
    budget: dict[str, object]
    leases: list[dict[str, object]]
    checkpoint_relative: str
    event_types: tuple[str, ...]
    terminal_outcome_bound: bool


@dataclass(frozen=True, slots=True)
class _ToolLoopBudgetUsage:
    agent_count: int
    tool_calls: int
    model_calls: int
    model_prompt_tokens: int
    model_completion_tokens: int
    model_tokens: int


def _verified_snapshot_json(
    snapshot: VerifiedRunSnapshot,
    relative_path: str,
    *,
    label: str,
) -> object:
    return parse_strict_json_bytes(
        snapshot.artifact_bytes(relative_path),
        label=label,
        max_bytes=MAX_CLI_RUN_ARTIFACT_BYTES,
    )


def _verified_tool_loop_run(
    outcome: ToolLoopOutcome,
    *,
    artifact_loader: ArtifactLoader,
) -> _VerifiedToolLoopRun:
    """Bind one returned Tool Loop outcome to its exact sealed terminal checkpoint."""

    checkpoint_relative = outcome.checkpoint_path.relative_to(outcome.run_path).as_posix()
    requested_paths = {
        "budget.json",
        "campaign.json",
        "run.json",
        "secrets.json",
        "tool-loop.json",
        checkpoint_relative,
    }
    snapshot = artifact_loader(
        outcome.run_path,
        requests={path: MAX_CLI_RUN_ARTIFACT_BYTES for path in requested_paths},
        expected_run_id=outcome.run_id,
    )
    campaign = CampaignManifest.model_validate(
        _verified_snapshot_json(
            snapshot,
            "campaign.json",
            label="sealed Tool Loop Campaign",
        )
    )
    state = ToolLoopCheckpoint.model_validate(
        _verified_snapshot_json(
            snapshot,
            "tool-loop.json",
            label="sealed Tool Loop terminal state",
        )
    )
    checkpoint = ToolLoopCheckpoint.model_validate(
        _verified_snapshot_json(
            snapshot,
            checkpoint_relative,
            label="sealed Tool Loop terminal checkpoint",
        )
    )
    summary = cli_json_object(
        _verified_snapshot_json(
            snapshot,
            "run.json",
            label="sealed Tool Loop Run summary",
        ),
        label="Tool Loop Run summary",
    )
    budget = cli_json_object(
        _verified_snapshot_json(
            snapshot,
            "budget.json",
            label="sealed Tool Loop budget",
        ),
        label="Tool Loop budget",
    )
    leases = cli_json_object_list(
        _verified_snapshot_json(
            snapshot,
            "secrets.json",
            label="sealed Tool Loop secret leases",
        ),
        label="Tool Loop secret leases",
    )
    expected_checkpoint_relative = (
        f"checkpoints/checkpoint_{checkpoint.checkpoint_seq:04d}_{checkpoint.status.value}.json"
    )
    terminal_outcome_bound = bool(
        checkpoint_relative == expected_checkpoint_relative
        and summary.get("runId") == outcome.run_id
        and summary.get("loopId") == checkpoint.loop_id
        and summary.get("status") == checkpoint.status.value
        and summary.get("error") == checkpoint.error
        and summary.get("checkpoint") == checkpoint_relative
        and checkpoint == state
        and checkpoint.run_id == outcome.run_id
        and checkpoint.campaign_name == campaign.metadata.name
        and checkpoint.status is outcome.status
        and checkpoint.pending_call == outcome.pending_call
        and checkpoint.tool_results == outcome.tool_results
        and checkpoint.final_content == outcome.final_content
        and checkpoint.error == outcome.error
    )
    return _VerifiedToolLoopRun(
        campaign=campaign,
        state=state,
        checkpoint=checkpoint,
        budget=budget,
        leases=leases,
        checkpoint_relative=checkpoint_relative,
        event_types=tuple(event.event_type for event in snapshot.events),
        terminal_outcome_bound=terminal_outcome_bound,
    )


def _tool_loop_budget_usage(budget: Mapping[str, object]) -> _ToolLoopBudgetUsage:
    return _ToolLoopBudgetUsage(
        agent_count=cli_json_integer(budget.get("agentCount"), label="agent count"),
        tool_calls=cli_json_integer(budget.get("toolCalls"), label="tool call count"),
        model_calls=cli_json_integer(budget.get("modelCalls"), label="model call count"),
        model_prompt_tokens=cli_json_integer(
            budget.get("modelPromptTokens"),
            label="model prompt-token count",
        ),
        model_completion_tokens=cli_json_integer(
            budget.get("modelCompletionTokens"),
            label="model completion-token count",
        ),
        model_tokens=cli_json_integer(budget.get("modelTokens"), label="model token count"),
    )


def _tool_loop_budget_limits_match(
    budget: Mapping[str, object],
    campaign: CampaignManifest,
) -> bool:
    limits = campaign.spec.budgets
    return bool(
        cli_json_integer(budget.get("maxAgents"), label="maximum agent count") == limits.max_agents
        and cli_json_integer(budget.get("maxToolCalls"), label="maximum tool call count")
        == limits.max_tool_calls
        and cli_json_integer(budget.get("maxModelCalls"), label="maximum model call count")
        == limits.max_model_calls
        and cli_json_integer(
            budget.get("maxModelTokens"),
            label="maximum model-token budget",
        )
        == limits.max_model_tokens
    )


def _tool_loop_budget_contract(
    verified: _VerifiedToolLoopRun,
    *,
    expected_turns: int,
    expected_agents: int,
    expected_tool_calls: int,
    expected_model_calls: int,
    expected_executed_tool_calls: int,
) -> bool:
    usage = _tool_loop_budget_usage(verified.budget)
    checkpoint_usage = _tool_loop_budget_usage(verified.state.budget)
    limits = verified.campaign.spec.budgets
    return bool(
        usage == checkpoint_usage
        and _tool_loop_budget_limits_match(verified.budget, verified.campaign)
        and _tool_loop_budget_limits_match(verified.state.budget, verified.campaign)
        and verified.state.turn == expected_turns
        and verified.state.provider_calls == expected_model_calls
        and verified.state.executed_tool_calls == expected_executed_tool_calls
        and usage.agent_count == expected_agents
        and usage.tool_calls == expected_tool_calls
        and usage.model_calls == expected_model_calls
        and usage.model_prompt_tokens > 0
        and usage.model_completion_tokens > 0
        and usage.model_tokens == usage.model_prompt_tokens + usage.model_completion_tokens
        and usage.agent_count <= limits.max_agents
        and usage.tool_calls <= limits.max_tool_calls
        and usage.model_calls <= limits.max_model_calls
        and usage.model_tokens <= limits.max_model_tokens
    )


def tool_loop_checks(
    outcome: ToolLoopOutcome,
    *,
    credential: str,
    artifact_loader: ArtifactLoader,
) -> dict[str, bool]:
    verified = _verified_tool_loop_run(outcome, artifact_loader=artifact_loader)
    state = verified.state.model_dump(mode="json")
    credential_present = verified_cli_run_contains_secret(
        outcome.run_path,
        outcome.run_id,
        credential,
    )
    messages = cli_json_object_list(
        state.get("messages", []),
        label="tool-loop messages",
    )
    tool_calls = cli_json_object_list(
        messages[2].get("tool_calls", []) if len(messages) >= 3 else [],
        label="assistant tool calls",
    )
    function = cli_json_object(
        tool_calls[0].get("function", {}) if tool_calls else {},
        label="assistant tool-call function",
    )
    call_id = tool_calls[0].get("id") if tool_calls else None
    return {
        "tool loop completed": (
            outcome.status is ToolLoopStatus.COMPLETED
            and verified.state.status is ToolLoopStatus.COMPLETED
        ),
        "provider requested one registered function": (
            len(messages) >= 3
            and messages[2].get("role") == "assistant"
            and len(tool_calls) == 1
            and function.get("name") == "probe_mock_agent"
        ),
        "specialist executed through gateway": (
            len(outcome.tool_results) == 1
            and verified.state.tool_results == outcome.tool_results
            and outcome.tool_results[0].success
            and outcome.tool_results[0].tool_id == "mock.agent-probe"
        ),
        "tool result returned with matching call ID": (
            len(messages) >= 4
            and isinstance(call_id, str)
            and messages[3].get("role") == "tool"
            and messages[3].get("tool_call_id") == call_id
        ),
        "provider returned final response": (
            outcome.final_content == "Authorized specialist result was received and summarized."
            and verified.state.final_content == outcome.final_content
        ),
        "turn tool model and agent budgets measured": _tool_loop_budget_contract(
            verified,
            expected_turns=2,
            expected_agents=3,
            expected_tool_calls=3,
            expected_model_calls=2,
            expected_executed_tool_calls=1,
        ),
        "provider secret leases revoked": (
            len(verified.leases) == 2
            and all(
                lease.get("status") == "revoked" and lease.get("remaining_uses") == 0
                for lease in verified.leases
            )
        ),
        "two Provider calls audited": (
            verified.event_types.count("model.call.completed") == 2
            and verified.event_types.count("model.call.failed") == 0
        ),
        "resumable checkpoint persisted": verified.terminal_outcome_bound,
        "credential absent from run artifacts": not credential_present,
    }


def tool_loop_approval_checks(
    waiting: ToolLoopOutcome,
    resumed: ToolLoopOutcome,
    *,
    approval_id: str,
    credential: str,
    artifact_loader: ArtifactLoader,
) -> dict[str, bool]:
    verified_waiting = _verified_tool_loop_run(waiting, artifact_loader=artifact_loader)
    verified_resumed = _verified_tool_loop_run(resumed, artifact_loader=artifact_loader)
    waiting_usage = _tool_loop_budget_usage(verified_waiting.budget)
    resumed_usage = _tool_loop_budget_usage(verified_resumed.budget)
    credential_present = any(
        verified_cli_run_contains_secret(outcome.run_path, outcome.run_id, credential)
        for outcome in (waiting, resumed)
    )
    return {
        "T3 intent paused before Worker dispatch": (
            waiting.status is ToolLoopStatus.AWAITING_APPROVAL
            and verified_waiting.state.status is ToolLoopStatus.AWAITING_APPROVAL
            and waiting.pending_call is not None
            and verified_waiting.state.pending_call == waiting.pending_call
            and waiting.pending_call.risk_tier is ToolRiskTier.T3
            and not waiting.tool_results
        ),
        "exact approval resumed a continuation run": (
            resumed.status is ToolLoopStatus.COMPLETED
            and verified_resumed.state.status is ToolLoopStatus.COMPLETED
            and resumed.run_id != waiting.run_id
            and verified_resumed.state.resumed_from_run_id == waiting.run_id
            and verified_resumed.state.loop_id == verified_waiting.state.loop_id
        ),
        "approval identity audited": verified_resumed.state.approval_ids == [approval_id],
        "approved Specialist executed once": (
            len(resumed.tool_results) == 1
            and verified_resumed.state.tool_results == resumed.tool_results
            and resumed.tool_results[0].tool_id == "mock.approval-probe"
            and resumed.tool_results[0].success
        ),
        "cumulative budgets restored": (
            _tool_loop_budget_contract(
                verified_waiting,
                expected_turns=1,
                expected_agents=2,
                expected_tool_calls=1,
                expected_model_calls=1,
                expected_executed_tool_calls=0,
            )
            and _tool_loop_budget_contract(
                verified_resumed,
                expected_turns=2,
                expected_agents=5,
                expected_tool_calls=3,
                expected_model_calls=2,
                expected_executed_tool_calls=1,
            )
            and resumed_usage.agent_count > waiting_usage.agent_count
            and resumed_usage.tool_calls > waiting_usage.tool_calls
            and resumed_usage.model_calls > waiting_usage.model_calls
            and resumed_usage.model_prompt_tokens > waiting_usage.model_prompt_tokens
            and resumed_usage.model_completion_tokens > waiting_usage.model_completion_tokens
            and resumed_usage.model_tokens > waiting_usage.model_tokens
        ),
        "cross-run Provider leases revoked": (
            len(verified_waiting.leases) == 1
            and len(verified_resumed.leases) == 1
            and all(
                lease.get("status") == "revoked" and lease.get("remaining_uses") == 0
                for lease in [*verified_waiting.leases, *verified_resumed.leases]
            )
        ),
        "both terminal checkpoints verified and bound": (
            verified_waiting.terminal_outcome_bound and verified_resumed.terminal_outcome_bound
        ),
        "two Provider calls audited across runs": (
            verified_waiting.event_types.count("model.call.completed") == 1
            and verified_resumed.event_types.count("model.call.completed") == 1
            and verified_waiting.event_types.count("model.call.failed") == 0
            and verified_resumed.event_types.count("model.call.failed") == 0
        ),
        "credential absent from both runs": not credential_present,
    }
