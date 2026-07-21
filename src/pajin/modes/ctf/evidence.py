"""Authoritative sealed-execution loading for CTF finalization."""

from __future__ import annotations

from dataclasses import dataclass

from pajin.domain.models import AgentPlan, CampaignManifest, ToolRequest, ToolResult
from pajin.domain.orchestration import RunStatus, TaskGraph, TaskStatus
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)
from pajin.workflow.multi_agent import MultiAgentRunOutcome

_MAX_MANAGED_JSON_BYTES = 64 * 1024 * 1024
_MAX_CAMPAIGN_JSON_BYTES = 64 * 1024 * 1024
_MAX_EVIDENCE_JSON_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class SealedCTFExecution:
    run_id: str
    campaign: CampaignManifest
    plan: AgentPlan
    tool_results: list[ToolResult]


def load_authoritative_ctf_execution(
    outcome: MultiAgentRunOutcome,
) -> SealedCTFExecution:
    """Reload the first-seal execution record instead of trusting mutable caller objects."""

    run_path = outcome.run_path.resolve()
    metadata_requests = {
        "run.json": _MAX_MANAGED_JSON_BYTES,
        "campaign.json": _MAX_CAMPAIGN_JSON_BYTES,
        "plan.json": _MAX_MANAGED_JSON_BYTES,
        "task-graph.json": _MAX_MANAGED_JSON_BYTES,
    }
    metadata = load_verified_run_artifacts(run_path, requests=metadata_requests)
    verification = metadata.verification
    if outcome.run_id != verification.run_id:
        raise ValueError("CTF outcome run ID differs from the sealed Run")

    try:
        run_state_raw = _snapshot_json(metadata, "run.json", label="sealed CTF Run state")
        campaign_raw = _snapshot_json(
            metadata,
            "campaign.json",
            label="sealed CTF campaign",
        )
        plan_raw = _snapshot_json(metadata, "plan.json", label="sealed CTF plan")
        graph_raw = _snapshot_json(metadata, "task-graph.json", label="sealed CTF task graph")
    except ValueError as exc:
        raise ValueError("sealed CTF execution metadata is invalid") from exc
    if (
        not isinstance(run_state_raw, dict)
        or run_state_raw.get("runId") != verification.run_id
        or run_state_raw.get("status") != RunStatus.COMPLETED.value
    ):
        raise ValueError("sealed CTF Run state is not completed or is identity-mismatched")
    try:
        campaign = CampaignManifest.model_validate(campaign_raw)
        plan = AgentPlan.model_validate(plan_raw)
        graph = TaskGraph.model_validate(graph_raw)
    except ValueError as exc:
        raise ValueError("sealed CTF campaign, plan, or task graph is invalid") from exc
    if outcome.plan != plan:
        raise ValueError("CTF outcome plan differs from the sealed plan")

    bound_requests: list[ToolRequest] = []
    for step in plan.steps:
        tasks = [
            task
            for task in graph.tasks.values()
            if task.request is not None
            and task.request.request_id == step.request.request_id
            and task.request.tool_id == step.request.tool_id
            and task.request.target == step.request.target
        ]
        if len(tasks) != 1:
            raise ValueError("sealed CTF task graph does not uniquely bind a plan request")
        task = tasks[0]
        assert task.request is not None
        expected_request = step.request.model_copy(update={"agent_id": task.request.agent_id})
        if (
            task.request != expected_request
            or task.assigned_agent_id != task.request.agent_id
            or task.status is not TaskStatus.SUCCEEDED
            or task.attempts != 1
        ):
            raise ValueError("sealed CTF Specialist task differs from the plan contract")
        bound_requests.append(task.request)

    evidence_requests = {
        f"evidence/{request.request_id}.json": _MAX_EVIDENCE_JSON_BYTES
        for request in bound_requests
    }
    snapshot = load_verified_run_artifacts(
        run_path,
        requests={**metadata_requests, **evidence_requests},
        expected_run_id=verification.run_id,
    )
    if snapshot.verification != verification:
        raise ValueError("sealed CTF Run changed while its evidence paths were derived")
    tool_results = [_load_sealed_tool_result(snapshot, request) for request in bound_requests]
    if outcome.tool_results != tool_results:
        raise ValueError("CTF outcome Tool results differ from sealed evidence")
    return SealedCTFExecution(
        run_id=verification.run_id,
        campaign=campaign,
        plan=plan,
        tool_results=tool_results,
    )


def _load_sealed_tool_result(snapshot: VerifiedRunSnapshot, request: ToolRequest) -> ToolResult:
    relative = f"evidence/{request.request_id}.json"
    try:
        raw = _snapshot_json(
            snapshot,
            relative,
            label=f"sealed CTF evidence for {request.request_id}",
        )
    except ValueError as exc:
        raise ValueError(
            f"sealed CTF evidence is missing or invalid for {request.request_id}"
        ) from exc
    if not isinstance(raw, dict):
        raise ValueError("sealed CTF evidence must contain a JSON object")
    decision = raw.get("policyDecision")
    if not isinstance(decision, dict) or decision.get("allowed") is not True:
        raise ValueError("sealed CTF evidence does not contain an allowed policy decision")
    try:
        observed_request = ToolRequest.model_validate(raw.get("request"))
        result = ToolResult.model_validate(raw.get("result"))
    except ValueError as exc:
        raise ValueError("sealed CTF request or Tool result is invalid") from exc
    if observed_request != request:
        raise ValueError("sealed CTF evidence request differs from the sealed plan")
    if result.request_id != request.request_id or result.tool_id != request.tool_id:
        raise ValueError("sealed CTF Tool result identity differs from its request")
    if result.evidence:
        raise ValueError("sealed CTF Tool result contains unbound nested evidence")
    return result.model_copy(update={"evidence": [relative]})


def _snapshot_json(snapshot: VerifiedRunSnapshot, relative_path: str, *, label: str) -> object:
    try:
        return parse_strict_json_bytes(snapshot.artifact_bytes(relative_path), label=label)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{label} is missing or invalid") from exc
