"""Truthful output contracts for Provider-focused CLI conformance commands."""

from __future__ import annotations

from pajin.agents.base import AgentReportNarrative
from pajin.domain.orchestration import RunStatus
from pajin.domain.validation import (
    FindingDisposition,
    ValidationCheckStatus,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.workflow.multi_agent import MultiAgentRunOutcome

from .common import (
    cli_json_integer,
    cli_json_object,
    cli_json_object_list,
    verified_cli_event_types,
    verified_cli_json_artifacts,
    verified_cli_run_contains_secret,
)


def provider_checks(
    outcome: MultiAgentRunOutcome,
    *,
    credential: str,
) -> dict[str, bool]:
    results = outcome.tool_results
    artifacts = verified_cli_json_artifacts(
        outcome.run_path,
        outcome.run_id,
        "secrets.json",
    )
    leases = cli_json_object_list(artifacts["secrets.json"], label="secret leases")
    tool_calls = results[2].data.get("tool_calls", []) if len(results) > 2 else []
    call = tool_calls[0] if isinstance(tool_calls, list) and tool_calls else {}
    arguments = call.get("arguments", {}) if isinstance(call, dict) else {}
    event_types = verified_cli_event_types(outcome.run_path, outcome.run_id)
    credential_present = verified_cli_run_contains_secret(
        outcome.run_path,
        outcome.run_id,
        credential,
    )
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
        "credential absent from run artifacts": not credential_present,
    }


def provider_agent_checks(
    outcome: MultiAgentRunOutcome,
    *,
    credential: str,
) -> dict[str, bool]:
    artifacts = verified_cli_json_artifacts(
        outcome.run_path,
        outcome.run_id,
        "budget.json",
        "model-narrative.json",
        "secrets.json",
    )
    event_types = verified_cli_event_types(outcome.run_path, outcome.run_id)
    budget = cli_json_object(artifacts["budget.json"], label="budget snapshot")
    narrative = AgentReportNarrative.model_validate(artifacts["model-narrative.json"])
    leases = cli_json_object_list(artifacts["secrets.json"], label="secret leases")
    model_calls = cli_json_integer(budget.get("modelCalls"), label="model call count")
    model_prompt_tokens = cli_json_integer(
        budget.get("modelPromptTokens"),
        label="model prompt-token count",
    )
    model_completion_tokens = cli_json_integer(
        budget.get("modelCompletionTokens"),
        label="model completion-token count",
    )
    model_tokens = cli_json_integer(budget.get("modelTokens"), label="model token count")
    max_model_tokens = cli_json_integer(
        budget.get("maxModelTokens"),
        label="maximum model-token budget",
    )
    credential_present = verified_cli_run_contains_secret(
        outcome.run_path,
        outcome.run_id,
        credential,
    )

    step = (
        outcome.plan.steps[0] if outcome.plan is not None and len(outcome.plan.steps) == 1 else None
    )
    result = outcome.tool_results[0] if len(outcome.tool_results) == 1 else None
    candidate = (
        outcome.validation.candidates[0] if len(outcome.validation.candidates) == 1 else None
    )
    decision = outcome.validation.decisions[0] if len(outcome.validation.decisions) == 1 else None
    decision_checks = (
        {check.check_id: check for check in decision.checks} if decision is not None else {}
    )
    exact_evidence = (
        list(result.evidence) if result is not None and result.success and result.evidence else None
    )
    objective_check_ids = {
        "target-declared",
        "threat-class-declared",
        "target-http-scope",
        "evidence-present",
        "evidence-result-links",
        "evidence-path-contained",
        "evidence-files",
        "evidence-provenance",
        "candidate-source-requests",
        "linked-executions",
    }
    objective_gate_passed = all(
        decision_checks.get(check_id) is not None
        and decision_checks[check_id].status is ValidationCheckStatus.PASS
        for check_id in objective_check_ids
    )

    plan_is_bounded_m03 = bool(
        step is not None
        and step.request.tool_id == "ai.chat-probe"
        and step.request.method == "POST"
        and step.scenario_id == "kisa.model.system-prompt-disclosure"
        and step.threat_classes == {"M03"}
        and step.request.arguments.get("scenario_id") == "kisa.model.system-prompt-disclosure"
        and step.request.arguments.get("threat_class") == "M03"
    )
    trusted_candidate_is_bound = bool(
        step is not None
        and result is not None
        and candidate is not None
        and exact_evidence is not None
        and result.request_id == step.request.request_id
        and result.tool_id == step.request.tool_id
        and result.data.get("target") == step.request.target
        and result.data.get("scenarioId") == step.scenario_id
        and result.data.get("threatClass") == "M03"
        and candidate.source == "trusted-core:candidate-producer"
        and candidate.source_agent_id == "trusted-core:kisa-candidate-producer"
        and candidate.source_request_ids == [step.request.request_id]
        and candidate.claim.target == step.request.target
        and candidate.claim.threat_class == "M03"
        and candidate.claim.validated is False
        and candidate.claim.evidence == exact_evidence
        and decision_checks.get("candidate-source-requests") is not None
        and decision_checks["candidate-source-requests"].status is ValidationCheckStatus.PASS
    )
    semantic_decision_is_bound = bool(
        candidate is not None
        and decision is not None
        and exact_evidence is not None
        and decision.candidate_id == candidate.candidate_id
        and decision.validator_id.startswith("agent:validator:")
        and decision.method is ValidationMethod.HYBRID_LEGACY_GATE
        and decision.supporting_evidence == exact_evidence
        and decision.contradicting_evidence == []
        and objective_gate_passed
        and decision_checks.get("legacy-validator-signal") is not None
        and decision_checks["legacy-validator-signal"].status is ValidationCheckStatus.PASS
        and decision_checks["legacy-validator-signal"].reason_code
        is ValidationReasonCode.VALIDATOR_CONFIRMED
    )
    independent_reproduction_boundary = bool(
        decision is not None
        and decision.disposition is FindingDisposition.NEEDS_REVIEW
        and decision.reason_codes == [ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING]
        and decision.confirmation_basis is None
        and decision.replay_request_ids == []
        and decision.replay_outcome_ids == []
        and decision.replay_lineage == []
        and decision_checks.get("independent-reproduction") is not None
        and decision_checks["independent-reproduction"].status is ValidationCheckStatus.FAIL
        and decision_checks["independent-reproduction"].reason_code
        is ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
        and outcome.findings == []
        and outcome.validation.confirmed_findings == []
    )
    return {
        "campaign completed": outcome.status is RunStatus.COMPLETED,
        "provider planner produced bounded M03 plan": plan_is_bounded_m03,
        "trusted M03 candidate bound to same-run authority": trusted_candidate_is_bound,
        "semantic decision supported exact same-run evidence": semantic_decision_is_bound,
        "independent reproduction boundary preserved": independent_reproduction_boundary,
        "provider reporter narrative sealed and valid": bool(
            narrative.summary
            and narrative.risk_overview
            and narrative.recommendations
            and narrative.limitations
        ),
        "three role model calls audited": (
            event_types.count("model.call.completed") == 3
            and event_types.count("model.fallback.activated") == 0
        ),
        "model call and conservative token budgets bounded": (
            model_calls == 3
            and model_prompt_tokens > 0
            and model_completion_tokens > 0
            and model_tokens == model_prompt_tokens + model_completion_tokens
            and model_tokens <= max_model_tokens
        ),
        "three provider secret leases revoked": (
            len(leases) == 3
            and all(
                lease.get("status") == "revoked" and lease.get("remaining_uses") == 0
                for lease in leases
            )
        ),
        "credential absent from run artifacts": not credential_present,
    }
