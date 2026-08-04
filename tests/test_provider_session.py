import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from pajin.agents.base import ModelCallFailure
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolResult
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.policy.engine import PolicyDecision
from pajin.providers import (
    BoundProviderChatCall,
    FunctionDefinition,
    FunctionTool,
    JSONSchemaDefinition,
    JSONSchemaResponseFormat,
    PolicyBoundProviderPort,
    ProviderAssistantToolCall,
    ProviderBoundChatOutcome,
    ProviderBoundOutcomeError,
    ProviderChargedUsage,
    ProviderChatRequest,
    ProviderFunctionCall,
    ProviderMessage,
    ProviderRegistration,
    ProviderReportedUsage,
    verify_provider_bound_chat_outcome,
)
from pajin.runtime.control import BudgetController, BudgetExceeded, DualModelUsageBudget
from pajin.runtime.store import RunStore
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.gateway import GatewayOutcome, canonical_tool_request_digest


class StubProviderGateway:
    def __init__(
        self,
        *,
        usage: dict[str, int] | None = None,
        executed: bool = True,
        success: bool = True,
        block: bool = False,
        data_updates: dict[str, object] | None = None,
        bound_sources: bool = False,
        worker_transcript: str = "",
    ) -> None:
        self.usage = usage
        self.executed = executed
        self.success = success
        self.block = block
        self.data_updates = data_updates or {}
        self.bound_sources = bound_sources
        self.worker_transcript = worker_transcript
        self.calls = 0
        self.cancelled = False
        self.requests: list[ToolRequest] = []
        self.outcomes: list[GatewayOutcome] = []

    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome:
        del campaign, grant, used_calls
        self.calls += 1
        self.requests.append(request.model_copy(deep=True))
        if self.block:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        now = datetime.now(UTC)
        data = {
            "provider_id": "session-provider",
            "response_id": "response-test",
            "model": "session-model",
            "content": "ok",
            "refusal": None,
            "finish_reason": "stop",
            "tool_calls": [],
            "usage": self.usage,
            "streamed": False,
            "chunks": 1,
            "target": request.target,
        }
        data.update(self.data_updates)
        worker_result = (
            WorkerResult(
                execution_id=f"exec_bound_{self.calls}",
                backend="provider-bound-test",
                status=WorkerStatus.SUCCEEDED,
                exit_code=0,
                stdout=self.worker_transcript,
                stderr=self.worker_transcript,
                network_log=self.worker_transcript,
                started_at=now,
                finished_at=now,
            )
            if self.bound_sources
            else None
        )
        outcome = GatewayOutcome(
            decision=PolicyDecision(allowed=True, reason="test fixture", policy="test"),
            result=ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=self.success,
                started_at=now,
                finished_at=now,
                data=data if self.success else {},
                error=None if self.success else "provider dispatch failed",
                evidence=(
                    [f"evidence/{request.request_id}.json"]
                    if self.bound_sources
                    else []
                ),
            ),
            worker_result=worker_result,
            executed=self.executed,
        )
        self.outcomes.append(outcome.model_copy(deep=True))
        return outcome


def _registration() -> ProviderRegistration:
    return ProviderRegistration.model_validate(
        {
            "provider_id": "session-provider",
            "endpoint": "https://provider.example/v1/chat/completions",
            "model": "session-model",
            "secret_ref": "provider/session/api-key",
            "allowed_function_tools": ["echo"],
            "input_cost_per_million_usd": 1_000,
            "output_cost_per_million_usd": 2_000,
        }
    )


def _chat(*, max_completion_tokens: int | None = 10) -> ProviderChatRequest:
    return ProviderChatRequest(
        messages=[ProviderMessage(role="user", content="hello")],
        max_completion_tokens=max_completion_tokens,
    )


def _nested_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            nested
            for item in value.values()
            for nested in _nested_keys(item)
        }
    if isinstance(value, list):
        return {nested for item in value for nested in _nested_keys(item)}
    return set()


def _port(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    gateway: StubProviderGateway,
    *,
    max_model_tokens: int = 10_000,
    max_cost_usd: float = 10,
    max_tool_calls: int = 10,
    max_model_calls: int = 10,
    elapsed_seconds: float = 0,
    dedicated_budget: BudgetController | None = None,
    dual_model_usage_budget: DualModelUsageBudget | None = None,
) -> tuple[PolicyBoundProviderPort, BudgetController]:
    registration = _registration()
    budgets = sample_campaign.spec.budgets.model_copy(
        update={
            "duration_seconds": 1,
            "max_tool_calls": max_tool_calls,
            "max_model_calls": max_model_calls,
            "max_model_tokens": max_model_tokens,
            "max_cost_usd": max_cost_usd,
        }
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"budgets": budgets})}
    )
    budget = BudgetController(budgets)
    if elapsed_seconds:
        budget.restore_usage(
            agent_count=0,
            tool_calls=0,
            model_calls=0,
            model_prompt_tokens=0,
            model_completion_tokens=0,
            cost_usd=0,
            elapsed_seconds=elapsed_seconds,
        )
    ledger = CapabilityLedger(max_depth=budgets.max_spawn_depth)
    tool_id = f"provider.{registration.provider_id}.chat"
    grant = ledger.issue_root(
        campaign,
        subject="agent:provider-session-test",
        tools={tool_id},
        targets={str(registration.endpoint)},
    )
    store = RunStore.create(tmp_path, campaign.metadata.name)
    return (
        PolicyBoundProviderPort(
            registration=registration,
            campaign=campaign,
            grant=grant,
            ledger=ledger,
            budget=budget,
            gateway=gateway,  # type: ignore[arg-type]
            store=store,
            dual_model_usage_budget=(
                dual_model_usage_budget
                if dual_model_usage_budget is not None
                else (
                    DualModelUsageBudget(budget, dedicated_budget)
                    if dedicated_budget is not None
                    else None
                )
            ),
        ),
        budget,
    )


def test_provider_prompt_bound_covers_maximum_contract_framing(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway()
    port, _budget = _port(tmp_path, sample_campaign, gateway)
    messages = [
        ProviderMessage(
            role="assistant",
            content="bounded",
            tool_calls=[
                ProviderAssistantToolCall(
                    id=f"call_{message_index}_{call_index}",
                    function=ProviderFunctionCall(name="noop", arguments="{}"),
                )
                for call_index in range(8)
            ],
        )
        for message_index in range(100)
    ]
    empty_object_schema = {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }
    tools = [
        FunctionTool(
            function=FunctionDefinition(
                name=f"tool_{tool_index}",
                parameters=empty_object_schema,
            )
        )
        for tool_index in range(50)
    ]
    chat = ProviderChatRequest(
        messages=messages,
        tools=tools,
        max_completion_tokens=10,
        response_format=JSONSchemaResponseFormat(
            json_schema=JSONSchemaDefinition.model_validate(
                {
                    "name": "maximum_contract",
                    "schema": empty_object_schema,
                    "strict": True,
                }
            )
        ),
    )
    canonical_bytes = json.dumps(
        {
            "model": "session-model",
            "request": chat.model_dump(mode="json", by_alias=True, exclude_none=True),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    expected_framing = 1_024 + 100 * 64 + 50 * 256 + 800 * 64 + 512

    bound = port._prompt_token_upper_bound(chat)

    assert bound == len(canonical_bytes) * 4 + expected_framing
    assert bound > len(canonical_bytes) + expected_framing


@pytest.mark.asyncio
async def test_provider_session_commits_bound_and_records_reported_usage_as_untrusted(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    )
    port, budget = _port(tmp_path, sample_campaign, gateway)
    chat = _chat()
    reserved_prompt_tokens = port._prompt_token_upper_bound(chat)
    reserved_cost = (reserved_prompt_tokens * 1_000 + 10 * 2_000) / 1_000_000

    result = await port.chat(role="test", attempt=1, chat=chat)

    assert result.content == "ok"
    assert gateway.calls == 1
    assert budget.snapshot()["modelPromptTokens"] == reserved_prompt_tokens
    assert budget.snapshot()["modelCompletionTokens"] == 10
    assert budget.snapshot()["modelTokens"] == reserved_prompt_tokens + 10
    assert budget.snapshot()["costUsd"] == pytest.approx(reserved_cost)

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    events = [json.loads(line) for line in (run_path / "events.jsonl").read_text().splitlines()]
    completed = next(event for event in events if event["event_type"] == "model.call.completed")
    assert completed["payload"]["usageTrust"] == "provider-reported-untrusted"
    assert completed["payload"]["promptTokens"] == 3
    assert completed["payload"]["completionTokens"] == 2
    assert completed["payload"]["chargedPromptTokens"] == reserved_prompt_tokens
    assert completed["payload"]["chargedCompletionTokens"] == 10
    assert completed["payload"]["chargedCostUsd"] == pytest.approx(reserved_cost)
    assert "boundOutcomeId" not in completed["payload"]
    assert "boundOutcomeDigest" not in completed["payload"]


@pytest.mark.asyncio
async def test_provider_session_rejects_cost_reservation_before_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    )
    port, budget = _port(tmp_path, sample_campaign, gateway, max_cost_usd=0)

    with pytest.raises(BudgetExceeded, match="cost"):
        await port.chat(role="test", attempt=1, chat=_chat())

    assert gateway.calls == 0
    assert budget.snapshot()["modelTokens"] == 0
    assert budget.snapshot()["costUsd"] == 0


@pytest.mark.asyncio
async def test_provider_session_rejects_token_reservation_before_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    )
    port, budget = _port(tmp_path, sample_campaign, gateway, max_model_tokens=10)

    with pytest.raises(BudgetExceeded, match="model-token"):
        await port.chat(role="test", attempt=1, chat=_chat())

    assert gateway.calls == 0
    assert budget.snapshot()["modelTokens"] == 0
    assert budget.snapshot()["costUsd"] == 0


@pytest.mark.asyncio
async def test_provider_session_keeps_reservation_when_dispatched_usage_is_missing(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(usage=None)
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ModelCallFailure, match="complete token usage"):
        await port.chat(role="test", attempt=1, chat=_chat())

    snapshot = budget.snapshot()
    assert gateway.calls == 1
    assert snapshot["modelPromptTokens"] > 0
    assert snapshot["modelCompletionTokens"] == 10
    assert snapshot["modelTokens"] > 10
    assert snapshot["costUsd"] > 0


@pytest.mark.asyncio
async def test_provider_session_releases_reservation_for_proven_non_execution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(executed=False, success=False)
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ModelCallFailure, match="provider gateway did not execute"):
        await port.chat(role="test", attempt=1, chat=_chat())

    assert gateway.calls == 1
    assert budget.snapshot()["modelTokens"] == 0
    assert budget.snapshot()["costUsd"] == 0
    grant_record = port._ledger.record(port._grant.grant_id)
    assert grant_record.remaining_calls == port._grant.max_calls - 1

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    events = [json.loads(line) for line in (run_path / "events.jsonl").read_text().splitlines()]
    call_events = [
        event["event_type"] for event in events if event["event_type"].startswith("model.call")
    ]
    assert call_events == ["model.call.started", "model.call.failed"]


@pytest.mark.asyncio
async def test_provider_session_dual_budget_denial_leaves_both_ledgers_unchanged(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    )
    dedicated_budgets = sample_campaign.spec.budgets.model_copy(
        update={
            "duration_seconds": 1,
            "max_tool_calls": 1,
            "max_model_calls": 1,
            "max_model_tokens": 1,
            "max_cost_usd": 10,
        }
    )
    dedicated_budget = BudgetController(dedicated_budgets)
    port, campaign_budget = _port(
        tmp_path,
        sample_campaign,
        gateway,
        dedicated_budget=dedicated_budget,
    )

    with pytest.raises(BudgetExceeded, match="model-token"):
        await port.chat(role="supervisor", attempt=1, chat=_chat())

    assert gateway.calls == 0
    for snapshot in (campaign_budget.snapshot(), dedicated_budget.snapshot()):
        assert snapshot["toolCalls"] == 0
        assert snapshot["modelCalls"] == 0
        assert snapshot["modelTokens"] == 0
        assert snapshot["costUsd"] == 0


def test_provider_session_rejects_dual_budget_for_another_campaign(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    foreign_campaign_budget = BudgetController(sample_campaign.spec.budgets)
    dedicated_budget = BudgetController(sample_campaign.spec.budgets)
    dual = DualModelUsageBudget(foreign_campaign_budget, dedicated_budget)

    with pytest.raises(ValueError, match="supplied Campaign budget"):
        _port(
            tmp_path,
            sample_campaign,
            StubProviderGateway(),
            dual_model_usage_budget=dual,
        )


@pytest.mark.asyncio
async def test_provider_session_dual_budget_commit_and_non_execution_release(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    dedicated_budgets = sample_campaign.spec.budgets.model_copy(
        update={
            "duration_seconds": 1,
            "max_tool_calls": 2,
            "max_model_calls": 2,
            "max_model_tokens": 10_000,
            "max_cost_usd": 10,
        }
    )
    dedicated_budget = BudgetController(dedicated_budgets)
    completed_gateway = StubProviderGateway(
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    )
    completed_port, campaign_budget = _port(
        tmp_path / "completed",
        sample_campaign,
        completed_gateway,
        dedicated_budget=dedicated_budget,
    )

    await completed_port.chat(role="supervisor", attempt=1, chat=_chat())

    campaign_after_completion = campaign_budget.snapshot()
    dedicated_after_completion = dedicated_budget.snapshot()
    assert campaign_after_completion["modelCalls"] == 1
    assert dedicated_after_completion["modelCalls"] == 1
    assert campaign_after_completion["modelTokens"] == dedicated_after_completion["modelTokens"]
    assert campaign_after_completion["costUsd"] == pytest.approx(
        dedicated_after_completion["costUsd"]
    )

    non_execution_gateway = StubProviderGateway(executed=False, success=False)
    non_execution_port, same_campaign_budget = _port(
        tmp_path / "not-executed",
        sample_campaign,
        non_execution_gateway,
        dedicated_budget=dedicated_budget,
    )

    with pytest.raises(ModelCallFailure, match="did not execute"):
        await non_execution_port.chat(role="supervisor", attempt=1, chat=_chat())

    assert same_campaign_budget.snapshot()["modelCalls"] == 0
    dedicated_after_release = dedicated_budget.snapshot()
    for field in (
        "toolCalls",
        "modelCalls",
        "modelPromptTokens",
        "modelCompletionTokens",
        "modelTokens",
        "costUsd",
    ):
        assert dedicated_after_release[field] == dedicated_after_completion[field]


@pytest.mark.asyncio
async def test_provider_bound_chat_uses_stable_id_and_returns_secret_free_outcome(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    prompt_marker = "BOUND-PROMPT-MUST-NOT-PERSIST"
    result_marker = "BOUND-RESULT-MUST-NOT-PERSIST"
    refusal_marker = "BOUND-REFUSAL-MUST-NOT-PERSIST"
    tool_argument_marker = "BOUND-TOOL-ARGUMENT-MUST-NOT-PERSIST"
    worker_marker = "BOUND-WORKER-MUST-NOT-PERSIST"
    request_id = "provider_bound_" + "a" * 64
    chat = ProviderChatRequest(
        messages=[ProviderMessage(role="user", content=prompt_marker)],
        tools=[
            FunctionTool(
                function=FunctionDefinition(
                    name="echo",
                    parameters={
                        "type": "object",
                        "properties": {"value": {"type": "string"}},
                        "required": ["value"],
                        "additionalProperties": False,
                    },
                )
            )
        ],
        max_completion_tokens=10,
    )
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        data_updates={
            "content": result_marker,
            "refusal": refusal_marker,
            "tool_calls": [
                {
                    "call_id": "call_bound",
                    "name": "echo",
                    "arguments_json": json.dumps({"value": tool_argument_marker}),
                    "arguments": {"value": tool_argument_marker},
                    "arguments_valid": True,
                }
            ],
        },
        bound_sources=True,
        worker_transcript=worker_marker,
    )
    dedicated = BudgetController(
        sample_campaign.spec.budgets.model_copy(
            update={
                "duration_seconds": 1,
                "max_tool_calls": 2,
                "max_model_calls": 2,
                "max_model_tokens": 10_000,
                "max_cost_usd": 10,
            }
        )
    )
    port, campaign_budget = _port(
        tmp_path,
        sample_campaign,
        gateway,
        dedicated_budget=dedicated,
    )

    completed = await port.chat_bound(
        role="supervisor",
        attempt=1,
        chat=chat,
        request_id=request_id,
    )

    assert isinstance(completed, BoundProviderChatCall)
    assert isinstance(completed.outcome, ProviderBoundChatOutcome)
    assert completed.result.content == result_marker
    assert gateway.requests[0].request_id == request_id
    outcome = completed.outcome
    assert outcome.request_id == request_id
    assert outcome.agent_id == gateway.requests[0].agent_id
    assert outcome.tool_id == gateway.requests[0].tool_id
    assert outcome.evidence_references == (f"evidence/{request_id}.json",)
    assert outcome.reported_usage.total_tokens == 5
    assert outcome.charged_usage.budget_scope == "campaign-and-dedicated"
    assert outcome.charged_usage.prompt_tokens > outcome.reported_usage.prompt_tokens
    assert outcome.decision_allowed
    assert outcome.executed
    assert outcome.result_identity_valid
    assert outcome.raw_request_embedded is False
    assert outcome.raw_result_embedded is False
    assert outcome.raw_worker_transcript_embedded is False
    serialized = outcome.model_dump_json(by_alias=True)
    for marker in (
        prompt_marker,
        result_marker,
        refusal_marker,
        tool_argument_marker,
        worker_marker,
        "provider/session/api-key",
        "https://provider.example/v1/chat/completions",
    ):
        assert marker not in serialized
    forbidden_keys = {
        "messages",
        "content",
        "refusal",
        "arguments",
        "stdout",
        "stderr",
        "networkLog",
        "secretRef",
        "rawResult",
    }
    assert _nested_keys(json.loads(serialized)).isdisjoint(forbidden_keys)
    assert campaign_budget.snapshot()["modelCalls"] == 1
    assert dedicated.snapshot()["modelCalls"] == 1
    completed_event = json.loads(
        port._store.events_path.read_text(encoding="utf-8").splitlines()[-1]
    )
    assert completed_event["payload"]["boundOutcomeId"] == outcome.outcome_id
    assert completed_event["payload"]["boundOutcomeDigest"] == outcome.outcome_digest

    wire = outcome.model_dump(mode="json", by_alias=True)
    for field in (
        "executed",
        "decisionAllowed",
        "toolResultSuccess",
        "resultIdentityValid",
        "rawRequestEmbedded",
        "automaticRedispatchAuthorized",
    ):
        forged_wire = dict(wire)
        forged_wire[field] = int(bool(wire[field]))
        with pytest.raises(ValueError, match="JSON booleans"):
            ProviderBoundChatOutcome.model_validate(forged_wire)
    forged_wire = dict(wire)
    forged_wire["rawProviderResponse"] = result_marker
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        ProviderBoundChatOutcome.model_validate(forged_wire)


@pytest.mark.asyncio
async def test_provider_bound_outcome_verifier_rejects_forgery_and_source_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    chat = _chat()
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        bound_sources=True,
    )
    port, _budget = _port(tmp_path, sample_campaign, gateway)
    completed = await port.chat_bound(
        role="supervisor",
        attempt=1,
        chat=chat,
        request_id="provider_bound_" + "b" * 64,
    )
    request = gateway.requests[0]
    raw_gateway = gateway.outcomes[0]

    verified = verify_provider_bound_chat_outcome(
        completed.outcome,
        registration=port._registration,
        grant=port._grant,
        chat=chat,
        request=request,
        result=completed.result,
        gateway_outcome=raw_gateway,
        charged_usage=completed.outcome.charged_usage,
        expected_budget_scope="campaign",
    )
    assert verified == completed.outcome

    forged = completed.outcome.model_copy(update={"tool_request_digest": "0" * 64})
    with pytest.raises(ProviderBoundOutcomeError):
        verify_provider_bound_chat_outcome(
            forged,
            registration=port._registration,
            grant=port._grant,
            chat=chat,
            request=request,
            result=completed.result,
            gateway_outcome=raw_gateway,
            charged_usage=completed.outcome.charged_usage,
            expected_budget_scope="campaign",
        )

    substituted_registration = port._registration.model_copy(
        update={"secret_ref": "provider/session/substituted-key"}
    )
    with pytest.raises(ProviderBoundOutcomeError):
        verify_provider_bound_chat_outcome(
            completed.outcome,
            registration=substituted_registration,
            grant=port._grant,
            chat=chat,
            request=request,
            result=completed.result,
            gateway_outcome=raw_gateway,
            charged_usage=completed.outcome.charged_usage,
            expected_budget_scope="campaign",
        )

    substituted_result = completed.result.model_copy(update={"content": "substituted"})
    with pytest.raises(ProviderBoundOutcomeError):
        verify_provider_bound_chat_outcome(
            completed.outcome,
            registration=port._registration,
            grant=port._grant,
            chat=chat,
            request=request,
            result=substituted_result,
            gateway_outcome=raw_gateway,
            charged_usage=completed.outcome.charged_usage,
            expected_budget_scope="campaign",
        )

    forged_arguments = dict(request.arguments)
    forged_arguments["max_completion_tokens"] = 10.0
    forged_request = request.model_copy(update={"arguments": forged_arguments})
    assert forged_request.arguments == request.arguments
    assert canonical_tool_request_digest(forged_request) != canonical_tool_request_digest(request)
    forged_request_wire = completed.outcome.model_dump(mode="json", by_alias=True)
    forged_request_wire["outcomeId"] = ""
    forged_request_wire["outcomeDigest"] = ""
    forged_request_wire["toolRequestDigest"] = canonical_tool_request_digest(forged_request)
    forged_request_outcome = ProviderBoundChatOutcome.model_validate(forged_request_wire)
    with pytest.raises(ProviderBoundOutcomeError):
        verify_provider_bound_chat_outcome(
            forged_request_outcome,
            registration=port._registration,
            grant=port._grant,
            chat=chat,
            request=forged_request,
            result=completed.result,
            gateway_outcome=raw_gateway,
            charged_usage=completed.outcome.charged_usage,
            expected_budget_scope="campaign",
        )

    charged = completed.outcome.charged_usage
    smaller_charge = charged.model_copy(
        update={
            "prompt_tokens": charged.prompt_tokens - 1,
            "total_tokens": charged.total_tokens - 1,
        }
    )
    with pytest.raises(ProviderBoundOutcomeError):
        verify_provider_bound_chat_outcome(
            completed.outcome,
            registration=port._registration,
            grant=port._grant,
            chat=chat,
            request=request,
            result=completed.result,
            gateway_outcome=raw_gateway,
            charged_usage=smaller_charge,
            expected_budget_scope="campaign",
        )

    undercharged_wire = completed.outcome.model_dump(mode="json", by_alias=True)
    undercharged_wire["outcomeId"] = ""
    undercharged_wire["outcomeDigest"] = ""
    undercharged_wire["chargedUsage"] = smaller_charge.model_dump(
        mode="json",
        by_alias=True,
    )
    undercharged_outcome = ProviderBoundChatOutcome.model_validate(undercharged_wire)
    with pytest.raises(
        ProviderBoundOutcomeError,
        match="conservative request bound",
    ):
        verify_provider_bound_chat_outcome(
            undercharged_outcome,
            registration=port._registration,
            grant=port._grant,
            chat=chat,
            request=request,
            result=completed.result,
            gateway_outcome=raw_gateway,
            charged_usage=undercharged_outcome.charged_usage,
            expected_budget_scope="campaign",
        )

    forged_scope_wire = completed.outcome.model_dump(mode="json", by_alias=True)
    forged_scope_wire["outcomeId"] = ""
    forged_scope_wire["outcomeDigest"] = ""
    forged_scope_usage = dict(forged_scope_wire["chargedUsage"])
    forged_scope_usage["budgetScope"] = "campaign-and-dedicated"
    forged_scope_wire["chargedUsage"] = forged_scope_usage
    forged_scope_outcome = ProviderBoundChatOutcome.model_validate(forged_scope_wire)
    with pytest.raises(ProviderBoundOutcomeError, match="expected budget scope"):
        verify_provider_bound_chat_outcome(
            forged_scope_outcome,
            registration=port._registration,
            grant=port._grant,
            chat=chat,
            request=request,
            result=completed.result,
            gateway_outcome=raw_gateway,
            charged_usage=forged_scope_outcome.charged_usage,
            expected_budget_scope="campaign",
        )

    multiple_evidence = raw_gateway.model_copy(
        update={
            "result": raw_gateway.result.model_copy(
                update={
                    "evidence": [
                        f"evidence/{request.request_id}.json",
                        "evidence/foreign.json",
                    ]
                }
            )
        }
    )
    with pytest.raises(ProviderBoundOutcomeError):
        verify_provider_bound_chat_outcome(
            completed.outcome,
            registration=port._registration,
            grant=port._grant,
            chat=chat,
            request=request,
            result=completed.result,
            gateway_outcome=multiple_evidence,
            charged_usage=completed.outcome.charged_usage,
            expected_budget_scope="campaign",
        )


@pytest.mark.parametrize(
    ("request_id", "evidence_reference"),
    [
        ("../escape", "evidence/../escape.json"),
        ("CON", "evidence/CON.json"),
    ],
)
def test_provider_bound_outcome_rejects_nonportable_request_evidence_coordinate(
    request_id: str,
    evidence_reference: str,
) -> None:
    payload: dict[str, object] = {
        "requestId": request_id,
        "agentId": "agent:test",
        "toolId": "provider.test.chat",
        "providerId": "test-provider",
        "model": "test-model",
        "providerRuntimeDigest": "0" * 64,
        "capabilityGrantDigest": "0" * 64,
        "chatRequestDigest": "0" * 64,
        "toolRequestDigest": "0" * 64,
        "policyDecisionDigest": "0" * 64,
        "toolResultDigest": "0" * 64,
        "workerResultDigest": "0" * 64,
        "gatewayOutcomeDigest": "0" * 64,
        "providerResultDigest": "0" * 64,
        "responseIdDigest": "0" * 64,
        "responseIdBytes": 1,
        "targetDigest": "0" * 64,
        "contentBytes": 0,
        "refusalBytes": 0,
        "finishReasonBytes": 0,
        "toolCallsDigest": "0" * 64,
        "evidenceReferenceDigests": ["0" * 64],
        "evidenceReferences": [evidence_reference],
        "toolCallCount": 0,
        "reportedUsage": {
            "promptTokens": 0,
            "completionTokens": 0,
            "totalTokens": 0,
            "costUsd": 0,
        },
        "chargedUsage": {
            "promptTokens": 0,
            "completionTokens": 0,
            "totalTokens": 0,
            "costUsd": 0,
            "budgetScope": "campaign",
        },
        "streamed": False,
        "chunks": 1,
        "workerStatus": "succeeded",
        "workerExecutionIdDigest": "0" * 64,
        "workerBackendDigest": "0" * 64,
        "workerExitCode": 0,
        "networkLogTrusted": False,
    }

    with pytest.raises(ValueError, match=r"requestId|evidence reference"):
        ProviderBoundChatOutcome.model_validate(payload)


def test_provider_bound_usage_canonicalizes_signed_zero_cost() -> None:
    charged = ProviderChargedUsage(
        promptTokens=0,
        completionTokens=0,
        totalTokens=0,
        costUsd=-0.0,
        budgetScope="campaign",
    )
    reported = ProviderReportedUsage(
        promptTokens=0,
        completionTokens=0,
        totalTokens=0,
        costUsd=-0.0,
    )

    assert charged.cost_usd.hex() == "0x0.0p+0"
    assert reported.cost_usd.hex() == "0x0.0p+0"
    assert "-0.0" not in charged.model_dump_json(by_alias=True)
    assert "-0.0" not in reported.model_dump_json(by_alias=True)


@pytest.mark.asyncio
async def test_provider_bound_chat_fails_closed_without_worker_evidence_and_keeps_charge(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    )
    dedicated = BudgetController(
        sample_campaign.spec.budgets.model_copy(
            update={
                "duration_seconds": 1,
                "max_tool_calls": 2,
                "max_model_calls": 2,
                "max_model_tokens": 10_000,
                "max_cost_usd": 10,
            }
        )
    )
    port, campaign_budget = _port(
        tmp_path,
        sample_campaign,
        gateway,
        dedicated_budget=dedicated,
    )

    with pytest.raises(ModelCallFailure, match="bound outcome construction failed"):
        await port.chat_bound(
            role="supervisor",
            attempt=1,
            chat=_chat(),
            request_id="provider_bound_" + "c" * 64,
        )

    assert campaign_budget.snapshot()["modelCalls"] == 1
    assert dedicated.snapshot()["modelCalls"] == 1
    events = [
        json.loads(line)["event_type"]
        for line in port._store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert events == ["model.call.started", "model.call.failed"]


@pytest.mark.parametrize("request_id", ["../invalid", "CON", "aux.txt", "COM1"])
@pytest.mark.asyncio
async def test_provider_bound_chat_rejects_invalid_stable_id_before_reservation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    request_id: str,
) -> None:
    gateway = StubProviderGateway()
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ValueError, match="request ID is invalid"):
        await port.chat_bound(
            role="supervisor",
            attempt=1,
            chat=_chat(),
            request_id=request_id,
        )

    assert gateway.calls == 0
    assert budget.snapshot()["modelCalls"] == 0


@pytest.mark.asyncio
async def test_provider_bound_chat_rejects_casefold_colliding_artifact_coordinate(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway()
    port, budget = _port(tmp_path, sample_campaign, gateway)
    port._store.write_json_create_only("requests/Provider_Collision.json", {"occupied": True})

    with pytest.raises(ValueError, match="request ID is invalid"):
        await port.chat_bound(
            role="supervisor",
            attempt=1,
            chat=_chat(),
            request_id="provider_collision",
        )

    assert gateway.calls == 0
    assert budget.snapshot()["modelCalls"] == 0


@pytest.mark.asyncio
async def test_provider_bound_chat_rejects_coerced_gateway_flag_and_keeps_charge(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    class CoercedOutcomeGateway(StubProviderGateway):
        async def execute(
            self,
            campaign: CampaignManifest,
            grant: CapabilityGrant,
            request: ToolRequest,
            *,
            used_calls: int,
        ) -> GatewayOutcome:
            outcome = await super().execute(
                campaign,
                grant,
                request,
                used_calls=used_calls,
            )
            material = outcome.model_dump(mode="python")
            material["executed"] = 1

            class RawGatewayOutcome:
                def model_dump(self, *, mode: str) -> dict[str, object]:
                    del mode
                    return material

            return cast(GatewayOutcome, RawGatewayOutcome())

    gateway = CoercedOutcomeGateway(bound_sources=True)
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ModelCallFailure, match="invalid outcome"):
        await port.chat_bound(
            role="supervisor",
            attempt=1,
            chat=_chat(),
            request_id="provider_bound_" + "d" * 64,
        )

    assert gateway.calls == 1
    assert budget.snapshot()["modelCalls"] == 1
    events = [
        json.loads(line)["event_type"]
        for line in port._store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert events == ["model.call.started", "model.call.failed"]


@pytest.mark.asyncio
async def test_provider_session_keeps_reservation_for_dispatched_error(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(executed=True, success=False)
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ModelCallFailure, match="provider model call failed"):
        await port.chat(role="test", attempt=1, chat=_chat())

    assert gateway.calls == 1
    assert budget.snapshot()["modelTokens"] > 10
    assert budget.snapshot()["costUsd"] > 0


@pytest.mark.asyncio
async def test_provider_session_does_not_persist_or_rethrow_gateway_error_detail(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    provider_secret = "provider-gateway-secret-MUST-NOT-PERSIST"

    class SecretErrorGateway(StubProviderGateway):
        async def execute(
            self,
            campaign: CampaignManifest,
            grant: CapabilityGrant,
            request: ToolRequest,
            *,
            used_calls: int,
        ) -> GatewayOutcome:
            outcome = await super().execute(
                campaign,
                grant,
                request,
                used_calls=used_calls,
            )
            return outcome.model_copy(
                update={"result": outcome.result.model_copy(update={"error": provider_secret})},
                deep=True,
            )

    gateway = SecretErrorGateway(executed=True, success=False)
    port, _budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ModelCallFailure) as captured:
        await port.chat(role="test", attempt=1, chat=_chat())

    run_path = next((tmp_path / sample_campaign.metadata.name).glob("run_*"))
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8") for path in run_path.rglob("*") if path.is_file()
    )
    assert provider_secret not in str(captured.value)
    assert provider_secret not in artifact_text
    assert "provider model call failed" in str(captured.value)


@pytest.mark.asyncio
async def test_provider_session_keeps_bound_when_reported_usage_exceeds_reservation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 9_000, "completion_tokens": 2, "total_tokens": 9_002}
    )
    port, budget = _port(tmp_path, sample_campaign, gateway)

    result = await port.chat(role="test", attempt=1, chat=_chat())

    snapshot = budget.snapshot()
    assert gateway.calls == 1
    assert result.content == "ok"
    assert 10 < snapshot["modelTokens"] < 9_002
    assert snapshot["modelCompletionTokens"] == 10


@pytest.mark.asyncio
async def test_provider_underreport_cannot_refund_authority_for_a_second_call(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    )
    probe_port, _probe_budget = _port(
        tmp_path / "probe",
        sample_campaign,
        StubProviderGateway(),
    )
    chat = _chat()
    reserved_tokens = probe_port._prompt_token_upper_bound(chat) + 10
    port, budget = _port(
        tmp_path / "bounded",
        sample_campaign,
        gateway,
        max_model_tokens=reserved_tokens + 5,
    )

    await port.chat(role="first", attempt=1, chat=chat)
    with pytest.raises(BudgetExceeded, match="model-token"):
        await port.chat(role="second", attempt=1, chat=chat)

    assert gateway.calls == 1
    assert budget.snapshot()["modelTokens"] == reserved_tokens


@pytest.mark.asyncio
async def test_provider_session_bounds_untrusted_usage_before_audit_persistence(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(
        usage={
            "prompt_tokens": 1_000_000_001,
            "completion_tokens": 0,
            "total_tokens": 1_000_000_001,
        }
    )
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ModelCallFailure, match="invalid result"):
        await port.chat(role="test", attempt=1, chat=_chat())

    snapshot = budget.snapshot()
    assert gateway.calls == 1
    assert 10 < snapshot["modelTokens"] < 1_000_000_001


@pytest.mark.asyncio
async def test_provider_session_duration_cancels_in_flight_gateway_and_keeps_reservation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(block=True)
    port, budget = _port(tmp_path, sample_campaign, gateway, elapsed_seconds=0.95)

    with pytest.raises(BudgetExceeded, match="duration"):
        await port.chat(role="test", attempt=1, chat=_chat())

    assert gateway.calls == 1
    assert gateway.cancelled
    assert budget.snapshot()["modelTokens"] > 10


@pytest.mark.asyncio
async def test_provider_session_external_cancellation_keeps_in_flight_reservation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(block=True)
    port, budget = _port(tmp_path, sample_campaign, gateway)
    task = asyncio.create_task(port.chat(role="test", attempt=1, chat=_chat()))
    while gateway.calls == 0:
        await asyncio.sleep(0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert gateway.cancelled
    assert budget.snapshot()["modelTokens"] > 10


@pytest.mark.asyncio
async def test_provider_session_preserves_cancellation_when_failure_audit_breaks(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = StubProviderGateway(block=True)
    port, budget = _port(tmp_path, sample_campaign, gateway)
    append_event = port._store.append_event

    def fail_failure_event(event_type: str, payload: dict[str, object]) -> None:
        if event_type == "model.call.failed":
            raise OSError("audit unavailable")
        append_event(event_type, payload)

    monkeypatch.setattr(port._store, "append_event", fail_failure_event)
    task = asyncio.create_task(port.chat(role="test", attempt=1, chat=_chat()))
    while gateway.calls == 0:
        await asyncio.sleep(0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert gateway.cancelled
    assert budget.snapshot()["modelTokens"] > 10


@pytest.mark.asyncio
async def test_provider_session_releases_budget_and_authority_when_started_audit_fails(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = StubProviderGateway()
    port, budget = _port(tmp_path, sample_campaign, gateway)

    def fail_started_event(_event_type: str, _payload: dict[str, object]) -> None:
        raise OSError("audit unavailable")

    monkeypatch.setattr(port._store, "append_event", fail_started_event)
    with pytest.raises(OSError, match="audit unavailable"):
        await port.chat(role="test", attempt=1, chat=_chat())

    assert gateway.calls == 0
    assert budget.snapshot()["modelTokens"] == 0
    record = port._ledger.record(port._grant.grant_id)
    assert record.remaining_calls == port._grant.max_calls


@pytest.mark.asyncio
async def test_provider_session_atomically_reserves_model_and_tool_call_counts(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(block=True)
    port, budget = _port(
        tmp_path,
        sample_campaign,
        gateway,
        max_tool_calls=1,
        max_model_calls=1,
    )
    first = asyncio.create_task(port.chat(role="first", attempt=1, chat=_chat()))
    while gateway.calls == 0:
        await asyncio.sleep(0)

    with pytest.raises(BudgetExceeded, match="tool-call"):
        await port.chat(role="second", attempt=1, chat=_chat())

    assert gateway.calls == 1
    assert budget.snapshot()["toolCalls"] == 1
    assert budget.snapshot()["modelCalls"] == 1
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first


@pytest.mark.asyncio
async def test_provider_session_atomically_reserves_tokens_across_in_flight_calls(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    probe_gateway = StubProviderGateway()
    probe_port, _probe_budget = _port(tmp_path / "probe", sample_campaign, probe_gateway)
    chat = _chat()
    token_bound = probe_port._prompt_token_upper_bound(chat) + 10
    gateway = StubProviderGateway(block=True)
    port, budget = _port(
        tmp_path / "bounded",
        sample_campaign,
        gateway,
        max_model_tokens=token_bound,
    )
    first = asyncio.create_task(port.chat(role="first", attempt=1, chat=chat))
    while gateway.calls == 0:
        await asyncio.sleep(0)

    with pytest.raises(BudgetExceeded, match="model-token"):
        await port.chat(role="second", attempt=1, chat=chat)

    assert gateway.calls == 1
    assert budget.snapshot()["modelTokens"] == token_bound
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first


@pytest.mark.asyncio
async def test_provider_session_requires_a_completion_bound_before_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway()
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(BudgetExceeded, match="max_completion_tokens"):
        await port.chat(role="test", attempt=1, chat=_chat(max_completion_tokens=None))

    assert gateway.calls == 0
    assert budget.snapshot()["modelTokens"] == 0


def test_provider_session_rejects_a_grant_forged_from_a_real_ledger_id(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    registration = _registration()
    ledger = CapabilityLedger(max_depth=sample_campaign.spec.budgets.max_spawn_depth)
    grant = ledger.issue_root(
        sample_campaign,
        subject="agent:provider-session-test",
        tools={f"provider.{registration.provider_id}.chat"},
        targets={str(registration.endpoint)},
    )
    forged = grant.model_copy(update={"subject": "agent:forged"})

    with pytest.raises(CapabilityError, match="ledger authority"):
        PolicyBoundProviderPort(
            registration=registration,
            campaign=sample_campaign,
            grant=forged,
            ledger=ledger,
            budget=BudgetController(sample_campaign.spec.budgets),
            gateway=StubProviderGateway(),  # type: ignore[arg-type]
            store=RunStore.create(tmp_path, sample_campaign.metadata.name),
        )


@pytest.mark.asyncio
async def test_provider_session_snapshots_chat_before_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    gateway = StubProviderGateway(block=True)
    port, _budget = _port(tmp_path, sample_campaign, gateway)
    chat = _chat()
    task = asyncio.create_task(port.chat(role="test", attempt=1, chat=chat))
    while gateway.calls == 0:
        await asyncio.sleep(0)

    chat.messages[0].content = "mutated after dispatch"

    assert gateway.requests[0].arguments["messages"][0]["content"] == "hello"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "data_updates",
    [
        {"provider_id": "forged-provider"},
        {"model": "forged-model"},
        {"target": "https://other.invalid/v1/chat/completions"},
        {"streamed": True},
    ],
)
async def test_provider_session_rejects_unbound_normalized_results(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    data_updates: dict[str, object],
) -> None:
    gateway = StubProviderGateway(
        usage={"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        data_updates=data_updates,
    )
    port, budget = _port(tmp_path, sample_campaign, gateway)

    with pytest.raises(ModelCallFailure, match="invalid result"):
        await port.chat(role="test", attempt=1, chat=_chat())

    assert gateway.calls == 1
    assert budget.snapshot()["modelTokens"] > 0
