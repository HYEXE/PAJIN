import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.base import ModelCallFailure
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolResult
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.policy.engine import PolicyDecision
from pajin.providers import (
    FunctionDefinition,
    FunctionTool,
    JSONSchemaDefinition,
    JSONSchemaResponseFormat,
    PolicyBoundProviderPort,
    ProviderAssistantToolCall,
    ProviderChatRequest,
    ProviderFunctionCall,
    ProviderMessage,
    ProviderRegistration,
)
from pajin.runtime.control import BudgetController, BudgetExceeded
from pajin.runtime.store import RunStore
from pajin.tools.gateway import GatewayOutcome


class StubProviderGateway:
    def __init__(
        self,
        *,
        usage: dict[str, int] | None = None,
        executed: bool = True,
        success: bool = True,
        block: bool = False,
        data_updates: dict[str, object] | None = None,
    ) -> None:
        self.usage = usage
        self.executed = executed
        self.success = success
        self.block = block
        self.data_updates = data_updates or {}
        self.calls = 0
        self.cancelled = False
        self.requests: list[ToolRequest] = []

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
        return GatewayOutcome(
            decision=PolicyDecision(allowed=True, reason="test fixture", policy="test"),
            result=ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=self.success,
                started_at=now,
                finished_at=now,
                data=data if self.success else {},
                error=None if self.success else "provider dispatch failed",
            ),
            executed=self.executed,
        )


def _registration() -> ProviderRegistration:
    return ProviderRegistration.model_validate(
        {
            "provider_id": "session-provider",
            "endpoint": "https://provider.example/v1/chat/completions",
            "model": "session-model",
            "secret_ref": "provider/session/api-key",
            "input_cost_per_million_usd": 1_000,
            "output_cost_per_million_usd": 2_000,
        }
    )


def _chat(*, max_completion_tokens: int | None = 10) -> ProviderChatRequest:
    return ProviderChatRequest(
        messages=[ProviderMessage(role="user", content="hello")],
        max_completion_tokens=max_completion_tokens,
    )


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
