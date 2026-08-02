import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

import pytest

import pajin.cli as cli
from pajin.agents.base import ModelCallFailure
from pajin.domain.manifest import load_manifest
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool, ProviderRegistration
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.control import CancellationKind, ExecutionCancellationContext
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.store import RunIntegrityError, RunStore, verify_run_integrity
from pajin.runtime.worker import (
    DockerWorkerBackend,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.mcp import MCPToolRegistration, RegisteredMCPTool
from pajin.tools.mock import ApprovalCheckTool, MockAgentProbe
from pajin.workflow.model_tool_trace import (
    ModelToolTraceEvent,
    ModelToolTraceIdentity,
    parse_model_tool_trace,
)
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopApproval,
    ToolLoopBinding,
    ToolLoopCheckpoint,
    ToolLoopConfig,
    ToolLoopStatus,
)


def _registration() -> ProviderRegistration:
    return ProviderRegistration.model_validate(
        {
            "provider_id": "loop-provider",
            "endpoint": "https://provider.example/v1/chat/completions",
            "model": "loop-model",
            "secret_ref": "provider/loop/api-key",
            "allowed_function_tools": {"probe_mock_agent"},
        }
    )


def _binding(tool_id: str = "mock.agent-probe") -> ToolLoopBinding:
    return ToolLoopBinding(
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
        tool_id=tool_id,
        target="https://staging.example.invalid/api/chat",
        method="POST",
    )


class LoopWorker:
    def __init__(
        self,
        *,
        repeat_call: bool = False,
        refusal: str | None = None,
        empty_tool_content: bool = False,
    ) -> None:
        self.repeat_call = repeat_call
        self.refusal = refusal
        self.empty_tool_content = empty_tool_content
        self.provider_requests: list[dict[str, object]] = []
        self.tool_calls = 0

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "tests.loop-worker/v1",
            "repeatCall": self.repeat_call,
            "refusalConfigured": self.refusal is not None,
            "emptyToolContent": self.empty_tool_content,
        }

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        now = datetime.now(UTC)
        request = json.loads(job.stdin)
        if job.command == ["openai-chat-completion"]:
            assert secrets and secrets[0].value == "loop-provider-secret"
            provider_request = request["request"]
            self.provider_requests.append(provider_request)
            has_tool_result = any(
                message.get("role") == "tool" for message in provider_request["messages"]
            )
            if self.refusal is not None:
                output = {
                    "provider_id": "loop-provider",
                    "response_id": f"chatcmpl-loop-{len(self.provider_requests)}",
                    "model": "loop-model",
                    "content": None,
                    "refusal": self.refusal,
                    "finish_reason": "content_filter",
                    "tool_calls": [],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
                    "streamed": False,
                    "chunks": 1,
                    "target": request["target"],
                }
            elif not has_tool_result or self.repeat_call:
                output = {
                    "provider_id": "loop-provider",
                    "response_id": f"chatcmpl-loop-{len(self.provider_requests)}",
                    "model": "loop-model",
                    "content": "" if self.empty_tool_content else None,
                    "refusal": None,
                    "finish_reason": "tool_calls",
                    "tool_calls": [
                        {
                            "call_id": "call_probe_1",
                            "name": "probe_mock_agent",
                            "arguments_json": '{"simulation":{"unauthorizedToolCall":true}}',
                            "arguments": {"simulation": {"unauthorizedToolCall": True}},
                            "arguments_valid": True,
                        }
                    ],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                    "streamed": False,
                    "chunks": 1,
                    "target": request["target"],
                }
            else:
                output = {
                    "provider_id": "loop-provider",
                    "response_id": f"chatcmpl-loop-{len(self.provider_requests)}",
                    "model": "loop-model",
                    "content": "Authorized specialist result was received and summarized.",
                    "refusal": None,
                    "finish_reason": "stop",
                    "tool_calls": [],
                    "usage": {"prompt_tokens": 4, "completion_tokens": 3, "total_tokens": 7},
                    "streamed": False,
                    "chunks": 1,
                    "target": request["target"],
                }
        else:
            assert job.command == ["mock-agent-probe"]
            self.tool_calls += 1
            output = {
                "target": request["target"],
                "vulnerable": bool(request["simulation"]["unauthorizedToolCall"]),
                "observation": (
                    "target accepted an untrusted instruction and invoked a protected tool"
                ),
                "networkPerformed": False,
            }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="loop-worker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=now,
            finished_at=now,
        )


class BlockingLoopWorker(LoopWorker):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.cancelled = False

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "tests.blocking-loop-worker/v1",
            "repeatCall": self.repeat_call,
        }

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        if job.command != ["openai-chat-completion"]:
            return await super().run(job, secrets=secrets)
        assert secrets and secrets[0].value == "loop-provider-secret"
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("blocking Provider Worker unexpectedly resumed")


class PausedProviderLoopWorker(LoopWorker):
    def __init__(self) -> None:
        super().__init__()
        self.provider_started = asyncio.Event()
        self.release_provider = asyncio.Event()

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "tests.paused-provider-loop-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        if job.command == ["openai-chat-completion"] and not self.provider_requests:
            self.provider_started.set()
            await self.release_provider.wait()
        return await super().run(job, secrets=secrets)


class HighRiskProbe(Tool):
    spec = ToolSpec(
        tool_id="test.high-risk-probe",
        version="1.0.0",
        description="Approval-gated high-risk test probe",
        risk_tier=ToolRiskTier.T3,
        categories=frozenset({"active-test"}),
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return WorkerJob(
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
            stdin=json.dumps({"target": request.target, **request.arguments}),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=result.status is WorkerStatus.SUCCEEDED,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=json.loads(result.stdout) if result.stdout else {},
            error=result.stderr or None,
        )


def _runner(
    tmp_path: Path,
    worker: WorkerBackend,
    *,
    high_risk: bool = False,
    max_turns: int = 6,
    max_tool_output_chars: int = 32_768,
) -> tuple[PolicyToolLoopRunner, SecretBroker]:
    registration = _registration()
    registry = ToolRegistry()
    registry.register(HighRiskProbe() if high_risk else MockAgentProbe())
    registry.register(OpenAICompatibleChatTool(registration))
    secrets = SecretBroker()
    secrets.register(registration.secret_ref, "loop-provider-secret")
    runner = PolicyToolLoopRunner(
        registration=registration,
        bindings=[_binding("test.high-risk-probe" if high_risk else "mock.agent-probe")],
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        secrets=secrets,
        output_root=tmp_path,
        config=ToolLoopConfig(
            max_turns=max_turns,
            max_tool_output_chars=max_tool_output_chars,
        ),
    )
    return runner, secrets


def _approval_runner(
    tmp_path: Path,
    worker: WorkerBackend,
) -> tuple[PolicyToolLoopRunner, SecretBroker]:
    registration = _registration()
    registry = ToolRegistry()
    registry.register(ApprovalCheckTool())
    registry.register(OpenAICompatibleChatTool(registration))
    secrets = SecretBroker()
    secrets.register(registration.secret_ref, "loop-provider-secret")
    return (
        PolicyToolLoopRunner(
            registration=registration,
            bindings=[_binding("mock.approval-probe")],
            tools=registry,
            policy=PolicyEngine(),
            worker=worker,
            secrets=secrets,
            output_root=tmp_path,
        ),
        secrets,
    )


def _mcp_runner(
    tmp_path: Path,
    worker: LoopWorker,
    *,
    server_id: str,
) -> PolicyToolLoopRunner:
    registration = _registration()
    registry = ToolRegistry()
    registry.register(
        RegisteredMCPTool(
            MCPToolRegistration(
                tool_id="test.approval-mcp",
                server_id=server_id,
                remote_tool_name="inspect_text",
                description="Approval-gated registered MCP fixture",
                risk_tier=ToolRiskTier.T3,
                categories={"mcp", "active-test"},
            )
        )
    )
    registry.register(OpenAICompatibleChatTool(registration))
    secrets = SecretBroker()
    secrets.register(registration.secret_ref, "loop-provider-secret")
    return PolicyToolLoopRunner(
        registration=registration,
        bindings=[_binding("test.approval-mcp")],
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        secrets=secrets,
        output_root=tmp_path,
    )


def _campaign(*, high_risk: bool = False):
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    if not high_risk:
        return campaign
    rules = campaign.spec.rules_of_engagement.model_copy(
        update={"max_tool_risk_tier": ToolRiskTier.T4}
    )
    return campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"rules_of_engagement": rules})}
    )


@pytest.mark.asyncio
async def test_tool_loop_seals_strict_raw_trace_and_sampling_identity(tmp_path: Path) -> None:
    worker = LoopWorker()
    registration = _registration()
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    registry.register(OpenAICompatibleChatTool(registration))
    secrets = SecretBroker()
    secrets.register(registration.secret_ref, "loop-provider-secret")
    identity = ModelToolTraceIdentity(
        agentImplementationId="tests.policy-tool-loop",
        agentImplementationVersion="v1",
        agentImplementationDigest="1" * 64,
        providerRegistrationDigest="2" * 64,
        modelRevision="fixture-model-revision",
        promptBundleDigest="3" * 64,
        toolCatalogDigest="4" * 64,
        runtimeConfigurationDigest="5" * 64,
    )
    runner = PolicyToolLoopRunner(
        registration=registration,
        bindings=[_binding()],
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        secrets=secrets,
        output_root=tmp_path,
        config=ToolLoopConfig(max_turns=2, temperature=0, top_p=1, model_seed=17),
        trace_identity=identity,
    )

    outcome = await runner.run(_campaign(), prompt="Inspect the declared mock target.")

    assert outcome.status is ToolLoopStatus.COMPLETED
    assert outcome.raw_trace_path is not None
    raw = outcome.raw_trace_path.read_bytes()
    records = parse_model_tool_trace(raw, expected_identity=identity)
    assert [record.event for record in records] == [
        ModelToolTraceEvent.IDENTITY,
        ModelToolTraceEvent.MODEL_REQUEST,
        ModelToolTraceEvent.MODEL_RESULT,
        ModelToolTraceEvent.PROVIDER_USAGE,
        ModelToolTraceEvent.TOOL_REQUEST,
        ModelToolTraceEvent.TOOL_RECEIPT,
        ModelToolTraceEvent.TOOL_RESULT,
        ModelToolTraceEvent.MODEL_REQUEST,
        ModelToolTraceEvent.MODEL_RESULT,
        ModelToolTraceEvent.PROVIDER_USAGE,
        ModelToolTraceEvent.CLEANUP,
    ]
    assert [request["temperature"] for request in worker.provider_requests] == [0.0, 0.0]
    assert [request["top_p"] for request in worker.provider_requests] == [1.0, 1.0]
    assert [request["seed"] for request in worker.provider_requests] == [17, 17]
    assert b"loop-provider-secret" not in raw


@pytest.mark.asyncio
async def test_tool_loop_cancellation_revokes_authority_and_seals_checkpoint(
    tmp_path: Path,
) -> None:
    worker = BlockingLoopWorker()
    runner, secrets = _runner(tmp_path, worker)
    cancellation = ExecutionCancellationContext(
        job_id="job_" + "1" * 32,
        control_plane_run_id="run_" + "2" * 32,
    )
    execution = asyncio.create_task(
        runner.run(
            _campaign(),
            prompt="Inspect the declared mock target.",
            cancellation=cancellation,
        )
    )
    await asyncio.wait_for(worker.started.wait(), timeout=1)

    cancellation.cancel(CancellationKind.RUN_CANCELLED, "Control Plane fence observed")
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(execution, timeout=1)

    assert worker.cancelled
    binding = cancellation.binding
    assert binding is not None
    state = json.loads((binding.path / "tool-loop.json").read_text(encoding="utf-8"))
    assert state["status"] == "cancelled"
    checkpoint = json.loads(
        next((binding.path / "checkpoints").glob("*cancelled.json")).read_text(encoding="utf-8")
    )
    assert checkpoint["status"] == "cancelled"
    capabilities = json.loads((binding.path / "capabilities.json").read_text(encoding="utf-8"))
    assert capabilities
    assert all(item["revoked"] is True for item in capabilities)
    assert secrets.snapshot()
    assert all(item["status"] == "revoked" for item in secrets.snapshot())
    assert verify_run_integrity(binding.path).valid


@pytest.mark.asyncio
async def test_pre_cancelled_context_blocks_tool_loop_provider_dispatch(
    tmp_path: Path,
) -> None:
    worker = LoopWorker()
    runner, _secrets = _runner(tmp_path, worker)
    cancellation = ExecutionCancellationContext()
    cancellation.cancel(CancellationKind.RUN_CANCELLED, "cancelled before dispatch")

    with pytest.raises(asyncio.CancelledError):
        await runner.run(
            _campaign(),
            prompt="Do not dispatch after cancellation.",
            cancellation=cancellation,
        )

    assert not worker.provider_requests
    assert worker.tool_calls == 0
    binding = cancellation.binding
    assert binding is not None
    assert (binding.path / "cancellation.json").is_file()


def test_tool_loop_reenters_gateway_and_returns_tool_result_to_provider(tmp_path: Path) -> None:
    worker = LoopWorker()
    runner, _ = _runner(tmp_path, worker)

    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared mock target."))

    assert outcome.status is ToolLoopStatus.COMPLETED
    assert outcome.final_content == "Authorized specialist result was received and summarized."
    assert worker.tool_calls == 1
    assert len(worker.provider_requests) == 2
    assert worker.provider_requests[0]["parallel_tool_calls"] is False
    assert worker.provider_requests[0]["tools"][0]["function"]["strict"] is True
    assert worker.provider_requests[1]["messages"][-1]["role"] == "tool"
    assert worker.provider_requests[1]["messages"][-1]["tool_call_id"] == "call_probe_1"
    budget = json.loads((outcome.run_path / "budget.json").read_text(encoding="utf-8"))
    assert budget["toolCalls"] == 3
    assert budget["modelCalls"] == 2
    assert budget["modelTokens"] > 12
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert events.count('"usageTrust":"provider-reported-untrusted"') == 2
    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    specialist = next(
        item["grant"]
        for item in capabilities
        if item["grant"]["subject"].startswith("agent:tool-loop-specialist:")
    )
    assert specialist["tools"] == ["mock.agent-probe"]
    assert specialist["targets"] == ["https://staging.example.invalid/api/chat"]
    assert outcome.checkpoint_path.is_file()
    execution_context = json.loads(
        (outcome.run_path / "execution-context.json").read_text(encoding="utf-8")
    )
    run_summary = json.loads((outcome.run_path / "run.json").read_text(encoding="utf-8"))
    assert outcome.execution_context.model_dump(mode="json", by_alias=True) == execution_context
    assert execution_context["backend"] == "custom"
    assert execution_context["simulated"] is False
    assert execution_context["evidenceScope"] == "custom-backend-unclassified"
    assert run_summary["executionContext"] == "execution-context.json"
    assert run_summary["workerBackend"] == execution_context["backend"]
    assert run_summary["simulated"] is execution_context["simulated"]
    assert run_summary["evidenceScope"] == execution_context["evidenceScope"]


def test_tool_loop_normalizes_empty_tool_call_content(tmp_path: Path) -> None:
    worker = LoopWorker(empty_tool_content=True)
    runner, _ = _runner(tmp_path, worker)

    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared mock target."))

    assert outcome.status is ToolLoopStatus.COMPLETED
    assert worker.tool_calls == 1
    assert worker.provider_requests[1]["messages"][-2]["role"] == "assistant"
    assert worker.provider_requests[1]["messages"][-2].get("content") is None


def test_tool_loop_blocks_duplicate_function_call(tmp_path: Path) -> None:
    worker = LoopWorker(repeat_call=True)
    runner, _ = _runner(tmp_path, worker)

    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect once."))

    assert outcome.status is ToolLoopStatus.FAILED
    assert outcome.error and "duplicate provider function call" in outcome.error
    assert worker.tool_calls == 1


def test_tool_loop_turn_budget_stops_before_another_provider_call(tmp_path: Path) -> None:
    worker = LoopWorker()
    runner, _ = _runner(tmp_path, worker, max_turns=1)

    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect within one turn."))

    assert outcome.status is ToolLoopStatus.BUDGET_EXHAUSTED
    assert outcome.error == "budget-exhausted: Tool Loop campaign budget was exhausted"
    assert worker.tool_calls == 1
    assert len(worker.provider_requests) == 1


def test_high_risk_tool_waits_for_exact_approval_and_resumes_in_new_run(
    tmp_path: Path,
) -> None:
    worker = LoopWorker()
    runner, secrets = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True)

    waiting = asyncio.run(runner.run(campaign, prompt="Run the approval-gated probe."))

    assert waiting.status is ToolLoopStatus.AWAITING_APPROVAL
    assert waiting.pending_call is not None
    assert waiting.pending_call.risk_tier is ToolRiskTier.T3
    assert worker.tool_calls == 0
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target=waiting.pending_call.target,
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )

    resumed = asyncio.run(
        runner.resume(
            campaign,
            checkpoint_path=waiting.checkpoint_path,
            approvals=[approval],
        )
    )

    assert resumed.status is ToolLoopStatus.COMPLETED
    assert resumed.run_id != waiting.run_id
    assert worker.tool_calls == 1
    resumed_state = json.loads((resumed.run_path / "tool-loop.json").read_text(encoding="utf-8"))
    assert resumed_state["resumed_from_run_id"] == waiting.run_id
    assert resumed_state["approval_ids"] == [approval.approval_id]
    assert resumed_state["budget"]["toolCalls"] == 3
    assert verify_run_integrity(waiting.run_path).valid
    claim_files = list((waiting.run_path.parent / ".pajin-tool-loop-claims").glob("*.json"))
    assert len(claim_files) == 1
    claim = json.loads(claim_files[0].read_text(encoding="utf-8"))
    assert claim["source_run_id"] == waiting.run_id
    assert claim["continuation_run_id"] == resumed.run_id
    assert claim_files[0].stat().st_mode & 0o777 == 0o600
    assert not waiting.checkpoint_path.with_suffix(
        waiting.checkpoint_path.suffix + ".claimed"
    ).exists()
    secret_snapshot = secrets.snapshot()
    assert len(secret_snapshot) == 2
    assert all(item["status"] == "revoked" for item in secret_snapshot)
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (waiting.run_path, resumed.run_path)
        for path in root.rglob("*")
        if path.is_file()
    )
    assert "loop-provider-secret" not in artifact_text

    with pytest.raises(ValueError, match="already been claimed"):
        asyncio.run(
            runner.resume(
                campaign,
                checkpoint_path=waiting.checkpoint_path,
                approvals=[approval],
            )
        )


@pytest.mark.asyncio
async def test_tool_loop_run_uses_private_campaign_authority_across_provider_await(
    tmp_path: Path,
) -> None:
    worker = PausedProviderLoopWorker()
    runner, _secrets = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True).model_copy(deep=True)
    campaign.spec.scope.deny.append(_binding().target)
    arguments = {"simulation": {"unauthorizedToolCall": True}}
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=runner.call_fingerprint(
            _binding("test.high-risk-probe"),
            arguments,
        ),
        tool_id="test.high-risk-probe",
        target=_binding().target,
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )
    execution = asyncio.create_task(
        runner.run(campaign, prompt="Run the exact T3 probe.", approvals=[approval])
    )
    await asyncio.wait_for(worker.provider_started.wait(), timeout=1)
    campaign.spec.scope.deny.clear()
    worker.release_provider.set()

    outcome = await asyncio.wait_for(execution, timeout=2)

    assert outcome.status is ToolLoopStatus.COMPLETED
    assert worker.tool_calls == 0
    assert len(outcome.tool_results) == 1
    assert outcome.tool_results[0].success is False
    assert outcome.tool_results[0].error == ("policy denied: target matches an explicit deny rule")
    sealed = json.loads((outcome.run_path / "campaign.json").read_text(encoding="utf-8"))
    assert _binding().target in sealed["spec"]["scope"]["deny"]


@pytest.mark.asyncio
async def test_tool_loop_resume_uses_sealed_campaign_after_digest_check(
    tmp_path: Path,
) -> None:
    worker = LoopWorker()
    runner, _secrets = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True).model_copy(deep=True)
    campaign.spec.scope.deny.append(_binding().target)
    waiting = await runner.run(campaign, prompt="Request the exact T3 probe.")
    assert waiting.pending_call is not None
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target=waiting.pending_call.target,
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )
    continuation = asyncio.create_task(
        runner.resume(
            campaign,
            checkpoint_path=waiting.checkpoint_path,
            approvals=[approval],
        )
    )
    asyncio.get_running_loop().call_soon(campaign.spec.scope.deny.clear)

    outcome = await asyncio.wait_for(continuation, timeout=2)

    assert outcome.status is ToolLoopStatus.COMPLETED
    assert worker.tool_calls == 0
    assert len(outcome.tool_results) == 1
    assert outcome.tool_results[0].success is False
    assert outcome.tool_results[0].error == ("policy denied: target matches an explicit deny rule")
    sealed = json.loads((outcome.run_path / "campaign.json").read_text(encoding="utf-8"))
    assert _binding().target in sealed["spec"]["scope"]["deny"]


def test_resume_accepts_semantically_exact_control_plane_checkpoint_copy(
    tmp_path: Path,
) -> None:
    worker = LoopWorker()
    runner, _secrets = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True)
    waiting = asyncio.run(runner.run(campaign, prompt="Request the T3 probe."))
    assert waiting.pending_call is not None
    checkpoint = ToolLoopCheckpoint.model_validate_json(waiting.checkpoint_path.read_bytes())
    copied_checkpoint = tmp_path / "control-plane-checkpoint-copy.json"
    copied_checkpoint.write_text(checkpoint.model_dump_json(), encoding="utf-8")
    assert copied_checkpoint.read_bytes() != waiting.checkpoint_path.read_bytes()
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target=waiting.pending_call.target,
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )

    resumed = asyncio.run(
        runner.resume(
            campaign,
            checkpoint_path=copied_checkpoint,
            approvals=[approval],
        )
    )

    assert resumed.status is ToolLoopStatus.COMPLETED
    assert worker.tool_calls == 1
    claim_path = next((waiting.run_path.parent / ".pajin-tool-loop-claims").glob("*.json"))
    claim = json.loads(claim_path.read_text(encoding="utf-8"))
    assert claim["checkpoint_path"] == str(waiting.checkpoint_path.resolve())


def test_resume_rejects_semantically_forged_copied_checkpoint_before_claim(
    tmp_path: Path,
) -> None:
    worker = LoopWorker()
    runner, _secrets = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True)
    waiting = asyncio.run(runner.run(campaign, prompt="Request the T3 probe."))
    forged = json.loads(waiting.checkpoint_path.read_text(encoding="utf-8"))
    forged["pending_call"]["risk_tier"] = int(ToolRiskTier.T0)
    copied_checkpoint = tmp_path / "forged-checkpoint-copy.json"
    copied_checkpoint.write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(ValueError, match="differs from its sealed source"):
        asyncio.run(
            runner.resume(
                campaign,
                checkpoint_path=copied_checkpoint,
                approvals=[],
            )
        )

    assert worker.tool_calls == 0
    assert [path.name for path in waiting.run_path.parent.glob("run_*")] == [waiting.run_id]
    assert not (waiting.run_path.parent / ".pajin-tool-loop-claims").exists()
    assert verify_run_integrity(waiting.run_path).valid


@pytest.mark.parametrize(
    ("source_run_id", "error"),
    [
        ("run_20000101T000000Z_deadbeef", "source Run is unavailable"),
        ("../../forged-run", "source Run ID is invalid"),
    ],
)
def test_resume_rejects_absent_or_traversing_source_run_before_claim(
    tmp_path: Path,
    source_run_id: str,
    error: str,
) -> None:
    worker = LoopWorker()
    runner, _secrets = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True)
    waiting = asyncio.run(runner.run(campaign, prompt="Request the T3 probe."))
    forged = json.loads(waiting.checkpoint_path.read_text(encoding="utf-8"))
    forged["run_id"] = source_run_id
    copied_checkpoint = tmp_path / "forged-source-checkpoint.json"
    copied_checkpoint.write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        asyncio.run(
            runner.resume(
                campaign,
                checkpoint_path=copied_checkpoint,
                approvals=[],
            )
        )

    assert [path.name for path in waiting.run_path.parent.glob("run_*")] == [waiting.run_id]
    assert not (waiting.run_path.parent / ".pajin-tool-loop-claims").exists()


def test_high_risk_resume_denies_non_matching_approval(tmp_path: Path) -> None:
    worker = LoopWorker()
    runner, _ = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True)
    waiting = asyncio.run(runner.run(campaign, prompt="Run the approval-gated probe."))
    assert waiting.pending_call is not None
    now = datetime.now(UTC)
    wrong_target = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target="https://staging.example.invalid/api/different",
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )

    denied = asyncio.run(
        runner.resume(
            campaign,
            checkpoint_path=waiting.checkpoint_path,
            approvals=[wrong_target],
        )
    )

    assert denied.status is ToolLoopStatus.DENIED
    assert denied.error == "provided approval does not authorize the pending tool call"
    assert worker.tool_calls == 0


def test_resume_rejects_registered_mcp_instance_configuration_substitution(
    tmp_path: Path,
) -> None:
    campaign = _campaign(high_risk=True)
    original = _mcp_runner(tmp_path, LoopWorker(), server_id="primary-security")
    waiting = asyncio.run(
        original.run(campaign, prompt="Request the approval-gated registered MCP Tool.")
    )
    changed = _mcp_runner(tmp_path, LoopWorker(), server_id="backup-security")

    with pytest.raises(ValueError, match="runner context"):
        asyncio.run(
            changed.resume(
                campaign,
                checkpoint_path=waiting.checkpoint_path,
                approvals=[],
            )
        )

    assert not waiting.checkpoint_path.with_suffix(
        waiting.checkpoint_path.suffix + ".claimed"
    ).exists()
    assert verify_run_integrity(waiting.run_path).valid


def test_resume_run_provision_failure_rolls_back_claim_without_mutating_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = LoopWorker()
    runner, _secrets = _runner(tmp_path, worker, high_risk=True)
    campaign = _campaign(high_risk=True)
    waiting = asyncio.run(runner.run(campaign, prompt="Request the T3 probe."))

    def fail_create(
        cls: type[RunStore],
        root: Path,
        campaign_name: str,
        *,
        run_id: str | None = None,
    ) -> RunStore:
        del cls, root, campaign_name, run_id
        raise OSError("injected continuation Run provisioning failure")

    monkeypatch.setattr(RunStore, "create", classmethod(fail_create))
    with pytest.raises(OSError, match="provisioning failure"):
        asyncio.run(
            runner.resume(
                campaign,
                checkpoint_path=waiting.checkpoint_path,
                approvals=[],
            )
        )

    claim_root = waiting.run_path.parent / ".pajin-tool-loop-claims"
    assert not list(claim_root.glob("*.json"))
    assert [path.name for path in waiting.run_path.parent.glob("run_*")] == [waiting.run_id]
    assert verify_run_integrity(waiting.run_path).valid


@pytest.mark.parametrize(
    "changed_worker",
    [
        DockerWorkerBackend(allowed_images={"pajin-worker:dev", "alternate-worker:dev"}),
        DockerWorkerBackend(
            allowed_images={"pajin-worker:dev"},
            docker_executable="/opt/pajin/bin/docker",
        ),
        DockerWorkerBackend(
            allowed_images={"pajin-worker:dev"},
            egress_proxy_image="alternate-egress-proxy:dev",
        ),
        DockerWorkerBackend(
            allowed_images={"pajin-worker:dev"},
            external_network="pajin-external",
        ),
    ],
)
def test_runner_context_binds_docker_worker_instance_configuration(
    tmp_path: Path,
    changed_worker: DockerWorkerBackend,
) -> None:
    original, _secrets = _runner(
        tmp_path,
        DockerWorkerBackend(allowed_images={"pajin-worker:dev"}),
    )
    changed, _changed_secrets = _runner(tmp_path, changed_worker)

    assert original._runner_context_digest() != changed._runner_context_digest()


def test_resumable_tool_loop_rejects_component_without_explicit_stable_context(
    tmp_path: Path,
) -> None:
    class OpaqueStatefulLoopWorker(LoopWorker):
        pass

    runner, _secrets = _runner(tmp_path, OpaqueStatefulLoopWorker())
    campaign = _campaign()

    with pytest.raises(TypeError, match="must explicitly implement stable_execution_context"):
        asyncio.run(runner.run(campaign, prompt="Do not trust opaque Worker state."))

    campaign_root = tmp_path / campaign.metadata.name
    assert not campaign_root.exists() or not list(campaign_root.glob("run_*"))


def _tool_result(*, data: dict[str, object]) -> ToolResult:
    now = datetime.now(UTC)
    return ToolResult(
        request_id="tool_" + "a" * 32,
        tool_id="mock.agent-probe",
        success=True,
        started_at=now,
        finished_at=now,
        data=data,
    )


def _assert_failure_artifacts_exclude(run_path: Path, forbidden: str) -> None:
    artifact_paths = [
        run_path / "tool-loop.json",
        run_path / "run.json",
        run_path / "events.jsonl",
        *sorted((run_path / "checkpoints").glob("*.json")),
    ]
    forbidden_bytes = forbidden.encode("utf-8")
    assert artifact_paths
    for artifact_path in artifact_paths:
        assert forbidden_bytes not in artifact_path.read_bytes()


def test_tool_message_preserves_normal_compact_json_contract(tmp_path: Path) -> None:
    runner, _secrets = _runner(tmp_path, LoopWorker())
    result = _tool_result(data={"observation": "정상 결과", "count": 2})

    encoded = runner._tool_message(result)

    assert encoded == json.dumps(
        {
            "success": True,
            "data": result.data,
            "error": None,
            "evidence": [],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


@pytest.mark.parametrize(
    "shape",
    ["encoded-size", "depth", "node-count", "huge-scalar"],
)
def test_tool_message_preflights_adversarial_json_before_full_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
) -> None:
    runner, _secrets = _runner(
        tmp_path,
        LoopWorker(),
        max_tool_output_chars=1_024,
    )
    if shape == "encoded-size":
        data: dict[str, object] = {"items": ["bounded-fragment" * 8 for _ in range(32)]}
    elif shape == "depth":
        nested: object = "leaf"
        for _ in range(70):
            nested = [nested]
        data = {"nested": nested}
    elif shape == "node-count":
        data = {"nodes": [None for _ in range(2_000)]}
    else:
        data = {"payload": "x" * 2_000_000}
    result = _tool_result(data=data)

    def reject_unbounded_dumps(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("unbounded json.dumps must not render Tool output")

    monkeypatch.setattr("pajin.workflow.tool_loop.json.dumps", reject_unbounded_dumps)
    encoded = runner._tool_message(result)

    assert len(encoded) <= 1_024
    assert json.loads(encoded) == {
        "success": True,
        "error": None,
        "evidence": [],
        "truncated": True,
    }


def test_provider_refusal_text_is_not_persisted_as_failure_diagnostic(tmp_path: Path) -> None:
    provider_fragment = "provider-secret-fragment-REFUSAL-9137"
    runner, _secrets = _runner(tmp_path, LoopWorker(refusal=provider_fragment))

    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared target."))

    assert outcome.status is ToolLoopStatus.DENIED
    assert outcome.error == "provider-refused: provider declined the tool-loop request"
    _assert_failure_artifacts_exclude(outcome.run_path, provider_fragment)
    assert verify_run_integrity(outcome.run_path).valid


def test_model_call_failure_text_is_not_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_fragment = "provider-secret-fragment-MODEL-4821"
    runner, _secrets = _runner(tmp_path, LoopWorker())

    async def fail_provider_call(
        _provider: PolicyBoundProviderPort,
        **_kwargs: object,
    ) -> object:
        raise ModelCallFailure(provider_fragment)

    monkeypatch.setattr(PolicyBoundProviderPort, "chat", fail_provider_call)
    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared target."))

    assert outcome.status is ToolLoopStatus.FAILED
    assert outcome.error == (
        "provider-call-failed: provider execution or response validation failed"
    )
    _assert_failure_artifacts_exclude(outcome.run_path, provider_fragment)
    assert verify_run_integrity(outcome.run_path).valid


def test_validation_exception_text_is_not_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_fragment = "provider-secret-fragment-VALIDATION-0674"
    runner, _secrets = _runner(tmp_path, LoopWorker())

    def fail_intent_validation(*_args: object, **_kwargs: object) -> object:
        raise ValueError(provider_fragment)

    monkeypatch.setattr(runner, "_intent", fail_intent_validation)
    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared target."))

    assert outcome.status is ToolLoopStatus.FAILED
    assert outcome.error == "validation-failed: Tool Loop input or output validation failed"
    _assert_failure_artifacts_exclude(outcome.run_path, provider_fragment)
    assert verify_run_integrity(outcome.run_path).valid


def test_cli_checks_accept_conservative_tool_loop_budget_and_verified_checkpoint(
    tmp_path: Path,
) -> None:
    runner, _secrets = _runner(tmp_path, LoopWorker())
    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared target."))

    checks = cli._tool_loop_checks(outcome, credential="loop-provider-secret")
    budget = json.loads((outcome.run_path / "budget.json").read_text(encoding="utf-8"))

    assert all(checks.values()), checks
    assert budget["modelPromptTokens"] > 0
    assert budget["modelCompletionTokens"] > 0
    assert budget["modelTokens"] == (budget["modelPromptTokens"] + budget["modelCompletionTokens"])
    assert budget["modelTokens"] != 30
    assert budget["modelTokens"] <= budget["maxModelTokens"]


def test_cli_approval_checks_bind_both_runs_and_cumulative_budgets(tmp_path: Path) -> None:
    runner, _secrets = _approval_runner(tmp_path, LoopWorker())
    campaign = _campaign(high_risk=True)
    waiting = asyncio.run(runner.run(campaign, prompt="Request the T3 probe."))
    assert waiting.pending_call is not None
    now = datetime.now(UTC)
    approval = ToolLoopApproval(
        call_fingerprint=waiting.pending_call.fingerprint,
        tool_id=waiting.pending_call.tool_id,
        target=waiting.pending_call.target,
        approved_by="security-owner",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )
    resumed = asyncio.run(
        runner.resume(
            campaign,
            checkpoint_path=waiting.checkpoint_path,
            approvals=[approval],
        )
    )

    checks = cli._tool_loop_approval_checks(
        waiting,
        resumed,
        approval_id=approval.approval_id,
        credential="loop-provider-secret",
    )
    waiting_budget = json.loads((waiting.run_path / "budget.json").read_text(encoding="utf-8"))
    resumed_budget = json.loads((resumed.run_path / "budget.json").read_text(encoding="utf-8"))

    assert all(checks.values()), checks
    assert resumed_budget["modelTokens"] > waiting_budget["modelTokens"] > 0
    assert resumed_budget["modelTokens"] != 30


@pytest.mark.parametrize(
    ("artifact_kind", "failed_check"),
    [
        ("budget", "turn tool model and agent budgets measured"),
        ("checkpoint", "resumable checkpoint persisted"),
    ],
)
def test_cli_tool_loop_checks_reject_semantically_tampered_verified_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_kind: str,
    failed_check: str,
) -> None:
    runner, _secrets = _runner(tmp_path, LoopWorker())
    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared target."))
    checkpoint_relative = outcome.checkpoint_path.relative_to(outcome.run_path).as_posix()
    target = "budget.json" if artifact_kind == "budget" else checkpoint_relative
    original_loader = cli.load_verified_run_artifacts

    def load_tampered_snapshot(*args: object, **kwargs: object):
        snapshot = original_loader(*args, **kwargs)
        if target not in snapshot.artifacts:
            return snapshot
        artifacts = dict(snapshot.artifacts)
        payload = json.loads(snapshot.artifact_bytes(target))
        if artifact_kind == "budget":
            payload["modelTokens"] = 1
        else:
            payload["run_id"] = "run_forged_checkpoint"
        artifacts[target] = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return replace(snapshot, artifacts=MappingProxyType(artifacts))

    monkeypatch.setattr(cli, "load_verified_run_artifacts", load_tampered_snapshot)
    checks = cli._tool_loop_checks(outcome, credential="loop-provider-secret")

    assert checks[failed_check] is False


@pytest.mark.parametrize("artifact_kind", ["budget", "checkpoint"])
def test_cli_tool_loop_checks_fail_closed_on_sealed_artifact_tampering(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    runner, _secrets = _runner(tmp_path, LoopWorker())
    outcome = asyncio.run(runner.run(_campaign(), prompt="Inspect the declared target."))
    target = (
        outcome.run_path / "budget.json" if artifact_kind == "budget" else outcome.checkpoint_path
    )
    payload = json.loads(target.read_text(encoding="utf-8"))
    if artifact_kind == "budget":
        payload["modelTokens"] = 1
    else:
        payload["run_id"] = "run_forged_checkpoint"
    target.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RunIntegrityError):
        cli._tool_loop_checks(outcome, credential="loop-provider-secret")
