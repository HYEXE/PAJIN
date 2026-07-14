import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.domain.manifest import load_manifest
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool, ProviderRegistration
from pajin.runtime.control import CancellationKind, ExecutionCancellationContext
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopApproval,
    ToolLoopBinding,
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
    def __init__(self, *, repeat_call: bool = False) -> None:
        self.repeat_call = repeat_call
        self.provider_requests: list[dict[str, object]] = []
        self.tool_calls = 0

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
            if not has_tool_result or self.repeat_call:
                output = {
                    "provider_id": "loop-provider",
                    "response_id": f"chatcmpl-loop-{len(self.provider_requests)}",
                    "model": "loop-model",
                    "content": None,
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
                "observation": "bounded mock probe completed",
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


class HighRiskProbe(Tool):
    spec = ToolSpec(
        tool_id="test.high-risk-probe",
        version="1.0.0",
        description="Approval-gated high-risk test probe",
        risk_tier=ToolRiskTier.T3,
        categories={"active-test"},
    )

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
    worker: LoopWorker,
    *,
    high_risk: bool = False,
    max_turns: int = 6,
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
        config=ToolLoopConfig(max_turns=max_turns),
    )
    return runner, secrets


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
        next((binding.path / "checkpoints").glob("*cancelled.json")).read_text(
            encoding="utf-8"
        )
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
    assert budget["modelTokens"] == 12
    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    specialist = next(
        item["grant"]
        for item in capabilities
        if item["grant"]["subject"].startswith("agent:tool-loop-specialist:")
    )
    assert specialist["tools"] == ["mock.agent-probe"]
    assert specialist["targets"] == ["https://staging.example.invalid/api/chat"]
    assert outcome.checkpoint_path.is_file()


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
    assert outcome.error == "maximum tool-loop turns exceeded"
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
