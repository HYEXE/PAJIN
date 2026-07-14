"""Trusted Job-kind bindings for the Control Plane Worker daemon."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from inspect import Parameter, signature
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field, model_validator

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.control_plane.models import ApprovalIntent, JobKind, JobView
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool, ProviderRegistration
from pajin.providers.models import NormalizedToolCall, ProviderChatResult, ProviderUsage
from pajin.runtime.control import ExecutionCancellationContext
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.mock import ApprovalCheckTool, MockAgentProbe, SleepCheckTool
from pajin.workflow.cancellation import seal_executor_quiescence
from pajin.workflow.local import LocalCampaignRunner
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopApproval,
    ToolLoopBinding,
    ToolLoopCheckpoint,
    ToolLoopStatus,
)


class ExecutionError(RuntimeError):
    """Base class for bounded Job execution errors."""


class PermanentExecutionError(ExecutionError):
    pass


class TransientExecutionError(ExecutionError):
    pass


class CompletedExecution(StrictModel):
    result: dict[str, Any]


class ApprovalCheckpointExecution(StrictModel):
    state: dict[str, Any]
    pending_intent: ApprovalIntent


type ExecutionOutcome = CompletedExecution | ApprovalCheckpointExecution


class JobExecutor(Protocol):
    kind: JobKind

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ExecutionOutcome:
        """Execute only the typed payload bound to this trusted kind."""


class CampaignJobInput(StrictModel):
    manifest: CampaignManifest
    profile: Literal["deterministic-local"] = "deterministic-local"

    @model_validator(mode="after")
    def restrict_local_targets(self) -> CampaignJobInput:
        supported = {"mock-agent", "mock-sleep"}
        unknown = {target.type for target in self.manifest.spec.targets} - supported
        if unknown:
            raise ValueError(f"deterministic-local profile rejects target types: {sorted(unknown)}")
        return self


class ToolLoopJobInput(StrictModel):
    manifest: CampaignManifest
    prompt: str = Field(min_length=1, max_length=32_768)
    profile: Literal["deterministic-approval-lab"] = "deterministic-approval-lab"

    @model_validator(mode="after")
    def restrict_lab_target(self) -> ToolLoopJobInput:
        if len(self.manifest.spec.targets) != 1:
            raise ValueError("deterministic tool-loop profile requires exactly one target")
        if self.manifest.spec.targets[0].type != "mock-agent":
            raise ValueError("deterministic tool-loop profile requires a mock-agent target")
        return self


class ToolLoopResumeState(StrictModel):
    job_input: ToolLoopJobInput
    tool_loop_checkpoint: ToolLoopCheckpoint


class ConsumedApproval(StrictModel):
    call_fingerprint: str = Field(alias="callFingerprint", pattern=r"^[0-9a-f]{64}$")
    tool_id: str = Field(alias="toolId")
    target: str
    risk_tier: int = Field(alias="riskTier", ge=3, le=4)
    approved_by: str = Field(alias="approvedBy", min_length=1)
    approved_at: datetime = Field(alias="approvedAt")
    expires_at: datetime = Field(alias="expiresAt")


class ExecutorRegistry:
    """Fail closed when a Job kind has no trusted, pre-registered adapter."""

    def __init__(self, executors: list[JobExecutor]) -> None:
        self._executors: dict[str, JobExecutor] = {}
        for executor in executors:
            cancellation_parameter = signature(executor.execute).parameters.get(
                "cancellation"
            )
            if cancellation_parameter is None or cancellation_parameter.kind not in {
                Parameter.POSITIONAL_OR_KEYWORD,
                Parameter.KEYWORD_ONLY,
            }:
                raise ValueError(
                    f"Job executor {executor.kind.value} must accept a cancellation context"
                )
            if executor.kind.value in self._executors:
                raise ValueError(f"duplicate Job executor: {executor.kind.value}")
            self._executors[executor.kind.value] = executor
        if not self._executors:
            raise ValueError("Worker daemon requires at least one Job executor")

    @property
    def kinds(self) -> list[str]:
        return sorted(self._executors)

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ExecutionOutcome:
        executor = self._executors.get(job.kind)
        if executor is None:
            raise PermanentExecutionError(f"unregistered Job kind: {job.kind}")
        return await executor.execute(job, cancellation=cancellation)


class CampaignJobExecutor:
    kind = JobKind.CAMPAIGN

    def __init__(
        self,
        *,
        output_root: Path,
        worker: WorkerBackend | None = None,
    ) -> None:
        self._output_root = output_root
        self._worker = worker or SimulatedWorkerBackend()

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        job_input = CampaignJobInput.model_validate(self._input(job))
        tools = ToolRegistry()
        tools.register(MockAgentProbe())
        tools.register(SleepCheckTool())
        runner = LocalCampaignRunner(
            agents=DeterministicAgentRuntime(),
            tools=tools,
            policy=PolicyEngine(),
            worker=self._worker,
            output_root=self._output_root,
        )
        try:
            outcome = await runner.run(job_input.manifest, cancellation=cancellation)
        except asyncio.CancelledError:
            if cancellation is not None and cancellation.active:
                seal_executor_quiescence(cancellation)
            raise
        failed = sum(not result.success for result in outcome.tool_results)
        return CompletedExecution(
            result={
                "engine": "local-campaign",
                "engineRunId": outcome.run_id,
                "runPath": str(outcome.run_path.resolve()),
                "reportPath": str(outcome.report_path.resolve()),
                "toolCalls": len(outcome.tool_results),
                "failedToolCalls": failed,
                "validatedFindings": len(outcome.findings),
            }
        )

    @staticmethod
    def _input(job: JobView) -> dict[str, Any]:
        value = job.payload.get("input")
        if not isinstance(value, dict):
            raise PermanentExecutionError("campaign Job payload.input must be an object")
        return value


class ToolLoopJobExecutor:
    """Bridge durable Control Plane checkpoints to the existing Tool Loop runner."""

    kind = JobKind.TOOL_LOOP

    def __init__(
        self,
        *,
        output_root: Path,
        runner_factory: Callable[[CampaignManifest], PolicyToolLoopRunner] | None = None,
    ) -> None:
        self._output_root = output_root
        self._runner_factory = runner_factory or self._deterministic_runner

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ExecutionOutcome:
        if "resumeFromCheckpointId" in job.payload:
            return await self._resume(job, cancellation=cancellation)
        value = job.payload.get("input")
        if not isinstance(value, dict):
            raise PermanentExecutionError("tool-loop Job payload.input must be an object")
        job_input = ToolLoopJobInput.model_validate(value)
        runner = self._runner_factory(job_input.manifest)
        try:
            outcome = await runner.run(
                job_input.manifest,
                prompt=job_input.prompt,
                cancellation=cancellation,
            )
        except asyncio.CancelledError:
            if cancellation is not None and cancellation.active:
                seal_executor_quiescence(cancellation)
            raise
        return self._translate_outcome(outcome, job_input=job_input)

    async def _resume(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None,
    ) -> ExecutionOutcome:
        raw_state = job.payload.get("state")
        raw_approval = job.payload.get("approval")
        approval_id = job.payload.get("approvalId")
        if not isinstance(raw_state, dict) or not isinstance(raw_approval, dict):
            raise PermanentExecutionError("continuation Job lacks signed state or approval")
        if not isinstance(approval_id, str):
            raise PermanentExecutionError("continuation Job lacks approval ID")
        state = ToolLoopResumeState.model_validate(raw_state)
        approval = ConsumedApproval.model_validate(raw_approval)
        pending = state.tool_loop_checkpoint.pending_call
        if pending is None:
            raise PermanentExecutionError("tool-loop checkpoint lacks a pending call")
        tool_approval = ToolLoopApproval(
            approval_id=approval_id,
            call_fingerprint=approval.call_fingerprint,
            tool_id=approval.tool_id,
            target=approval.target,
            approved_by=approval.approved_by,
            approved_at=approval.approved_at,
            expires_at=approval.expires_at,
        )
        resume_dir = self._output_root / "_control-plane-resume" / job.job_id
        resume_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = resume_dir / f"attempt-{job.attempts}.json"
        checkpoint_path.write_text(state.tool_loop_checkpoint.model_dump_json(), encoding="utf-8")
        runner = self._runner_factory(state.job_input.manifest)
        try:
            outcome = await runner.resume(
                state.job_input.manifest,
                checkpoint_path=checkpoint_path,
                approvals=[tool_approval],
                cancellation=cancellation,
            )
        except asyncio.CancelledError:
            if cancellation is not None and cancellation.active:
                seal_executor_quiescence(cancellation)
            raise
        return self._translate_outcome(outcome, job_input=state.job_input)

    def _translate_outcome(
        self,
        outcome: Any,
        *,
        job_input: ToolLoopJobInput,
    ) -> ExecutionOutcome:
        if outcome.status is ToolLoopStatus.AWAITING_APPROVAL:
            if outcome.pending_call is None:
                raise PermanentExecutionError("approval outcome lacks a pending Tool intent")
            checkpoint = ToolLoopCheckpoint.model_validate_json(
                outcome.checkpoint_path.read_text(encoding="utf-8")
            )
            return ApprovalCheckpointExecution(
                state=ToolLoopResumeState(
                    job_input=job_input,
                    tool_loop_checkpoint=checkpoint,
                ).model_dump(mode="json"),
                pending_intent=ApprovalIntent(
                    call_fingerprint=outcome.pending_call.fingerprint,
                    tool_id=outcome.pending_call.tool_id,
                    target=outcome.pending_call.target,
                    risk_tier=outcome.pending_call.risk_tier,
                    expires_at=datetime.now(UTC).replace(microsecond=0) + _APPROVAL_WINDOW,
                ),
            )
        if outcome.status is not ToolLoopStatus.COMPLETED:
            raise PermanentExecutionError(
                f"tool-loop engine ended with {outcome.status.value}: {outcome.error}"
            )
        return CompletedExecution(
            result={
                "engine": "policy-tool-loop",
                "engineRunId": outcome.run_id,
                "runPath": str(outcome.run_path.resolve()),
                "checkpointPath": str(outcome.checkpoint_path.resolve()),
                "toolCalls": len(outcome.tool_results),
                "finalContent": outcome.final_content,
            }
        )

    def _deterministic_runner(self, campaign: CampaignManifest) -> PolicyToolLoopRunner:
        registration = ProviderRegistration.model_validate(
            {
                "provider_id": "daemon-lab",
                "endpoint": "https://deterministic-provider.invalid/v1/chat/completions",
                "model": "pajin-daemon-deterministic",
                "secret_ref": "provider/daemon-lab/api-key",
                "allowed_function_tools": {"probe_mock_agent"},
            }
        )
        tools = ToolRegistry()
        tools.register(ApprovalCheckTool())
        tools.register(OpenAICompatibleChatTool(registration))
        secrets = SecretBroker()
        secrets.register(registration.secret_ref, "deterministic-provider-lab-fixture")
        target = campaign.spec.targets[0]
        binding = ToolLoopBinding(
            function_name="probe_mock_agent",
            description="Run the approval-gated deterministic mock probe.",
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
        return PolicyToolLoopRunner(
            registration=registration,
            bindings=[binding],
            tools=tools,
            policy=PolicyEngine(),
            worker=DeterministicToolLoopBackend(),
            secrets=secrets,
            output_root=self._output_root,
        )


class DeterministicToolLoopBackend:
    """No-network lab backend that still exercises the real Provider and Tool gateways."""

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        now = datetime.now(UTC)
        try:
            payload = json.loads(job.stdin)
            if job.command == ["openai-chat-completion"]:
                if not secrets or {item.binding for item in secrets} != {"provider-api-key"}:
                    raise ValueError("deterministic provider requires one bound credential")
                provider_request = payload["request"]
                messages = provider_request["messages"]
                has_tool_result = any(message.get("role") == "tool" for message in messages)
                output = self._provider_result(payload, has_tool_result=has_tool_result)
            elif job.command == ["mock-agent-probe"]:
                if secrets:
                    raise ValueError("mock probe does not accept secrets")
                output = {
                    "target": payload["target"],
                    "vulnerable": bool(
                        payload.get("simulation", {}).get("unauthorizedToolCall", False)
                    ),
                    "observation": "bounded approval probe completed",
                }
            else:
                raise ValueError("deterministic backend rejects unregistered action")
            return WorkerResult(
                execution_id=job.execution_id,
                backend="deterministic-tool-loop",
                status=WorkerStatus.SUCCEEDED,
                exit_code=0,
                stdout=json.dumps(output, separators=(",", ":")),
                started_at=now,
                finished_at=datetime.now(UTC),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return WorkerResult(
                execution_id=job.execution_id,
                backend="deterministic-tool-loop",
                status=WorkerStatus.FAILED,
                exit_code=2,
                stderr=f"invalid deterministic worker input: {exc}",
                started_at=now,
                finished_at=datetime.now(UTC),
            )

    @staticmethod
    def _provider_result(payload: dict[str, Any], *, has_tool_result: bool) -> dict[str, Any]:
        target = str(payload["target"])
        result = ProviderChatResult(
            provider_id="daemon-lab",
            response_id=f"chatcmpl-daemon-{int(has_tool_result)}",
            model="pajin-daemon-deterministic",
            content=(
                "Authorized specialist result was received and summarized."
                if has_tool_result
                else None
            ),
            finish_reason="stop" if has_tool_result else "tool_calls",
            tool_calls=(
                []
                if has_tool_result
                else [
                    NormalizedToolCall(
                        call_id="call_daemon_probe",
                        name="probe_mock_agent",
                        arguments_json='{"simulation":{"unauthorizedToolCall":true}}',
                        arguments={"simulation": {"unauthorizedToolCall": True}},
                        arguments_valid=True,
                    )
                ]
            ),
            usage=ProviderUsage(prompt_tokens=3, completion_tokens=2, total_tokens=5),
            streamed=False,
            chunks=1,
            target=target,
        )
        return result.model_dump(mode="json")


_APPROVAL_WINDOW = timedelta(minutes=5)
