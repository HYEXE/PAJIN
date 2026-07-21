"""Safe worker-backed tool for validating the orchestration boundary."""

from __future__ import annotations

import json

from pydantic import ConfigDict, Field, StrictBool, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
    decode_strict_worker_json_object,
)


class MockAgentProbeSimulation(StrictModel):
    """The complete synthetic behavior authorized by a mock probe request."""

    unauthorized_tool_call: StrictBool = Field(
        default=False,
        alias="unauthorizedToolCall",
    )


class MockAgentProbeInput(StrictModel):
    """Typed input used by the independent mock-result Validator."""

    simulation: MockAgentProbeSimulation = Field(default_factory=MockAgentProbeSimulation)


class MockAgentProbeOutput(StrictModel):
    """Strict synthetic Worker observation; verdict authority remains with the Validator."""

    target: str = Field(min_length=1, max_length=2_000)
    vulnerable: StrictBool
    observation: str = Field(min_length=1, max_length=2_000)
    network_performed: StrictBool = Field(alias="networkPerformed")

    @model_validator(mode="after")
    def require_synthetic_execution(self) -> MockAgentProbeOutput:
        if self.network_performed:
            raise ValueError("mock agent probe cannot claim network execution")
        return self


class SleepCheckInput(StrictModel):
    """Exact bounded duration requested from the cancellable sleep fixture."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    seconds: int | float = Field(default=5, ge=0.1, le=30)


class SleepCheckOutput(StrictModel):
    """Exact Worker observation required before a sleep check can succeed."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    slept: StrictBool
    seconds: int | float = Field(ge=0.1, le=30)

    @model_validator(mode="after")
    def require_completed_sleep(self) -> SleepCheckOutput:
        if not self.slept:
            raise ValueError("sleep check output must report completed sleep")
        return self


class MockAgentProbe(Tool):
    """Return a configured observation without making a network request."""

    spec = ToolSpec(
        tool_id="mock.agent-probe",
        version="1.0.0",
        description="Safe simulated probe for an agentic AI target",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"active-test", "ai-redteam"}),
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._validate_request_identity(request)
        probe = MockAgentProbeInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "simulation": probe.simulation.model_dump(mode="json", by_alias=True),
                }
            ),
            network=NetworkMode.NONE,
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_worker_failure(result),
            )
        if result.stdout_truncated or result.stderr_truncated:
            return self._invalid_worker_output(
                request,
                result,
                ValueError("successful Worker output was truncated"),
            )
        try:
            self._validate_request_identity(request)
            probe = MockAgentProbeInput.model_validate(request.arguments)
            output = MockAgentProbeOutput.model_validate(
                decode_strict_worker_json_object(result, label="mock agent probe output")
            )
            expected_vulnerable = probe.simulation.unauthorized_tool_call
            expected_observation = self._expected_observation(expected_vulnerable)
            if output.target != request.target:
                raise ValueError("worker output target differs from request target")
            if output.vulnerable is not expected_vulnerable:
                raise ValueError("worker verdict differs from the authorized simulation")
            if output.observation != expected_observation:
                raise ValueError("worker observation differs from the authorized simulation")
        except ValueError as exc:
            return self._invalid_worker_output(request, result, exc)
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=output.model_dump(mode="json", by_alias=True),
        )

    def _validate_request_identity(self, request: ToolRequest) -> None:
        if request.tool_id != self.spec.tool_id:
            raise ValueError("request tool ID differs from the registered mock tool")
        if request.method != "POST":
            raise ValueError("mock agent probes require POST")

    @staticmethod
    def _expected_observation(vulnerable: bool) -> str:
        if vulnerable:
            return "target accepted an untrusted instruction and invoked a protected tool"
        return "target rejected the untrusted instruction"

    @staticmethod
    def _invalid_worker_output(
        request: ToolRequest,
        result: WorkerResult,
        error: BaseException,
    ) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=False,
            started_at=result.started_at,
            finished_at=result.finished_at,
            error=audit_safe_tool_interpretation_failure(
                "invalid worker output",
                error,
            ),
        )


class ApprovalCheckTool(MockAgentProbe):
    """Safe lab fixture classified T3 to verify explicit approval handling."""

    spec = ToolSpec(
        tool_id="mock.approval-probe",
        version="1.0.0",
        description="Approval-gated mock probe used only to verify T3 workflow controls",
        risk_tier=ToolRiskTier.T3,
        categories=frozenset({"active-test", "approval-verification"}),
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()


class SleepCheckTool(Tool):
    """Bounded verification tool used to exercise cooperative campaign cancellation."""

    spec = ToolSpec(
        tool_id="mock.sleep-check",
        version="1.0.0",
        description="Sleep inside the isolated Worker for cancellation verification",
        risk_tier=ToolRiskTier.T0,
        categories=frozenset({"verification"}),
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._validate_request_identity(request)
        sleep = SleepCheckInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["sleep-check"],
            stdin=json.dumps(sleep.model_dump(mode="json")),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_worker_failure(result),
            )
        try:
            self._validate_request_identity(request)
            if result.stdout_truncated or result.stderr_truncated:
                raise ValueError("successful Worker output was truncated")
            expected = SleepCheckInput.model_validate(request.arguments)
            output = SleepCheckOutput.model_validate(
                decode_strict_worker_json_object(result, label="sleep check output")
            )
            if output.seconds != expected.seconds:
                raise ValueError("worker duration differs from the requested duration")
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_tool_interpretation_failure(
                    "invalid worker output",
                    exc,
                ),
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data={
                "target": request.target,
                **output.model_dump(mode="json"),
            },
        )

    def _validate_request_identity(self, request: ToolRequest) -> None:
        if request.tool_id != self.spec.tool_id:
            raise ValueError("request tool ID differs from the registered sleep tool")
        if request.method != "POST":
            raise ValueError("sleep checks require POST")
