"""Provider-neutral conversation probe for authorized AI application targets."""

from __future__ import annotations

import json
from enum import StrEnum

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolSpec


class ChatRole(StrEnum):
    DEVELOPER = "developer"
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ChatMessage(StrictModel):
    role: ChatRole
    content: str = Field(min_length=1, max_length=32_768)


class ProbeTurn(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    messages: list[ChatMessage] = Field(min_length=1, max_length=20)


class ProbeCheckKind(StrEnum):
    RESPONSE_CONTAINS = "response-contains"
    RESPONSE_EXCLUDES = "response-excludes"


class ProbeCheck(StrictModel):
    check_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9.-]*$")
    kind: ProbeCheckKind
    turn: int = Field(ge=0, le=19)
    value: str = Field(min_length=1, max_length=4_096)
    sensitive: bool = False


class AIChatProbeInput(StrictModel):
    scenario_id: str = Field(pattern=r"^kisa\.[a-z0-9.-]+$")
    threat_class: str = Field(pattern=r"^[DMAS]\d{2}$")
    session_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    turns: list[ProbeTurn] = Field(min_length=1, max_length=20)
    checks: list[ProbeCheck] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def checks_reference_existing_turns(self) -> AIChatProbeInput:
        if any(check.turn >= len(self.turns) for check in self.checks):
            raise ValueError("probe check references a missing turn")
        return self


class AIChatRegressionInput(StrictModel):
    session_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    turns: list[ProbeTurn] = Field(min_length=1, max_length=20)
    checks: list[ProbeCheck] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def checks_reference_existing_turns(self) -> AIChatRegressionInput:
        if any(check.turn >= len(self.turns) for check in self.checks):
            raise ValueError("regression check references a missing turn")
        return self


class AIChatProbeTool(Tool):
    """Execute bounded multi-turn probes against the PAJIN AI chat contract."""

    spec = ToolSpec(
        tool_id="ai.chat-probe",
        version="1.0.0",
        description="POST a bounded provider-neutral conversation to an authorized AI target",
        risk_tier=ToolRiskTier.T2,
        categories={"active-test", "ai-redteam", "llm", "rag", "agent"},
        evidence_types={"json", "conversation"},
        network_access=True,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "POST":
            raise ValueError("AI chat probes require POST")
        probe = AIChatProbeInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["ai-chat-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "probe": probe.model_dump(mode="json"),
                },
                separators=(",", ":"),
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
                error=f"worker {result.status.value}: {result.stderr or 'no error detail'}",
            )
        try:
            data = json.loads(result.stdout)
            if not isinstance(data, dict):
                raise TypeError("worker output must be a JSON object")
            self._validate_output_shape(data)
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=f"invalid AI probe output: {exc}",
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
        )

    @staticmethod
    def _validate_output_shape(data: dict[str, object]) -> None:
        required = {
            "target": str,
            "scenarioId": str,
            "threatClass": str,
            "sessionId": str,
            "vulnerable": bool,
            "turns": list,
            "checks": list,
            "sensitiveExposureCount": int,
        }
        for field, expected_type in required.items():
            if not isinstance(data[field], expected_type):
                raise TypeError(f"{field} must be {expected_type.__name__}")
        latency = data.get("meanResponseLatencySeconds")
        if not isinstance(latency, (int, float)) or isinstance(latency, bool) or latency < 0:
            raise TypeError("meanResponseLatencySeconds must be a non-negative number")
        turns = data["turns"]
        checks = data["checks"]
        assert isinstance(turns, list)
        assert isinstance(checks, list)
        for turn in turns:
            if not isinstance(turn, dict) or not isinstance(turn.get("response"), dict):
                raise TypeError("each turn must contain a response object")
            message = turn["response"].get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), str):
                raise TypeError("each response must contain message.content")
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("matched"), bool):
                raise TypeError("each check must contain a boolean matched value")


class AIChatRegressionTool(AIChatProbeTool):
    """Verify normal chat behavior without contributing an attack finding."""

    spec = ToolSpec(
        tool_id="ai.normal-probe",
        version="1.0.0",
        description="POST a bounded normal-use conversation to an authorized AI target",
        risk_tier=ToolRiskTier.T1,
        categories={"active-test", "ai-redteam", "regression"},
        evidence_types={"json", "conversation"},
        network_access=True,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "POST":
            raise ValueError("AI normal-function probes require POST")
        probe = AIChatRegressionInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["ai-chat-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "probe": {
                        "scenario_id": "retest.normal-chat-function",
                        "threat_class": "A00",
                        "session_id": probe.session_id,
                        "turns": [turn.model_dump(mode="json") for turn in probe.turns],
                        "checks": [check.model_dump(mode="json") for check in probe.checks],
                        "purpose": "regression",
                    },
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        interpreted = super().interpret(request, result)
        if not interpreted.success:
            return interpreted
        if not isinstance(interpreted.data.get("regressionPassed"), bool):
            return interpreted.model_copy(
                update={
                    "success": False,
                    "data": {},
                    "error": "invalid AI regression output: regressionPassed must be boolean",
                }
            )
        return interpreted


def evaluate_probe_check(check: ProbeCheck, turn_records: list[dict[str, object]]) -> bool:
    """Evaluate a scenario assertion over a normalized transcript."""

    try:
        response = turn_records[check.turn]["response"]
        if not isinstance(response, dict):
            return False
        message = response["message"]
        if not isinstance(message, dict):
            return False
        content = message["content"]
        if not isinstance(content, str):
            return False
    except (IndexError, KeyError, TypeError):
        return False
    contains = check.value in content
    if check.kind is ProbeCheckKind.RESPONSE_CONTAINS:
        return contains
    if check.kind is ProbeCheckKind.RESPONSE_EXCLUDES:
        return not contains
    return False
