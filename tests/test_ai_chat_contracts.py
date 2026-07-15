import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pajin.domain.models import ToolRequest
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.ai import (
    AIChatProbeInput,
    AIChatProbeOutput,
    AIChatProbeTool,
    AIChatRegressionInput,
    AIChatRegressionTool,
    ChatMessage,
    ChatRole,
    ProbeCheck,
    ProbeCheckKind,
    ProbePurpose,
    ProbeTurn,
)


def _attack_contract() -> tuple[AIChatProbeTool, ToolRequest, dict[str, object]]:
    scenario = next(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.model.system-prompt-disclosure"
    )
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class="M03",
        session_id="pajin:test:typed-output:1",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    tool = AIChatProbeTool()
    request = ToolRequest(
        request_id="tool_attack_1",
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )
    raw = _output(
        target=request.target,
        scenario_id=probe.scenario_id,
        threat_class=probe.threat_class,
        session_id=probe.session_id,
        turns=probe.turns,
        checks=probe.checks,
        purpose=ProbePurpose.ATTACK,
    )
    return tool, request, raw


def _output(
    *,
    target: str,
    scenario_id: str,
    threat_class: str,
    session_id: str,
    turns: list[ProbeTurn],
    checks: list[ProbeCheck],
    purpose: ProbePurpose,
) -> dict[str, object]:
    turn_records: list[dict[str, object]] = []
    for index, turn in enumerate(turns):
        markers = [check.value for check in checks if check.turn == index]
        turn_records.append(
            {
                "index": index,
                "name": turn.name,
                "request": {
                    "sessionId": session_id,
                    "messages": [message.model_dump(mode="json") for message in turn.messages],
                    "metadata": {"scenarioId": scenario_id, "turn": index},
                },
                "response": {
                    "sessionId": session_id,
                    "message": {
                        "role": "assistant",
                        "content": " ".join(["observed", *markers]),
                    },
                    "toolCalls": [],
                    "safety": {"blocked": False, "reason": None},
                    "memoryWrites": [],
                    "model": "pajin-contract-test-v1",
                },
                "responseLatencySeconds": 0.01,
            }
        )
    return {
        "target": target,
        "scenarioId": scenario_id,
        "threatClass": threat_class,
        "sessionId": session_id,
        "purpose": purpose.value,
        "vulnerable": purpose is ProbePurpose.ATTACK,
        "observation": "Typed but untrusted Worker observation.",
        "turns": turn_records,
        "checks": [
            {
                "checkId": check.check_id,
                "kind": check.kind.value,
                "turn": check.turn,
                "matched": True,
                "sensitive": check.sensitive,
            }
            for check in checks
        ],
        "sensitiveExposureCount": sum(check.sensitive for check in checks),
        "meanResponseLatencySeconds": 0.01,
        "regressionPassed": True if purpose is ProbePurpose.REGRESSION else None,
        "networkPerformed": True,
    }


def _worker_result(raw: dict[str, object]) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id="execution_ai_contract_1",
        backend="contract-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(raw),
        started_at=now,
        finished_at=now,
    )


def test_ai_chat_probe_output_has_strict_nested_wire_contract() -> None:
    _tool, _request, raw = _attack_contract()

    output = AIChatProbeOutput.model_validate(raw)

    assert output.purpose is ProbePurpose.ATTACK
    assert output.turns[0].request.metadata is not None
    assert output.turns[0].response.message.role is ChatRole.ASSISTANT
    assert output.model_dump(mode="json", by_alias=True) == raw

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AIChatProbeOutput.model_validate({**raw, "command": ["curl", raw["target"]]})


def test_ai_chat_probe_tool_uses_typed_output_and_binds_request_identity() -> None:
    tool, request, raw = _attack_contract()

    result = tool.interpret(request, _worker_result(raw))

    assert result.success is True
    assert result.data == AIChatProbeOutput.model_validate(raw).model_dump(
        mode="json",
        by_alias=True,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target", "https://different.example/v1/chat"),
        ("scenarioId", "kisa.model.jailbreak-policy-bypass"),
        ("threatClass", "M06"),
        ("sessionId", "pajin:different:session"),
        ("purpose", "regression"),
        ("networkPerformed", False),
    ],
)
def test_ai_chat_probe_tool_rejects_worker_identity_substitution(
    field: str,
    value: object,
) -> None:
    tool, request, raw = _attack_contract()
    raw[field] = value

    result = tool.interpret(request, _worker_result(raw))

    assert result.success is False
    assert result.data == {}
    assert result.error is not None
    assert "invalid AI probe output" in result.error


def test_ai_chat_output_keeps_worker_verdict_typed_but_not_authoritative() -> None:
    _tool, _request, raw = _attack_contract()
    raw["vulnerable"] = False
    checks = raw["checks"]
    assert isinstance(checks, list)
    assert isinstance(checks[0], dict)
    checks[0]["matched"] = False

    output = AIChatProbeOutput.model_validate(raw)

    assert output.vulnerable is False
    assert output.checks[0].matched is False
    assert "PAJIN_SYSTEM_SENTINEL_COBALT" in output.turns[0].response.message.content


def test_ai_chat_regression_tool_requires_regression_specific_output() -> None:
    regression = AIChatRegressionInput(
        session_id="pajin:test:regression:1",
        turns=[
            ProbeTurn(
                name="normal-use",
                messages=[ChatMessage(role=ChatRole.USER, content="Say hello.")],
            )
        ],
        checks=[
            ProbeCheck(
                check_id="normal-response",
                kind=ProbeCheckKind.RESPONSE_CONTAINS,
                turn=0,
                value="hello",
            )
        ],
    )
    tool = AIChatRegressionTool()
    request = ToolRequest(
        request_id="tool_regression_1",
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=regression.model_dump(mode="json"),
    )
    raw = _output(
        target=request.target,
        scenario_id="retest.normal-chat-function",
        threat_class="A00",
        session_id=regression.session_id,
        turns=regression.turns,
        checks=regression.checks,
        purpose=ProbePurpose.REGRESSION,
    )
    raw["vulnerable"] = False

    assert tool.interpret(request, _worker_result(raw)).success is True

    raw["regressionPassed"] = None
    rejected = tool.interpret(request, _worker_result(raw))
    assert rejected.success is False
    assert rejected.error is not None
    assert "regressionPassed" in rejected.error
