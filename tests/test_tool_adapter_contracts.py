import json
from datetime import UTC, datetime

import pytest

from pajin.domain.models import ToolRequest
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import Tool
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import MockAgentProbe, SleepCheckTool

STRICT_WORKER_JSON_ADAPTERS = [
    pytest.param(AIChatProbeTool(), id="ai-chat"),
    pytest.param(BooleanSQLiProbeTool(), id="boolean-sqli"),
    pytest.param(CTFWebBackupProbeTool(), id="ctf-web"),
    pytest.param(CTFCryptoXORTool(), id="ctf-crypto"),
    pytest.param(HTTPGetTool(), id="http-get"),
]


def _request(
    tool_id: str,
    *,
    target: str = "https://target.example.invalid/tool",
    arguments: dict[str, object] | None = None,
    method: str = "POST",
) -> ToolRequest:
    return ToolRequest(
        agent_id="agent:test",
        tool_id=tool_id,
        target=target,
        method=method,
        arguments=arguments or {},
    )


def _worker_result(
    payload: object,
    *,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
) -> WorkerResult:
    now = datetime.now(UTC)
    stdout = payload if isinstance(payload, str) else json.dumps(payload)
    return WorkerResult(
        execution_id="exec_adapter_contract",
        backend="adapter-contract",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=stdout,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        started_at=now,
        finished_at=now,
    )


@pytest.mark.parametrize("tool", STRICT_WORKER_JSON_ADAPTERS)
def test_worker_json_adapters_reject_duplicate_object_keys(tool: Tool) -> None:
    request = _request(tool.spec.tool_id)
    raw = '{"target":"first","target":"last"}'

    interpreted = tool.interpret(request, _worker_result(raw))

    assert not interpreted.success
    assert interpreted.error is not None
    assert "duplicate" in interpreted.error


@pytest.mark.parametrize("tool", STRICT_WORKER_JSON_ADAPTERS)
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_worker_json_adapters_reject_truncated_success_transcripts(
    tool: Tool,
    stream: str,
) -> None:
    request = _request(tool.spec.tool_id)

    interpreted = tool.interpret(
        request,
        _worker_result(
            {},
            stdout_truncated=stream == "stdout",
            stderr_truncated=stream == "stderr",
        ),
    )

    assert not interpreted.success
    assert interpreted.error is not None
    assert "truncated" in interpreted.error


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("depth", "nesting-depth limit"),
        ("nodes", "node-count limit"),
        ("nonfinite", "non-finite JSON constant"),
        ("invalid-utf8", "invalid UTF-8 text"),
    ],
)
def test_common_worker_json_decoder_rejects_ambiguous_or_unbounded_trees(
    mutation: str,
    error: str,
) -> None:
    tool = HTTPGetTool()
    payload: object = None
    for _ in range(66 if mutation == "depth" else 0):
        payload = [payload]
    raw = json.dumps({"nested": payload})
    if mutation == "nodes":
        raw = json.dumps({"nodes": [0] * 100_001})
    elif mutation == "nonfinite":
        raw = '{"value":NaN}'
    elif mutation == "invalid-utf8":
        raw = '{"value":"\\ud800"}'

    interpreted = tool.interpret(_request(tool.spec.tool_id), _worker_result(raw))

    assert not interpreted.success
    assert interpreted.error is not None
    assert error in interpreted.error


def _mock_payload(target: str, *, vulnerable: bool) -> dict[str, object]:
    return {
        "target": target,
        "vulnerable": vulnerable,
        "observation": (
            "target accepted an untrusted instruction and invoked a protected tool"
            if vulnerable
            else "target rejected the untrusted instruction"
        ),
        "networkPerformed": False,
    }


def test_mock_probe_accepts_only_the_exact_request_derived_simulation() -> None:
    tool = MockAgentProbe()
    target = "https://target.example.invalid/mock"
    request = _request(
        tool.spec.tool_id,
        target=target,
        arguments={"simulation": {"unauthorizedToolCall": True}},
    )

    interpreted = tool.interpret(request, _worker_result(_mock_payload(target, vulnerable=True)))

    assert interpreted.success
    assert interpreted.error is None
    assert interpreted.data == _mock_payload(target, vulnerable=True)


@pytest.mark.parametrize(
    "mutation",
    [
        "arbitrary-object",
        "missing-field",
        "extra-field",
        "wrong-target",
        "forged-verdict",
        "forged-observation",
        "network-performed",
        "numeric-network-flag",
        "coerced-verdict",
        "invalid-request-simulation",
        "wrong-method",
        "wrong-tool",
        "stdout-truncated",
        "stderr-truncated",
    ],
)
def test_mock_probe_rejects_unbound_or_noncanonical_worker_output(mutation: str) -> None:
    tool = MockAgentProbe()
    target = "https://target.example.invalid/mock"
    request = _request(
        tool.spec.tool_id,
        target=target,
        arguments={"simulation": {"unauthorizedToolCall": False}},
    )
    payload = _mock_payload(target, vulnerable=False)
    stdout_truncated = False
    stderr_truncated = False
    if mutation == "arbitrary-object":
        payload = {"looksPlausible": True}
    elif mutation == "missing-field":
        payload.pop("observation")
    elif mutation == "extra-field":
        payload["attested"] = True
    elif mutation == "wrong-target":
        payload["target"] = "https://outside.example.invalid/mock"
    elif mutation == "forged-verdict":
        payload = _mock_payload(target, vulnerable=True)
    elif mutation == "forged-observation":
        payload["observation"] = "looks safe"
    elif mutation == "network-performed":
        payload["networkPerformed"] = True
    elif mutation == "numeric-network-flag":
        payload["networkPerformed"] = 0
    elif mutation == "coerced-verdict":
        payload["vulnerable"] = "false"
    elif mutation == "invalid-request-simulation":
        request = request.model_copy(
            update={"arguments": {"simulation": {"unauthorizedToolCall": "false"}}}
        )
    elif mutation == "wrong-method":
        request = request.model_copy(update={"method": "GET"})
    elif mutation == "wrong-tool":
        request = request.model_copy(update={"tool_id": "mock.approval-probe"})
    elif mutation == "stdout-truncated":
        stdout_truncated = True
    elif mutation == "stderr-truncated":
        stderr_truncated = True

    interpreted = tool.interpret(
        request,
        _worker_result(
            payload,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        ),
    )

    assert not interpreted.success
    assert interpreted.data == {}
    assert interpreted.error is not None
    assert "invalid worker output" in interpreted.error


def test_mock_probe_rejects_duplicate_worker_output_keys() -> None:
    tool = MockAgentProbe()
    target = "https://target.example.invalid/mock"
    request = _request(
        tool.spec.tool_id,
        target=target,
        arguments={"simulation": {"unauthorizedToolCall": False}},
    )
    raw = (
        f'{{"target":"{target}","vulnerable":true,"vulnerable":false,'
        '"observation":"target rejected the untrusted instruction",'
        '"networkPerformed":false}'
    )

    interpreted = tool.interpret(request, _worker_result(raw))

    assert not interpreted.success
    assert interpreted.error is not None
    assert "duplicate Worker output JSON field" in interpreted.error


def test_sleep_check_accepts_only_the_exact_requested_duration() -> None:
    tool = SleepCheckTool()
    target = "https://target.example.invalid/sleep"
    request = _request(tool.spec.tool_id, target=target, arguments={"seconds": 0.25})

    prepared = json.loads(tool.prepare(request).stdin)
    interpreted = tool.interpret(
        request,
        _worker_result({"slept": True, "seconds": 0.25}),
    )

    assert prepared == {"seconds": 0.25}
    assert interpreted.success
    assert interpreted.error is None
    assert interpreted.data == {"target": target, "slept": True, "seconds": 0.25}


@pytest.mark.parametrize(
    "mutation",
    [
        "arbitrary-object",
        "missing-seconds",
        "extra-field",
        "false-success",
        "numeric-success",
        "wrong-duration",
        "coerced-duration",
        "invalid-request-duration",
        "wrong-method",
        "wrong-tool",
        "stdout-truncated",
        "stderr-truncated",
        "duplicate-key",
    ],
)
def test_sleep_check_rejects_forged_or_ambiguous_success(mutation: str) -> None:
    tool = SleepCheckTool()
    request = _request(tool.spec.tool_id, arguments={"seconds": 0.25})
    payload: object = {"slept": True, "seconds": 0.25}
    if mutation == "arbitrary-object":
        payload = {"looksPlausible": True}
    elif mutation == "missing-seconds":
        payload = {"slept": True}
    elif mutation == "extra-field":
        payload = {"slept": True, "seconds": 0.25, "attested": True}
    elif mutation == "false-success":
        payload = {"slept": False, "seconds": 0.25}
    elif mutation == "numeric-success":
        payload = {"slept": 1, "seconds": 0.25}
    elif mutation == "wrong-duration":
        payload = {"slept": True, "seconds": 0.5}
    elif mutation == "coerced-duration":
        payload = {"slept": True, "seconds": "0.25"}
    elif mutation == "invalid-request-duration":
        request = request.model_copy(update={"arguments": {"seconds": "0.25"}})
    elif mutation == "wrong-method":
        request = request.model_copy(update={"method": "GET"})
    elif mutation == "wrong-tool":
        request = request.model_copy(update={"tool_id": "mock.other-sleep-check"})
    elif mutation == "duplicate-key":
        payload = '{"slept":true,"seconds":0.5,"seconds":0.25}'

    interpreted = tool.interpret(
        request,
        _worker_result(
            payload,
            stdout_truncated=mutation == "stdout-truncated",
            stderr_truncated=mutation == "stderr-truncated",
        ),
    )

    assert not interpreted.success
    assert interpreted.data == {}
    assert interpreted.error is not None
    assert "invalid worker output" in interpreted.error


def _mcp_payload() -> dict[str, object]:
    return {
        "isError": False,
        "structuredContent": {
            "vulnerable": False,
            "observation": "no instruction-hijacking pattern detected",
        },
        "content": [{"type": "text", "text": "inspection complete"}],
    }


def test_registered_mcp_adapter_accepts_bounded_canonical_bridge_output() -> None:
    tool = demo_mcp_tool()
    target = "https://mcp.internal/demo-security/inspect-text"
    request = _request(tool.spec.tool_id, target=target, arguments={"text": "ordinary text"})

    interpreted = tool.interpret(request, _worker_result(_mcp_payload()))

    assert interpreted.success
    assert interpreted.error is None
    assert interpreted.data == {
        "vulnerable": False,
        "observation": "no instruction-hijacking pattern detected",
        "target": target,
        "mcpServerId": "demo-security",
        "mcpToolName": "inspect_text",
        "mcpContent": [{"type": "text", "text": "inspection complete"}],
    }


@pytest.mark.parametrize(
    "raw_output",
    [
        ('{"isError":false,"isError":true,"structuredContent":null,"content":[]}'),
        (
            '{"isError":false,"structuredContent":{"vulnerable":false,'
            '"vulnerable":true},"content":[]}'
        ),
    ],
    ids=["duplicate-envelope-key", "duplicate-nested-key"],
)
def test_registered_mcp_adapter_rejects_duplicate_json_keys(raw_output: str) -> None:
    tool = demo_mcp_tool()
    request = _request(
        tool.spec.tool_id,
        target="https://mcp.internal/demo-security/inspect-text",
        arguments={"text": "ordinary text"},
    )

    interpreted = tool.interpret(request, _worker_result(raw_output))

    assert not interpreted.success
    assert interpreted.data == {}
    assert interpreted.error is not None
    assert "duplicate MCP bridge output field" in interpreted.error


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-is-error",
        "string-is-error",
        "numeric-is-error",
        "extra-envelope-field",
        "non-object-structured-content",
        "reserved-target",
        "reserved-server",
        "reserved-tool",
        "reserved-content",
        "non-list-content",
        "missing-text",
        "extra-content-field",
        "wrong-method",
        "wrong-tool",
        "stdout-truncated",
        "stderr-truncated",
        "oversized-envelope",
    ],
)
def test_registered_mcp_adapter_rejects_ambiguous_or_unbound_bridge_output(
    mutation: str,
) -> None:
    tool = demo_mcp_tool()
    target = "https://mcp.internal/demo-security/inspect-text"
    request = _request(tool.spec.tool_id, target=target, arguments={"text": "ordinary text"})
    payload = _mcp_payload()
    payload_updates: dict[str, tuple[str, object]] = {
        "string-is-error": ("isError", "false"),
        "numeric-is-error": ("isError", 0),
        "extra-envelope-field": ("serverId", "demo-security"),
        "non-object-structured-content": ("structuredContent", []),
        "reserved-target": ("structuredContent", {"target": target}),
        "reserved-server": (
            "structuredContent",
            {"mcpServerId": "demo-security"},
        ),
        "reserved-tool": ("structuredContent", {"mcpToolName": "inspect_text"}),
        "reserved-content": ("structuredContent", {"mcpContent": []}),
        "non-list-content": (
            "content",
            {"type": "text", "text": "inspection complete"},
        ),
        "missing-text": ("content", [{"type": "text"}]),
        "extra-content-field": (
            "content",
            [{"type": "text", "text": "inspection complete", "unexpected": True}],
        ),
        "oversized-envelope": ("structuredContent", {"text": "x" * 1_000_001}),
    }
    if mutation == "missing-is-error":
        payload.pop("isError")
    elif payload_update := payload_updates.get(mutation):
        key, value = payload_update
        payload[key] = value
    request_updates = {
        "wrong-method": {"method": "GET"},
        "wrong-tool": {"tool_id": "mcp.other.inspect-text"},
    }
    if request_update := request_updates.get(mutation):
        request = request.model_copy(update=request_update)

    interpreted = tool.interpret(
        request,
        _worker_result(
            payload,
            stdout_truncated=mutation == "stdout-truncated",
            stderr_truncated=mutation == "stderr-truncated",
        ),
    )

    assert not interpreted.success
    assert interpreted.data == {}
    assert interpreted.error is not None
    assert "invalid MCP bridge output" in interpreted.error
