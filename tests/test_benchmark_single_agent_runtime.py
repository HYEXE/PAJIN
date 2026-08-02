import base64
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pajin.benchmark.single_agent_baseline import (
    registered_generic_single_agent_adapter_contract,
)
from pajin.benchmark.single_agent_runtime import (
    QWEN_GGUF_SHA256,
    SINGLE_AGENT_FINDING_ID,
    SINGLE_AGENT_FUNCTION_NAME,
    SINGLE_AGENT_OBJECTIVE,
    SINGLE_AGENT_TARGET,
    LocalLlamaCppSingleAgentRegistration,
    local_llama_cpp_tool_binding,
    local_llama_cpp_tool_loop_config,
    parse_local_llama_cpp_single_agent_trace,
    registered_local_llama_cpp_single_agent,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.providers.models import (
    NormalizedToolCall,
    ProviderChatRequest,
    ProviderChatResult,
    ProviderMessage,
    ProviderUsage,
)
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.ai import ChatRole
from pajin.tools.bug_bounty import BOOLEAN_SQLI_SCENARIO
from pajin.workflow.model_tool_trace import (
    CleanupTracePayload,
    ModelRequestTracePayload,
    ModelResultTracePayload,
    ModelToolTraceEvent,
    ModelToolTraceRecord,
    ProviderUsageTracePayload,
    ToolReceiptTracePayload,
    ToolRequestTracePayload,
    ToolResultTracePayload,
    encode_model_tool_trace,
    model_tool_trace_record,
)
from pajin.workflow.tool_loop import TOOL_LOOP_DEVELOPER_PROMPT

_RUNTIME_IMAGE_ID = "sha256:" + "a" * 64


def _registration() -> LocalLlamaCppSingleAgentRegistration:
    return registered_local_llama_cpp_single_agent(
        registered_generic_single_agent_adapter_contract(),
        runtime_image_id=_RUNTIME_IMAGE_ID,
    )


def _probe_data() -> dict[str, object]:
    observations = []
    for name, count in (("baseline", 1), ("negative-control", 0), ("boolean-probe", 3)):
        body = json.dumps({"recordCount": count, "synthetic": True}).encode()
        observations.append(
            {
                "name": name,
                "status": 200,
                "recordCount": count,
                "synthetic": True,
                "bodySha256": __import__("hashlib").sha256(body).hexdigest(),
                "responseBodyBase64": base64.b64encode(body).decode(),
            }
        )
    return {
        "target": SINGLE_AGENT_TARGET,
        "scenarioId": BOOLEAN_SQLI_SCENARIO,
        "vulnerable": True,
        "checks": {
            "baselineSingleRecord": True,
            "negativeControlEmpty": True,
            "booleanProbeExpanded": True,
            "syntheticLabOnly": True,
        },
        "observations": observations,
        "networkPerformed": True,
    }


def _raw_trace(
    registration: LocalLlamaCppSingleAgentRegistration,
) -> bytes:
    records: list[ModelToolTraceRecord] = []
    model_tool_trace_record(records, ModelToolTraceEvent.IDENTITY, registration.trace_identity())
    binding = local_llama_cpp_tool_binding()
    config = local_llama_cpp_tool_loop_config(seed=17)
    messages = [
        ProviderMessage(role=ChatRole.DEVELOPER, content=TOOL_LOOP_DEVELOPER_PROMPT),
        ProviderMessage(
            role=ChatRole.USER,
            content=json.dumps(
                {
                    "objective": SINGLE_AGENT_OBJECTIVE,
                    "declaredTargets": [SINGLE_AGENT_TARGET],
                },
                separators=(",", ":"),
            ),
        ),
    ]
    request_one = ProviderChatRequest(
        messages=messages,
        tools=[binding.function_tool()],
        max_completion_tokens=2048,
        temperature=config.temperature,
        top_p=config.top_p,
        seed=config.model_seed,
        parallel_tool_calls=False,
    )
    usage_one = ProviderUsage(prompt_tokens=20, completion_tokens=8, total_tokens=28)
    result_one = ProviderChatResult(
        provider_id=registration.provider_registration.provider_id,
        response_id="response-1",
        model=registration.provider_registration.model,
        content=None,
        finish_reason="tool_calls",
        tool_calls=[
            NormalizedToolCall(
                call_id="call-1",
                name=SINGLE_AGENT_FUNCTION_NAME,
                arguments_json=json.dumps(
                    {"scenario_id": BOOLEAN_SQLI_SCENARIO}, separators=(",", ":")
                ),
                arguments={"scenario_id": BOOLEAN_SQLI_SCENARIO},
                arguments_valid=True,
            )
        ],
        usage=usage_one,
        streamed=False,
        chunks=1,
        target=str(registration.provider_registration.endpoint),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.MODEL_REQUEST,
        ModelRequestTracePayload(attempt=1, request=request_one),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.MODEL_RESULT,
        ModelResultTracePayload(attempt=1, result=result_one),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.PROVIDER_USAGE,
        ProviderUsageTracePayload(attempt=1, usage=usage_one),
    )
    tool_request = ToolRequest(
        request_id="tool-call-1",
        agent_id="agent:tool-loop-specialist:test",
        tool_id=binding.tool_id,
        target=binding.target,
        method=binding.method,
        arguments={"scenario_id": BOOLEAN_SQLI_SCENARIO},
    )
    now = datetime.now(UTC)
    tool_result = ToolResult(
        request_id=tool_request.request_id,
        tool_id=tool_request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        data=_probe_data(),
    )
    worker_result = WorkerResult(
        execution_id="exec-trace-test",
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        started_at=now,
        finished_at=now,
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.TOOL_REQUEST,
        ToolRequestTracePayload(callId="call-1", request=tool_request),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.TOOL_RECEIPT,
        ToolReceiptTracePayload(
            callId="call-1",
            executed=True,
            workerResult=worker_result,
            networkLogTrusted=True,
            resultIdentityValid=True,
        ),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.TOOL_RESULT,
        ToolResultTracePayload(callId="call-1", result=tool_result),
    )
    final_content = json.dumps(
        {
            "findingId": SINGLE_AGENT_FINDING_ID,
            "vulnerable": True,
            "evidence": "fixed-boolean-sqli-probe",
        },
        separators=(",", ":"),
    )
    request_two = request_one.model_copy(
        update={
            "messages": [
                *messages,
                ProviderMessage(
                    role=ChatRole.ASSISTANT,
                    tool_calls=[
                        {
                            "id": "call-1",
                            "function": {
                                "name": SINGLE_AGENT_FUNCTION_NAME,
                                "arguments": json.dumps(
                                    {"scenario_id": BOOLEAN_SQLI_SCENARIO},
                                    separators=(",", ":"),
                                ),
                            },
                        }
                    ],
                ),
                ProviderMessage(
                    role=ChatRole.TOOL,
                    tool_call_id="call-1",
                    content=json.dumps(
                        {
                            "success": True,
                            "data": _probe_data(),
                            "error": None,
                            "evidence": [],
                        },
                        separators=(",", ":"),
                    ),
                ),
            ]
        },
        deep=True,
    )
    usage_two = ProviderUsage(prompt_tokens=40, completion_tokens=12, total_tokens=52)
    result_two = ProviderChatResult(
        provider_id=registration.provider_registration.provider_id,
        response_id="response-2",
        model=registration.provider_registration.model,
        content=final_content,
        finish_reason="stop",
        usage=usage_two,
        streamed=False,
        chunks=1,
        target=str(registration.provider_registration.endpoint),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.MODEL_REQUEST,
        ModelRequestTracePayload(attempt=2, request=request_two),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.MODEL_RESULT,
        ModelResultTracePayload(attempt=2, result=result_two),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.PROVIDER_USAGE,
        ProviderUsageTracePayload(attempt=2, usage=usage_two),
    )
    model_tool_trace_record(
        records,
        ModelToolTraceEvent.CLEANUP,
        CleanupTracePayload(status="completed", workerExecutionCount=3, activeSecretLeaseCount=0),
    )
    return encode_model_tool_trace(records)


def test_local_registration_binds_exact_model_provider_prompt_tool_and_runtime() -> None:
    registration = _registration()

    assert registration.model_artifact_sha256 == QWEN_GGUF_SHA256
    assert registration.provider_registration.input_cost_per_million_usd == 0
    assert registration.provider_registration.output_cost_per_million_usd == 0
    assert registration.trace_identity().model_revision == registration.model_revision


def test_local_registration_rejects_model_or_runtime_substitution() -> None:
    registration = _registration()
    raw = registration.model_dump(mode="json", by_alias=True)
    raw["runtimeImageId"] = "sha256:" + "b" * 64

    with pytest.raises(ValidationError, match="single-agent identity differs"):
        LocalLlamaCppSingleAgentRegistration.model_validate(raw)


def test_local_trace_reader_binds_two_model_calls_one_tool_and_usage() -> None:
    registration = _registration()
    raw = _raw_trace(registration)

    trace = parse_local_llama_cpp_single_agent_trace(raw, registration=registration)

    assert trace.model_call_count == 2
    assert trace.tool_call_count == 1
    assert trace.prompt_tokens == 60
    assert trace.completion_tokens == 20
    assert trace.total_tokens == 80
    assert trace.vulnerable is True
    assert trace.cost_usd == 0


def test_local_trace_reader_rejects_identity_or_raw_event_mutation() -> None:
    registration = _registration()
    raw = _raw_trace(registration)
    lines = raw.decode().splitlines()
    record = json.loads(lines[4])
    record["payload"]["request"]["target"] = "http://foreign:8080/v1/users/lookup"
    lines[4] = json.dumps(record, separators=(",", ":"), sort_keys=True)
    mutated = ("\n".join(lines) + "\n").encode()

    with pytest.raises(ValueError, match="Tool execution differs"):
        parse_local_llama_cpp_single_agent_trace(mutated, registration=registration)


def test_local_trace_reader_rejects_tool_message_substitution() -> None:
    registration = _registration()
    lines = _raw_trace(registration).decode().splitlines()
    record = json.loads(lines[7])
    record["payload"]["request"]["messages"][3]["content"] = json.dumps(
        {"success": False, "data": {}, "error": None, "evidence": []},
        separators=(",", ":"),
    )
    lines[7] = json.dumps(record, separators=(",", ":"), sort_keys=True)
    mutated = ("\n".join(lines) + "\n").encode()

    with pytest.raises(ValueError, match="Tool message differs"):
        parse_local_llama_cpp_single_agent_trace(mutated, registration=registration)
