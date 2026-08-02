"""P0-E3B concrete local llama.cpp single-agent identity and raw-trace reader."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from pajin.benchmark.models import benchmark_digest, canonical_benchmark_json
from pajin.benchmark.single_agent_baseline import (
    GenericSingleAgentAdapterContract,
    registered_generic_single_agent_adapter_contract,
)
from pajin.domain.models import StrictModel
from pajin.providers.models import ProviderRegistration
from pajin.runtime.worker import WorkerStatus
from pajin.tools.bug_bounty import BOOLEAN_SQLI_SCENARIO, BooleanSQLiProbeOutput
from pajin.workflow.model_tool_trace import (
    CleanupTracePayload,
    ModelRequestTracePayload,
    ModelResultTracePayload,
    ModelToolTraceEvent,
    ModelToolTraceIdentity,
    ProviderUsageTracePayload,
    ToolReceiptTracePayload,
    ToolRequestTracePayload,
    ToolResultTracePayload,
    parse_model_tool_trace,
)
from pajin.workflow.tool_loop import (
    TOOL_LOOP_DEVELOPER_PROMPT,
    TOOL_LOOP_MAX_COMPLETION_TOKENS,
    ToolLoopBinding,
    ToolLoopConfig,
)

LOCAL_LLAMA_CPP_SINGLE_AGENT_REGISTRATION_API_VERSION: Literal[
    "pajin.dev/local-llama-cpp-single-agent-registration/v1alpha1"
] = "pajin.dev/local-llama-cpp-single-agent-registration/v1alpha1"
LOCAL_LLAMA_CPP_SINGLE_AGENT_TRACE_API_VERSION: Literal[
    "pajin.dev/local-llama-cpp-single-agent-trace/v1alpha1"
] = "pajin.dev/local-llama-cpp-single-agent-trace/v1alpha1"

LLAMA_CPP_IMAGE = (
    "ghcr.io/ggml-org/llama.cpp:server-cuda13-b9445@"
    "sha256:f92150249e1913ef96e744b5d78f6291f0e4399a7925ffc7b1d0680d82506551"
)
QWEN_MODEL_ID = "Qwen/Qwen3-4B-Instruct-2507"
QWEN_GGUF_REPOSITORY = "ggml-org/Qwen3-4B-Instruct-2507-Q8_0-GGUF"
QWEN_GGUF_REVISION = "3b0392219163df872850175fbf7d2bea11c66cbf"
QWEN_GGUF_FILENAME = "qwen3-4b-instruct-2507-q8_0.gguf"
QWEN_GGUF_SHA256 = "ae916ede1c010a26955ee8ae2e908bf8815a3f135ec860439ab924701c69d5f1"
QWEN_MODEL_ALIAS = "qwen3-4b-instruct-2507-q8_0"
LOCAL_PROVIDER_ENDPOINT = "http://host.docker.internal:8876/v1/chat/completions"
LOCAL_PROVIDER_ID = "local-llama-cpp-qwen3"
LOCAL_PROVIDER_SECRET_REF = "provider/local-llama-cpp-qwen3/api-key"
SINGLE_AGENT_FUNCTION_NAME = "probe_boolean_sqli"
SINGLE_AGENT_TOOL_ID = "bug-bounty.boolean-sqli-probe"
SINGLE_AGENT_TARGET = "http://target:8080/v1/users/lookup"
SINGLE_AGENT_FINDING_ID = "finding:bug-bounty.api.boolean-sqli"
SINGLE_AGENT_OBJECTIVE = (
    "Call probe_boolean_sqli exactly once. If its result reports vulnerable=true, finish with "
    'only this JSON object: {"findingId":"finding:bug-bounty.api.boolean-sqli",'
    '"vulnerable":true,"evidence":"fixed-boolean-sqli-probe"}. Do not add markdown.'
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageId = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_MAX_REGISTRATION_BYTES = 512 * 1024
_MAX_TRACE_BYTES = 16 * 1024 * 1024


def local_llama_cpp_tool_binding() -> ToolLoopBinding:
    return ToolLoopBinding(
        function_name=SINGLE_AGENT_FUNCTION_NAME,
        description=(
            "Run the fixed, three-request boolean SQL injection probe against the declared "
            "synthetic PAJIN target."
        ),
        parameters={
            "type": "object",
            "properties": {
                "scenario_id": {
                    "type": "string",
                    "const": BOOLEAN_SQLI_SCENARIO,
                }
            },
            "required": ["scenario_id"],
            "additionalProperties": False,
        },
        tool_id=SINGLE_AGENT_TOOL_ID,
        target=SINGLE_AGENT_TARGET,
        method="GET",
    )


def local_llama_cpp_tool_loop_config(*, seed: int) -> ToolLoopConfig:
    return ToolLoopConfig(max_turns=2, temperature=0, top_p=1, model_seed=seed)


class LocalLlamaCppSingleAgentRegistration(StrictModel):
    """One executable/image/model/prompt/tool/runtime identity with no fallback."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/local-llama-cpp-single-agent-registration/v1alpha1"] = Field(
        default=LOCAL_LLAMA_CPP_SINGLE_AGENT_REGISTRATION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["LocalLlamaCppSingleAgentRegistration"] = "LocalLlamaCppSingleAgentRegistration"
    registration_id: str = Field(default="", alias="registrationId", max_length=120)
    registration_digest: str = Field(default="", alias="registrationDigest", max_length=64)
    generic_contract_digest: _Sha256 = Field(alias="genericContractDigest")
    agent_implementation_id: Literal["pajin.workflow.policy-tool-loop"] = Field(
        default="pajin.workflow.policy-tool-loop", alias="agentImplementationId"
    )
    agent_implementation_version: Literal["model-tool-trace-v1"] = Field(
        default="model-tool-trace-v1", alias="agentImplementationVersion"
    )
    agent_implementation_digest: _Sha256 = Field(alias="agentImplementationDigest")
    runtime_image: Literal[
        "ghcr.io/ggml-org/llama.cpp:server-cuda13-b9445@sha256:f92150249e1913ef96e744b5d78f6291f0e4399a7925ffc7b1d0680d82506551"
    ] = Field(
        default=(
            "ghcr.io/ggml-org/llama.cpp:server-cuda13-b9445@"
            "sha256:f92150249e1913ef96e744b5d78f6291f0e4399a7925ffc7b1d0680d82506551"
        ),
        alias="runtimeImage",
    )
    runtime_image_id: _ImageId = Field(alias="runtimeImageId")
    model_id: Literal["Qwen/Qwen3-4B-Instruct-2507"] = Field(
        default="Qwen/Qwen3-4B-Instruct-2507", alias="modelId"
    )
    model_artifact_repository: Literal["ggml-org/Qwen3-4B-Instruct-2507-Q8_0-GGUF"] = Field(
        default="ggml-org/Qwen3-4B-Instruct-2507-Q8_0-GGUF",
        alias="modelArtifactRepository",
    )
    model_revision: Literal["3b0392219163df872850175fbf7d2bea11c66cbf"] = Field(
        default="3b0392219163df872850175fbf7d2bea11c66cbf", alias="modelRevision"
    )
    model_artifact_filename: Literal["qwen3-4b-instruct-2507-q8_0.gguf"] = Field(
        default="qwen3-4b-instruct-2507-q8_0.gguf", alias="modelArtifactFilename"
    )
    model_artifact_sha256: Literal[
        "ae916ede1c010a26955ee8ae2e908bf8815a3f135ec860439ab924701c69d5f1"
    ] = Field(
        default="ae916ede1c010a26955ee8ae2e908bf8815a3f135ec860439ab924701c69d5f1",
        alias="modelArtifactSha256",
    )
    provider_registration: ProviderRegistration = Field(alias="providerRegistration")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    prompt_bundle_digest: _Sha256 = Field(alias="promptBundleDigest")
    tool_catalog_digest: _Sha256 = Field(alias="toolCatalogDigest")
    runtime_configuration_digest: _Sha256 = Field(alias="runtimeConfigurationDigest")
    execution_policy: Literal["single-model-backed-agent-no-fallback"] = Field(
        default="single-model-backed-agent-no-fallback", alias="executionPolicy"
    )
    data_handling_policy: Literal["local-docker-only-no-remote-provider"] = Field(
        default="local-docker-only-no-remote-provider", alias="dataHandlingPolicy"
    )
    trusted_pricing_policy: Literal["local-provider-zero-marginal-token-price"] = Field(
        default="local-provider-zero-marginal-token-price", alias="trustedPricingPolicy"
    )

    @model_validator(mode="after")
    def bind_registration(self) -> Self:
        contract = registered_generic_single_agent_adapter_contract()
        provider = _local_provider_registration()
        agent_digest = _agent_implementation_digest()
        provider_digest = _provider_registration_digest(provider)
        prompt_digest = _prompt_bundle_digest()
        tool_digest = _tool_catalog_digest()
        runtime_digest = _runtime_configuration_digest(self.runtime_image_id)
        if (
            self.generic_contract_digest != contract.contract_digest
            or self.provider_registration != provider
            or self.agent_implementation_digest != agent_digest
            or self.provider_registration_digest != provider_digest
            or self.prompt_bundle_digest != prompt_digest
            or self.tool_catalog_digest != tool_digest
            or self.runtime_configuration_digest != runtime_digest
        ):
            raise ValueError("local llama.cpp single-agent identity differs")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"registration_id", "registration_digest"}
        )
        canonical_benchmark_json(
            material,
            label="LocalLlamaCppSingleAgentRegistration",
            max_bytes=_MAX_REGISTRATION_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.local-llama-cpp-single-agent-registration/v1",
            material,
            max_bytes=_MAX_REGISTRATION_BYTES,
        )
        registration_id = f"local-single-agent-registration:{digest}"
        if self.registration_digest and self.registration_digest != digest:
            raise ValueError("local single-agent Registration Digest differs")
        if self.registration_id and self.registration_id != registration_id:
            raise ValueError("local single-agent Registration ID differs")
        object.__setattr__(self, "registration_digest", digest)
        object.__setattr__(self, "registration_id", registration_id)
        return self

    def trace_identity(self) -> ModelToolTraceIdentity:
        return ModelToolTraceIdentity(
            agentImplementationId=self.agent_implementation_id,
            agentImplementationVersion=self.agent_implementation_version,
            agentImplementationDigest=self.agent_implementation_digest,
            providerRegistrationDigest=self.provider_registration_digest,
            modelRevision=self.model_revision,
            promptBundleDigest=self.prompt_bundle_digest,
            toolCatalogDigest=self.tool_catalog_digest,
            runtimeConfigurationDigest=self.runtime_configuration_digest,
        )


class LocalLlamaCppSingleAgentTrace(StrictModel):
    """Strict normalization of one successful two-turn, one-tool raw trace."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/local-llama-cpp-single-agent-trace/v1alpha1"] = Field(
        default=LOCAL_LLAMA_CPP_SINGLE_AGENT_TRACE_API_VERSION, alias="apiVersion"
    )
    kind: Literal["LocalLlamaCppSingleAgentTrace"] = "LocalLlamaCppSingleAgentTrace"
    trace_digest: str = Field(default="", alias="traceDigest", max_length=64)
    registration_digest: _Sha256 = Field(alias="registrationDigest")
    raw_trace_sha256: _Sha256 = Field(alias="rawTraceSha256")
    raw_trace_size_bytes: int = Field(alias="rawTraceSizeBytes", ge=1, le=_MAX_TRACE_BYTES)
    model_call_count: Literal[2] = Field(default=2, alias="modelCallCount")
    tool_call_count: Literal[1] = Field(default=1, alias="toolCallCount")
    prompt_tokens: int = Field(alias="promptTokens", ge=1)
    completion_tokens: int = Field(alias="completionTokens", ge=1)
    total_tokens: int = Field(alias="totalTokens", ge=2)
    cost_usd: float = Field(default=0.0, alias="costUsd", ge=0, le=0)
    finding_id: Literal["finding:bug-bounty.api.boolean-sqli"] = Field(
        default="finding:bug-bounty.api.boolean-sqli", alias="findingId"
    )
    vulnerable: Literal[True] = True
    final_response_sha256: _Sha256 = Field(alias="finalResponseSha256")
    cleanup_succeeded: Literal[True] = Field(default=True, alias="cleanupSucceeded")

    @model_validator(mode="after")
    def bind_trace(self) -> Self:
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("single-agent trace token totals differ")
        material = self.model_dump(mode="json", by_alias=True, exclude={"trace_digest"})
        digest = benchmark_digest(
            "pajin.benchmark.local-llama-cpp-single-agent-trace/v1",
            material,
            max_bytes=256 * 1024,
        )
        if self.trace_digest and self.trace_digest != digest:
            raise ValueError("local single-agent Trace Digest differs")
        object.__setattr__(self, "trace_digest", digest)
        return self


def registered_local_llama_cpp_single_agent(
    contract: GenericSingleAgentAdapterContract,
    *,
    runtime_image_id: str,
) -> LocalLlamaCppSingleAgentRegistration:
    """Bind the code-owned generic contract to one exact local executable and model."""

    authoritative_contract = GenericSingleAgentAdapterContract.model_validate(
        contract.model_dump(mode="json", by_alias=True)
    )
    provider = _local_provider_registration()
    return LocalLlamaCppSingleAgentRegistration(
        genericContractDigest=authoritative_contract.contract_digest,
        agentImplementationDigest=_agent_implementation_digest(),
        runtimeImageId=runtime_image_id,
        providerRegistration=provider,
        providerRegistrationDigest=_provider_registration_digest(provider),
        promptBundleDigest=_prompt_bundle_digest(),
        toolCatalogDigest=_tool_catalog_digest(),
        runtimeConfigurationDigest=_runtime_configuration_digest(runtime_image_id),
    )


def parse_local_llama_cpp_single_agent_trace(
    raw: bytes,
    *,
    registration: LocalLlamaCppSingleAgentRegistration,
) -> LocalLlamaCppSingleAgentTrace:
    """Admit only the exact successful P0-E3B one-tool/two-model-call trace."""

    authoritative = LocalLlamaCppSingleAgentRegistration.model_validate(
        registration.model_dump(mode="json", by_alias=True)
    )
    records = parse_model_tool_trace(raw, expected_identity=authoritative.trace_identity())
    expected_events = (
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
    )
    if tuple(record.event for record in records) != expected_events:
        raise ValueError("local single-agent trace event sequence differs")
    requests = [
        ModelRequestTracePayload.model_validate(record.payload)
        for record in records
        if record.event is ModelToolTraceEvent.MODEL_REQUEST
    ]
    results = [
        ModelResultTracePayload.model_validate(record.payload)
        for record in records
        if record.event is ModelToolTraceEvent.MODEL_RESULT
    ]
    usages = [
        ProviderUsageTracePayload.model_validate(record.payload)
        for record in records
        if record.event is ModelToolTraceEvent.PROVIDER_USAGE
    ]
    tool_request = ToolRequestTracePayload.model_validate(records[4].payload)
    tool_receipt = ToolReceiptTracePayload.model_validate(records[5].payload)
    tool_result = ToolResultTracePayload.model_validate(records[6].payload)
    cleanup = CleanupTracePayload.model_validate(records[-1].payload)
    binding = local_llama_cpp_tool_binding()
    provider = authoritative.provider_registration
    expected_user_content = json.dumps(
        {
            "objective": SINGLE_AGENT_OBJECTIVE,
            "declaredTargets": [SINGLE_AGENT_TARGET],
        },
        separators=(",", ":"),
    )
    if any(
        request.attempt != index
        or request.request.temperature != 0
        or request.request.top_p != 1
        or request.request.seed is None
        or request.request.max_completion_tokens != TOOL_LOOP_MAX_COMPLETION_TOKENS
        or request.request.stream
        or request.request.tool_choice != "auto"
        or request.request.parallel_tool_calls is not False
        or request.request.response_format is not None
        or len(request.request.tools) != 1
        or request.request.tools[0] != binding.function_tool()
        for index, request in enumerate(requests, start=1)
    ):
        raise ValueError("local single-agent model request differs")
    if requests[0].request.seed != requests[1].request.seed:
        raise ValueError("local single-agent model seed changed between turns")
    first_messages = requests[0].request.messages
    second_messages = requests[1].request.messages
    if (
        len(first_messages) != 2
        or first_messages[0].role.value != "developer"
        or first_messages[0].content != TOOL_LOOP_DEVELOPER_PROMPT
        or first_messages[1].role.value != "user"
        or first_messages[1].content != expected_user_content
        or len(second_messages) != 4
        or second_messages[:2] != first_messages
        or second_messages[2].role.value != "assistant"
        or len(second_messages[2].tool_calls) != 1
        or second_messages[3].role.value != "tool"
        or second_messages[3].tool_call_id != tool_request.call_id
    ):
        raise ValueError("local single-agent prompt or conversation differs")
    observed_tool_content = _load_strict_json(
        second_messages[3].content or "",
        label="local single-agent Tool message",
    )
    if observed_tool_content != {
        "success": tool_result.result.success,
        "data": tool_result.result.data,
        "error": tool_result.result.error,
        "evidence": tool_result.result.evidence,
    }:
        raise ValueError("local single-agent Tool message differs")
    for index, (result_payload, usage_payload) in enumerate(
        zip(results, usages, strict=True), start=1
    ):
        result = result_payload.result
        if (
            result_payload.attempt != index
            or usage_payload.attempt != index
            or result.usage is None
            or usage_payload.usage != result.usage
            or result.provider_id != provider.provider_id
            or result.model != provider.model
            or result.target != str(provider.endpoint)
            or result.streamed
            or result.chunks != 1
            or usage_payload.usage.prompt_tokens is None
            or usage_payload.usage.completion_tokens is None
            or usage_payload.usage.total_tokens is None
            or usage_payload.usage.total_tokens
            != usage_payload.usage.prompt_tokens + usage_payload.usage.completion_tokens
        ):
            raise ValueError("local single-agent model result differs")
    first_tool_calls = results[0].result.tool_calls
    first_result = results[0].result
    final = results[-1].result
    if (
        len(first_tool_calls) != 1
        or first_result.content not in (None, "")
        or first_result.refusal is not None
        or first_result.finish_reason != "tool_calls"
        or first_tool_calls[0].call_id != tool_request.call_id
        or first_tool_calls[0].name != binding.function_name
        or first_tool_calls[0].arguments != {"scenario_id": BOOLEAN_SQLI_SCENARIO}
        or not first_tool_calls[0].arguments_valid
        or second_messages[2].tool_calls[0].id != tool_request.call_id
        or second_messages[2].tool_calls[0].function.name != binding.function_name
        or second_messages[2].tool_calls[0].function.arguments
        != first_tool_calls[0].arguments_json
        or tool_request.call_id != tool_receipt.call_id
        or tool_request.call_id != tool_result.call_id
        or tool_request.request.request_id != tool_result.result.request_id
        or tool_result.result.tool_id != binding.tool_id
        or tool_request.request.tool_id != binding.tool_id
        or tool_request.request.target != binding.target
        or tool_request.request.method != binding.method
        or tool_request.request.arguments != {"scenario_id": BOOLEAN_SQLI_SCENARIO}
        or not tool_receipt.executed
        or tool_receipt.worker_result is None
        or tool_receipt.worker_result.backend != "docker"
        or tool_receipt.worker_result.status is not WorkerStatus.SUCCEEDED
        or tool_receipt.worker_result.exit_code != 0
        or not tool_receipt.network_log_trusted
        or not tool_receipt.result_identity_valid
        or not tool_result.result.success
    ):
        raise ValueError("local single-agent Tool execution differs")
    probe = BooleanSQLiProbeOutput.model_validate(tool_result.result.data)
    if not probe.vulnerable:
        raise ValueError("local single-agent Tool result did not prove the known finding")
    if (
        final.tool_calls
        or not final.content
        or final.refusal is not None
        or final.finish_reason != "stop"
    ):
        raise ValueError("local single-agent final response differs")
    final_value = _load_strict_json(
        final.content,
        label="local single-agent final response",
    )
    if final_value != {
        "findingId": SINGLE_AGENT_FINDING_ID,
        "vulnerable": True,
        "evidence": "fixed-boolean-sqli-probe",
    }:
        raise ValueError("local single-agent final finding differs")
    if (
        cleanup.status != "completed"
        or cleanup.worker_execution_count != 3
        or cleanup.active_secret_lease_count != 0
    ):
        raise ValueError("local single-agent cleanup differs")
    prompt_tokens = sum(item.usage.prompt_tokens or 0 for item in usages)
    completion_tokens = sum(item.usage.completion_tokens or 0 for item in usages)
    total_tokens = sum(item.usage.total_tokens or 0 for item in usages)
    if (
        prompt_tokens < 1
        or completion_tokens < 1
        or total_tokens != prompt_tokens + completion_tokens
    ):
        raise ValueError("local single-agent Provider usage differs")
    return LocalLlamaCppSingleAgentTrace(
        registrationDigest=authoritative.registration_digest,
        rawTraceSha256=sha256(raw).hexdigest(),
        rawTraceSizeBytes=len(raw),
        promptTokens=prompt_tokens,
        completionTokens=completion_tokens,
        totalTokens=total_tokens,
        finalResponseSha256=sha256(final.content.encode("utf-8")).hexdigest(),
    )


def _local_provider_registration() -> ProviderRegistration:
    return ProviderRegistration.model_validate(
        {
            "provider_id": LOCAL_PROVIDER_ID,
            "endpoint": LOCAL_PROVIDER_ENDPOINT,
            "model": QWEN_MODEL_ALIAS,
            "secret_ref": LOCAL_PROVIDER_SECRET_REF,
            "allow_streaming": False,
            "allowed_function_tools": {SINGLE_AGENT_FUNCTION_NAME},
            "lease_ttl_seconds": 30,
            "allow_private_networks": True,
            "input_cost_per_million_usd": 0,
            "output_cost_per_million_usd": 0,
        }
    )


def _provider_registration_digest(provider: ProviderRegistration) -> str:
    return benchmark_digest(
        "pajin.benchmark.local-provider-registration/v1",
        provider.model_dump(mode="json", by_alias=True),
        max_bytes=128 * 1024,
    )


def _agent_implementation_digest() -> str:
    return benchmark_digest(
        "pajin.benchmark.policy-tool-loop-implementation/v1",
        {
            "implementation": "pajin.workflow.policy-tool-loop",
            "version": "model-tool-trace-v1",
            "developerPrompt": TOOL_LOOP_DEVELOPER_PROMPT,
            "maxCompletionTokens": TOOL_LOOP_MAX_COMPLETION_TOKENS,
            "fallback": "disabled",
            "trace": "pajin-model-tool-trace-jsonl/v1",
        },
        max_bytes=128 * 1024,
    )


def _prompt_bundle_digest() -> str:
    return benchmark_digest(
        "pajin.benchmark.local-single-agent-prompt-bundle/v1",
        {
            "developer": TOOL_LOOP_DEVELOPER_PROMPT,
            "objective": SINGLE_AGENT_OBJECTIVE,
            "declaredTarget": SINGLE_AGENT_TARGET,
        },
        max_bytes=128 * 1024,
    )


def _tool_catalog_digest() -> str:
    binding = local_llama_cpp_tool_binding()
    return benchmark_digest(
        "pajin.benchmark.local-single-agent-tool-catalog/v1",
        {
            "binding": binding.model_dump(mode="json", by_alias=True),
            "functionTool": binding.function_tool().model_dump(mode="json", by_alias=True),
            "arguments": {"scenario_id": BOOLEAN_SQLI_SCENARIO},
        },
        max_bytes=256 * 1024,
    )


def _runtime_configuration_digest(runtime_image_id: str) -> str:
    return benchmark_digest(
        "pajin.benchmark.local-single-agent-runtime-configuration/v1",
        {
            "runtimeImage": LLAMA_CPP_IMAGE,
            "runtimeImageId": runtime_image_id,
            "modelArtifactSha256": QWEN_GGUF_SHA256,
            "contextTokens": 8_192,
            "gpuLayers": 99,
            "parallelSlots": 1,
            "temperature": 0,
            "topP": 1,
            "seed": "benchmark-coordinate-seed",
            "maxTurns": 2,
            "maxCompletionTokens": TOOL_LOOP_MAX_COMPLETION_TOKENS,
            "retryCount": 0,
            "fallback": "disabled",
        },
        max_bytes=256 * 1024,
    )


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("single-agent final response contains a duplicate JSON key")
        value[key] = item
    return value


def _load_strict_json(text: str, *, label: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_strict_json_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
