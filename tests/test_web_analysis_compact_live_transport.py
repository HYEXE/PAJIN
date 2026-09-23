from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import pajin.web_assessment.analysis_compact_live_transport as compact_transport_module
from pajin.benchmark.effectiveness.suite import MODEL_IMAGE, PLATFORM_MANIFESTS, model_pins
from pajin.domain.models import ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderMessage
from pajin.runtime.worker import NetworkMode, WorkerResult, WorkerStatus
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_capacity import (
    _digest as capacity_digest,
)
from pajin.web_assessment.analysis_capacity import (
    _json_wire as capacity_json_wire,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    WebAnalysisCapacityV2Pin,
    _model_materialization_policy_digest,
)
from pajin.web_assessment.analysis_compact_live_pins import (
    COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_VERSION,
    COMPACT_WEB_ANALYSIS_WORKER_WIRE_PROTOCOL_VERSION,
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
    build_compact_web_analysis_runtime_pin,
    build_compact_web_analysis_transport_pin,
)
from pajin.web_assessment.analysis_compact_live_transport import (
    CompactWebAnalysisTransportError,
    cleanup_compact_web_analysis_transport_resources,
    expected_compact_web_analysis_provider_worker_context,
    expected_compact_web_analysis_transport_job_metadata,
    interpret_compact_web_analysis_transport_result,
    prepare_compact_web_analysis_transport_job,
    verify_compact_web_analysis_provider_worker_context,
    verify_compact_web_analysis_transport_cleanup_proof,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    COMPACT_LIVE_PREPARATION_STATUS,
    COMPACT_LIVE_REQUEST_API_VERSION,
    CompactSkillBoundWebAnalysisLiveRequest,
    _local_provider_registration,
    _zero_dispatch_state,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    _digest as preparation_digest,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportCleanupProof,
    WebAnalysisTransportRuntimePin,
)

_EXECUTION_ID = "exec_" + "a" * 32
_EXTERNAL_NETWORK = "pajin-web-analysis-live-network-" + "a" * 32


def _worker_entry() -> ModuleType:
    path = Path(__file__).parents[1] / "containers" / "worker" / "worker_entry.py"
    spec = importlib.util.spec_from_file_location("pajin_compact_live_worker_entry", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def bound_inputs() -> tuple[
    WebAnalysisCapacityV2Pin,
    CompactSkillBoundWebAnalysisLiveRequest,
    WebAnalysisTransportRuntimePin,
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
]:
    lineage = WebAnalysisTransportRuntimePin(
        baseRuntimeDigest="1" * 64,
        workerImage="sha256:" + "2" * 64,
        proxyImage="sha256:" + "3" * 64,
    )
    model = model_pins()[0]
    model_material = {
        "name": model.name,
        "repository": model.repository,
        "revision": model.revision,
        "filename": model.filename,
        "sizeBytes": model.size_bytes,
        "sha256": model.sha256,
    }
    model_pin_digest = capacity_digest(
        "registered-model-pin",
        capacity_json_wire(
            model_material,
            label="test registered model Pin",
            max_bytes=64 * 1024,
        ),
    )
    registration = _local_provider_registration(model.name)
    chat = ProviderChatRequest(
        messages=[
            ProviderMessage(role=ChatRole.DEVELOPER, content="code-owned compact instruction"),
            ProviderMessage(role=ChatRole.USER, content="bounded evidence projection"),
        ],
        stream=False,
        tools=[],
        tool_choice="none",
        max_completion_tokens=1024,
        temperature=0.0,
        top_p=1.0,
        seed=0,
        parallel_tool_calls=False,
    )
    registration_digest = preparation_digest(
        "provider-registration/v1",
        registration.model_dump(mode="json", by_alias=True),
    )
    chat_digest = preparation_digest(
        "provider-chat-request/v1",
        chat.model_dump(mode="json", by_alias=True),
    )
    projection_digest = "4" * 64
    skill_run_id = "run_20260923T010203Z_1234abcd"
    skill_root_digest = "5" * 64
    skill_snapshot_digest = "6" * 64
    image_id = "sha256:" + MODEL_IMAGE.rsplit("@sha256:", 1)[-1]
    capacity_pin = WebAnalysisCapacityV2Pin(
        compactProjectionDigest=projection_digest,
        chatRequestDigest=chat_digest,
        modelId=model.name,
        modelRepository=model.repository,
        modelRevision=model.revision,
        modelFilename=model.filename,
        modelSizeBytes=model.size_bytes,
        modelSha256=model.sha256,
        modelPinDigest=model_pin_digest,
        modelImage=MODEL_IMAGE,
        modelPlatform="linux/arm64",
        modelPlatformManifest=PLATFORM_MANIFESTS["linux/arm64"],
        tokenizerRuntimeDigest="",
        tokenizerImage=MODEL_IMAGE,
        tokenizerImageId=image_id,
        transportPinDigest=lineage.pin_digest,
        skillRunId=skill_run_id,
        skillRunRootDigest=skill_root_digest,
        skillProjectionDigest=skill_snapshot_digest,
        sourceRunId="run_20260923T000000Z_abcdef12",
        sourceRootDigest="7" * 64,
        sourceArtifactDigest="8" * 64,
        conservativeCampaignPromptTokens=128,
        modelMaterializationPolicyDigest=_model_materialization_policy_digest(),
    )
    live_request = CompactSkillBoundWebAnalysisLiveRequest.model_validate(
        {
            "apiVersion": COMPACT_LIVE_REQUEST_API_VERSION,
            "kind": "CompactSkillBoundWebAnalysisLiveRequest",
            "requestDigest": "",
            "status": COMPACT_LIVE_PREPARATION_STATUS,
            "skillRunId": skill_run_id,
            "skillRunRootDigest": skill_root_digest,
            "skillSnapshotDigest": skill_snapshot_digest,
            "compactProjectionDigest": projection_digest,
            "capacityCompactProjectionDigest": projection_digest,
            "providerRegistration": registration,
            "providerRegistrationDigest": registration_digest,
            "chatRequest": chat,
            "chatRequestDigest": chat_digest,
            "capacityChatRequestDigest": chat_digest,
            "executionState": _zero_dispatch_state(),
        }
    )
    runtime = build_compact_web_analysis_runtime_pin(capacity_pin, live_request, lineage)
    transport = build_compact_web_analysis_transport_pin(runtime, lineage)
    return capacity_pin, live_request, lineage, runtime, transport


def _tool_request(live_request: CompactSkillBoundWebAnalysisLiveRequest) -> ToolRequest:
    registration = live_request.provider_registration
    return ToolRequest(
        request_id="tool_" + "a" * 32,
        agent_id="web-analysis-compact-live",
        tool_id=f"provider.{registration.provider_id}.chat",
        target=str(registration.endpoint),
        method="POST",
        arguments=live_request.chat_request.model_dump(mode="python", by_alias=True),
    )


def _kwargs(
    bound_inputs: tuple[
        WebAnalysisCapacityV2Pin,
        CompactSkillBoundWebAnalysisLiveRequest,
        WebAnalysisTransportRuntimePin,
        CompactWebAnalysisRuntimePin,
        CompactWebAnalysisTransportPin,
    ],
) -> dict[str, Any]:
    capacity_pin, live_request, lineage, runtime_pin, transport_pin = bound_inputs
    return {
        "request": _tool_request(live_request),
        "capacity_pin": capacity_pin,
        "registration": live_request.provider_registration,
        "live_request": live_request,
        "lineage_transport_pin": lineage,
        "runtime_pin": runtime_pin,
        "transport_pin": transport_pin,
        "expected_capacity_pin_digest": capacity_pin.pin_digest,
        "expected_lineage_transport_pin_digest": lineage.pin_digest,
        "expected_runtime_pin_digest": runtime_pin.pin_digest,
        "expected_transport_pin_digest": transport_pin.pin_digest,
        "execution_id": _EXECUTION_ID,
    }


def _provider_result(
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
) -> WorkerResult:
    now = datetime.now(UTC)
    registration = live_request.provider_registration
    return WorkerResult(
        execution_id=_EXECUTION_ID,
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(
            {
                "provider_id": registration.provider_id,
                "response_id": "response-1",
                "model": registration.model,
                "content": '{"proposal":"bounded"}',
                "refusal": None,
                "finish_reason": "stop",
                "tool_calls": [],
                "usage": None,
                "streamed": False,
                "chunks": 1,
                "target": str(registration.endpoint),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        started_at=now,
        finished_at=now,
    )


def test_compact_transport_prepares_exact_single_request_without_legacy_runtime(
    bound_inputs: tuple[
        WebAnalysisCapacityV2Pin,
        CompactSkillBoundWebAnalysisLiveRequest,
        WebAnalysisTransportRuntimePin,
        CompactWebAnalysisRuntimePin,
        CompactWebAnalysisTransportPin,
    ],
) -> None:
    kwargs = _kwargs(bound_inputs)
    job = prepare_compact_web_analysis_transport_job(**kwargs)
    transport_pin = kwargs["transport_pin"]
    assert isinstance(transport_pin, CompactWebAnalysisTransportPin)

    assert job.execution_id == _EXECUTION_ID
    assert job.image == transport_pin.worker_image
    assert job.command == [transport_pin.worker_action]
    assert job.network is NetworkMode.EGRESS_PROXY
    assert job.limits.timeout_seconds == 180
    assert job.egress_policy is not None
    assert job.egress_policy.max_requests == 1
    assert job.egress_policy.allowed_methods == {"POST"}
    assert job.egress_policy.allow == [kwargs["request"].target]
    assert len(job.secret_requests) == 1

    payload = json.loads(job.stdin)
    assert transport_pin.transport_version == COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_VERSION
    assert (
        payload["transportVersion"]
        == transport_pin.worker_wire_protocol_version
        == COMPACT_WEB_ANALYSIS_WORKER_WIRE_PROTOCOL_VERSION
    )
    assert payload["requestTimeoutSeconds"] == 180
    assert payload["request"]["max_completion_tokens"] == 1024


def test_compact_transport_stdin_conforms_to_actual_pinned_worker_protocol(
    bound_inputs: tuple[
        WebAnalysisCapacityV2Pin,
        CompactSkillBoundWebAnalysisLiveRequest,
        WebAnalysisTransportRuntimePin,
        CompactWebAnalysisRuntimePin,
        CompactWebAnalysisTransportPin,
    ],
) -> None:
    kwargs = _kwargs(bound_inputs)
    job = prepare_compact_web_analysis_transport_job(**kwargs)
    lineage = kwargs["lineage_transport_pin"]
    transport_pin = kwargs["transport_pin"]
    assert isinstance(lineage, WebAnalysisTransportRuntimePin)
    assert isinstance(transport_pin, CompactWebAnalysisTransportPin)
    assert transport_pin.transport_version != lineage.transport_version
    assert transport_pin.worker_wire_protocol_version == lineage.transport_version

    worker = _worker_entry()
    payload = worker._read_worker_input(StringIO(job.stdin))

    assert job.command == [worker._PINNED_PROVIDER_ACTION]
    assert payload["transportVersion"] == worker._PINNED_PROVIDER_TRANSPORT_VERSION
    assert worker._pinned_provider_timeout(payload) == 180.0


def test_compact_transport_rejects_request_and_pin_recombination(
    bound_inputs: tuple[
        WebAnalysisCapacityV2Pin,
        CompactSkillBoundWebAnalysisLiveRequest,
        WebAnalysisTransportRuntimePin,
        CompactWebAnalysisRuntimePin,
        CompactWebAnalysisTransportPin,
    ],
) -> None:
    kwargs = _kwargs(bound_inputs)
    request = kwargs["request"]
    assert isinstance(request, ToolRequest)
    drifted_arguments = dict(request.arguments)
    drifted_arguments["max_completion_tokens"] = 128
    kwargs["request"] = ToolRequest.model_validate(
        {**request.model_dump(mode="python"), "arguments": drifted_arguments}
    )
    with pytest.raises(CompactWebAnalysisTransportError, match="preparation failed closed"):
        prepare_compact_web_analysis_transport_job(**kwargs)

    kwargs = _kwargs(bound_inputs)
    kwargs["expected_transport_pin_digest"] = "0" * 64
    with pytest.raises(CompactWebAnalysisTransportError, match="preparation failed closed"):
        prepare_compact_web_analysis_transport_job(**kwargs)

    kwargs = _kwargs(bound_inputs)
    kwargs["expected_capacity_pin_digest"] = "0" * 64
    with pytest.raises(CompactWebAnalysisTransportError, match="preparation failed closed"):
        prepare_compact_web_analysis_transport_job(**kwargs)

    kwargs = _kwargs(bound_inputs)
    kwargs["expected_lineage_transport_pin_digest"] = "0" * 64
    with pytest.raises(CompactWebAnalysisTransportError, match="preparation failed closed"):
        prepare_compact_web_analysis_transport_job(**kwargs)

    kwargs = _kwargs(bound_inputs)
    runtime_pin = kwargs["runtime_pin"]
    lineage = kwargs["lineage_transport_pin"]
    assert isinstance(runtime_pin, CompactWebAnalysisRuntimePin)
    assert isinstance(lineage, WebAnalysisTransportRuntimePin)
    runtime_raw = runtime_pin.model_dump(mode="json", by_alias=True)
    runtime_raw["pinDigest"] = ""
    runtime_raw["modelSha256"] = "0" * 64
    recombined_runtime = CompactWebAnalysisRuntimePin.model_validate(runtime_raw)
    recombined_transport = build_compact_web_analysis_transport_pin(
        recombined_runtime,
        lineage,
    )
    kwargs["runtime_pin"] = recombined_runtime
    kwargs["transport_pin"] = recombined_transport
    kwargs["expected_runtime_pin_digest"] = recombined_runtime.pin_digest
    kwargs["expected_transport_pin_digest"] = recombined_transport.pin_digest
    with pytest.raises(CompactWebAnalysisTransportError, match="preparation failed closed"):
        prepare_compact_web_analysis_transport_job(**kwargs)


def test_compact_transport_interprets_only_exact_single_completion(
    bound_inputs: tuple[
        WebAnalysisCapacityV2Pin,
        CompactSkillBoundWebAnalysisLiveRequest,
        WebAnalysisTransportRuntimePin,
        CompactWebAnalysisRuntimePin,
        CompactWebAnalysisTransportPin,
    ],
) -> None:
    kwargs = _kwargs(bound_inputs)
    live_request = kwargs["live_request"]
    assert isinstance(live_request, CompactSkillBoundWebAnalysisLiveRequest)
    result = interpret_compact_web_analysis_transport_result(
        kwargs.pop("request"),
        _provider_result(live_request),
        expected_execution_id=kwargs.pop("execution_id"),
        **kwargs,
    )
    assert result.content == '{"proposal":"bounded"}'
    assert result.streamed is False
    assert result.chunks == 1

    kwargs = _kwargs(bound_inputs)
    bad = _provider_result(live_request).model_copy(update={"stdout_truncated": True})
    with pytest.raises(CompactWebAnalysisTransportError, match="interpretation failed closed"):
        interpret_compact_web_analysis_transport_result(
            kwargs.pop("request"),
            bad,
            expected_execution_id=kwargs.pop("execution_id"),
            **kwargs,
        )


def test_compact_transport_reconstructs_metadata_and_verifies_worker_context(
    bound_inputs: tuple[
        WebAnalysisCapacityV2Pin,
        CompactSkillBoundWebAnalysisLiveRequest,
        WebAnalysisTransportRuntimePin,
        CompactWebAnalysisRuntimePin,
        CompactWebAnalysisTransportPin,
    ],
) -> None:
    kwargs = _kwargs(bound_inputs)
    metadata = expected_compact_web_analysis_transport_job_metadata(
        **kwargs,
        lease_ids=["lease_" + "b" * 32],
    )
    assert metadata["executionId"] == _EXECUTION_ID
    assert metadata["network"] == "egress-proxy"

    live_request = kwargs["live_request"]
    capacity_pin = kwargs["capacity_pin"]
    lineage = kwargs["lineage_transport_pin"]
    runtime_pin = kwargs["runtime_pin"]
    transport_pin = kwargs["transport_pin"]
    assert isinstance(live_request, CompactSkillBoundWebAnalysisLiveRequest)
    assert isinstance(capacity_pin, WebAnalysisCapacityV2Pin)
    assert isinstance(lineage, WebAnalysisTransportRuntimePin)
    assert isinstance(runtime_pin, CompactWebAnalysisRuntimePin)
    assert isinstance(transport_pin, CompactWebAnalysisTransportPin)
    context = expected_compact_web_analysis_provider_worker_context(
        runtime_pin,
        transport_pin,
        capacity_pin=capacity_pin,
        lineage_transport_pin=lineage,
        expected_capacity_pin_digest=capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=lineage.pin_digest,
        expected_runtime_pin_digest=runtime_pin.pin_digest,
        expected_transport_pin_digest=transport_pin.pin_digest,
        live_request=live_request,
        external_network=_EXTERNAL_NETWORK,
        claim_digest="c" * 64,
        execution_id=_EXECUTION_ID,
    )
    assert (
        verify_compact_web_analysis_provider_worker_context(
            context,
            capacity_pin=capacity_pin,
            live_request=live_request,
            lineage_transport_pin=lineage,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=capacity_pin.pin_digest,
            expected_lineage_transport_pin_digest=lineage.pin_digest,
            expected_runtime_pin_digest=runtime_pin.pin_digest,
            expected_transport_pin_digest=transport_pin.pin_digest,
            expected_external_network=_EXTERNAL_NETWORK,
            expected_claim_digest="c" * 64,
            expected_execution_id=_EXECUTION_ID,
        )
        == context
    )


def test_compact_transport_cleanup_wrappers_use_effective_pin_without_docker(
    monkeypatch: pytest.MonkeyPatch,
    bound_inputs: tuple[
        WebAnalysisCapacityV2Pin,
        CompactSkillBoundWebAnalysisLiveRequest,
        WebAnalysisTransportRuntimePin,
        CompactWebAnalysisRuntimePin,
        CompactWebAnalysisTransportPin,
    ],
) -> None:
    kwargs = _kwargs(bound_inputs)
    live_request = kwargs["live_request"]
    capacity_pin = kwargs["capacity_pin"]
    lineage = kwargs["lineage_transport_pin"]
    runtime_pin = kwargs["runtime_pin"]
    transport_pin = kwargs["transport_pin"]
    assert isinstance(live_request, CompactSkillBoundWebAnalysisLiveRequest)
    assert isinstance(capacity_pin, WebAnalysisCapacityV2Pin)
    assert isinstance(lineage, WebAnalysisTransportRuntimePin)
    assert isinstance(runtime_pin, CompactWebAnalysisRuntimePin)
    assert isinstance(transport_pin, CompactWebAnalysisTransportPin)
    proof = WebAnalysisTransportCleanupProof(
        executionId=_EXECUTION_ID,
        transportPinDigest=transport_pin.pin_digest,
        externalNetwork=_EXTERNAL_NETWORK,
        observedResources=(),
    )
    observed: dict[str, object] = {}

    def fake_cleanup(**call: object) -> WebAnalysisTransportCleanupProof:
        observed.update(call)
        return proof

    monkeypatch.setattr(
        compact_transport_module,
        "cleanup_web_analysis_bound_transport_resources",
        fake_cleanup,
    )
    cleaned = cleanup_compact_web_analysis_transport_resources(
        execution_id=_EXECUTION_ID,
        external_network=_EXTERNAL_NETWORK,
        capacity_pin=capacity_pin,
        live_request=live_request,
        lineage_transport_pin=lineage,
        runtime_pin=runtime_pin,
        transport_pin=transport_pin,
        expected_capacity_pin_digest=capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=lineage.pin_digest,
        expected_runtime_pin_digest=runtime_pin.pin_digest,
        expected_transport_pin_digest=transport_pin.pin_digest,
        docker_executable="never-called-docker",
    )
    assert cleaned == proof
    assert observed == {
        "execution_id": _EXECUTION_ID,
        "external_network": _EXTERNAL_NETWORK,
        "transport_pin_digest": transport_pin.pin_digest,
        "worker_image": transport_pin.worker_image,
        "proxy_image": transport_pin.proxy_image,
        "docker_executable": "never-called-docker",
    }
    assert (
        verify_compact_web_analysis_transport_cleanup_proof(
            proof,
            execution_id=_EXECUTION_ID,
            external_network=_EXTERNAL_NETWORK,
            capacity_pin=capacity_pin,
            live_request=live_request,
            lineage_transport_pin=lineage,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=capacity_pin.pin_digest,
            expected_lineage_transport_pin_digest=lineage.pin_digest,
            expected_runtime_pin_digest=runtime_pin.pin_digest,
            expected_transport_pin_digest=transport_pin.pin_digest,
        )
        == proof
    )
