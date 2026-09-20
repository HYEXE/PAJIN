from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from pydantic import AnyHttpUrl, ValidationError

from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderMessage, ProviderRegistration
from pajin.runtime.worker import WorkerJob, WorkerLimits, WorkerSecretRequest
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_transport import (
    WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
    WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
    WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION,
    WEB_ANALYSIS_TRANSPORT_RUNTIME_PIN_API_VERSION,
    WebAnalysisTransportError,
    WebAnalysisTransportRuntimePin,
    bind_web_analysis_transport_job,
    expected_web_analysis_legacy_job_metadata,
    expected_web_analysis_provider_worker_context,
    expected_web_analysis_transport_job_metadata,
    load_verified_web_analysis_transport_runtime_pin,
    verify_web_analysis_legacy_job_metadata,
    verify_web_analysis_provider_worker_context,
    verify_web_analysis_transport_job_metadata,
    web_analysis_transport_runtime_pin,
)


def _runtime_pin(
    *,
    worker_digit: str = "1",
    proxy_digit: str = "2",
) -> RuntimePin:
    return RuntimePin(
        platform="linux/arm64",
        platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
        worker_image="sha256:" + worker_digit * 64,
        proxy_image="sha256:" + proxy_digit * 64,
    )


def _transport_pin(runtime: RuntimePin) -> WebAnalysisTransportRuntimePin:
    return web_analysis_transport_runtime_pin(
        runtime,
        worker_image="sha256:" + "3" * 64,
        proxy_image="sha256:" + "4" * 64,
    )


def _provider_payload() -> dict[str, object]:
    return {
        "providerId": "local-web-analysis",
        "request": {
            "messages": [
                {"role": "developer", "content": "code-owned instruction projection"},
                {"role": "user", "content": "evidence-only projection"},
            ],
            "model": "qwen3-4b",
            "stream": False,
        },
        "target": "http://model.internal:8080/v1/chat/completions",
    }


def _provider_job(
    runtime: RuntimePin,
    *,
    payload: object | None = None,
) -> WorkerJob:
    return WorkerJob(
        execution_id="exec_web_analysis_transport_test",
        image=runtime.worker_image,
        command=["openai-chat-completion"],
        stdin=json.dumps(
            _provider_payload() if payload is None else payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        limits=WorkerLimits(timeout_seconds=runtime.request_timeout_seconds),
        secret_requests=[
            WorkerSecretRequest(
                secret_ref="provider/local-web-analysis/api-key",
                binding="provider-api-key",
                ttl_seconds=180,
            )
        ],
    )


def _successor_metadata_inputs(
    runtime: RuntimePin,
) -> tuple[ProviderRegistration, ToolRequest]:
    registration = ProviderRegistration(
        provider_id="local-web-analysis",
        endpoint=AnyHttpUrl("http://127.0.0.1:11434/v1/chat/completions"),
        model="qwen3-4b",
        secret_ref="provider/local-web-analysis/api-key",
        lease_ttl_seconds=180,
        allow_private_networks=True,
        allow_streaming=False,
        allowed_function_tools=set(),
    )
    chat = ProviderChatRequest(
        messages=[ProviderMessage(role=ChatRole.USER, content="bounded evidence")],
        tools=[],
        tool_choice="none",
        max_completion_tokens=16,
    )
    request = ToolRequest(
        request_id="web_analysis_" + "a" * 64,
        agent_id="agent:web-analysis-test",
        tool_id="provider.local-web-analysis.chat",
        target=str(registration.endpoint),
        method="POST",
        arguments=chat.model_dump(mode="json", by_alias=True),
    )
    assert runtime.request_timeout_seconds == 180
    return registration, request


def test_transport_pin_binds_exact_successor_contract_and_digest() -> None:
    runtime = _runtime_pin()
    runtime_before = runtime.model_dump(mode="json")

    pin = _transport_pin(runtime)
    same_pin = _transport_pin(runtime)
    material = pin.model_dump(mode="json", by_alias=True)
    material_without_digest = dict(material)
    material_without_digest.pop("pinDigest")
    expected_digest = sha256(
        b"PAJIN-WEB-ANALYSIS-TRANSPORT\0"
        + canonical_json_bytes(
            material_without_digest,
            label="test Web analysis transport runtime Pin",
            max_bytes=64 * 1024,
        )
    ).hexdigest()

    assert material == {
        "apiVersion": WEB_ANALYSIS_TRANSPORT_RUNTIME_PIN_API_VERSION,
        "kind": "WebAnalysisTransportRuntimePin",
        "pinDigest": expected_digest,
        "transportVersion": WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION,
        "workerAction": WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
        "baseRuntimeDigest": pin.base_runtime_digest,
        "workerImage": "sha256:" + "3" * 64,
        "proxyImage": "sha256:" + "4" * 64,
        "workerOpenTimeoutSeconds": WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
        "proxyExchangeTimeoutSeconds": WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
        "jobTimeoutSeconds": WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
        "singleDispatchOnly": True,
        "externalEgressAuthorized": False,
    }
    assert pin.pin_digest == same_pin.pin_digest == expected_digest
    assert runtime.model_dump(mode="json") == runtime_before
    assert pin.worker_image != runtime.worker_image
    assert pin.proxy_image != runtime.proxy_image


def test_transport_pin_artifact_loader_requires_exact_wire_and_independent_digest(
    tmp_path: Path,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    path = tmp_path / "transport-pin.json"
    path.write_text(
        json.dumps(pin.model_dump(mode="json", by_alias=True)),
        encoding="utf-8",
    )

    assert (
        load_verified_web_analysis_transport_runtime_pin(
            path,
            runtime=runtime,
            expected_pin_digest=pin.pin_digest,
        )
        == pin
    )

    with pytest.raises(WebAnalysisTransportError, match="verification failed closed"):
        load_verified_web_analysis_transport_runtime_pin(
            path,
            runtime=runtime,
            expected_pin_digest="0" * 64,
        )

    omitted = pin.model_dump(mode="json", by_alias=True)
    omitted.pop("pinDigest")
    path.write_text(json.dumps(omitted), encoding="utf-8")
    with pytest.raises(WebAnalysisTransportError, match="loading failed closed"):
        load_verified_web_analysis_transport_runtime_pin(
            path,
            runtime=runtime,
            expected_pin_digest=pin.pin_digest,
        )


@pytest.mark.parametrize("case", ["missing", "malformed", "duplicate", "oversize", "symlink"])
def test_transport_pin_artifact_loader_rejects_unsafe_files(
    tmp_path: Path,
    case: str,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    path = tmp_path / "transport-pin.json"
    if case == "malformed":
        path.write_text("{", encoding="utf-8")
    elif case == "duplicate":
        path.write_text('{"pinDigest":"a","pinDigest":"b"}', encoding="utf-8")
    elif case == "oversize":
        path.write_text('"' + "x" * (64 * 1024) + '"', encoding="utf-8")
    elif case == "symlink":
        target = tmp_path / "target.json"
        target.write_text(
            json.dumps(pin.model_dump(mode="json", by_alias=True)),
            encoding="utf-8",
        )
        path.symlink_to(target)

    with pytest.raises(WebAnalysisTransportError, match="loading failed closed"):
        load_verified_web_analysis_transport_runtime_pin(
            path,
            runtime=runtime,
            expected_pin_digest=pin.pin_digest,
        )


def test_transport_pin_is_frozen_and_digest_detects_image_drift() -> None:
    pin = _transport_pin(_runtime_pin())

    with pytest.raises(ValidationError, match="frozen"):
        pin.worker_image = "sha256:" + "5" * 64

    raw = pin.model_dump(mode="json", by_alias=True)
    raw["proxyImage"] = "sha256:" + "6" * 64
    with pytest.raises(ValidationError, match="digest differs"):
        WebAnalysisTransportRuntimePin.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workerOpenTimeoutSeconds", 180.0),
        ("proxyExchangeTimeoutSeconds", 180.0),
        ("jobTimeoutSeconds", 180.0),
        ("singleDispatchOnly", 1),
        ("externalEgressAuthorized", 0),
    ],
)
def test_transport_pin_rejects_coercible_timeout_and_authority_literals(
    field: str,
    value: object,
) -> None:
    raw = _transport_pin(_runtime_pin()).model_dump(mode="json", by_alias=True)
    raw["pinDigest"] = ""
    raw[field] = value

    with pytest.raises(ValidationError):
        WebAnalysisTransportRuntimePin.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("apiVersion", "pajin.dev/web-analysis-transport-runtime-pin/v1"),
        ("transportVersion", "pajin.web-analysis.provider-transport/v1"),
        ("workerAction", "openai-chat-completion"),
        ("workerOpenTimeoutSeconds", 179),
        ("proxyExchangeTimeoutSeconds", 181),
        ("jobTimeoutSeconds", 30),
        ("singleDispatchOnly", False),
        ("externalEgressAuthorized", True),
        ("workerImage", "pajin-worker:latest"),
        ("proxyImage", "sha256:not-a-digest"),
    ],
)
def test_transport_pin_rejects_version_authority_budget_and_image_drift(
    field: str,
    value: object,
) -> None:
    raw = _transport_pin(_runtime_pin()).model_dump(mode="json", by_alias=True)
    raw["pinDigest"] = ""
    raw[field] = value

    with pytest.raises(ValidationError):
        WebAnalysisTransportRuntimePin.model_validate(raw)


def test_transport_pin_rejects_unknown_fields_and_reuse_of_sealed_base_images() -> None:
    runtime = _runtime_pin()
    raw = _transport_pin(runtime).model_dump(mode="json", by_alias=True)
    raw["pinDigest"] = ""
    raw["futureAuthority"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        WebAnalysisTransportRuntimePin.model_validate(raw)

    successor_worker = "sha256:" + "3" * 64
    successor_proxy = "sha256:" + "4" * 64
    collisions = (
        (runtime.worker_image, successor_proxy),
        (runtime.proxy_image, successor_proxy),
        (successor_worker, runtime.worker_image),
        (successor_worker, runtime.proxy_image),
        (successor_worker, successor_worker),
    )
    for worker_image, proxy_image in collisions:
        with pytest.raises(WebAnalysisTransportError):
            web_analysis_transport_runtime_pin(
                runtime,
                worker_image=worker_image,
                proxy_image=proxy_image,
            )


def test_transport_pin_rejects_noncanonical_base_runtime_timeout() -> None:
    runtime = _runtime_pin().model_copy(update={"request_timeout_seconds": 30})

    with pytest.raises(WebAnalysisTransportError, match="construction failed closed"):
        web_analysis_transport_runtime_pin(
            runtime,
            worker_image="sha256:" + "3" * 64,
            proxy_image="sha256:" + "4" * 64,
        )


def test_bind_versions_v1_job_without_mutating_v1_runtime_or_job() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    job = _provider_job(runtime)
    runtime_before = runtime.model_dump(mode="python")
    job_before = job.model_dump(mode="python")

    rebound = bind_web_analysis_transport_job(
        job,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
    )
    payload = json.loads(rebound.stdin)
    expected_payload = {
        **_provider_payload(),
        "requestTimeoutSeconds": 180,
        "transportVersion": WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION,
    }

    assert rebound is not job
    assert rebound.execution_id == job.execution_id
    assert rebound.command == [WEB_ANALYSIS_PINNED_PROVIDER_ACTION]
    assert rebound.image == pin.worker_image
    assert payload == expected_payload
    assert type(payload["requestTimeoutSeconds"]) is int
    assert rebound.stdin == json.dumps(
        expected_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )

    rebound_other = rebound.model_dump(mode="python")
    original_other = dict(job_before)
    for field in ("command", "image", "stdin"):
        rebound_other.pop(field)
        original_other.pop(field)
    assert rebound_other == original_other

    assert runtime.model_dump(mode="python") == runtime_before
    assert job.model_dump(mode="python") == job_before
    assert job.command == ["openai-chat-completion"]
    assert job.image == runtime.worker_image
    assert set(json.loads(job.stdin)) == {"providerId", "request", "target"}


@pytest.mark.parametrize("drift", ["command", "image", "timeout"])
def test_bind_rejects_nonexact_v1_provider_job(drift: str) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    job = _provider_job(runtime)
    if drift == "command":
        job = job.model_copy(update={"command": ["openai-chat-completion-v2"]})
    elif drift == "image":
        job = job.model_copy(update={"image": "sha256:" + "9" * 64})
    else:
        job = job.model_copy(
            update={"limits": job.limits.model_copy(update={"timeout_seconds": 179})}
        )

    with pytest.raises(WebAnalysisTransportError, match="binding failed closed"):
        bind_web_analysis_transport_job(
            job,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {
            **_provider_payload(),
            "futureAuthority": True,
        },
        {
            "providerId": "local-web-analysis",
            "request": {},
        },
        ["providerId", "request", "target"],
    ],
)
def test_bind_rejects_nonexact_v1_provider_payload(payload: object) -> None:
    runtime = _runtime_pin()
    job = _provider_job(runtime, payload=payload)
    pin = _transport_pin(runtime)

    with pytest.raises(WebAnalysisTransportError, match="binding failed closed"):
        bind_web_analysis_transport_job(
            job,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
        )


def test_bind_rejects_malformed_or_duplicate_key_payload() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    valid_job = _provider_job(runtime)
    malformed = valid_job.model_copy(update={"stdin": "{"})
    duplicate = valid_job.model_copy(
        update={
            "stdin": (
                '{"providerId":"first","providerId":"second",'
                '"request":{},"target":"http://model.internal"}'
            )
        }
    )

    for job in (malformed, duplicate):
        with pytest.raises(WebAnalysisTransportError, match="binding failed closed"):
            bind_web_analysis_transport_job(
                job,
                runtime=runtime,
                transport_pin=pin,
                expected_transport_pin_digest=pin.pin_digest,
            )


def test_bind_rejects_transport_pin_from_another_base_runtime() -> None:
    runtime = _runtime_pin()
    other_runtime = _runtime_pin(proxy_digit="8")
    pin = _transport_pin(runtime)
    job = _provider_job(other_runtime)

    with pytest.raises(WebAnalysisTransportError):
        bind_web_analysis_transport_job(
            job,
            runtime=other_runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
        )


def test_successor_worker_metadata_binds_exact_job_egress_and_secret_contract() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    execution_id = "exec_" + "b" * 32
    lease_id = "lease_" + "c" * 32

    metadata = expected_web_analysis_transport_job_metadata(
        request,
        registration=registration,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        execution_id=execution_id,
        lease_ids=[lease_id],
    )

    assert metadata["image"] == pin.worker_image
    assert metadata["command"] == [WEB_ANALYSIS_PINNED_PROVIDER_ACTION]
    assert metadata["network"] == "egress-proxy"
    assert metadata["limits"]["timeout_seconds"] == 180
    assert metadata["egressPolicy"] == {
        "allow": [str(registration.endpoint)],
        "deny": [],
        "allowed_methods": ["POST"],
        "allow_private_networks": True,
        "max_response_bytes": 8 * 1024 * 1024,
        "max_requests": 1,
    }
    assert metadata["secretLeaseIds"] == [lease_id]
    assert (
        verify_web_analysis_transport_job_metadata(
            metadata,
            request,
            registration=registration,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            execution_id=execution_id,
            lease_ids=[lease_id],
        )
        == metadata
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command", [WEB_ANALYSIS_PINNED_PROVIDER_ACTION]),
        ("command", ["openai-chat-completion-v2"]),
        ("image", "sha256:" + "3" * 64),
    ],
)
def test_legacy_worker_metadata_rejects_successor_transport_smuggling(
    field: str,
    value: object,
) -> None:
    runtime = _runtime_pin()
    registration, request = _successor_metadata_inputs(runtime)
    execution_id = "exec_" + "b" * 32
    metadata = expected_web_analysis_legacy_job_metadata(
        request,
        registration=registration,
        runtime=runtime,
        execution_id=execution_id,
        lease_ids=[],
    )
    assert (
        verify_web_analysis_legacy_job_metadata(
            metadata,
            request,
            registration=registration,
            runtime=runtime,
            execution_id=execution_id,
            lease_ids=[],
        )
        == metadata
    )
    drifted = json.loads(json.dumps(metadata))
    drifted[field] = value

    with pytest.raises(WebAnalysisTransportError, match="verification failed closed"):
        verify_web_analysis_legacy_job_metadata(
            drifted,
            request,
            registration=registration,
            runtime=runtime,
            execution_id=execution_id,
            lease_ids=[],
        )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("image",), "sha256:" + "9" * 64),
        (("command",), ["openai-chat-completion"]),
        (("network",), "none"),
        (("limits", "timeout_seconds"), 30.0),
        (("egressPolicy", "allow"), ["http://foreign.invalid/**"]),
        (("egressPolicy", "allowed_methods"), ["GET"]),
        (("egressPolicy", "allow_private_networks"), False),
        (("egressPolicy", "max_requests"), 2),
        (("stdinBytes",), 1),
        (("stdinSha256",), "0" * 64),
    ],
)
def test_successor_worker_metadata_rejects_transport_drift(
    path: tuple[str, ...],
    value: object,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    execution_id = "exec_" + "b" * 32
    metadata = expected_web_analysis_transport_job_metadata(
        request,
        registration=registration,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        execution_id=execution_id,
        lease_ids=[],
    )
    drifted = json.loads(json.dumps(metadata))
    current = drifted
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value

    with pytest.raises(WebAnalysisTransportError, match="verification failed closed"):
        verify_web_analysis_transport_job_metadata(
            drifted,
            request,
            registration=registration,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            execution_id=execution_id,
            lease_ids=[],
        )


@pytest.mark.parametrize(
    ("path", "alias"),
    [
        (("egressPolicy", "max_requests"), True),
        (("stdinBytes",), "float"),
        (("secretRequests", 0, "ttlSeconds"), "float"),
    ],
)
def test_successor_worker_metadata_rejects_json_numeric_type_aliases(
    path: tuple[str | int, ...],
    alias: object,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    execution_id = "exec_" + "b" * 32
    metadata = expected_web_analysis_transport_job_metadata(
        request,
        registration=registration,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        execution_id=execution_id,
        lease_ids=[],
    )
    drifted = json.loads(json.dumps(metadata))
    current: Any = drifted
    for segment in path[:-1]:
        current = current[segment]
    leaf = path[-1]
    original = current[leaf]
    current[leaf] = float(original) if alias == "float" else alias

    with pytest.raises(WebAnalysisTransportError, match="verification failed closed"):
        verify_web_analysis_transport_job_metadata(
            drifted,
            request,
            registration=registration,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            execution_id=execution_id,
            lease_ids=[],
        )


def test_successor_worker_metadata_rejects_remote_provider_registration() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    remote = registration.model_copy(
        update={"endpoint": AnyHttpUrl("https://provider.example/v1/chat/completions")}
    )
    remote_request = request.model_copy(update={"target": str(remote.endpoint)})

    with pytest.raises(WebAnalysisTransportError, match="reconstruction failed closed"):
        expected_web_analysis_transport_job_metadata(
            remote_request,
            registration=remote,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            execution_id="exec_" + "b" * 32,
            lease_ids=[],
        )


def test_successor_worker_context_rejects_proxy_and_route_drift() -> None:
    pin = _transport_pin(_runtime_pin())
    context = expected_web_analysis_provider_worker_context(
        pin,
        external_network="pajin-effect-test",
    )
    assert (
        verify_web_analysis_provider_worker_context(
            context,
            transport_pin=pin,
            expected_external_network="pajin-effect-test",
        )
        == context
    )

    for field, value in (
        ("egressProxyImage", "sha256:" + "9" * 64),
        ("externalNetworkRoutes", {WEB_ANALYSIS_PINNED_PROVIDER_ACTION: "foreign"}),
    ):
        drifted = json.loads(json.dumps(context))
        drifted["context"][field] = value
        with pytest.raises(WebAnalysisTransportError, match="verification failed closed"):
            verify_web_analysis_provider_worker_context(
                drifted,
                transport_pin=pin,
            )
