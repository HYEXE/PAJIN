from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from pydantic import AnyHttpUrl, ValidationError

import pajin.web_assessment.analysis_transport as transport_module
from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderMessage, ProviderRegistration
from pajin.runtime.worker import (
    WorkerJob,
    WorkerLimits,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_transport import (
    WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
    WEB_ANALYSIS_PRE_CLEANUP_BARRIER_API_VERSION,
    WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
    WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION,
    WEB_ANALYSIS_TRANSPORT_CLEANUP_PROOF_API_VERSION,
    WEB_ANALYSIS_TRANSPORT_RUNTIME_PIN_API_VERSION,
    WebAnalysisTransportCleanupProof,
    WebAnalysisTransportError,
    WebAnalysisTransportRuntimePin,
    bind_web_analysis_transport_job,
    cleanup_web_analysis_transport_resources,
    expected_web_analysis_legacy_job_metadata,
    expected_web_analysis_provider_worker_context,
    expected_web_analysis_transport_job_metadata,
    interpret_web_analysis_transport_result,
    load_verified_web_analysis_transport_runtime_pin,
    prepare_web_analysis_transport_job,
    verify_web_analysis_legacy_job_metadata,
    verify_web_analysis_provider_worker_context,
    verify_web_analysis_transport_cleanup_proof,
    verify_web_analysis_transport_job_metadata,
    web_analysis_transport_pre_cleanup_barrier_context,
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


def _provider_worker_result(
    *,
    registration: ProviderRegistration,
    execution_id: str,
) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id=execution_id,
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


class _FakeTransportDocker:
    docker_executable = "fake-docker"
    execution_id = "exec_" + "b" * 32
    external_network = "pajin-web-analysis-live-network-" + "b" * 32
    worker_id = "1" * 64
    proxy_id = "2" * 64
    network_id = "3" * 64
    worker_name = f"pajin-{execution_id}-" + "a" * 32
    proxy_name = "pajin-proxy-" + "c" * 32
    network_name = "pajin-egress-" + "c" * 32

    def __init__(self, pin: WebAnalysisTransportRuntimePin) -> None:
        label = {"pajin.execution-id": self.execution_id}
        self.containers: dict[str, dict[str, Any]] = {
            self.worker_id: {
                "Id": self.worker_id,
                "Name": f"/{self.worker_name}",
                "Image": pin.worker_image,
                "Config": {"Image": pin.worker_image, "Labels": dict(label)},
                "NetworkSettings": {"Networks": {self.network_name: {}}},
            },
            self.proxy_id: {
                "Id": self.proxy_id,
                "Name": f"/{self.proxy_name}",
                "Image": pin.proxy_image,
                "Config": {"Image": pin.proxy_image, "Labels": dict(label)},
                "NetworkSettings": {
                    "Networks": {
                        self.network_name: {},
                        self.external_network: {},
                    }
                },
            },
        }
        self.networks: dict[str, dict[str, Any]] = {
            self.network_id: {
                "Id": self.network_id,
                "Name": self.network_name,
                "Driver": "bridge",
                "Internal": True,
                "Labels": dict(label),
                "Containers": {
                    self.worker_id: {},
                    self.proxy_id: {},
                },
            }
        }
        self.commands: list[tuple[str, ...]] = []

    def run(self, arguments: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(arguments)
        if arguments[0] != self.docker_executable:
            return self._completed(arguments, 127, stderr=b"unknown executable")
        noun = arguments[1]
        operation = arguments[2]
        if operation == "ls":
            resources = self.containers if noun == "container" else self.networks
            matching = [
                resource_id
                for resource_id, resource in resources.items()
                if self._labels(resource).get("pajin.execution-id") == self.execution_id
            ]
            return self._completed(arguments, stdout=("\n".join(matching) + "\n").encode())
        if operation == "inspect":
            resource_id = arguments[3]
            resources = self.containers if noun == "container" else self.networks
            resource = resources.get(resource_id)
            if resource is None:
                return self._completed(
                    arguments,
                    1,
                    stderr=f"Error: No such {noun}: {resource_id}".encode(),
                )
            return self._completed(arguments, stdout=json.dumps([resource]).encode())
        if noun == "container" and operation == "rm":
            resource_id = arguments[-1]
            if resource_id not in self.containers:
                return self._completed(arguments, 1, stderr=b"No such container")
            self.containers.pop(resource_id)
            for network in self.networks.values():
                network["Containers"].pop(resource_id, None)
            return self._completed(arguments, stdout=f"{resource_id}\n".encode())
        if noun == "network" and operation == "rm":
            resource_id = arguments[3]
            network = self.networks.get(resource_id)
            if network is None:
                return self._completed(arguments, 1, stderr=b"No such network")
            if network["Containers"]:
                return self._completed(arguments, 1, stderr=b"network has active endpoints")
            self.networks.pop(resource_id)
            return self._completed(arguments, stdout=f"{resource_id}\n".encode())
        return self._completed(arguments, 2, stderr=b"unsupported fake Docker command")

    @staticmethod
    def _labels(resource: dict[str, Any]) -> dict[str, object]:
        config = resource.get("Config")
        labels = resource.get("Labels") if config is None else config.get("Labels")
        assert isinstance(labels, dict)
        return labels

    @staticmethod
    def _completed(
        arguments: tuple[str, ...],
        returncode: int = 0,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(arguments, returncode, stdout, stderr)


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
    assert context == {
        "type": "pajin.runtime.worker.DockerWorkerBackend",
        "context": {
            "implementationVersion": "pajin.docker-worker/v2",
            "allowedImages": [pin.worker_image],
            "dockerExecutable": "docker",
            "egressProxyImage": pin.proxy_image,
            "externalNetwork": "pajin-effect-test",
            "externalNetworkRoutes": {WEB_ANALYSIS_PINNED_PROVIDER_ACTION: "pajin-effect-test"},
        },
    }
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


def test_successor_worker_context_exactly_binds_gate_d_cleanup_barrier() -> None:
    pin = _transport_pin(_runtime_pin())
    claim_digest = "a" * 64
    execution_id = "exec_" + "b" * 32
    external_network = "pajin-web-analysis-live-network-" + "b" * 32
    barrier = web_analysis_transport_pre_cleanup_barrier_context(
        claim_digest=claim_digest,
        execution_id=execution_id,
    )

    assert barrier == {
        "apiVersion": WEB_ANALYSIS_PRE_CLEANUP_BARRIER_API_VERSION,
        "kind": "WebAnalysisLiveClaimPreCleanupBarrier",
        "claimDigest": claim_digest,
        "executionId": execution_id,
        "pendingCleanupRequired": True,
    }
    context = expected_web_analysis_provider_worker_context(
        pin,
        external_network=external_network,
        claim_digest=claim_digest,
        execution_id=execution_id,
    )
    assert context["context"]["implementationVersion"] == "pajin.docker-worker/v6"
    assert context["context"]["preCleanupBarrier"] == barrier
    assert context["context"]["preCleanupBarrierExecution"] == {
        "mode": "posix-main-thread-real-timer",
        "timeoutSeconds": 30.0,
    }
    assert (
        verify_web_analysis_provider_worker_context(
            context,
            transport_pin=pin,
            expected_external_network=external_network,
            expected_claim_digest=claim_digest,
            expected_execution_id=execution_id,
        )
        == context
    )

    with pytest.raises(WebAnalysisTransportError, match="verification failed closed"):
        verify_web_analysis_provider_worker_context(
            context,
            transport_pin=pin,
            expected_external_network=external_network,
        )


@pytest.mark.parametrize(
    "drift",
    [
        "claim",
        "execution",
        "raw-result",
        "barrier-mode",
        "barrier-timeout",
        "incomplete-anchor",
        "cross-claim-network",
    ],
)
def test_successor_worker_context_rejects_cleanup_barrier_drift(drift: str) -> None:
    pin = _transport_pin(_runtime_pin())
    claim_digest = "a" * 64
    execution_id = "exec_" + "b" * 32
    external_network = "pajin-web-analysis-live-network-" + "b" * 32
    context = expected_web_analysis_provider_worker_context(
        pin,
        external_network=external_network,
        claim_digest=claim_digest,
        execution_id=execution_id,
    )
    drifted = json.loads(json.dumps(context))
    expected_claim_digest: str | None = claim_digest
    expected_execution_id: str | None = execution_id
    if drift == "claim":
        drifted["context"]["preCleanupBarrier"]["claimDigest"] = "c" * 64
    elif drift == "execution":
        drifted["context"]["preCleanupBarrier"]["executionId"] = "exec_" + "c" * 32
    elif drift == "raw-result":
        drifted["context"]["preCleanupBarrier"]["workerResult"] = {"content": "secret"}
    elif drift == "barrier-mode":
        drifted["context"]["preCleanupBarrierExecution"]["mode"] = "asyncio-task"
    elif drift == "barrier-timeout":
        drifted["context"]["preCleanupBarrierExecution"]["timeoutSeconds"] = 29.0
    elif drift == "incomplete-anchor":
        expected_execution_id = None
    else:
        external_network = "pajin-web-analysis-live-network-" + "c" * 32

    with pytest.raises(WebAnalysisTransportError, match="failed closed"):
        verify_web_analysis_provider_worker_context(
            drifted,
            transport_pin=pin,
            expected_external_network=external_network,
            expected_claim_digest=expected_claim_digest,
            expected_execution_id=expected_execution_id,
        )


def test_prepare_successor_job_preserves_claim_execution_identity() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    execution_id = "exec_" + "b" * 32

    job = prepare_web_analysis_transport_job(
        request,
        registration=registration,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        execution_id=execution_id,
    )
    payload = json.loads(job.stdin)

    assert job.execution_id == execution_id
    assert job.command == [WEB_ANALYSIS_PINNED_PROVIDER_ACTION]
    assert job.image == pin.worker_image
    assert job.network.value == "egress-proxy"
    assert job.egress_policy is not None
    assert job.egress_policy.allow == [str(registration.endpoint)]
    assert job.egress_policy.allowed_methods == {"POST"}
    assert job.egress_policy.max_requests == 1
    assert payload["providerId"] == registration.provider_id
    assert payload["target"] == str(registration.endpoint)
    assert payload["transportVersion"] == WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION
    assert payload["requestTimeoutSeconds"] == WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS


def test_prepare_successor_job_preserves_capacity_network_alias_endpoint() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    endpoint = AnyHttpUrl("http://host.docker.internal:11434/v1/chat/completions")
    aliased_registration = ProviderRegistration.model_validate(
        {**registration.model_dump(mode="python"), "endpoint": endpoint}
    )
    aliased_request = ToolRequest.model_validate(
        {**request.model_dump(mode="python"), "target": str(endpoint)}
    )

    job = prepare_web_analysis_transport_job(
        aliased_request,
        registration=aliased_registration,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        execution_id="exec_" + "b" * 32,
    )

    assert json.loads(job.stdin)["target"] == str(endpoint)
    assert job.egress_policy is not None
    assert job.egress_policy.allow == [str(endpoint)]


@pytest.mark.parametrize(
    "execution_id",
    [
        "exec_web_analysis_transport_test",
        "exec_" + "B" * 32,
        "exec_" + "b" * 31,
    ],
)
def test_prepare_successor_job_rejects_nonclaim_execution_identity(
    execution_id: str,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)

    with pytest.raises(WebAnalysisTransportError, match="preparation failed closed"):
        prepare_web_analysis_transport_job(
            request,
            registration=registration,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            execution_id=execution_id,
        )


def test_interpret_successor_result_returns_exact_provider_result() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    execution_id = "exec_" + "b" * 32
    worker_result = _provider_worker_result(
        registration=registration,
        execution_id=execution_id,
    )

    result = interpret_web_analysis_transport_result(
        request,
        worker_result,
        registration=registration,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        expected_execution_id=execution_id,
    )

    assert result.provider_id == registration.provider_id
    assert result.model == registration.model
    assert result.target == str(registration.endpoint)
    assert result.content == '{"proposal":"bounded"}'
    assert result.streamed is False
    assert result.chunks == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"execution_id": "exec_" + "c" * 32},
        {"backend": "process"},
        {"status": WorkerStatus.FAILED, "exit_code": 1},
        {"stdout_truncated": True},
        {"stderr_truncated": True},
    ],
)
def test_interpret_successor_result_rejects_nonexact_worker_result(
    changes: dict[str, object],
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    registration, request = _successor_metadata_inputs(runtime)
    execution_id = "exec_" + "b" * 32
    worker_result = WorkerResult.model_validate(
        {
            **_provider_worker_result(
                registration=registration,
                execution_id=execution_id,
            ).model_dump(mode="python"),
            **changes,
        }
    )

    with pytest.raises(WebAnalysisTransportError, match="interpretation failed closed"):
        interpret_web_analysis_transport_result(
            request,
            worker_result,
            registration=registration,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            expected_execution_id=execution_id,
        )


def test_transport_cleanup_removes_only_owned_resources_and_proves_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    fake = _FakeTransportDocker(pin)
    monkeypatch.setattr(transport_module, "_run_transport_cleanup_command", fake.run)

    proof = cleanup_web_analysis_transport_resources(
        execution_id=fake.execution_id,
        external_network=fake.external_network,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        docker_executable=fake.docker_executable,
    )

    assert proof.api_version == WEB_ANALYSIS_TRANSPORT_CLEANUP_PROOF_API_VERSION
    assert proof.execution_id == fake.execution_id
    assert proof.external_network == fake.external_network
    assert proof.transport_pin_digest == pin.pin_digest
    assert proof.cleanup_attempted
    assert proof.owned_resources_removed
    assert proof.absence_verified
    assert not proof.provider_dispatch_authority
    assert not proof.target_request_authority
    assert not proof.automatic_redispatch_authority
    assert [resource.resource_kind for resource in proof.observed_resources] == [
        "egress-network",
        "proxy-container",
        "worker-container",
    ]
    assert fake.containers == {}
    assert fake.networks == {}
    removal_commands = [command for command in fake.commands if command[2] == "rm"]
    assert [(command[1], command[-1]) for command in removal_commands] == [
        ("container", fake.worker_id),
        ("container", fake.proxy_id),
        ("network", fake.network_id),
    ]
    assert not any(
        command[:3] == (fake.docker_executable, "network", "rm")
        and command[3] == fake.external_network
        for command in fake.commands
    )
    assert (
        verify_web_analysis_transport_cleanup_proof(
            proof,
            execution_id=fake.execution_id,
            external_network=fake.external_network,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
        )
        == proof
    )


def test_transport_cleanup_is_idempotent_after_resources_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    fake = _FakeTransportDocker(pin)
    monkeypatch.setattr(transport_module, "_run_transport_cleanup_command", fake.run)
    first = cleanup_web_analysis_transport_resources(
        execution_id=fake.execution_id,
        external_network=fake.external_network,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        docker_executable=fake.docker_executable,
    )

    second = cleanup_web_analysis_transport_resources(
        execution_id=fake.execution_id,
        external_network=fake.external_network,
        runtime=runtime,
        transport_pin=pin,
        expected_transport_pin_digest=pin.pin_digest,
        docker_executable=fake.docker_executable,
    )

    assert second.observed_resources == ()
    assert second.resource_absence_digest == first.resource_absence_digest
    assert second.cleanup_digest != first.cleanup_digest


def test_transport_cleanup_rejects_cross_claim_external_network_before_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    fake = _FakeTransportDocker(pin)
    monkeypatch.setattr(transport_module, "_run_transport_cleanup_command", fake.run)

    with pytest.raises(WebAnalysisTransportError, match="cleanup failed closed"):
        cleanup_web_analysis_transport_resources(
            execution_id=fake.execution_id,
            external_network="pajin-web-analysis-live-network-" + "e" * 32,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            docker_executable=fake.docker_executable,
        )

    assert fake.commands == []


@pytest.mark.parametrize(
    "tamper",
    [
        "foreign-label",
        "worker-name",
        "worker-image",
        "foreign-network-member",
        "proxy-network-pair",
    ],
)
def test_transport_cleanup_rejects_foreign_or_tampered_ownership_before_removal(
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    fake = _FakeTransportDocker(pin)
    if tamper == "foreign-label":
        fake.containers[fake.worker_id]["Config"]["Labels"]["foreign.owner"] = "true"
    elif tamper == "worker-name":
        fake.containers[fake.worker_id]["Name"] = "/foreign-worker"
    elif tamper == "worker-image":
        fake.containers[fake.worker_id]["Image"] = "sha256:" + "9" * 64
    elif tamper == "foreign-network-member":
        fake.networks[fake.network_id]["Containers"]["4" * 64] = {}
    else:
        fake.containers[fake.proxy_id]["Name"] = "/pajin-proxy-" + "d" * 32
    monkeypatch.setattr(transport_module, "_run_transport_cleanup_command", fake.run)

    with pytest.raises(WebAnalysisTransportError, match="cleanup failed closed"):
        cleanup_web_analysis_transport_resources(
            execution_id=fake.execution_id,
            external_network=fake.external_network,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            docker_executable=fake.docker_executable,
        )

    assert fake.worker_id in fake.containers
    assert fake.proxy_id in fake.containers
    assert fake.network_id in fake.networks
    assert not any(command[2] == "rm" for command in fake.commands)


def test_transport_cleanup_rejects_identity_change_before_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    fake = _FakeTransportDocker(pin)
    worker_inspections = 0

    def run_with_race(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
        nonlocal worker_inspections
        result = fake.run(arguments)
        if arguments == (
            fake.docker_executable,
            "container",
            "inspect",
            fake.worker_id,
        ):
            worker_inspections += 1
            if worker_inspections == 1:
                fake.containers[fake.worker_id]["Name"] = "/foreign-worker"
        return result

    monkeypatch.setattr(
        transport_module,
        "_run_transport_cleanup_command",
        run_with_race,
    )

    with pytest.raises(WebAnalysisTransportError, match="cleanup failed closed"):
        cleanup_web_analysis_transport_resources(
            execution_id=fake.execution_id,
            external_network=fake.external_network,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
            docker_executable=fake.docker_executable,
        )

    assert worker_inspections == 2
    assert not any(command[2] == "rm" for command in fake.commands)


def test_cleanup_proof_strict_reload_rejects_anchor_or_digest_drift() -> None:
    runtime = _runtime_pin()
    pin = _transport_pin(runtime)
    proof = WebAnalysisTransportCleanupProof(
        executionId="exec_" + "b" * 32,
        transportPinDigest=pin.pin_digest,
        externalNetwork="pajin-web-analysis-live-network-" + "b" * 32,
    )

    with pytest.raises(WebAnalysisTransportError, match="verification failed closed"):
        verify_web_analysis_transport_cleanup_proof(
            proof,
            execution_id="exec_" + "c" * 32,
            external_network=proof.external_network,
            runtime=runtime,
            transport_pin=pin,
            expected_transport_pin_digest=pin.pin_digest,
        )

    payload = proof.model_dump(mode="python", by_alias=True)
    payload["resourceAbsenceDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="resource absence digest differs"):
        WebAnalysisTransportCleanupProof.model_validate(payload)


def test_transport_module_does_not_import_forbidden_legacy_runtime() -> None:
    source = Path(transport_module.__file__).read_text(encoding="utf-8")

    assert "LocalModelRuntime" not in source
    assert "analysis_runtime" not in source
    assert "analysis_skill_runtime" not in source
    assert "analysis_skill_receipts" not in source
    assert "analysis_local" not in source
    assert "benchmark.effectiveness.docker" not in source
