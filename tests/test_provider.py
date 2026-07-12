import asyncio
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import ValidationError

from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolRiskTier
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool, ProviderRegistration
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    DockerWorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway


def _registration(endpoint: str) -> ProviderRegistration:
    return ProviderRegistration.model_validate(
        {
            "provider_id": "test-provider",
            "endpoint": endpoint,
            "model": "fixed-model",
            "secret_ref": "provider/test/api-key",
            "allowed_function_tools": {"get_weather"},
        }
    )


def _request(registration: ProviderRegistration) -> ToolRequest:
    return ToolRequest(
        agent_id="agent:specialist:test",
        tool_id="provider.test-provider.chat",
        target=str(registration.endpoint),
        method="POST",
        arguments={
            "messages": [{"role": "user", "content": "hello"}],
            "stream": False,
        },
    )


def test_provider_tool_fixes_endpoint_model_and_secret_binding() -> None:
    registration = _registration("https://provider.example/v1/chat/completions")
    tool = OpenAICompatibleChatTool(registration)

    job = tool.prepare(_request(registration))
    payload = json.loads(job.stdin)

    assert payload["target"] == str(registration.endpoint)
    assert payload["request"]["model"] == "fixed-model"
    assert job.secret_requests == [
        WorkerSecretRequest(
            secret_ref="provider/test/api-key",
            binding="provider-api-key",
            ttl_seconds=30,
        )
    ]
    assert "provider/test/api-key" not in job.stdin
    assert "api-key" not in json.dumps(payload)

    overridden = _request(registration).model_copy(
        update={"arguments": {"messages": [{"role": "user", "content": "hi"}], "model": "x"}}
    )
    with pytest.raises(ValidationError):
        tool.prepare(overridden)


def test_provider_tool_forwards_only_validated_strict_response_schema() -> None:
    registration = _registration("https://provider.example/v1/chat/completions")
    request = _request(registration).model_copy(
        update={
            "arguments": {
                "messages": [{"role": "developer", "content": "Return structured output."}],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "pajin_test_output",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "properties": {"answer": {"type": "string"}},
                            "required": ["answer"],
                            "additionalProperties": False,
                        },
                    },
                },
            }
        }
    )

    job = OpenAICompatibleChatTool(registration).prepare(request)
    provider_request = json.loads(job.stdin)["request"]

    assert provider_request["response_format"]["type"] == "json_schema"
    assert provider_request["response_format"]["json_schema"]["strict"] is True
    assert (
        provider_request["response_format"]["json_schema"]["schema"]["additionalProperties"]
        is False
    )


def test_worker_secret_wire_envelope_is_not_part_of_job_metadata() -> None:
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["openai-chat-completion"],
        stdin='{"providerId":"test"}',
        secret_requests=[
            WorkerSecretRequest(
                secret_ref="provider/test/api-key",
                binding="provider-api-key",
            )
        ],
    )
    material = SecretMaterial(
        lease_id="lease_test",
        binding="provider-api-key",
        value="wire-only-secret",
    )
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})

    wire = json.loads(backend._wire_stdin(job, [material]))
    args = backend._docker_args(job, "pajin-test")

    assert wire["payload"] == {"providerId": "test"}
    assert wire["secrets"] == {"provider-api-key": "wire-only-secret"}
    assert "wire-only-secret" not in job.model_dump_json()
    assert "wire-only-secret" not in " ".join(args)


class EchoSecretWorker:
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        assert secrets and len(secrets) == 1
        now = datetime.now(UTC)
        secret = secrets[0].value
        request = json.loads(job.stdin)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="secret-echo-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(
                {
                    "provider_id": "test-provider",
                    "response_id": "chatcmpl-test",
                    "model": "fixed-model",
                    "content": secret,
                    "finish_reason": "stop",
                    "tool_calls": [],
                    "usage": None,
                    "streamed": False,
                    "chunks": 1,
                    "target": request["target"],
                }
            ),
            stderr=f"error could echo {secret}",
            network_log=f"header accidentally contained {secret}",
            started_at=now,
            finished_at=now,
        )


class RaisingSecretWorker:
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del job
        assert secrets
        raise RuntimeError(f"backend diagnostic included {secrets[0].value}")


def test_gateway_redacts_provider_secret_and_revokes_lease(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    endpoint = sample_campaign.spec.targets[0].endpoint
    registration = _registration(endpoint)
    registry = ToolRegistry()
    registry.register(OpenAICompatibleChatTool(registration))
    broker = SecretBroker()
    credential = "gateway-never-persist-this-secret"
    broker.register(registration.secret_ref, credential)
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=EchoSecretWorker(),
        store=store,
        secrets=broker,
    )
    request = _request(registration)
    grant = CapabilityGrant(
        subject=request.agent_id,
        campaign=sample_campaign.metadata.name,
        tools={request.tool_id},
        targets={request.target},
        max_risk_tier=ToolRiskTier.T1,
        max_calls=1,
        expires_at=sample_campaign.spec.authorization.expires_at,
    )

    outcome = asyncio.run(gateway.execute(sample_campaign, grant, request, used_calls=0))
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8") for path in store.path.rglob("*") if path.is_file()
    )

    assert outcome.result.success
    assert outcome.result.data["content"] == "<redacted-secret>"
    assert outcome.worker_result is not None
    assert outcome.worker_result.stderr == "error could echo <redacted-secret>"
    assert credential not in artifact_text
    assert broker.snapshot()[0]["status"] == "revoked"
    assert broker.snapshot()[0]["remaining_uses"] == 0


def test_gateway_redacts_secret_from_backend_exception(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    endpoint = sample_campaign.spec.targets[0].endpoint
    registration = _registration(endpoint)
    registry = ToolRegistry()
    registry.register(OpenAICompatibleChatTool(registration))
    broker = SecretBroker()
    credential = "backend-error-secret-must-not-persist"
    broker.register(registration.secret_ref, credential)
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    request = _request(registration)
    grant = CapabilityGrant(
        subject=request.agent_id,
        campaign=sample_campaign.metadata.name,
        tools={request.tool_id},
        targets={request.target},
        max_risk_tier=ToolRiskTier.T1,
        max_calls=1,
        expires_at=sample_campaign.spec.authorization.expires_at,
    )
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=RaisingSecretWorker(),
        store=store,
        secrets=broker,
    )

    outcome = asyncio.run(gateway.execute(sample_campaign, grant, request, used_calls=0))
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8") for path in store.path.rglob("*") if path.is_file()
    )

    assert not outcome.result.success
    assert outcome.worker_result is not None
    assert "<redacted-secret>" in outcome.worker_result.stderr
    assert credential not in artifact_text
    assert broker.snapshot()[0]["status"] == "revoked"


def _worker_entry() -> ModuleType:
    path = Path(__file__).parents[1] / "containers" / "worker" / "worker_entry.py"
    spec = importlib.util.spec_from_file_location("pajin_worker_entry", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sse_tool_call_fragments_are_normalized_without_execution() -> None:
    module = _worker_entry()
    chunks = [
        {
            "id": "chatcmpl-stream",
            "model": "fixed-model",
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_weather",
                                "function": {"name": "get_weather", "arguments": ""},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ],
        },
        {
            "id": "chatcmpl-stream",
            "model": "fixed-model",
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "function": {"arguments": '{"location":"Seoul"}'}}
                        ]
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        },
    ]
    response = [f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks] + [
        b"data: [DONE]\n\n"
    ]

    normalized = module._normalize_stream_provider(
        response,
        provider_id="test-provider",
        target="https://provider.example/v1/chat/completions",
    )

    assert normalized["streamed"] is True
    assert normalized["tool_calls"] == [
        {
            "call_id": "call_weather",
            "name": "get_weather",
            "arguments_json": '{"location":"Seoul"}',
            "arguments": {"location": "Seoul"},
            "arguments_valid": True,
        }
    ]
