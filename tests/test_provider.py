import asyncio
import base64
import importlib.util
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import pajin.cli as cli_module
from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolRiskTier
from pajin.domain.orchestration import RunStatus
from pajin.policy.engine import PolicyEngine
from pajin.providers import (
    FunctionDefinition,
    JSONSchemaDefinition,
    OpenAICompatibleChatTool,
    PolicyBoundProviderPort,
    ProviderRegistration,
    ProviderValidationPlanner,
)
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.runtime.worker import (
    DockerWorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _registration(endpoint: str, **updates: object) -> ProviderRegistration:
    payload: dict[str, object] = {
        "provider_id": "test-provider",
        "endpoint": endpoint,
        "model": "fixed-model",
        "secret_ref": "provider/test/api-key",
        "allowed_function_tools": {"get_weather"},
    }
    payload.update(updates)
    return ProviderRegistration.model_validate(payload)


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


def _bounded_function_schema(value: object) -> FunctionDefinition:
    return FunctionDefinition(name="bounded_function", parameters=value, strict=False)


def _bounded_output_schema(value: object) -> JSONSchemaDefinition:
    return JSONSchemaDefinition.model_validate(
        {
            "name": "bounded_output",
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "payload": value,
            },
            "strict": True,
        }
    )


def test_provider_registration_requires_https_except_fixed_local_lab_hosts() -> None:
    with pytest.raises(ValidationError, match="Bearer endpoints require HTTPS"):
        _registration("http://provider.example/v1/chat/completions")
    with pytest.raises(ValidationError, match="Bearer endpoints require HTTPS"):
        _registration(
            "http://10.0.0.8/v1/chat/completions",
            allow_private_networks=True,
        )
    with pytest.raises(ValidationError, match="URL credentials"):
        _registration("https://user:password@provider.example/v1/chat/completions")
    with pytest.raises(ValidationError, match="URL fragment"):
        _registration("https://provider.example/v1/chat/completions#unroutable")
    with pytest.raises(ValidationError, match="explicit allow_private_networks"):
        _registration("http://localhost:8765/v1/chat/completions")

    for endpoint in (
        "http://localhost:8765/v1/chat/completions",
        "http://127.0.0.1:8765/v1/chat/completions",
        "http://[::1]:8765/v1/chat/completions",
        "http://host.docker.internal:8765/v1/chat/completions",
    ):
        assert _registration(endpoint, allow_private_networks=True).endpoint.scheme == "http"


def test_provider_check_cli_propagates_manifest_private_network_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def planner(registration: ProviderRegistration) -> object:
        observed["registration"] = registration
        return object()

    class FakeRunner:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["planner"] is not None

        async def run(self, campaign: CampaignManifest) -> object:
            assert campaign.spec.rules_of_engagement.allow_private_networks
            return SimpleNamespace(
                run_id="provider-check-test",
                report_path=tmp_path / "report.md",
            )

    monkeypatch.setenv("PAJIN_PROVIDER_API_KEY", "local-provider-check-secret")
    monkeypatch.setattr(cli_module, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli_module, "ProviderValidationPlanner", planner)
    monkeypatch.setattr(cli_module, "MultiAgentCampaignRunner", FakeRunner)
    monkeypatch.setattr(
        cli_module,
        "_provider_checks",
        lambda *_args, **_kwargs: {"safe": True},
    )

    result = CliRunner().invoke(
        cli_module.app,
        [
            "provider-check",
            "examples/provider-openai-compatible-lab.yaml",
            "--output",
            str(tmp_path / "runs"),
            "--worker",
            "simulated",
        ],
    )

    assert result.exit_code == 0, result.output
    registration = observed["registration"]
    assert isinstance(registration, ProviderRegistration)
    assert registration.allow_private_networks
    assert registration.endpoint.host == "host.docker.internal"


class ProviderConformanceWorker:
    def __init__(self, credential: str) -> None:
        self._credential = credential
        self.calls = 0

    def stable_execution_context(self) -> dict[str, object]:
        return {"fixture": "provider-conformance-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        assert job.command == ["openai-chat-completion"]
        assert secrets and [material.value for material in secrets] == [self._credential]
        payload = json.loads(job.stdin)
        request = payload["request"]
        streamed = request["stream"]
        messages = request["messages"]
        prompt = messages[-1]["content"]
        content: str | None
        tool_calls: list[dict[str, object]] = []
        finish_reason = "stop"
        if request.get("tools"):
            content = None
            finish_reason = "tool_calls"
            tool_calls = [
                {
                    "call_id": "call_weather",
                    "name": "get_weather",
                    "arguments_json": '{"location":"Seoul"}',
                    "arguments": {"location": "Seoul"},
                    "arguments_valid": True,
                }
            ]
        elif "credential" in prompt:
            content = self._credential
        elif streamed:
            content = "provider gateway stream response"
        else:
            content = "provider gateway non-stream response"
        self.calls += 1
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="provider-conformance-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(
                {
                    "provider_id": payload["providerId"],
                    "response_id": f"response-{self.calls}",
                    "model": request["model"],
                    "content": content,
                    "refusal": None,
                    "finish_reason": finish_reason,
                    "tool_calls": tool_calls,
                    "usage": None,
                    "streamed": streamed,
                    "chunks": 3 if streamed else 1,
                    "target": payload["target"],
                }
            ),
            started_at=now,
            finished_at=now,
        )


def test_provider_validation_full_runner_executes_four_conformance_calls(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/provider-openai-compatible-lab.yaml"))
    credential = "provider-conformance-secret"
    registration = _registration(
        campaign.spec.targets[0].endpoint,
        allow_private_networks=True,
    )
    worker = ProviderConformanceWorker(credential)
    secrets = SecretBroker()
    secrets.register(registration.secret_ref, credential)
    registry = ToolRegistry()
    registry.register(OpenAICompatibleChatTool(registration))
    runner = MultiAgentCampaignRunner(
        planner=ProviderValidationPlanner(registration),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
        secrets=secrets,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.status is RunStatus.COMPLETED
    assert worker.calls == 4
    assert len(outcome.tool_results) == 4
    assert all(result.success for result in outcome.tool_results)
    assert all(cli_module._provider_checks(outcome, credential=credential).values())
    assert verify_run_integrity(outcome.run_path).valid


def test_https_provider_policy_adds_connect_authority_without_weakening_adapter_target(
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = _registration("https://provider.example/v1/chat/completions")

    provider_campaign = PolicyBoundProviderPort._provider_policy_campaign(
        sample_campaign,
        registration,
    )

    assert provider_campaign.spec.scope.allow == [
        "https://provider.example/v1/chat/completions",
        "https://provider.example/**",
    ]
    proxy_policy = {
        "allow": provider_campaign.spec.scope.allow,
        "deny": provider_campaign.spec.scope.deny,
        "allowed_methods": list(provider_campaign.spec.rules_of_engagement.allowed_methods),
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
    }
    monkeypatch.setenv(
        "PAJIN_EGRESS_POLICY_B64",
        base64.b64encode(json.dumps(proxy_policy).encode()).decode(),
    )
    proxy_path = Path("containers/egress-proxy/proxy.py")
    proxy_spec = importlib.util.spec_from_file_location(
        "provider_policy_egress_proxy",
        proxy_path,
    )
    assert proxy_spec is not None and proxy_spec.loader is not None
    proxy_module = importlib.util.module_from_spec(proxy_spec)
    proxy_spec.loader.exec_module(proxy_module)
    assert proxy_module.request_allowed(
        "CONNECT",
        "https://provider.example:443/",
        authority_only=True,
    )

    mismatched = _request(registration).model_copy(
        update={"target": "https://provider.example/v1/other"}
    )
    with pytest.raises(ValueError, match="differs from registered endpoint"):
        OpenAICompatibleChatTool(registration).prepare(mismatched)


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


def test_provider_validation_planner_requires_one_exact_provider_target(
    sample_campaign: CampaignManifest,
) -> None:
    registration = _registration("https://provider.example/v1/chat/completions")
    planner = ProviderValidationPlanner(registration)
    provider_target = sample_campaign.spec.targets[0].model_copy(
        update={
            "type": "openai-compatible-provider",
            "endpoint": str(registration.endpoint),
        }
    )
    exact_campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"targets": [provider_target]})}
    )

    plan = asyncio.run(planner.plan(exact_campaign))

    assert len(plan.steps) == 4
    assert {step.request.target for step in plan.steps} == {str(registration.endpoint)}

    extra_target = provider_target.model_copy(update={"id": "silently-ignored-before"})
    multiple = exact_campaign.model_copy(
        update={
            "spec": exact_campaign.spec.model_copy(
                update={"targets": [provider_target, extra_target]}
            )
        }
    )
    with pytest.raises(ValueError, match="exactly one"):
        asyncio.run(planner.plan(multiple))

    wrong_type = exact_campaign.model_copy(
        update={
            "spec": exact_campaign.spec.model_copy(
                update={"targets": [provider_target.model_copy(update={"type": "ai-chat-api"})]}
            )
        }
    )
    with pytest.raises(ValueError, match="type openai-compatible-provider"):
        asyncio.run(planner.plan(wrong_type))


@pytest.mark.parametrize(
    "factory",
    [_bounded_function_schema, _bounded_output_schema],
    ids=["function-parameters", "structured-output"],
)
def test_provider_schemas_reject_non_json_cycles_and_resource_exhaustion(
    factory: Callable[[object], object],
) -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    with pytest.raises(ValidationError, match="Python container cycles"):
        factory(cycle)

    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(34):
        nested: dict[str, object] = {}
        cursor["next"] = nested
        cursor = nested
    with pytest.raises(ValidationError, match="nesting-depth limit"):
        factory(deep)

    with pytest.raises(ValidationError, match="node-count limit"):
        factory({"nodes": [None] * 20_001})
    with pytest.raises(ValidationError, match="canonical byte limit"):
        factory({"description": "x" * 262_145})
    with pytest.raises(ValidationError, match="object keys must be strings"):
        factory({1: "not-json"})
    with pytest.raises(ValidationError, match="numbers must be finite"):
        factory({"number": float("nan")})
    with pytest.raises(ValidationError, match="non-JSON value"):
        factory({"python": object()})


def test_provider_schemas_are_immutable_detached_snapshots_and_allow_json_refs() -> None:
    schema = {
        "type": "object",
        "properties": {"node": {"$ref": "#/$defs/node"}},
        "required": ["node"],
        "additionalProperties": False,
        "$defs": {
            "node": {
                "type": "object",
                "properties": {"next": {"$ref": "#/$defs/node"}},
                "required": ["next"],
                "additionalProperties": False,
            }
        },
    }
    function = FunctionDefinition(name="recursive_ref", parameters=schema)
    output = JSONSchemaDefinition.model_validate(
        {"name": "recursive_ref", "schema": schema, "strict": True}
    )

    schema["properties"]["node"]["$ref"] = "https://attacker.invalid/schema"

    assert function.model_dump(mode="json")["parameters"]["properties"]["node"] == {
        "$ref": "#/$defs/node"
    }
    assert output.model_dump(mode="json", by_alias=True)["schema"]["properties"]["node"] == {
        "$ref": "#/$defs/node"
    }
    with pytest.raises(TypeError):
        function.parameters["type"] = "array"
    with pytest.raises(TypeError):
        output.schema_["type"] = "array"
    with pytest.raises(ValidationError):
        function.name = "mutated"


@pytest.mark.parametrize(
    ("model_update", "expected_success"),
    [("fixed-model", True), ("different-model", False), (None, False)],
)
def test_provider_tool_binds_normalized_model_to_registration(
    model_update: str | None,
    expected_success: bool,
) -> None:
    registration = _registration("https://provider.example/v1/chat/completions")
    tool = OpenAICompatibleChatTool(registration)
    request = _request(registration)
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "provider_id": registration.provider_id,
        "response_id": "chatcmpl-model-binding",
        "content": "bounded",
        "finish_reason": "stop",
        "tool_calls": [],
        "usage": None,
        "streamed": False,
        "chunks": 1,
        "target": request.target,
    }
    if model_update is not None:
        payload["model"] = model_update
    worker_result = WorkerResult(
        execution_id="exec_provider_model_binding",
        backend="provider-model-binding-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(payload),
        started_at=now,
        finished_at=now,
    )

    result = tool.interpret(request, worker_result)

    assert result.success is expected_success
    if not expected_success:
        assert result.error is not None and "invalid provider response" in result.error


@pytest.mark.parametrize(
    "mutation",
    ["duplicate-key", "nonfinite", "deep", "wide", "truncated"],
)
def test_provider_tool_rejects_ambiguous_or_unbounded_worker_json(
    mutation: str,
) -> None:
    registration = _registration("https://provider.example/v1/chat/completions")
    tool = OpenAICompatibleChatTool(registration)
    request = _request(registration)
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "provider_id": registration.provider_id,
        "response_id": "chatcmpl-strict-json",
        "model": registration.model,
        "content": "bounded",
        "finish_reason": "stop",
        "tool_calls": [],
        "usage": None,
        "streamed": False,
        "chunks": 1,
        "target": request.target,
    }
    raw = json.dumps(payload, separators=(",", ":"))
    if mutation == "duplicate-key":
        raw = '{"provider_id":"substituted",' + raw[1:]
    elif mutation == "nonfinite":
        raw = raw.replace('"chunks":1', '"chunks":NaN')
    elif mutation == "deep":
        nested: object = None
        for _ in range(66):
            nested = [nested]
        payload["untrusted"] = nested
        raw = json.dumps(payload, separators=(",", ":"))
    elif mutation == "wide":
        payload["untrusted"] = [0] * 20_001
        raw = json.dumps(payload, separators=(",", ":"))

    worker_result = WorkerResult(
        execution_id="exec_provider_strict_json",
        backend="provider-strict-json-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=raw,
        stdout_truncated=mutation == "truncated",
        started_at=now,
        finished_at=now,
    )

    result = tool.interpret(request, worker_result)

    assert result.success is False
    assert result.error is not None
    assert "invalid provider response" in result.error


def test_provider_tool_seals_registration_against_caller_mutation() -> None:
    registration = _registration("https://provider.example/v1/chat/completions")
    request = _request(registration)
    tool = OpenAICompatibleChatTool(registration)
    observed = tool.registration

    registration.endpoint = "https://attacker.invalid/v1/chat/completions"  # type: ignore[assignment]
    registration.model = "retargeted-model"
    registration.secret_ref = "provider/attacker/api-key"
    observed.secret_ref = "provider/observer/api-key"
    job = tool.prepare(request)
    payload = json.loads(job.stdin)

    assert payload["target"] == "https://provider.example/v1/chat/completions"
    assert payload["request"]["model"] == "fixed-model"
    assert job.secret_requests[0].secret_ref == "provider/test/api-key"
    assert tool.registration.secret_ref == "provider/test/api-key"


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


def test_gateway_omits_secret_from_backend_exception(
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
    assert outcome.worker_result.stderr == (
        "worker backend failed; exception_type=RuntimeError; stage=worker-backend; detail=omitted"
    )
    assert "<redacted-secret>" not in outcome.worker_result.stderr
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


def test_sse_reader_rejects_oversized_line_before_unbounded_allocation() -> None:
    module = _worker_entry()

    class OversizedLineResponse:
        def __init__(self) -> None:
            self.read_sizes: list[int] = []

        def readline(self, size: int) -> bytes:
            self.read_sizes.append(size)
            return b"x" * size

    response = OversizedLineResponse()

    with pytest.raises(ValueError, match="line exceeded byte limit"):
        module._normalize_stream_provider(
            response,
            provider_id="test-provider",
            target="https://provider.example/v1/chat/completions",
        )

    assert response.read_sizes == [module.MAX_PROVIDER_SSE_LINE_BYTES + 1]


def test_sse_normalizer_rejects_identity_changes_and_incomplete_completion() -> None:
    module = _worker_entry()
    target = "https://provider.example/v1/chat/completions"

    def sse(chunk: dict[str, object]) -> bytes:
        return f"data: {json.dumps(chunk)}\n\n".encode()

    identity_swap = [
        sse(
            {
                "id": "first",
                "model": "fixed",
                "choices": [{"delta": {"content": "a"}, "finish_reason": None}],
            }
        ),
        sse(
            {
                "id": "second",
                "model": "fixed",
                "choices": [{"delta": {"content": "b"}, "finish_reason": "stop"}],
            }
        ),
        b"data: [DONE]\n\n",
    ]
    incomplete = [
        sse(
            {
                "id": "first",
                "model": "fixed",
                "choices": [{"delta": {"content": "a"}, "finish_reason": None}],
            }
        ),
        b"data: [DONE]\n\n",
    ]

    with pytest.raises(ValueError, match="id changed"):
        module._normalize_stream_provider(
            identity_swap,
            provider_id="test-provider",
            target=target,
        )
    with pytest.raises(ValueError, match="finish reason"):
        module._normalize_stream_provider(
            incomplete,
            provider_id="test-provider",
            target=target,
        )


def test_provider_normalizers_reject_malformed_tool_calls_and_usage() -> None:
    module = _worker_entry()
    payload = {
        "id": "chatcmpl-nonstream",
        "model": "fixed-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": ["silently-dropped-before"],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }

    with pytest.raises(TypeError, match="malformed tool call"):
        module._normalize_nonstream_provider(
            payload,
            provider_id="test-provider",
            target="https://provider.example/v1/chat/completions",
        )
    with pytest.raises(TypeError, match="non-negative integer"):
        module._provider_usage({"prompt_tokens": True, "completion_tokens": 1, "total_tokens": 2})
    with pytest.raises(ValueError, match="inconsistent"):
        module._provider_usage({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 3})
