from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import timedelta
from pathlib import Path
from threading import Event
from typing import Any, ClassVar, cast

import pytest

from pajin.benchmark.effectiveness.docker import LocalModelRuntime
from pajin.benchmark.effectiveness.evidence import Lifecycle
from pajin.benchmark.effectiveness.runtime import LocalEvaluationTool
from pajin.benchmark.effectiveness.suite import (
    PLATFORM_MANIFESTS,
    ModelPin,
    RuntimePin,
    model_pins,
)
from pajin.domain.models import ToolRequest, ToolRiskTier
from pajin.providers.models import ProviderChatRequest, ProviderMessage
from pajin.providers.usage import ProviderModelUsageBound, provider_model_usage_upper_bound
from pajin.runtime.worker import NetworkMode, WorkerJob
from pajin.tools import gateway as gateway_module
from pajin.tools.ai import ChatRole
from pajin.web_assessment import analysis_local, analysis_proposal
from pajin.web_assessment.analysis_local import (
    WEB_ANALYSIS_LOCAL_DURATION_SECONDS,
    WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS,
    WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
    WEB_ANALYSIS_LOCAL_PROVIDER_ID,
    WEB_ANALYSIS_LOCAL_SECRET_REF,
    LocalWebAnalysisProviderAssembly,
    WebAnalysisLocalRuntimeError,
    build_local_web_analysis_provider_registration,
    build_local_web_analysis_provider_runtime,
    require_local_web_analysis_request_fits_model_budget,
    require_local_web_analysis_request_fits_runtime_context,
)
from pajin.web_assessment.analysis_proposal import build_web_analysis_snapshot
from pajin.web_assessment.analysis_runtime import (
    WebAnalysisProviderExecutionContext,
    build_web_analysis_chat_request,
)
from pajin.web_assessment.analysis_skill_invocation import (
    SkillBoundWebAnalysisProviderExecutionContext,
    build_skill_bound_web_analysis_chat_request,
)
from pajin.web_assessment.analysis_skill_projection import (
    build_skill_bound_web_analysis_snapshot,
)
from pajin.web_assessment.analysis_skill_runtime import (
    SkillBoundWebAnalysisRuntimeError,
    bind_skill_bound_web_analysis_provider_runtime,
)
from pajin.web_assessment.analysis_transport import (
    WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
    WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
    WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION,
    expected_web_analysis_provider_worker_context,
    web_analysis_transport_runtime_pin,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun
from tests.test_web_analysis_proposal import _verified_source


@dataclass
class _FakeStore:
    run_id: str
    path: Path
    artifacts: dict[str, object] = field(default_factory=dict)
    events: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    def write_json_create_only(self, relative_path: str, data: object) -> str:
        if relative_path in self.artifacts:
            raise FileExistsError(relative_path)
        self.artifacts[relative_path] = data
        return relative_path

    def append_event(self, event_type: str, payload: dict[str, object]) -> None:
        self.events.append((event_type, payload))

    def artifact_exists(self, relative_path: str) -> bool:
        return relative_path in self.artifacts


class _FakeRunStore:
    calls: ClassVar[list[tuple[Path, str]]] = []

    @classmethod
    def create(cls, root: Path, campaign_name: str) -> _FakeStore:
        cls.calls.append((root, campaign_name))
        return _FakeStore(
            run_id="run_20260915T000001Z_5678abcd",
            path=root / campaign_name / "run_20260915T000001Z_5678abcd",
        )


class _FakeDockerWorkerBackend:
    instances: ClassVar[list[_FakeDockerWorkerBackend]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.run_calls = 0
        self.instances.append(self)

    async def run(self, *_args: object, **_kwargs: object) -> object:
        self.run_calls += 1
        raise AssertionError("unit tests must not start a Docker Worker")

    def stable_execution_context(self) -> dict[str, object]:
        routes = dict(self.kwargs.get("external_network_routes", {}))
        context: dict[str, object] = {
            "implementationVersion": (
                "pajin.docker-worker/v2" if routes else "pajin.docker-worker/v1"
            ),
            "allowedImages": sorted(self.kwargs["allowed_images"]),
            "dockerExecutable": "docker",
            "egressProxyImage": self.kwargs["egress_proxy_image"],
            "externalNetwork": self.kwargs["external_network"],
        }
        if routes:
            context["externalNetworkRoutes"] = dict(sorted(routes.items()))
        return context


@pytest.fixture
def runtime_pin() -> RuntimePin:
    return RuntimePin(
        platform="linux/arm64",
        platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
        worker_image="sha256:" + "1" * 64,
        proxy_image="sha256:" + "2" * 64,
    )


@pytest.fixture
def model_pin() -> ModelPin:
    return model_pins()[0]


@pytest.fixture
def model_runtime(
    tmp_path: Path,
    runtime_pin: RuntimePin,
    model_pin: ModelPin,
) -> LocalModelRuntime:
    value = LocalModelRuntime(
        runtime=runtime_pin,
        model=model_pin,
        model_path=tmp_path / "model.gguf",
        key_file=tmp_path / "model-api-key",
    )
    value.lifecycle = Lifecycle(
        owner=value.owner,
        container_id="3" * 64,
        network_id="4" * 64,
        healthy=True,
        startup_seconds=1.25,
        model_image_id="sha256:" + "5" * 64,
        internal_network=True,
        published_ports=False,
        read_only=True,
        memory_bytes=runtime_pin.model_memory_mb * 1024 * 1024,
        nano_cpus=runtime_pin.model_cpus * 1_000_000_000,
        pids_limit=runtime_pin.model_pids,
    )
    return value


@pytest.fixture
def source() -> VerifiedAuthenticatedDiscoveryRun:
    return _verified_source()


def test_local_provider_registration_and_request_budget_share_one_boundary(
    runtime_pin: RuntimePin,
    model_pin: ModelPin,
) -> None:
    registration = build_local_web_analysis_provider_registration(
        runtime=runtime_pin,
        model=model_pin,
    )
    assert registration.provider_id == WEB_ANALYSIS_LOCAL_PROVIDER_ID
    assert str(registration.endpoint) == WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT
    assert registration.model == model_pin.name
    assert registration.lease_ttl_seconds == runtime_pin.request_timeout_seconds

    ordinary = ProviderChatRequest(
        messages=[ProviderMessage(role=ChatRole.USER, content="bounded local analysis")],
        max_completion_tokens=128,
    )
    require_local_web_analysis_request_fits_model_budget(
        ordinary,
        registration=registration,
    )
    require_local_web_analysis_request_fits_runtime_context(
        ordinary,
        registration=registration,
        runtime=runtime_pin,
    )

    oversized = ProviderChatRequest(
        messages=[ProviderMessage(role=ChatRole.USER, content="x" * 20_000)],
        max_completion_tokens=1_024,
    )
    with pytest.raises(WebAnalysisLocalRuntimeError, match="model-token budget"):
        require_local_web_analysis_request_fits_model_budget(
            oversized,
            registration=registration,
        )


def test_context_admission_rejects_request_below_campaign_budget_before_worker_start(
    runtime_pin: RuntimePin,
    model_pin: ModelPin,
) -> None:
    registration = build_local_web_analysis_provider_registration(
        runtime=runtime_pin,
        model=model_pin,
    )
    request = ProviderChatRequest(
        messages=[ProviderMessage(role=ChatRole.USER, content="x" * 1_000)],
        max_completion_tokens=128,
    )
    bound = provider_model_usage_upper_bound(registration, request)

    assert bound.prompt_tokens + bound.completion_tokens < WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS
    assert bound.prompt_tokens + bound.completion_tokens > runtime_pin.context_size
    require_local_web_analysis_request_fits_model_budget(
        request,
        registration=registration,
    )
    with pytest.raises(WebAnalysisLocalRuntimeError, match="pinned model context"):
        require_local_web_analysis_request_fits_runtime_context(
            request,
            registration=registration,
            runtime=runtime_pin,
        )
    assert _FakeDockerWorkerBackend.instances == []


def test_current_skill_bound_request_is_rejected_by_campaign_accounting_budget(
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    runtime_pin: RuntimePin,
    model_pin: ModelPin,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    snapshot = build_skill_bound_web_analysis_snapshot(
        source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
    )
    request = build_skill_bound_web_analysis_chat_request(snapshot)
    registration = build_local_web_analysis_provider_registration(
        runtime=runtime_pin,
        model=model_pin,
    )
    bound = provider_model_usage_upper_bound(registration, request)

    assert bound.prompt_tokens == 87_400
    assert bound.completion_tokens == 1_024
    assert bound.prompt_tokens + bound.completion_tokens > WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS
    with pytest.raises(WebAnalysisLocalRuntimeError, match="model-token budget"):
        require_local_web_analysis_request_fits_model_budget(
            request,
            registration=registration,
        )
    assert _FakeDockerWorkerBackend.instances == []


@pytest.fixture(autouse=True)
def reset_fakes() -> None:
    _FakeRunStore.calls = []
    _FakeDockerWorkerBackend.instances = []


def _patch_runtime_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    reloaded: VerifiedAuthenticatedDiscoveryRun | None = None,
) -> list[tuple[Path, str, str]]:
    reload_calls: list[tuple[Path, str, str]] = []

    def load(
        run_path: Path,
        *,
        expected_run_id: str,
        expected_root_digest: str,
    ) -> VerifiedAuthenticatedDiscoveryRun:
        reload_calls.append((run_path, expected_run_id, expected_root_digest))
        return reloaded or source

    monkeypatch.setattr(analysis_local, "load_verified_authenticated_discovery", load)
    monkeypatch.setattr(analysis_proposal, "load_verified_authenticated_discovery", load)
    monkeypatch.setattr(analysis_local, "RunStore", _FakeRunStore)
    monkeypatch.setattr(gateway_module, "RunStore", _FakeStore)
    monkeypatch.setattr(analysis_local, "DockerWorkerBackend", _FakeDockerWorkerBackend)
    return reload_calls


def test_factory_builds_one_source_bound_local_only_provider_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    runtime_pin: RuntimePin,
    model_pin: ModelPin,
    model_runtime: LocalModelRuntime,
) -> None:
    reload_calls = _patch_runtime_boundaries(monkeypatch, source)
    api_key = "unit-test-local-provider-key"

    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key=api_key,
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
    )
    runtime = assembly.provider_runtime

    assert reload_calls == [
        (
            source.run_path,
            source.verification.run_id,
            source.verification.root_digest,
        ),
        (
            source.run_path,
            source.verification.run_id,
            source.verification.root_digest,
        ),
    ]
    registration = runtime.registration
    assert registration.provider_id == WEB_ANALYSIS_LOCAL_PROVIDER_ID
    assert str(registration.endpoint) == WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT
    assert registration.model == model_pin.name
    assert registration.secret_ref == WEB_ANALYSIS_LOCAL_SECRET_REF
    assert registration.allow_private_networks is True
    assert registration.allow_streaming is False
    assert registration.allowed_function_tools == set()
    assert registration.input_cost_per_million_usd == 0
    assert registration.output_cost_per_million_usd == 0
    assert registration.lease_ttl_seconds == 180

    snapshot = build_web_analysis_snapshot(
        source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
    )
    chat_request = build_web_analysis_chat_request(snapshot)
    usage_bound = provider_model_usage_upper_bound(registration, chat_request)
    assert usage_bound.completion_tokens == 1024
    assert usage_bound.prompt_tokens + usage_bound.completion_tokens <= 65_536
    assert WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS == 65_536

    campaign = runtime.campaign
    assert [target.endpoint for target in campaign.spec.targets] == [
        WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT
    ]
    assert [target.type for target in campaign.spec.targets] == ["local-llm"]
    assert campaign.spec.scope.allow == [WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT]
    assert campaign.spec.scope.deny == []
    assert campaign.spec.rules_of_engagement.allowed_methods == {"POST"}
    assert campaign.spec.rules_of_engagement.allowed_tool_categories == {
        "chat-completions",
        "model-provider",
    }
    assert campaign.spec.rules_of_engagement.allow_private_networks is True
    assert campaign.spec.rules_of_engagement.max_requests_per_minute == 1
    assert campaign.spec.rules_of_engagement.prohibit == {
        "browser",
        "shell",
        "target-execution",
    }
    budgets = campaign.spec.budgets
    assert budgets.duration_seconds == WEB_ANALYSIS_LOCAL_DURATION_SECONDS == 180
    assert budgets.max_tool_calls == 1
    assert budgets.max_model_calls == 1
    assert budgets.max_model_tokens == WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS == 65_536
    assert budgets.max_agents == 1
    assert budgets.max_spawn_depth == 0
    assert budgets.max_cost_usd == 0
    assert campaign.spec.authorization.expires_at - campaign.spec.authorization.approved_at == (
        timedelta(seconds=180)
    )

    grant = runtime.grant
    assert grant.parent_grant_id is not None
    assert grant.depth == 1
    assert grant.tools == {f"provider.{WEB_ANALYSIS_LOCAL_PROVIDER_ID}.chat"}
    assert grant.targets == {WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT}
    assert grant.max_risk_tier is ToolRiskTier.T1
    assert grant.max_calls == 1
    child_record = runtime.ledger.record(grant.grant_id)
    root_record = runtime.ledger.record(grant.parent_grant_id)
    assert child_record.grant == grant
    assert child_record.remaining_calls == 1
    assert root_record.grant.parent_grant_id is None
    assert root_record.grant.subject != grant.subject
    assert root_record.remaining_calls == 1
    assert len(runtime.ledger.snapshot()) == 2
    assert runtime.budget.snapshot()["toolCalls"] == 0
    assert runtime.budget.snapshot()["modelCalls"] == 0

    assert _FakeRunStore.calls == [
        (
            (tmp_path / "provider-store").absolute(),
            campaign.metadata.name,
        )
    ]
    assert runtime.analysis_output_root == (tmp_path / "analysis-output").absolute()
    assert runtime.gateway.is_bound_to_store(runtime.store) is True
    assert (
        runtime.gateway.is_bound_to_store(
            _FakeStore(run_id=runtime.store.run_id, path=runtime.store.path)
        )
        is False
    )
    registry = runtime.gateway._tools
    assert registry.tool_ids() == grant.tools
    tool = registry.tool(next(iter(grant.tools)))
    assert isinstance(tool, LocalEvaluationTool)
    stable_context = tool.stable_execution_context()
    assert stable_context["implementationVersion"] == "pajin.tool-adapter/v1"
    assert "webAnalysisTransport" not in stable_context
    assert stable_context["effectRuntime"] == runtime_pin.model_dump(mode="json")
    assert stable_context["effectModel"] == model_pin.model_dump(mode="json")
    assert stable_context["effectModel"]["sha256"] == model_pin.sha256
    execution_context = runtime.execution_context
    assert execution_context.provider_id == registration.provider_id
    assert execution_context.model == model_pin.name
    assert execution_context.tool_id == tool.spec.tool_id
    assert execution_context.effect_runtime_pin == runtime_pin
    assert execution_context.effect_runtime_pin.max_completion_tokens == 128
    assert execution_context.model_pin == model_pin
    invocation_pin = execution_context.invocation_pin
    assert invocation_pin.role == "web-analysis-proposal"
    assert invocation_pin.attempt == 1
    assert invocation_pin.max_completion_tokens == 1024
    assert invocation_pin.seed == 0
    assert invocation_pin.temperature == 0
    assert invocation_pin.top_p == 1
    assert invocation_pin.response_schema_name == "web_analysis_proposal_draft"
    assert invocation_pin.tool_choice == "none"
    assert invocation_pin.tools_allowed is False
    assert invocation_pin.streaming_allowed is False
    assert invocation_pin.parallel_tool_calls_allowed is False
    assert invocation_pin.automatic_redispatch_authorized is False
    assert execution_context.tool_stable_execution_context == {
        "type": ("pajin.web_assessment.analysis_local._PinnedWebAnalysisProviderTool"),
        "context": stable_context,
    }
    assert execution_context.secret_material_embedded is False
    assert execution_context.execution_authority is False
    worker = _FakeDockerWorkerBackend.instances[0]
    assert runtime.gateway._worker is worker
    assert worker.kwargs == {
        "allowed_images": {runtime_pin.worker_image},
        "egress_proxy_image": runtime_pin.proxy_image,
        "external_network": model_runtime.network_name,
        "external_network_routes": {"openai-chat-completion": model_runtime.network_name},
    }
    assert worker.run_calls == 0

    chat = ProviderChatRequest(
        messages=[ProviderMessage(role=ChatRole.USER, content="opaque discovery projection")],
        tools=[],
        tool_choice="none",
        max_completion_tokens=1,
    )
    request = ToolRequest(
        agent_id=grant.subject,
        tool_id=tool.spec.tool_id,
        target=WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
        method="POST",
        arguments=chat.model_dump(mode="json", by_alias=True),
    )
    job = tool.prepare(request)
    assert job.image == runtime_pin.worker_image
    assert job.command == ["openai-chat-completion"]
    assert job.network is NetworkMode.NONE
    assert job.limits.timeout_seconds == runtime_pin.request_timeout_seconds
    assert [item.secret_ref for item in job.secret_requests] == [WEB_ANALYSIS_LOCAL_SECRET_REF]
    assert assembly.execution_ids == (job.execution_id,)

    public_runtime = json.dumps(
        {
            "registration": registration.model_dump(mode="json"),
            "campaign": campaign.model_dump(mode="json", by_alias=True),
            "grant": grant.model_dump(mode="json"),
            "executionContext": execution_context.model_dump(mode="json", by_alias=True),
        },
        sort_keys=True,
    )
    assert api_key not in public_runtime
    assert "http://127.0.0.1:3000" not in public_runtime
    assert str(model_runtime.model_path) not in json.dumps(stable_context, sort_keys=True)
    assert str(model_runtime.key_file) not in json.dumps(stable_context, sort_keys=True)


def test_factory_uses_separately_pinned_successor_transport_without_changing_model_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    runtime_pin: RuntimePin,
    model_pin: ModelPin,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    transport_pin = web_analysis_transport_runtime_pin(
        runtime_pin,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )

    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
        transport_pin=transport_pin,
        expected_transport_pin_digest=transport_pin.pin_digest,
    )
    runtime = assembly.provider_runtime
    worker = _FakeDockerWorkerBackend.instances[0]
    dispatch_guard = runtime.gateway._worker_dispatch_guard

    assert worker.kwargs == {
        "allowed_images": {transport_pin.worker_image},
        "egress_proxy_image": transport_pin.proxy_image,
        "external_network": model_runtime.network_name,
        "external_network_routes": {
            WEB_ANALYSIS_PINNED_PROVIDER_ACTION: model_runtime.network_name
        },
    }
    assert runtime_pin.worker_image not in worker.kwargs["allowed_images"]
    assert runtime_pin.proxy_image != worker.kwargs["egress_proxy_image"]
    assert callable(dispatch_guard)
    assert runtime.gateway._worker is worker
    dispatch_guard(worker)
    with pytest.raises(WebAnalysisLocalRuntimeError, match="Worker identity changed"):
        dispatch_guard(cast(Any, object()))

    tool_id = next(iter(runtime.grant.tools))
    tool = runtime.gateway._tools.tool(tool_id)
    assert isinstance(tool, LocalEvaluationTool)
    stable_context = tool.stable_execution_context()
    assert stable_context["implementationVersion"] == (
        "pajin.tool-adapter/web-analysis-transport-v2"
    )
    assert stable_context["effectRuntime"] == runtime_pin.model_dump(mode="json")
    assert stable_context["effectModel"] == model_pin.model_dump(mode="json")
    assert stable_context["webAnalysisTransport"] == transport_pin.model_dump(
        mode="json",
        by_alias=True,
    )
    assert stable_context["providerWorker"] == expected_web_analysis_provider_worker_context(
        transport_pin,
        external_network=model_runtime.network_name,
    )
    assert runtime.execution_context.effect_runtime_pin == runtime_pin

    job = tool.prepare(
        ToolRequest(
            agent_id=runtime.grant.subject,
            tool_id=tool.spec.tool_id,
            target=WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
            method="POST",
            arguments=ProviderChatRequest(
                messages=[ProviderMessage(role=ChatRole.USER, content="proposal")],
                tools=[],
                tool_choice="none",
                max_completion_tokens=1,
            ).model_dump(mode="json", by_alias=True),
        )
    )
    payload = json.loads(job.stdin)

    assert job.image == transport_pin.worker_image
    assert job.command == [WEB_ANALYSIS_PINNED_PROVIDER_ACTION]
    assert job.limits.timeout_seconds == WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS
    assert set(payload) == {
        "providerId",
        "request",
        "requestTimeoutSeconds",
        "target",
        "transportVersion",
    }
    assert payload["requestTimeoutSeconds"] == WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS
    assert payload["transportVersion"] == WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allowed_images", {"sha256:" + "8" * 64}),
        ("egress_proxy_image", "sha256:" + "8" * 64),
        ("external_network", "bridge"),
        (
            "external_network_routes",
            {WEB_ANALYSIS_PINNED_PROVIDER_ACTION: "bridge"},
        ),
    ],
)
def test_successor_dispatch_guard_rejects_live_worker_configuration_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    runtime_pin: RuntimePin,
    model_runtime: LocalModelRuntime,
    field: str,
    value: object,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    transport_pin = web_analysis_transport_runtime_pin(
        runtime_pin,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
        transport_pin=transport_pin,
        expected_transport_pin_digest=transport_pin.pin_digest,
    )
    runtime = assembly.provider_runtime
    worker = _FakeDockerWorkerBackend.instances[0]
    worker.kwargs[field] = value
    tool_id = next(iter(runtime.grant.tools))

    outcome = asyncio.run(
        runtime.gateway.execute(
            runtime.campaign,
            runtime.grant,
            ToolRequest(
                agent_id=runtime.grant.subject,
                tool_id=tool_id,
                target=WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
                method="POST",
                arguments=ProviderChatRequest(
                    messages=[ProviderMessage(role=ChatRole.USER, content="proposal")],
                    tools=[],
                    tool_choice="none",
                    max_completion_tokens=1,
                ).model_dump(mode="json", by_alias=True),
            ),
            used_calls=0,
        )
    )

    assert outcome.decision.allowed
    assert not outcome.executed
    assert outcome.result.error is not None
    assert "tool preparation failed" in outcome.result.error
    assert worker.run_calls == 0
    assert assembly.execution_ids == ()
    event_types = [event_type for event_type, _payload in runtime.store.events]
    assert "tool.preparation_failed" in event_types
    assert "worker.dispatched" not in event_types
    assert "secret.lease.issued" not in event_types


def test_successor_runtime_wraps_base_context_without_replacing_cleanup_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    runtime_pin: RuntimePin,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    transport_pin = web_analysis_transport_runtime_pin(
        runtime_pin,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
        transport_pin=transport_pin,
        expected_transport_pin_digest=transport_pin.pin_digest,
    )

    successor = bind_skill_bound_web_analysis_provider_runtime(
        assembly,
        transport_pin=transport_pin,
        expected_transport_pin_digest=transport_pin.pin_digest,
        expected_external_network=model_runtime.network_name,
    )

    assert successor.base_runtime is assembly.provider_runtime
    assert successor.execution_context.base_provider_execution_context == (
        assembly.provider_runtime.execution_context
    )
    assert (
        successor.execution_context.provider_id
        == assembly.provider_runtime.registration.provider_id
    )
    assert successor.execution_context.model == assembly.provider_runtime.registration.model
    assert successor.execution_context.tool_id == next(iter(assembly.provider_runtime.grant.tools))
    assert successor.execution_context.transport_pin == transport_pin
    assert successor.execution_context.invocation_pin.role == "skill-bound-web-analysis-proposal"
    assert (
        successor.execution_context.base_provider_execution_context.invocation_pin.role
        == "web-analysis-proposal"
    )
    assert successor.execution_context.secret_material_embedded is False
    assert successor.execution_context.execution_authority is False
    assert successor.expected_external_network == model_runtime.network_name

    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        bind_skill_bound_web_analysis_provider_runtime(
            assembly,
            transport_pin=transport_pin,
            expected_transport_pin_digest="0" * 64,
            expected_external_network=model_runtime.network_name,
        )
    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        bind_skill_bound_web_analysis_provider_runtime(
            LocalWebAnalysisProviderAssembly(
                provider_runtime=assembly.provider_runtime,
                finalizer=cast(Any, object()),
            ),
            transport_pin=transport_pin,
            expected_transport_pin_digest=transport_pin.pin_digest,
            expected_external_network="foreign-network",
        )
    with pytest.raises(SkillBoundWebAnalysisRuntimeError, match="binding failed closed"):
        bind_skill_bound_web_analysis_provider_runtime(
            assembly,
            transport_pin=transport_pin,
            expected_transport_pin_digest=transport_pin.pin_digest,
            expected_external_network=model_runtime.network_name,
        )

    forged_base = assembly.provider_runtime.execution_context.model_copy(
        update={"unmodeled_authority": True}
    )
    with pytest.raises(ValueError):
        SkillBoundWebAnalysisProviderExecutionContext(
            baseProviderExecutionContext=forged_base,
            transportPin=transport_pin,
            secretMaterialEmbedded=False,
            executionAuthority=False,
        )

    base_wire = assembly.provider_runtime.execution_context.model_dump(
        mode="json",
        by_alias=True,
    )
    base_wire["contextId"] = ""
    base_wire["contextDigest"] = ""
    nested = base_wire["toolStableExecutionContext"]["context"]
    nested["providerWorker"]["context"]["egressProxyImage"] = "sha256:" + "8" * 64
    forged_worker_context = WebAnalysisProviderExecutionContext.model_validate(base_wire)
    with pytest.raises(ValueError):
        SkillBoundWebAnalysisProviderExecutionContext(
            baseProviderExecutionContext=forged_worker_context,
            transportPin=transport_pin,
            secretMaterialEmbedded=False,
            executionAuthority=False,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("healthy", False),
        ("internal_network", False),
        ("published_ports", True),
        ("container_id", None),
        ("network_id", None),
        ("read_only", False),
        ("cleanup_observed", True),
    ],
)
def test_factory_rejects_nonlive_or_nonisolated_model_lifecycle_before_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
    field: str,
    value: object,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    model_runtime.lifecycle = model_runtime.lifecycle.model_copy(update={field: value})

    with pytest.raises(WebAnalysisLocalRuntimeError, match="healthy owned internal lifecycle"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []


def test_factory_rejects_unpinned_model_and_changed_owned_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    model_runtime.model = model_runtime.model.model_copy(update={"revision": "0" * 40})

    with pytest.raises(WebAnalysisLocalRuntimeError, match="immutable model allowlist"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    model_runtime.model = model_pins()[0]
    model_runtime.network_name = "bridge"
    with pytest.raises(WebAnalysisLocalRuntimeError, match="healthy owned internal lifecycle"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []


def test_factory_rejects_subclassed_runtime_and_hidden_pin_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)

    class DerivedLocalModelRuntime(LocalModelRuntime):
        pass

    derived = DerivedLocalModelRuntime(
        runtime=model_runtime.runtime,
        model=model_runtime.model,
        model_path=model_runtime.model_path,
        key_file=model_runtime.key_file,
    )
    derived.lifecycle = model_runtime.lifecycle
    with pytest.raises(WebAnalysisLocalRuntimeError, match="exact started EFFECT-001"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=derived,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    model_runtime.runtime = model_runtime.runtime.model_copy(
        update={"targetAuthority": "http://127.0.0.1:3000"}
    )
    with pytest.raises(WebAnalysisLocalRuntimeError, match="runtime pin type or state differs"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []


def test_factory_rejects_request_above_fixed_model_budget_before_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    monkeypatch.setattr(
        analysis_local,
        "provider_model_usage_upper_bound",
        lambda _registration, _request: ProviderModelUsageBound(
            prompt_tokens=WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS,
            completion_tokens=1,
            cost_usd=0,
        ),
    )

    with pytest.raises(WebAnalysisLocalRuntimeError, match="exceeds its model-token budget"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []


def test_assembly_cleans_exact_tool_execution_ids_once_and_verifies_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
    )
    tool_id = next(iter(assembly.provider_runtime.grant.tools))
    tool = assembly.provider_runtime.gateway._tools.tool(tool_id)
    assert isinstance(tool, LocalEvaluationTool)
    grant = assembly.provider_runtime.grant
    job = tool.prepare(
        ToolRequest(
            agent_id=grant.subject,
            tool_id=tool.spec.tool_id,
            target=WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
            method="POST",
            arguments=ProviderChatRequest(
                messages=[ProviderMessage(role=ChatRole.USER, content="proposal")],
                tools=[],
                tool_choice="none",
                max_completion_tokens=1,
            ).model_dump(mode="json", by_alias=True),
        )
    )
    execution_id = job.execution_id
    cleanup_calls: list[list[str]] = []

    def cleanup(execution_ids: list[str]) -> None:
        cleanup_calls.append(list(execution_ids))
        model_runtime.lifecycle = model_runtime.lifecycle.model_copy(
            update={
                "execution_ids": tuple(execution_ids),
                "remaining_containers": (),
                "remaining_networks": (),
                "cleanup_observed": True,
            }
        )

    monkeypatch.setattr(model_runtime, "cleanup", cleanup)
    assembly.provider_runtime.finalize_provider_run()
    first = assembly.cleanup()
    second = assembly.cleanup()

    assert first is second
    assert first.execution_ids == (execution_id,)
    assert first.lifecycle == model_runtime.lifecycle
    assert first.lifecycle.clean is True
    assert cleanup_calls == [[execution_id]]
    store = assembly.provider_runtime.store
    assert store.artifacts == {
        "local-provider-finalization.json": {
            "apiVersion": "pajin.dev/web-analysis-local-provider-finalization/v1alpha1",
            "kind": "WebAnalysisLocalProviderFinalization",
            "providerRunId": store.run_id,
            "providerId": WEB_ANALYSIS_LOCAL_PROVIDER_ID,
            "providerExecutionContextId": (assembly.provider_runtime.execution_context.context_id),
            "providerExecutionContextDigest": (
                assembly.provider_runtime.execution_context.context_digest
            ),
            "executionIds": [execution_id],
            "lifecycle": first.lifecycle.model_dump(mode="json"),
            "cleanupObserved": True,
            "externalDeliveryPerformed": False,
        }
    }
    assert store.events == [
        (
            "web-analysis.local-provider.finalized",
            {
                "providerExecutionContextId": (
                    assembly.provider_runtime.execution_context.context_id
                ),
                "providerExecutionContextDigest": (
                    assembly.provider_runtime.execution_context.context_digest
                ),
                "executionIds": [execution_id],
                "cleanupObserved": True,
                "externalDeliveryPerformed": False,
            },
        )
    ]


def test_assembly_uses_captured_execution_id_and_rejects_changed_owner_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
    )
    tool_id = next(iter(assembly.provider_runtime.grant.tools))
    tool = assembly.provider_runtime.gateway._tools.tool(tool_id)
    assert isinstance(tool, LocalEvaluationTool)
    cleanup_calls: list[list[str]] = []
    original_label = model_runtime.label
    original_lifecycle = model_runtime.lifecycle
    model_runtime.label = "pajin.effect-001-owner=" + "7" * 32
    with pytest.raises(WebAnalysisLocalRuntimeError, match="healthy owned internal lifecycle"):
        assembly.cleanup()
    model_runtime.label = original_label
    model_runtime.lifecycle = original_lifecycle.model_copy(update={"container_id": "7" * 64})
    with pytest.raises(WebAnalysisLocalRuntimeError, match="changed after assembly"):
        assembly.cleanup()
    model_runtime.lifecycle = original_lifecycle

    grant = assembly.provider_runtime.grant
    job = tool.prepare(
        ToolRequest(
            agent_id=grant.subject,
            tool_id=tool.spec.tool_id,
            target=WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
            method="POST",
            arguments=ProviderChatRequest(
                messages=[ProviderMessage(role=ChatRole.USER, content="proposal")],
                tools=[],
                tool_choice="none",
                max_completion_tokens=1,
            ).model_dump(mode="json", by_alias=True),
        )
    )
    forged_id = "exec_" + "7" * 32
    tool.execution_ids.append(forged_id)

    def cleanup(execution_ids: list[str]) -> None:
        cleanup_calls.append(list(execution_ids))
        model_runtime.lifecycle = model_runtime.lifecycle.model_copy(
            update={
                "execution_ids": tuple(execution_ids),
                "cleanup_observed": True,
            }
        )

    monkeypatch.setattr(model_runtime, "cleanup", cleanup)
    result = assembly.cleanup()

    assert assembly.execution_ids == (job.execution_id,)
    assert result.execution_ids == (job.execution_id,)
    assert forged_id not in result.execution_ids
    assert cleanup_calls == [[job.execution_id]]


def test_assembly_rejects_changed_resource_identity_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
    )
    cleanup_calls: list[list[str]] = []

    def cleanup(execution_ids: list[str]) -> None:
        cleanup_calls.append(list(execution_ids))
        model_runtime.lifecycle = model_runtime.lifecycle.model_copy(
            update={
                "container_id": "8" * 64,
                "execution_ids": tuple(execution_ids),
                "cleanup_observed": True,
            }
        )

    monkeypatch.setattr(model_runtime, "cleanup", cleanup)

    with pytest.raises(WebAnalysisLocalRuntimeError, match="cleanup evidence differs"):
        assembly.cleanup()

    assert cleanup_calls == [[]]


@pytest.mark.parametrize("failure_stage", ["artifact", "event"])
def test_assembly_resumes_evidence_recording_without_repeating_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
    failure_stage: str,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
    )
    cleanup_calls: list[list[str]] = []

    def cleanup(execution_ids: list[str]) -> None:
        cleanup_calls.append(list(execution_ids))
        model_runtime.lifecycle = model_runtime.lifecycle.model_copy(
            update={
                "execution_ids": tuple(execution_ids),
                "cleanup_observed": True,
            }
        )

    monkeypatch.setattr(model_runtime, "cleanup", cleanup)
    store = assembly.provider_runtime.store
    original_write = store.write_json_create_only
    original_append = store.append_event
    write_calls = 0
    event_calls = 0

    def write(relative_path: str, data: object) -> str:
        nonlocal write_calls
        write_calls += 1
        if failure_stage == "artifact" and write_calls == 1:
            raise OSError("synthetic artifact failure")
        return original_write(relative_path, data)

    def append(event_type: str, payload: dict[str, object]) -> None:
        nonlocal event_calls
        event_calls += 1
        if failure_stage == "event" and event_calls == 1:
            raise OSError("synthetic event failure")
        original_append(event_type, payload)

    monkeypatch.setattr(store, "write_json_create_only", write)
    monkeypatch.setattr(store, "append_event", append)

    with pytest.raises(OSError, match=f"synthetic {failure_stage} failure"):
        assembly.cleanup()
    result = assembly.cleanup()

    assert result.lifecycle.clean is True
    assert cleanup_calls == [[]]
    assert write_calls == (2 if failure_stage == "artifact" else 1)
    assert event_calls == (1 if failure_stage == "artifact" else 2)
    assert list(store.artifacts) == ["local-provider-finalization.json"]
    assert [event_type for event_type, _payload in store.events] == [
        "web-analysis.local-provider.finalized"
    ]


def test_cleanup_closes_tool_before_any_later_prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
    )
    tool_id = next(iter(assembly.provider_runtime.grant.tools))
    tool = assembly.provider_runtime.gateway._tools.tool(tool_id)
    assert isinstance(tool, LocalEvaluationTool)
    grant = assembly.provider_runtime.grant
    request = ToolRequest(
        agent_id=grant.subject,
        tool_id=tool.spec.tool_id,
        target=WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
        method="POST",
        arguments=ProviderChatRequest(
            messages=[ProviderMessage(role=ChatRole.USER, content="proposal")],
            tools=[],
            tool_choice="none",
            max_completion_tokens=1,
        ).model_dump(mode="json", by_alias=True),
    )
    cleanup_calls: list[list[str]] = []

    def cleanup(execution_ids: list[str]) -> None:
        cleanup_calls.append(list(execution_ids))
        model_runtime.lifecycle = model_runtime.lifecycle.model_copy(
            update={
                "execution_ids": tuple(execution_ids),
                "cleanup_observed": True,
            }
        )

    monkeypatch.setattr(model_runtime, "cleanup", cleanup)

    result = assembly.cleanup()
    with pytest.raises(WebAnalysisLocalRuntimeError, match="closed or already prepared"):
        tool.prepare(request)

    assert result.execution_ids == ()
    assert cleanup_calls == [[]]


def test_prepare_and_cleanup_share_one_atomic_terminal_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)
    assembly = build_local_web_analysis_provider_runtime(
        source=source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
        model_runtime=model_runtime,
        api_key="unit-test-local-provider-key",
        provider_store_root=tmp_path / "provider-store",
        analysis_output_root=tmp_path / "analysis-output",
    )
    tool_id = next(iter(assembly.provider_runtime.grant.tools))
    tool = assembly.provider_runtime.gateway._tools.tool(tool_id)
    assert isinstance(tool, LocalEvaluationTool)
    grant = assembly.provider_runtime.grant
    request = ToolRequest(
        agent_id=grant.subject,
        tool_id=tool.spec.tool_id,
        target=WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
        method="POST",
        arguments=ProviderChatRequest(
            messages=[ProviderMessage(role=ChatRole.USER, content="proposal")],
            tools=[],
            tool_choice="none",
            max_completion_tokens=1,
        ).model_dump(mode="json", by_alias=True),
    )
    prepare_entered = Event()
    allow_prepare = Event()
    original_prepare = LocalEvaluationTool.prepare

    def blocking_prepare(self: LocalEvaluationTool, value: ToolRequest) -> WorkerJob:
        prepare_entered.set()
        assert allow_prepare.wait(timeout=5)
        return original_prepare(self, value)

    monkeypatch.setattr(LocalEvaluationTool, "prepare", blocking_prepare)
    cleanup_calls: list[list[str]] = []

    def cleanup(execution_ids: list[str]) -> None:
        cleanup_calls.append(list(execution_ids))
        model_runtime.lifecycle = model_runtime.lifecycle.model_copy(
            update={
                "execution_ids": tuple(execution_ids),
                "cleanup_observed": True,
            }
        )

    monkeypatch.setattr(model_runtime, "cleanup", cleanup)
    with ThreadPoolExecutor(max_workers=2) as pool:
        prepare_future = pool.submit(tool.prepare, request)
        assert prepare_entered.wait(timeout=5)
        cleanup_future = pool.submit(assembly.cleanup)
        allow_prepare.set()
        job = prepare_future.result(timeout=5)
        result = cleanup_future.result(timeout=5)

    assert result.execution_ids == (job.execution_id,)
    assert cleanup_calls == [[job.execution_id]]


def test_factory_requires_independent_discovery_anchors_before_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    reload_calls = _patch_runtime_boundaries(monkeypatch, source)

    with pytest.raises(WebAnalysisLocalRuntimeError, match="independent discovery anchors"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id="run_20260916T000000Z_00000000",
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )
    with pytest.raises(WebAnalysisLocalRuntimeError, match="independent discovery anchors"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest="0" * 64,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert reload_calls == []
    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []


def test_factory_rejects_changed_source_and_output_inside_sealed_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    changed = replace(
        source,
        index=source.index.model_copy(update={"discovery_evidence_digest": "d" * 64}),
    )
    _patch_runtime_boundaries(monkeypatch, source, reloaded=changed)

    with pytest.raises(WebAnalysisLocalRuntimeError, match="changed during strict reload"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    _patch_runtime_boundaries(monkeypatch, source)
    with pytest.raises(WebAnalysisLocalRuntimeError, match="sealed source Run"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=source.run_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []


def test_factory_resolves_output_symlink_before_sealed_run_containment_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    sealed_run = tmp_path / "sealed-discovery-run"
    sealed_run.mkdir()
    output_alias = tmp_path / "output-alias"
    output_alias.symlink_to(sealed_run, target_is_directory=True)
    relocated = replace(source, run_path=sealed_run)
    _patch_runtime_boundaries(monkeypatch, relocated)

    with pytest.raises(WebAnalysisLocalRuntimeError, match="sealed source Run"):
        build_local_web_analysis_provider_runtime(
            source=relocated,
            expected_run_id=relocated.verification.run_id,
            expected_root_digest=relocated.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=output_alias / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []


def test_factory_rejects_wrong_source_type_and_empty_secret_before_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: VerifiedAuthenticatedDiscoveryRun,
    model_runtime: LocalModelRuntime,
) -> None:
    _patch_runtime_boundaries(monkeypatch, source)

    with pytest.raises(WebAnalysisLocalRuntimeError, match="exact verified discovery source type"):
        build_local_web_analysis_provider_runtime(  # type: ignore[arg-type]
            source=object(),
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="unit-test-local-provider-key",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    with pytest.raises(WebAnalysisLocalRuntimeError, match="construction failed closed"):
        build_local_web_analysis_provider_runtime(
            source=source,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
            model_runtime=model_runtime,
            api_key="",
            provider_store_root=tmp_path / "provider-store",
            analysis_output_root=tmp_path / "analysis-output",
        )

    assert _FakeDockerWorkerBackend.instances == []
    assert _FakeRunStore.calls == []
