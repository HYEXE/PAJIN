"""Fixed local Provider registration and the existing Policy/Gateway/Worker call path."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import AnyHttpUrl

from pajin.benchmark.effectiveness.evidence import Trial
from pajin.benchmark.effectiveness.suite import ENDPOINT, Coordinate, RuntimePin
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest
from pajin.policy.capability import CapabilityLedger
from pajin.policy.engine import PolicyEngine
from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.providers.openai_compatible import OpenAICompatibleChatTool
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.control import BudgetController
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend, WorkerJob
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway


def registration_for(coordinate: Coordinate) -> ProviderRegistration:
    return ProviderRegistration(
        provider_id="effect-001",
        endpoint=AnyHttpUrl(ENDPOINT),
        model=coordinate.model,
        secret_ref="effect-001/local-api-key",
        allow_private_networks=True,
        allow_streaming=False,
        lease_ttl_seconds=240,
    )


def local_campaign() -> CampaignManifest:
    """The CLI operator selects this fixed disposable-local scope; no remote target input."""
    now = datetime.now(UTC)
    return CampaignManifest.model_validate(
        {
            "apiVersion": "pajin.dev/v1alpha1",
            "kind": "Campaign",
            "metadata": {"name": "effect-001-run"},
            "spec": {
                "mode": "ai-redteam",
                "autonomy": "lab-autonomous",
                "authorization": {
                    "approvedBy": "local-evaluation-operator",
                    "approvedAt": now,
                    "expiresAt": now + timedelta(days=1),
                    "evidence": "explicit-local-effect-001-cli-invocation",
                },
                "targets": [{"type": "local-llm", "id": "effect-001", "endpoint": ENDPOINT}],
                "scope": {"allow": [ENDPOINT]},
                "objectives": ["Private canary detector evaluation"],
                "rulesOfEngagement": {
                    "maxToolRiskTier": "T1",
                    "allowedMethods": ["POST"],
                    "allowPrivateNetworks": True,
                },
                "budgets": {
                    "durationSeconds": 86400,
                    "maxCostUsd": 0,
                    "maxAgents": 1,
                    "maxSpawnDepth": 1,
                    "maxToolCalls": 384,
                    "maxModelCalls": 384,
                    "maxModelTokens": 10000000,
                },
                "outputs": [],
            },
        }
    )


class LocalEvaluationTool(OpenAICompatibleChatTool):
    """Pin only this evaluation's Worker image and timeout, without changing global defaults."""

    def __init__(self, registration: ProviderRegistration, runtime: RuntimePin) -> None:
        super().__init__(registration)
        self.runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        self.execution_ids: list[str] = []

    def stable_execution_context(self) -> dict[str, object]:
        return {**super().stable_execution_context(), "effectRuntime": self.runtime.model_dump()}

    def prepare(self, request: ToolRequest) -> WorkerJob:
        original = super().prepare(request)
        job = WorkerJob.model_validate(
            {
                **original.model_dump(),
                "image": self.runtime.worker_image,
                "limits": {
                    **original.limits.model_dump(),
                    "timeout_seconds": self.runtime.request_timeout_seconds,
                },
            }
        )
        self.execution_ids.append(job.execution_id)
        return job


class RecordingGateway(ToolGateway):
    """Keep detached sources for the bound-outcome verifier; dispatch stays in ToolGateway."""

    last_request: ToolRequest | None = None
    last_outcome: GatewayOutcome | None = None

    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome:
        self.last_request = request.model_copy(deep=True)
        self.last_outcome = None
        result = await super().execute(campaign, grant, request, used_calls=used_calls)
        self.last_outcome = result.model_copy(deep=True)
        return result


def provider_port(
    *,
    coordinate: Coordinate,
    runtime: RuntimePin,
    network: str,
    key: str,
    campaign: CampaignManifest,
    budget: BudgetController,
    ledger: CapabilityLedger,
    root_grant: CapabilityGrant,
    store: RunStore,
) -> tuple[PolicyBoundProviderPort, RecordingGateway, LocalEvaluationTool, CapabilityGrant]:
    registration = registration_for(coordinate)
    tool = LocalEvaluationTool(registration, runtime)
    registry = ToolRegistry()
    registry.register(tool)
    broker = SecretBroker()
    broker.register(registration.secret_ref, key)
    worker = DockerWorkerBackend(
        allowed_images={runtime.worker_image},
        egress_proxy_image=runtime.proxy_image,
        external_network=network,
        external_network_routes={"openai-chat-completion": network},
    )
    grant = ledger.delegate(
        root_grant.grant_id,
        subject=f"agent:{store.run_id}",
        tools={tool.spec.tool_id},
        targets={ENDPOINT},
        max_risk_tier=tool.spec.risk_tier,
        max_calls=16,
    )
    gateway = RecordingGateway(
        policy=PolicyEngine(), tools=registry, worker=worker, store=store, secrets=broker
    )
    port = PolicyBoundProviderPort(
        registration=registration,
        campaign=campaign,
        grant=grant,
        ledger=ledger,
        budget=budget,
        gateway=gateway,
        store=store,
    )
    return port, gateway, tool, grant


async def execute_trial(
    *,
    port: PolicyBoundProviderPort,
    gateway: RecordingGateway,
    grant: CapabilityGrant,
    case_id: str,
    chat: ProviderChatRequest,
    run_id: str,
) -> Trial:
    from time import monotonic

    started = monotonic()
    gateway.last_request = None
    gateway.last_outcome = None
    try:
        call = await port.chat_bound(
            role="local-evaluation", attempt=1, chat=chat, request_id=f"{run_id}-{case_id}"
        )
    except Exception as exc:
        return Trial(
            case_id=case_id,
            elapsed_seconds=monotonic() - started,
            error_type=type(exc).__name__,
            chat=chat,
            grant=grant,
            request=gateway.last_request,
            gateway=gateway.last_outcome,
        )
    return Trial(
        case_id=case_id,
        elapsed_seconds=monotonic() - started,
        chat=chat,
        grant=grant,
        request=gateway.last_request,
        gateway=gateway.last_outcome,
        result=call.result,
        receipt=call.outcome,
    )
