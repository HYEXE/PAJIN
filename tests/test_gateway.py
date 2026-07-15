import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolRiskTier
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    NetworkMode,
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.tools.http import HTTPGetTool
from pajin.tools.mock import MockAgentProbe


class NeverWorker:
    async def run(self, job: WorkerJob) -> WorkerResult:
        raise AssertionError(f"worker must not run for denied request: {job.execution_id}")


class RecordingWorker:
    def __init__(self) -> None:
        self.job: WorkerJob | None = None

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.job = job
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="recording",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout='{"status":200}',
            started_at=now,
            finished_at=now,
        )


def _grant(campaign: CampaignManifest, target: str) -> CapabilityGrant:
    return CapabilityGrant(
        subject="agent:planner-local",
        campaign=campaign.metadata.name,
        tools={"mock.agent-probe"},
        targets={target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=5,
        expires_at=campaign.spec.authorization.expires_at,
        delegable=True,
    )


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    return registry


def test_gateway_never_dispatches_policy_denied_request(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    denied_target = "https://staging.example.invalid/api/admin/delete"
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=NeverWorker(),
        store=store,
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=denied_target,
        method="POST",
    )

    outcome = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, denied_target),
            request,
            used_calls=0,
        )
    )

    assert not outcome.executed
    assert not outcome.result.success
    assert outcome.decision.policy == "scope-deny"


def test_gateway_records_sanitized_job_metadata_and_worker_result(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=SimulatedWorkerBackend(),
        store=store,
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"simulation": target.simulation},
    )

    outcome = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request,
            used_calls=0,
        )
    )

    assert outcome.executed
    assert outcome.result.success
    evidence_path = store.path / outcome.result.evidence[0]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert "stdin" not in evidence["workerJob"]
    assert len(evidence["workerJob"]["stdinSha256"]) == 64
    assert evidence["workerResult"]["backend"] == "simulated"


def test_gateway_is_the_only_component_that_grants_egress(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    registry = ToolRegistry()
    registry.register(HTTPGetTool())
    worker = RecordingWorker()
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=worker,
        store=store,
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="http.get",
        target=target,
        method="GET",
    )
    grant = CapabilityGrant(
        subject=request.agent_id,
        campaign=sample_campaign.metadata.name,
        tools={request.tool_id},
        targets={target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=sample_campaign.spec.authorization.expires_at,
    )

    outcome = asyncio.run(gateway.execute(sample_campaign, grant, request, used_calls=0))

    assert outcome.executed
    assert worker.job is not None
    assert worker.job.network is NetworkMode.EGRESS_PROXY
    assert worker.job.egress_policy is not None
    assert worker.job.egress_policy.allow == sample_campaign.spec.scope.allow
    assert worker.job.egress_policy.deny == sample_campaign.spec.scope.deny
    assert worker.job.egress_policy.allowed_methods == {"GET", "HEAD", "POST"}


def test_gateway_enforces_per_campaign_request_rate(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    rules = sample_campaign.spec.rules_of_engagement.model_copy(
        update={"max_requests_per_minute": 1}
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"rules_of_engagement": rules})}
    )
    target = campaign.spec.targets[0]
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=SimulatedWorkerBackend(),
        store=RunStore.create(tmp_path, campaign.metadata.name),
        clock=lambda: datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    def request() -> ToolRequest:
        return ToolRequest(
            agent_id="agent:planner-local",
            tool_id="mock.agent-probe",
            target=target.endpoint,
            method="POST",
            arguments={"simulation": target.simulation},
        )

    first = asyncio.run(
        gateway.execute(campaign, _grant(campaign, target.endpoint), request(), used_calls=0)
    )
    second = asyncio.run(
        gateway.execute(campaign, _grant(campaign, target.endpoint), request(), used_calls=1)
    )

    assert first.executed
    assert not second.executed
    assert second.decision.policy == "rate-limit"


def test_gateway_counts_every_ai_chat_turn_against_the_request_rate(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    rules = sample_campaign.spec.rules_of_engagement.model_copy(
        update={"max_requests_per_minute": 1}
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"rules_of_engagement": rules})}
    )
    scenario = next(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.agent.memory-poisoning-persistence"
    )
    assert scenario.probe is not None
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="ai.chat-probe",
        target=campaign.spec.targets[0].endpoint,
        method="POST",
        arguments=AIChatProbeInput(
            scenario_id=scenario.scenario_id,
            threat_class="A04",
            session_id="pajin:test:rate",
            turns=scenario.probe.turns,
            checks=scenario.probe.checks,
        ).model_dump(mode="json"),
    )
    registry = ToolRegistry()
    registry.register(AIChatProbeTool())
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=NeverWorker(),
        store=RunStore.create(tmp_path, campaign.metadata.name),
        clock=lambda: datetime(2026, 7, 15, 1, tzinfo=UTC),
    )
    grant = CapabilityGrant(
        subject=request.agent_id,
        campaign=campaign.metadata.name,
        tools={request.tool_id},
        targets={request.target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=campaign.spec.authorization.expires_at,
    )

    outcome = asyncio.run(gateway.execute(campaign, grant, request, used_calls=0))

    assert AIChatProbeTool().network_request_cost(request) == 2
    assert not outcome.executed
    assert outcome.decision.policy == "rate-limit"
