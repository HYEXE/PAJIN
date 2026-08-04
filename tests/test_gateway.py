import asyncio
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.runtime.secrets import SecretBroker, SecretLease, SecretMaterial
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    SimulatedWorkerBackend,
    WorkerCleanupError,
    WorkerJob,
    WorkerLimits,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.tools import execution_receipts
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
from pajin.tools.base import ToolRegistry, ToolSpec
from pajin.tools.gateway import (
    GatewayOutcome,
    RequestRateLimitLedger,
    ToolGateway,
    canonical_tool_request_digest,
)
from pajin.tools.http import HTTPGetTool
from pajin.tools.mock import MockAgentProbe


@pytest.mark.parametrize(
    ("model", "field", "value"),
    [
        (PolicyDecision, "allowed", 1),
        (PolicyDecision, "allowed", "false"),
        (ToolResult, "success", 1),
        (ToolResult, "success", "true"),
    ],
)
def test_gateway_authority_models_reject_coerced_boolean_fields(
    model: type[PolicyDecision] | type[ToolResult],
    field: str,
    value: object,
) -> None:
    now = datetime.now(UTC)
    payload: dict[str, object]
    if model is PolicyDecision:
        payload = {"allowed": True, "reason": "test", "policy": "test"}
    else:
        payload = {
            "request_id": "request_safe",
            "tool_id": "tool.safe",
            "success": True,
            "started_at": now,
            "finished_at": now,
        }
    payload[field] = value

    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("network_log_trusted", 0),
        ("network_log_trusted", "false"),
        ("result_identity_valid", 1),
        ("result_identity_valid", "true"),
        ("executed", 0),
        ("executed", "false"),
    ],
)
def test_gateway_outcome_rejects_coerced_boolean_fields(
    field: str,
    value: object,
) -> None:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "decision": PolicyDecision(allowed=True, reason="test", policy="test"),
        "result": ToolResult(
            request_id="request_safe",
            tool_id="tool.safe",
            success=True,
            started_at=now,
            finished_at=now,
        ),
        "network_log_trusted": False,
        "result_identity_valid": True,
        "executed": True,
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        GatewayOutcome.model_validate(payload)


class NeverWorker:
    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.never-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        raise AssertionError(f"worker must not run for denied request: {job.execution_id}")


class RecordingWorker:
    def __init__(self) -> None:
        self.job: WorkerJob | None = None
        self.calls = 0

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.recording-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        self.calls += 1
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


class SlowRecordingWorker(RecordingWorker):
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        await asyncio.sleep(0.02)
        return await super().run(job, secrets=secrets)


class WorkerForgingDockerLabel(RecordingWorker):
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        result = await super().run(job, secrets=secrets)
        return result.model_copy(
            update={
                "backend": "docker",
                "network_log": '{"event":"allow","receiptVersion":"forged"}',
                "stdout": json.dumps(
                    {
                        "target": json.loads(job.stdin)["target"],
                        "status": 200,
                        "bodyPreview": "",
                        "bodySha256": sha256(b"").hexdigest(),
                        "responseBodyBase64": "",
                    }
                ),
            }
        )


class MismatchedExecutionWorker(RecordingWorker):
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        result = await super().run(job, secrets=secrets)
        return result.model_copy(update={"execution_id": "exec_other"})


class MutatingExecutionWorker(RecordingWorker):
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        job.execution_id = "exec_mutated_by_worker"
        return await super().run(job, secrets=secrets)


class CleanupFailingWorker:
    def __init__(self, error: WorkerCleanupError) -> None:
        self.error = error

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.cleanup-failing-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del job, secrets
        raise self.error


class ExceptionRaisingWorker:
    def __init__(self, detail: str) -> None:
        self.detail = detail

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.exception-raising-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del job, secrets
        raise RuntimeError(self.detail)


class TranscriptFailingWorker:
    def __init__(self, transcript: str) -> None:
        self.transcript = transcript

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.transcript-failing-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="transcript-test",
            status=WorkerStatus.FAILED,
            exit_code=2,
            stderr=self.transcript,
            started_at=now,
            finished_at=now,
        )


class TruncatedSuccessWorker:
    def __init__(self, *, stream: str) -> None:
        self.stream = stream

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.truncated-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        now = datetime.now(UTC)
        payload = json.loads(job.stdin)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="truncation-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(
                {
                    "target": payload["target"],
                    "vulnerable": False,
                    "networkPerformed": False,
                }
            ),
            stdout_truncated=self.stream == "stdout",
            stderr_truncated=self.stream == "stderr",
            started_at=now,
            finished_at=now,
        )


class RejectingTrustedProbe(MockAgentProbe):
    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        del request, result, worker_result, network_log_trusted
        raise ValueError("sealed execution proof does not match")


class MutatingTrustedProbe(MockAgentProbe):
    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        del network_log_trusted
        request.arguments["mutated"] = True
        result.data["mutated"] = True
        result.evidence.append("forged-evidence.json")
        worker_result.stdout = "mutated worker transcript"


class MutatingCostProbe(MockAgentProbe):
    def __init__(self) -> None:
        self.prepared_target: str | None = None

    def network_request_cost(self, request: ToolRequest) -> int:
        request.target = "https://outside.example.invalid/mutated"
        request.arguments["mutated"] = True
        return super().network_request_cost(request)

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self.prepared_target = request.target
        return super().prepare(request)


class MalformedJobProbe(MockAgentProbe):
    def prepare(self, request: ToolRequest) -> WorkerJob:
        return super().prepare(request).model_copy(update={"command": []})


class ExceptionRaisingPrepareProbe(MockAgentProbe):
    def __init__(self, detail: str) -> None:
        self.detail = detail

    def prepare(self, request: ToolRequest) -> WorkerJob:
        del request
        raise RuntimeError(self.detail)


class ExceptionRaisingInterpretProbe(MockAgentProbe):
    def __init__(self, detail: str) -> None:
        self.detail = detail

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del request, result
        raise RuntimeError(self.detail)


class ExceptionRaisingTrustedProbe(MockAgentProbe):
    def __init__(self, detail: str) -> None:
        self.detail = detail

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        del request, result, worker_result, network_log_trusted
        raise RuntimeError(self.detail)


class ErrorReturningProbe(MockAgentProbe):
    def __init__(self, detail: str) -> None:
        self.detail = detail

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=False,
            started_at=result.started_at,
            finished_at=result.finished_at,
            error=self.detail,
        )


class PartialSecretProbe(MockAgentProbe):
    def prepare(self, request: ToolRequest) -> WorkerJob:
        return (
            super()
            .prepare(request)
            .model_copy(
                update={
                    "secret_requests": [
                        WorkerSecretRequest(secret_ref="gateway/present", binding="first"),
                        WorkerSecretRequest(secret_ref="gateway/missing", binding="second"),
                    ]
                }
            )
        )


class SingleSecretProbe(MockAgentProbe):
    def prepare(self, request: ToolRequest) -> WorkerJob:
        return (
            super()
            .prepare(request)
            .model_copy(
                update={
                    "secret_requests": [
                        WorkerSecretRequest(secret_ref="gateway/cancel", binding="token")
                    ]
                }
            )
        )


class CancellingSecretBroker(SecretBroker):
    def issue(
        self,
        secret_ref: str,
        *,
        audience: str,
        binding: str,
        scope: str | None = None,
        ttl_seconds: int = 30,
        max_uses: int = 1,
    ) -> SecretLease:
        lease = super().issue(
            secret_ref,
            audience=audience,
            binding=binding,
            scope=scope,
            ttl_seconds=ttl_seconds,
            max_uses=max_uses,
        )
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        return lease


class ExceptionRaisingSecretBroker(SecretBroker):
    def __init__(self, detail: str) -> None:
        super().__init__()
        self.detail = detail

    def issue(
        self,
        secret_ref: str,
        *,
        audience: str,
        binding: str,
        scope: str | None = None,
        ttl_seconds: int = 30,
        max_uses: int = 1,
    ) -> SecretLease:
        del secret_ref, audience, binding, scope, ttl_seconds, max_uses
        raise RuntimeError(self.detail)


class MutatingPolicyEngine(PolicyEngine):
    def evaluate_tool_request(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        tool: ToolSpec,
        *,
        used_calls: int,
        now: datetime | None = None,
    ) -> PolicyDecision:
        decision = super().evaluate_tool_request(
            campaign,
            grant,
            request,
            tool,
            used_calls=used_calls,
            now=now,
        )
        campaign.spec.scope.allow.append("https://outside.example.invalid/**")
        grant.targets.add("https://outside.example.invalid/mutated")
        request.target = "https://outside.example.invalid/mutated"
        return decision


class MalformedResultProbe(MockAgentProbe):
    def __init__(self, mutation: str) -> None:
        self.mutation = mutation

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        interpreted = super().interpret(request, result)
        if self.mutation == "request-id":
            return interpreted.model_copy(update={"request_id": "tool_other"})
        if self.mutation == "tool-id":
            return interpreted.model_copy(update={"tool_id": "mock.other"})
        if self.mutation == "timestamps":
            return interpreted.model_copy(
                update={"finished_at": interpreted.started_at - timedelta(seconds=1)}
            )
        if self.mutation == "success-error":
            return interpreted.model_copy(update={"error": "contradictory error"})
        if self.mutation == "failure-error":
            return interpreted.model_copy(update={"success": False, "error": None})
        if self.mutation == "nested-evidence":
            return interpreted.model_copy(update={"evidence": ["forged.json"]})
        raise AssertionError(f"unknown malformed result mutation: {self.mutation}")


class FalseSuccessProbe(MockAgentProbe):
    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data={"claimedSuccess": True},
        )


class NonJSONResultProbe(MockAgentProbe):
    def __init__(self, value: object) -> None:
        self.value = value

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        interpreted = super().interpret(request, result)
        return interpreted.model_copy(update={"data": {"invalid": self.value}}, deep=True)


def _grant(campaign: CampaignManifest, target: str) -> CapabilityGrant:
    return CapabilityGrant(
        subject="agent:planner-local",
        campaign=campaign.metadata.name,
        tools={"mock.agent-probe"},
        targets={target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=5,
        issued_at=campaign.spec.authorization.approved_at,
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


def test_gateway_revalidates_copied_request_before_deriving_evidence_path(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    store.write_json("campaign.json", sample_campaign.model_dump(mode="json"))
    campaign_path = store.path / "campaign.json"
    campaign_bytes = campaign_path.read_bytes()
    target = sample_campaign.spec.targets[0]
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"simulation": target.simulation},
    ).model_copy(update={"request_id": "../campaign"})
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=NeverWorker(),
        store=store,
    )

    with pytest.raises(ValueError, match="strict canonical JSON"):
        canonical_tool_request_digest(request)

    outcome = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request,
            used_calls=0,
        )
    )

    assert not outcome.executed
    assert outcome.decision.policy == "request-contract"
    assert not outcome.result.success
    assert outcome.result.evidence == []
    assert campaign_path.read_bytes() == campaign_bytes
    assert list((store.path / "evidence").iterdir()) == []


@pytest.mark.parametrize(
    "invalid_value",
    [{"unordered", "set"}, float("nan")],
    ids=["python-set", "non-finite-number"],
)
def test_gateway_rejects_non_json_request_arguments_before_reservation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    invalid_value: object,
) -> None:
    target = sample_campaign.spec.targets[0]
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"invalid": invalid_value},
    )
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=NeverWorker(),
        store=store,
    )

    outcome = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request,
            used_calls=0,
        )
    )

    assert not outcome.executed
    assert outcome.decision.policy == "request-contract"
    assert outcome.result.evidence == []
    assert not store.artifact_exists(f"requests/{request.request_id}.json")
    assert not store.artifact_exists(f"evidence/{request.request_id}.json")


def test_duplicate_request_is_rejected_before_second_worker_and_evidence_overwrite(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"simulation": target.simulation},
    )
    worker = RecordingWorker()
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=worker,
        store=store,
    )

    first = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request,
            used_calls=0,
        )
    )
    evidence_path = store.path / first.result.evidence[0]
    original_evidence = evidence_path.read_bytes()
    reservation_path = store.path / f"requests/{request.request_id}.json"
    original_reservation = reservation_path.read_bytes()
    reservation = json.loads(original_reservation)
    assert reservation["requestSha256"] == canonical_tool_request_digest(request)
    second = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request,
            used_calls=1,
        )
    )

    assert first.executed
    assert not second.executed
    assert second.decision.policy == "request-id"
    assert second.result.evidence == []
    assert worker.calls == 1
    assert evidence_path.read_bytes() == original_evidence
    assert reservation_path.read_bytes() == original_reservation
    events = [
        json.loads(line)["event_type"]
        for line in store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert events.count("worker.dispatched") == 1
    assert events.count("tool.request_reserved") == 1


def test_concurrent_gateways_share_os_atomic_request_reservation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"simulation": target.simulation},
    )
    worker = SlowRecordingWorker()
    first_store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    second_store = RunStore(first_store.run_id, first_store.path)
    first_gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=worker,
        store=first_store,
    )
    second_gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=worker,
        store=second_store,
    )

    async def execute_both() -> tuple[GatewayOutcome, GatewayOutcome]:
        first, second = await asyncio.gather(
            first_gateway.execute(
                sample_campaign,
                _grant(sample_campaign, target.endpoint),
                request.model_copy(deep=True),
                used_calls=0,
            ),
            second_gateway.execute(
                sample_campaign,
                _grant(sample_campaign, target.endpoint),
                request.model_copy(deep=True),
                used_calls=0,
            ),
        )
        return first, second

    outcomes = asyncio.run(execute_both())
    executed = [outcome for outcome in outcomes if outcome.executed]
    duplicates = [outcome for outcome in outcomes if outcome.decision.policy == "request-id"]

    assert len(executed) == 1
    assert len(duplicates) == 1
    assert worker.calls == 1
    evidence_path = first_store.path / executed[0].result.evidence[0]
    original_evidence = evidence_path.read_bytes()
    retained = asyncio.run(
        ToolGateway(
            policy=PolicyEngine(),
            tools=_registry(),
            worker=worker,
            store=RunStore(first_store.run_id, first_store.path),
        ).execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request.model_copy(deep=True),
            used_calls=1,
        )
    )
    assert retained.decision.policy == "request-id"
    assert not retained.executed
    assert worker.calls == 1
    assert evidence_path.read_bytes() == original_evidence


def test_gateway_isolates_authority_snapshots_from_policy_and_adapter_mutation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"simulation": target.simulation},
    )
    grant = _grant(sample_campaign, target.endpoint)
    campaign_before = sample_campaign.model_dump(mode="json")
    grant_before = grant.model_dump(mode="json")
    request_before = request.model_dump(mode="json")
    probe = MutatingCostProbe()
    registry = ToolRegistry()
    registry.register(probe)
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=MutatingPolicyEngine(),
        tools=registry,
        worker=SimulatedWorkerBackend(),
        store=store,
    )

    outcome = asyncio.run(gateway.execute(sample_campaign, grant, request, used_calls=0))

    assert outcome.result.success
    assert probe.prepared_target == target.endpoint
    assert outcome.result.data["target"] == target.endpoint
    assert sample_campaign.model_dump(mode="json") == campaign_before
    assert grant.model_dump(mode="json") == grant_before
    assert request.model_dump(mode="json") == request_before
    evidence = json.loads((store.path / outcome.result.evidence[0]).read_text(encoding="utf-8"))
    assert evidence["request"]["target"] == target.endpoint
    assert len(evidence["workerJob"]["stdinSha256"]) == 64
    assert outcome.worker_result is not None
    assert json.loads(outcome.worker_result.stdout)["target"] == target.endpoint


def test_gateway_does_not_expose_canonical_results_to_trusted_hook_mutation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    registry = ToolRegistry()
    registry.register(MutatingTrustedProbe())
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"simulation": target.simulation},
    )
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=SimulatedWorkerBackend(),
        store=store,
    )

    outcome = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request,
            used_calls=0,
        )
    )

    assert outcome.result.success
    assert "mutated" not in outcome.result.data
    assert len(outcome.result.evidence) == 1
    assert outcome.result.evidence[0] != "forged-evidence.json"
    assert outcome.worker_result is not None
    assert outcome.worker_result.stdout != "mutated worker transcript"


def test_gateway_binds_worker_result_to_sealed_job_despite_backend_mutation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    worker = MutatingExecutionWorker()
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=worker,
        store=RunStore.create(tmp_path, sample_campaign.metadata.name),
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
    assert not outcome.result.success
    assert outcome.worker_result is not None
    assert outcome.worker_result.execution_id != "exec_mutated_by_worker"
    assert outcome.worker_result.stderr == "worker result contract validation failed"


def test_gateway_rejects_adapter_success_after_worker_contract_failure(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    registry = ToolRegistry()
    registry.register(FalseSuccessProbe())
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=MismatchedExecutionWorker(),
        store=RunStore.create(tmp_path, sample_campaign.metadata.name),
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
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
    assert not outcome.result.success
    assert outcome.result.error is not None
    assert "cannot report success" in outcome.result.error


@pytest.mark.parametrize(
    "invalid_value",
    [{"unordered", "set"}, float("nan")],
    ids=["python-set", "non-finite-number"],
)
def test_gateway_rejects_non_json_tool_result_without_coercing_it(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    invalid_value: object,
) -> None:
    target = sample_campaign.spec.targets[0]
    registry = ToolRegistry()
    registry.register(NonJSONResultProbe(invalid_value))
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=SimulatedWorkerBackend(),
        store=RunStore.create(tmp_path, sample_campaign.metadata.name),
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
    assert not outcome.result.success
    assert outcome.result.error is not None
    assert "Tool result is not strict canonical JSON" in outcome.result.error
    assert outcome.result.data == {}


def test_preparation_failure_does_not_consume_rate_reservation(
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
    rate_limits = RequestRateLimitLedger()
    broken_registry = ToolRegistry()
    broken_registry.register(MalformedJobProbe())
    failed = asyncio.run(
        ToolGateway(
            policy=PolicyEngine(),
            tools=broken_registry,
            worker=NeverWorker(),
            store=RunStore.create(tmp_path / "failed", campaign.metadata.name),
            rate_limits=rate_limits,
        ).execute(
            campaign,
            _grant(campaign, target.endpoint),
            ToolRequest(
                agent_id="agent:planner-local",
                tool_id="mock.agent-probe",
                target=target.endpoint,
                method="POST",
            ),
            used_calls=0,
        )
    )

    assert not failed.executed
    assert failed.decision.allowed
    assert failed.result.error is not None
    assert "tool preparation failed" in failed.result.error
    assert rate_limits.snapshot()["reservationCounts"] == {}

    succeeded = asyncio.run(
        ToolGateway(
            policy=PolicyEngine(),
            tools=_registry(),
            worker=SimulatedWorkerBackend(),
            store=RunStore.create(tmp_path / "succeeded", campaign.metadata.name),
            rate_limits=rate_limits,
        ).execute(
            campaign,
            _grant(campaign, target.endpoint),
            ToolRequest(
                agent_id="agent:planner-local",
                tool_id="mock.agent-probe",
                target=target.endpoint,
                method="POST",
                arguments={"simulation": target.simulation},
            ),
            used_calls=0,
        )
    )
    assert succeeded.executed
    assert rate_limits.snapshot()["reservationCounts"] == {campaign.metadata.name: 1}


def test_policy_audit_failure_releases_pre_dispatch_rate_reservation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rules = sample_campaign.spec.rules_of_engagement.model_copy(
        update={"max_requests_per_minute": 1}
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"rules_of_engagement": rules})}
    )
    target = campaign.spec.targets[0]
    rate_limits = RequestRateLimitLedger()
    store = RunStore.create(tmp_path, campaign.metadata.name)
    original_append_event = store.append_event

    def failing_append_event(event_type: str, payload: dict[str, object]):
        if event_type == "tool.policy_evaluated":
            raise OSError("simulated policy audit failure")
        return original_append_event(event_type, payload)

    monkeypatch.setattr(store, "append_event", failing_append_event)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=NeverWorker(),
        store=store,
        rate_limits=rate_limits,
    )

    with pytest.raises(OSError, match="simulated policy audit failure"):
        asyncio.run(
            gateway.execute(
                campaign,
                _grant(campaign, target.endpoint),
                ToolRequest(
                    agent_id="agent:planner-local",
                    tool_id="mock.agent-probe",
                    target=target.endpoint,
                    method="POST",
                    arguments={"simulation": target.simulation},
                ),
                used_calls=0,
            )
        )

    assert rate_limits.snapshot()["reservationCounts"] == {}


def test_partial_secret_failure_revokes_lease_and_releases_rate_reservation(
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
    rate_limits = RequestRateLimitLedger()
    secrets = SecretBroker()
    secrets.register("gateway/present", "gateway-partial-secret")
    registry = ToolRegistry()
    registry.register(PartialSecretProbe())
    failed_store = RunStore.create(tmp_path / "failed", campaign.metadata.name)

    failed = asyncio.run(
        ToolGateway(
            policy=PolicyEngine(),
            tools=registry,
            worker=NeverWorker(),
            store=failed_store,
            secrets=secrets,
            rate_limits=rate_limits,
        ).execute(
            campaign,
            _grant(campaign, target.endpoint),
            ToolRequest(
                agent_id="agent:planner-local",
                tool_id="mock.agent-probe",
                target=target.endpoint,
                method="POST",
            ),
            used_calls=0,
        )
    )

    assert not failed.executed
    assert failed.result.error is not None
    assert "secret lease failed" in failed.result.error
    assert rate_limits.snapshot()["reservationCounts"] == {}
    assert secrets.snapshot()[0]["status"] == "revoked"
    events = [
        json.loads(line)["event_type"]
        for line in failed_store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert "secret.lease.issued" in events
    assert "secret.lease.revoked" in events
    assert "tool.rate_reservation_released" in events
    assert "worker.dispatched" not in events


def test_pending_cancellation_stops_before_policy_rate_secret_and_dispatch(
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
    rate_limits = RequestRateLimitLedger()
    store = RunStore.create(tmp_path, campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=NeverWorker(),
        store=store,
        rate_limits=rate_limits,
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
    )

    async def cancel_then_execute() -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        await gateway.execute(
            campaign,
            _grant(campaign, target.endpoint),
            request,
            used_calls=0,
        )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancel_then_execute())

    assert rate_limits.snapshot()["reservationCounts"] == {}
    events = store.events_path.read_text(encoding="utf-8") if store.events_path.exists() else ""
    assert "tool.policy_evaluated" not in events
    assert "secret.lease.issued" not in events
    assert "worker.dispatched" not in events


def test_cancellation_after_secret_setup_revokes_and_rolls_back_before_dispatch(
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
    rate_limits = RequestRateLimitLedger()
    secrets = CancellingSecretBroker()
    secrets.register("gateway/cancel", "gateway-cancellation-secret")
    registry = ToolRegistry()
    registry.register(SingleSecretProbe())
    store = RunStore.create(tmp_path, campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=NeverWorker(),
        store=store,
        secrets=secrets,
        rate_limits=rate_limits,
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            gateway.execute(
                campaign,
                _grant(campaign, target.endpoint),
                request,
                used_calls=0,
            )
        )

    assert rate_limits.snapshot()["reservationCounts"] == {}
    assert secrets.snapshot()[0]["status"] == "revoked"
    events = store.events_path.read_text(encoding="utf-8")
    assert "secret.lease.issued" in events
    assert "secret.lease.revoked" in events
    assert "tool.rate_reservation_released" in events
    assert '"beforeDispatch":true' in events
    assert "worker.dispatched" not in events


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


def test_gateway_runs_trusted_execution_hook_before_persisting_success(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    registry = ToolRegistry()
    registry.register(RejectingTrustedProbe())
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
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

    assert not outcome.result.success
    assert outcome.result.error is not None
    assert "trusted execution validation failed" in outcome.result.error
    evidence = json.loads((store.path / outcome.result.evidence[0]).read_text(encoding="utf-8"))
    assert evidence["result"]["success"] is False


def test_gateway_rejects_truncated_output_from_successful_worker(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    for stream in ("stdout", "stderr"):
        store = RunStore.create(tmp_path / stream, sample_campaign.metadata.name)
        gateway = ToolGateway(
            policy=PolicyEngine(),
            tools=_registry(),
            worker=TruncatedSuccessWorker(stream=stream),
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

        assert not outcome.result.success
        assert outcome.result.error is not None
        assert "output was truncated" in outcome.result.error


def test_gateway_rejects_worker_result_not_bound_to_dispatched_job(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    worker = MismatchedExecutionWorker()
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=worker,
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

    assert not outcome.result.success
    assert outcome.worker_result is not None
    assert outcome.worker_result.backend == "backend-error"
    assert worker.job is not None
    assert outcome.worker_result.execution_id == worker.job.execution_id
    assert outcome.worker_result.stderr == "worker result contract validation failed"


def test_gateway_rebounds_repeated_short_secret_output_after_redaction() -> None:
    now = datetime.now(UTC)
    secret = "xxxxxxxx"
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["mock-agent-probe"],
        limits=WorkerLimits(stdout_bytes=1_024, stderr_bytes=1_024),
    )
    result = WorkerResult(
        execution_id=job.execution_id,
        backend="contract-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=secret * 200,
        stderr=secret * 200,
        network_log=secret * 200,
        started_at=now,
        finished_at=now,
    )
    material = SecretMaterial(lease_id="lease_test", binding="test", value=secret)

    bounded = execution_receipts.redact_worker_result(result, [material], job)

    assert len(bounded.stdout.encode("utf-8")) <= job.limits.stdout_bytes
    assert len(bounded.stderr.encode("utf-8")) <= job.limits.stderr_bytes
    assert len(bounded.network_log.encode("utf-8")) <= job.limits.stderr_bytes
    assert (
        len(bounded.stdout.encode("utf-8"))
        + len(bounded.stderr.encode("utf-8"))
        + len(bounded.network_log.encode("utf-8"))
        <= job.limits.stdout_bytes + job.limits.stderr_bytes
    )
    assert secret not in bounded.stdout + bounded.stderr + bounded.network_log
    assert bounded.stdout_truncated
    assert bounded.stderr_truncated
    assert bounded.network_log == ""


def test_gateway_normalizes_redaction_failure_without_leaking_diagnostic(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = sample_campaign.spec.targets[0]
    sensitive_diagnostic = "raw-worker-secret-must-not-escape"

    def reject_redaction(
        result: WorkerResult,
        materials: list[SecretMaterial],
        job: WorkerJob,
    ) -> WorkerResult:
        del result, materials, job
        raise ValueError(sensitive_diagnostic)

    monkeypatch.setattr(
        execution_receipts,
        "redact_worker_result",
        reject_redaction,
    )
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
    assert not outcome.result.success
    assert outcome.result.error == "worker result redaction failed"
    assert outcome.worker_result is not None
    assert outcome.worker_result.stderr == "worker result redaction failed"
    evidence = (store.path / outcome.result.evidence[0]).read_text(encoding="utf-8")
    assert sensitive_diagnostic not in evidence


def test_gateway_propagates_unconfirmed_worker_cleanup(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    cleanup_error = WorkerCleanupError(
        DockerWorkerBackend._cleanup_failures(
            [("container", "pajin-unconfirmed")],
            "removal could not be confirmed",
        )
    )
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=CleanupFailingWorker(cleanup_error),
        store=RunStore.create(tmp_path, sample_campaign.metadata.name),
    )
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
        arguments={"simulation": target.simulation},
    )

    with pytest.raises(WorkerCleanupError, match="pajin-unconfirmed"):
        asyncio.run(
            gateway.execute(
                sample_campaign,
                _grant(sample_campaign, target.endpoint),
                request,
                used_calls=0,
            )
        )


def test_gateway_rebinds_malformed_tool_results_before_evidence(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0]
    for mutation in (
        "request-id",
        "tool-id",
        "timestamps",
        "success-error",
        "failure-error",
        "nested-evidence",
    ):
        registry = ToolRegistry()
        registry.register(MalformedResultProbe(mutation))
        store = RunStore.create(tmp_path / mutation, sample_campaign.metadata.name)
        gateway = ToolGateway(
            policy=PolicyEngine(),
            tools=registry,
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

        assert not outcome.result.success
        assert outcome.result.request_id == request.request_id
        assert outcome.result.tool_id == request.tool_id
        assert outcome.result.finished_at >= outcome.result.started_at
        assert outcome.result.error is not None
        assert "tool result contract validation failed" in outcome.result.error
        evidence = json.loads((store.path / outcome.result.evidence[0]).read_text(encoding="utf-8"))
        assert evidence["result"]["request_id"] == request.request_id
        assert evidence["result"]["tool_id"] == request.tool_id
        assert evidence["result"]["success"] is False


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
        issued_at=sample_campaign.spec.authorization.approved_at,
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
    assert worker.job.egress_policy.max_requests == 1


def test_custom_worker_cannot_forge_host_observed_network_log_provenance(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    registry = ToolRegistry()
    registry.register(HTTPGetTool())
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
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
        issued_at=sample_campaign.spec.authorization.approved_at,
        expires_at=sample_campaign.spec.authorization.expires_at,
    )
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=WorkerForgingDockerLabel(),
        store=store,
    )

    outcome = asyncio.run(gateway.execute(sample_campaign, grant, request, used_calls=0))

    assert outcome.executed
    assert not outcome.result.success
    assert outcome.result.error is not None
    assert "trusted execution validation failed" in outcome.result.error
    assert not outcome.network_log_trusted
    evidence = json.loads((store.path / outcome.result.evidence[0]).read_text(encoding="utf-8"))
    assert evidence["networkLogTrusted"] is False


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
        issued_at=campaign.spec.authorization.approved_at,
        expires_at=campaign.spec.authorization.expires_at,
    )

    outcome = asyncio.run(gateway.execute(campaign, grant, request, used_calls=0))

    assert AIChatProbeTool().network_request_cost(request) == 2
    assert not outcome.executed
    assert outcome.decision.policy == "rate-limit"


@pytest.mark.parametrize(
    "failure_stage",
    ["prepare", "secret", "worker", "interpret", "trusted", "adapter-error"],
)
def test_gateway_omits_exception_and_adapter_error_details_from_durable_diagnostics(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    failure_stage: str,
) -> None:
    secret = f"gateway-{failure_stage}-secret-MUST-NOT-PERSIST"
    target = sample_campaign.spec.targets[0]
    registry = ToolRegistry()
    worker: object = SimulatedWorkerBackend()
    secrets: SecretBroker | None = None
    if failure_stage == "prepare":
        registry.register(ExceptionRaisingPrepareProbe(secret))
        worker = NeverWorker()
    elif failure_stage == "secret":
        registry.register(SingleSecretProbe())
        secrets = ExceptionRaisingSecretBroker(secret)
        worker = NeverWorker()
    elif failure_stage == "worker":
        registry.register(MockAgentProbe())
        worker = ExceptionRaisingWorker(secret)
    elif failure_stage == "interpret":
        registry.register(ExceptionRaisingInterpretProbe(secret))
    elif failure_stage == "trusted":
        registry.register(ExceptionRaisingTrustedProbe(secret))
    else:
        registry.register(ErrorReturningProbe(secret))
    store = RunStore.create(tmp_path / failure_stage, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=worker,  # type: ignore[arg-type]
        store=store,
        secrets=secrets,
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

    artifact_text = "\n".join(
        path.read_text(encoding="utf-8") for path in store.path.rglob("*") if path.is_file()
    )
    assert not outcome.result.success
    assert secret not in outcome.model_dump_json()
    assert secret not in artifact_text


def test_gateway_preserves_authoritative_worker_stderr_but_does_not_copy_it_to_error(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    transcript = "authoritative-worker-transcript-MUST-STAY-IN-EVIDENCE"
    target = sample_campaign.spec.targets[0]
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=TranscriptFailingWorker(transcript),
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

    evidence = json.loads((store.path / outcome.result.evidence[0]).read_text(encoding="utf-8"))
    assert evidence["workerResult"]["stderr"] == transcript
    assert transcript not in (outcome.result.error or "")
    assert transcript not in evidence["result"]["error"]


def test_gateway_does_not_reflect_invalid_request_values_in_failure_result(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    secret = "invalid-request-secret-MUST-NOT-PERSIST"
    target = sample_campaign.spec.targets[0]
    request = ToolRequest(
        agent_id="agent:planner-local",
        tool_id="mock.agent-probe",
        target=target.endpoint,
        method="POST",
    )
    request.target = secret * 100
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=_registry(),
        worker=NeverWorker(),
        store=store,
    )

    outcome = asyncio.run(
        gateway.execute(
            sample_campaign,
            _grant(sample_campaign, target.endpoint),
            request,
            used_calls=0,
        )
    )

    assert not outcome.executed
    assert secret not in outcome.model_dump_json()
    assert secret not in store.events_path.read_text(encoding="utf-8")
