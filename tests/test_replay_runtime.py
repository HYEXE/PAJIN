from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import JsonValue

from pajin.domain.manifest import load_manifest
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CampaignMode,
    CapabilityGrant,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.domain.replay import (
    CompiledReplaySpec,
    ModeReplayContract,
    ReplayAttempt,
    ReplayAttemptStatus,
    ReplayExecutionStatus,
    ReplayIntent,
    ReplayOracleResult,
    ReplayOracleVerdict,
    ReplayPurpose,
    ReplaySessionPolicy,
    ValidationEvidenceExcerpt,
    ValidationPacket,
    replay_evidence_digest,
    replay_request_digest,
)
from pajin.domain.validation import CandidateFinding
from pajin.policy.engine import PolicyEngine
from pajin.replay.compiler import ReplayCompiler, replay_scenario_digest
from pajin.replay.runtime import (
    GatewayRestrictedReproducerRuntime,
    ReplayModeOracle,
    ReplayOracleRegistry,
    ReplayRuntimeReason,
    VerifiedReplayResult,
    load_verified_replay_result,
)
from pajin.replay.tickets import (
    ReplayExecutionAuthority,
    ReplayExecutionTicket,
    replay_context_digest,
)
from pajin.runtime.control import (
    BudgetController,
    CancellationKind,
    ExecutionCancellationContext,
)
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, RequestRateLimitLedger
from pajin.tools.mock import MockAgentProbe

NOW = datetime(2026, 7, 15, 7, 0, tzinfo=UTC)
TARGET_ID = "staging-assistant"
TARGET = "https://staging.example.invalid/api/chat"
SCENARIO_ID = "test.mock.unauthorized-tool-call"
THREAT_CLASS = "A01"
ORIGINAL_REQUEST_ID = "tool_original_replay_1"
ORIGINAL_EVIDENCE = f"evidence/{ORIGINAL_REQUEST_ID}.json"


@dataclass(frozen=True)
class MockReplayScenario:
    scenario_id: str = SCENARIO_ID
    target_types: set[str] = field(default_factory=lambda: {"mock-agent"})
    threat_classes: set[str] = field(default_factory=lambda: {THREAT_CLASS})
    tool_id: str = "mock.agent-probe"
    method: str = "POST"


@dataclass
class ReplayFixture:
    campaign: CampaignManifest
    source_store: RunStore
    replay_store: RunStore
    source_root_digest: str
    authority: ReplayExecutionAuthority
    ticket: ReplayExecutionTicket
    scenario: MockReplayScenario


class RecordingReplayTicketVerifier:
    def __init__(self, *, expected_compilation_digest: str) -> None:
        self.expected_compilation_digest = expected_compilation_digest
        self.called = False

    def verify_finalized(
        self,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        assert ticket_id
        assert final_seal_root_digest
        assert artifact_set_digest
        assert candidate_source_root_digest
        assert replay_run_id
        assert compilation_digest == self.expected_compilation_digest
        self.called = True


class ThresholdMockOracle:
    oracle_id = "test.mock-vulnerability"
    oracle_version = "1.0.0"
    observation_schema = "pajin.test/mock-probe-output/v1"
    mode = CampaignMode.AI_REDTEAM
    scenario_id = SCENARIO_ID
    tool_id = "mock.agent-probe"

    def __init__(self, scenario: MockReplayScenario) -> None:
        self.scenario_digest = replay_scenario_digest(scenario)

    def observation(
        self,
        spec: CompiledReplaySpec,
        request: ToolRequest,
        materialization: object,
        outcome: GatewayOutcome,
    ) -> Mapping[str, JsonValue]:
        del spec, request, materialization
        return dict(outcome.result.data)

    def classify_failure(self, outcome: GatewayOutcome) -> ReplayAttemptStatus:
        if "target unavailable" in (outcome.result.error or "").lower():
            return ReplayAttemptStatus.TARGET_UNAVAILABLE
        return ReplayAttemptStatus.FAILED

    async def evaluate(
        self,
        spec: CompiledReplaySpec,
        attempts: Sequence[ReplayAttempt],
        *,
        evaluated_at: datetime,
    ) -> ReplayOracleResult:
        supportive = [
            attempt for attempt in attempts if attempt.observation.get("vulnerable") is True
        ]
        required = spec.required_successes
        if len(supportive) >= required:
            verdict = ReplayOracleVerdict.SUPPORTS
        elif not supportive:
            verdict = ReplayOracleVerdict.CONTRADICTS
        else:
            verdict = ReplayOracleVerdict.INCONCLUSIVE
        return ReplayOracleResult(
            oracle_result_id="replay-oracle_test_1",
            spec_id=spec.spec_id,
            binding=spec.binding,
            oracle_id=self.oracle_id,
            oracle_version=self.oracle_version,
            observation_schema=self.observation_schema,
            verdict=verdict,
            attempt_ids=[attempt.attempt_id for attempt in attempts],
            supporting_evidence=[
                reference for attempt in supportive for reference in attempt.evidence
            ],
            support_count=len(supportive),
            required_support_count=required,
            summary="The typed mock observations were evaluated independently.",
            evaluated_at=evaluated_at,
        )


class CountingWorker:
    def __init__(self) -> None:
        self.delegate = SimulatedWorkerBackend()
        self.jobs: list[WorkerJob] = []

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        self.jobs.append(job)
        return await self.delegate.run(job, secrets=secrets)


class NeverWorker:
    def __init__(self) -> None:
        self.calls = 0

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        self.calls += 1
        raise AssertionError(f"Worker must not dispatch: {job.execution_id}, {secrets!r}")


class UnavailableWorker:
    def __init__(self) -> None:
        self.calls = 0

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        self.calls += 1
        return WorkerResult(
            execution_id=job.execution_id,
            backend="unavailable-test",
            status=WorkerStatus.FAILED,
            exit_code=None,
            stderr="target unavailable",
            started_at=NOW,
            finished_at=NOW,
        )


class FailThenSucceedWorker:
    def __init__(self) -> None:
        self.calls = 0
        self.delegate = SimulatedWorkerBackend()

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        self.calls += 1
        if self.calls == 1:
            return WorkerResult(
                execution_id=job.execution_id,
                backend="flaky-test",
                status=WorkerStatus.FAILED,
                exit_code=1,
                stderr="transient worker failure",
                started_at=NOW,
                finished_at=NOW,
            )
        return await self.delegate.run(job, secrets=secrets)


class HangingWorker:
    def __init__(self) -> None:
        self.calls = 0
        self.started = asyncio.Event()

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        self.calls += 1
        self.started.set()
        await asyncio.sleep(60)
        raise AssertionError(f"hanging Worker unexpectedly completed: {job.execution_id}")


class IdentitySubstitutingProbe(MockAgentProbe):
    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        interpreted = super().interpret(request, result)
        return interpreted.model_copy(update={"request_id": "tool_foreign_result"})


class VersionSubstitutingProbe(MockAgentProbe):
    spec = MockAgentProbe.spec.model_copy(update={"version": "9.9.9"})


class SubstitutingOracle(ThresholdMockOracle):
    async def evaluate(
        self,
        spec: CompiledReplaySpec,
        attempts: Sequence[ReplayAttempt],
        *,
        evaluated_at: datetime,
    ) -> ReplayOracleResult:
        result = await super().evaluate(spec, attempts, evaluated_at=evaluated_at)
        return result.model_copy(update={"spec_id": "compiled-replay_foreign"})


class HangingOracle(ThresholdMockOracle):
    def __init__(self, scenario: MockReplayScenario) -> None:
        super().__init__(scenario)
        self.started = asyncio.Event()

    async def evaluate(
        self,
        spec: CompiledReplaySpec,
        attempts: Sequence[ReplayAttempt],
        *,
        evaluated_at: datetime,
    ) -> ReplayOracleResult:
        self.started.set()
        await asyncio.sleep(60)
        raise AssertionError(f"hanging Oracle unexpectedly completed: {spec.spec_id}")


class SecretRequestingProbe(MockAgentProbe):
    def prepare(self, request: ToolRequest) -> WorkerJob:
        return (
            super()
            .prepare(request)
            .model_copy(
                update={
                    "secret_requests": [
                        WorkerSecretRequest(
                            secret_ref="provider/test",
                            binding="api-key",
                        )
                    ]
                }
            )
        )


def _campaign(
    *,
    expires_at: datetime | None = None,
    request_limit: int | None = None,
    duration_seconds: int | None = None,
) -> CampaignManifest:
    campaign = load_manifest(Path("examples/ai-redteam.yaml"))
    authorization = campaign.spec.authorization
    rules = campaign.spec.rules_of_engagement
    if expires_at is not None:
        authorization = authorization.model_copy(update={"expires_at": expires_at})
    if request_limit is not None:
        rules = rules.model_copy(update={"max_requests_per_minute": request_limit})
    budgets = campaign.spec.budgets
    if duration_seconds is not None:
        budgets = budgets.model_copy(update={"duration_seconds": duration_seconds})
    return campaign.model_copy(
        update={
            "spec": campaign.spec.model_copy(
                update={
                    "authorization": authorization,
                    "rules_of_engagement": rules,
                    "budgets": budgets,
                }
            )
        }
    )


def _fixture(
    tmp_path: Path,
    *,
    vulnerable: bool = True,
    repetitions: int = 2,
    session_policy: ReplaySessionPolicy = ReplaySessionPolicy.STATELESS,
    campaign: CampaignManifest | None = None,
    allowed_argument_fields: set[str] | None = None,
) -> ReplayFixture:
    resolved = campaign or _campaign()
    scenario = MockReplayScenario()
    source_store = RunStore.create(tmp_path / "candidate", resolved.metadata.name)
    source_store.append_event(
        "tool.completed",
        {"requestId": ORIGINAL_REQUEST_ID, "toolId": "mock.agent-probe"},
    )
    source_store.write_json(
        ORIGINAL_EVIDENCE,
        {"requestId": ORIGINAL_REQUEST_ID, "observation": "candidate evidence"},
    )
    source_root = source_store.seal().root_digest
    replay_store = RunStore.create(tmp_path / "replay", resolved.metadata.name)

    arguments = {"simulation": {"unauthorizedToolCall": vulnerable}}
    planned = ToolRequest(
        request_id=ORIGINAL_REQUEST_ID,
        agent_id="agent:planner-untrusted",
        tool_id="mock.agent-probe",
        target=TARGET,
        method="POST",
        arguments=arguments,
    )
    executed = planned.model_copy(update={"agent_id": "agent:specialist:a01:1"})
    plan = AgentPlan(
        summary="Execute the trusted mock replay scenario.",
        steps=[
            PlannedStep(
                step_id="step_mock_replay_1",
                title="Unauthorized tool call",
                rationale="Execute only the cataloged mock operation.",
                request=planned,
                scenario_id=SCENARIO_ID,
                threat_classes={THREAT_CLASS},
            )
        ],
    )
    candidate = CandidateFinding(
        candidate_id="candidate_mock_replay_1",
        claim=Finding(
            finding_id="finding_mock_replay_1",
            title="Unauthorized tool call observed",
            severity=FindingSeverity.HIGH,
            threat_class=THREAT_CLASS,
            target=TARGET,
            summary="The original mock observation reported an unauthorized call.",
            reproduction=["Replay the exact trusted operation."],
            evidence=[ORIGINAL_EVIDENCE],
            confidence=1,
        ),
        source="trusted-core:test-candidate-producer",
        source_agent_id="trusted-core:test-candidate-producer",
        source_request_ids=[ORIGINAL_REQUEST_ID],
        created_at=NOW - timedelta(minutes=5),
    )
    packet = ValidationPacket(
        packet_id="validation-packet_mock_replay_1",
        candidate_run_id=source_store.run_id,
        candidate=candidate,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=SCENARIO_ID,
        target_id=TARGET_ID,
        target=TARGET,
        threat_class=THREAT_CLASS,
        original_request_ids=[ORIGINAL_REQUEST_ID],
        evidence=[
            ValidationEvidenceExcerpt(
                reference=ORIGINAL_EVIDENCE,
                sha256="a" * 64,
                excerpt="Redacted candidate observation.",
            )
        ],
        semantic_support_required=False,
        replay_contract_id="replay-contract:test-mock:v1",
        created_at=NOW - timedelta(minutes=4),
    )
    intent = ReplayIntent(
        intent_id="replay-intent_mock_1",
        replay_contract_id="replay-contract:test-mock:v1",
        candidate_id=candidate.candidate_id,
        candidate_run_id=source_store.run_id,
        original_request_id=ORIGINAL_REQUEST_ID,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=SCENARIO_ID,
        threat_class=THREAT_CLASS,
        comparison_goals=["Compare the typed fresh mock observation."],
        rationale="The admitted Candidate requires independent reproduction.",
        created_at=NOW - timedelta(minutes=3),
    )
    contract = ModeReplayContract(
        contract_id="replay-contract:test-mock:v1",
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=SCENARIO_ID,
        tool_id="mock.agent-probe",
        tool_version="1.0.0",
        method="POST",
        risk_tier=ToolRiskTier.T2,
        automatic=True,
        replay_safe=True,
        idempotent=True,
        session_policy=session_policy,
        materializer_id=(
            "test.mock-fresh-session"
            if session_policy is ReplaySessionPolicy.FRESH_SESSION
            else None
        ),
        materializer_version=(
            "1.0.0" if session_policy is ReplaySessionPolicy.FRESH_SESSION else None
        ),
        ephemeral_argument_fields=(
            {"session_id"} if session_policy is ReplaySessionPolicy.FRESH_SESSION else set()
        ),
        repetitions=repetitions,
        required_successes=repetitions,
        oracle_id=ThresholdMockOracle.oracle_id,
        oracle_version=ThresholdMockOracle.oracle_version,
        observation_schema=ThresholdMockOracle.observation_schema,
        semantic_support_required=False,
        allowed_argument_fields=allowed_argument_fields or {"simulation"},
    )
    grant = CapabilityGrant(
        grant_id="grant_specialist_mock_1",
        parent_grant_id="grant_supervisor_mock_1",
        subject=executed.agent_id,
        campaign=resolved.metadata.name,
        tools={executed.tool_id},
        targets={TARGET},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=min(NOW + timedelta(hours=1), resolved.spec.authorization.expires_at),
        delegable=False,
        issued_at=NOW - timedelta(minutes=10),
        depth=1,
    )
    authority = ReplayExecutionAuthority()
    ticket = ReplayCompiler.compile_ticket(
        ticket_issuer=authority.issuer(),
        candidate_source_root_digest=source_root,
        campaign=resolved,
        plan=plan,
        original_request=executed,
        specialist_grant=grant,
        validation_packet=packet,
        intent=intent,
        contract=contract,
        scenario=scenario,
        registered_tools={"mock.agent-probe": MockAgentProbe.spec},
        evidence_by_request={ORIGINAL_REQUEST_ID: [ORIGINAL_EVIDENCE]},
        trusted_original_request_digest=replay_request_digest(executed),
        trusted_original_evidence_digest=replay_evidence_digest([ORIGINAL_EVIDENCE]),
        replay_run_id=replay_store.run_id,
        used_campaign_calls=1,
        compiled_at=NOW,
    )
    return ReplayFixture(
        campaign=resolved,
        source_store=source_store,
        replay_store=replay_store,
        source_root_digest=source_root,
        authority=authority,
        ticket=ticket,
        scenario=scenario,
    )


def _runtime(
    fixture: ReplayFixture,
    *,
    worker: WorkerBackend,
    oracle: ReplayModeOracle | None = None,
    tool: MockAgentProbe | None = None,
    budget: BudgetController | None = None,
    rate_limits: RequestRateLimitLedger | None = None,
    secrets: SecretBroker | None = None,
) -> GatewayRestrictedReproducerRuntime:
    tools = ToolRegistry()
    tools.register(tool or MockAgentProbe())
    oracles = ReplayOracleRegistry()
    if oracle is not None:
        oracles.register(oracle)
    shared_budget = budget or BudgetController(fixture.campaign.spec.budgets)
    if budget is None:
        shared_budget.record_tool_call()
    return GatewayRestrictedReproducerRuntime(
        tools=tools,
        policy=PolicyEngine(),
        worker=worker,
        store=fixture.replay_store,
        oracles=oracles,
        tickets=fixture.authority.claimer(),
        budget=shared_budget,
        rate_limits=rate_limits or RequestRateLimitLedger(),
        secrets=secrets,
        clock=lambda: NOW,
        request_id_factory=lambda _spec, number: f"tool_replay_{number}",
    )


def _run(
    fixture: ReplayFixture,
    runtime: GatewayRestrictedReproducerRuntime,
) -> VerifiedReplayResult:
    return asyncio.run(
        runtime.reproduce(
            fixture.campaign,
            fixture.ticket,
            candidate_source_root_digest=fixture.source_root_digest,
        )
    )


def _reseal_replay_artifacts(
    run_path: Path,
    receipt_payload: dict[str, object],
) -> None:
    receipt_path = run_path / "replay/verification-receipt.json"
    integrity_path = run_path / "run-integrity.jsonl"
    replay_run_id = receipt_payload["replay_run_id"]
    assert isinstance(replay_run_id, str)
    receipt_path.unlink()
    integrity_path.unlink()
    resealer = RunStore(run_id=replay_run_id, path=run_path)
    artifact_seal = resealer.seal()
    receipt_payload["artifact_seal_root_digest"] = artifact_seal.root_digest
    receipt_path.write_text(
        json.dumps(receipt_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    resealer.seal()


def test_reproducer_executes_fresh_requests_and_returns_verified_receipt(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    worker = CountingWorker()
    runtime = _runtime(
        fixture,
        worker=worker,
        oracle=ThresholdMockOracle(fixture.scenario),
    )

    result = _run(fixture, runtime)

    outcome = result.artifact_set.outcome
    assert outcome.supports_claim
    assert outcome.execution_status is ReplayExecutionStatus.SUCCEEDED
    assert outcome.replay_request_ids == ["tool_replay_1", "tool_replay_2"]
    assert ORIGINAL_REQUEST_ID not in outcome.replay_request_ids
    assert outcome.evidence == [
        "evidence/tool_replay_1.json",
        "evidence/tool_replay_2.json",
    ]
    assert len(worker.jobs) == 2
    assert all(job.command == ["mock-agent-probe"] for job in worker.jobs)
    assert result.receipt.candidate_source_root_digest == fixture.source_root_digest
    assert result.receipt.artifact_set_digest
    assert result.verification.seal_count == 2
    assert verify_run_integrity(result.run_path).root_digest == result.verification.root_digest
    compilation_payload = json.loads(
        (result.run_path / "replay/compilation.json").read_text(encoding="utf-8")
    )
    assert result.receipt.compilation_digest == replay_context_digest(compilation_payload)

    verifier = fixture.authority.verifier()
    verifier.verify_finalized(
        result.receipt.ticket_id,
        final_seal_root_digest=result.receipt_seal_root_digest,
        artifact_set_digest=result.receipt.artifact_set_digest,
        compilation_digest=result.receipt.compilation_digest,
        candidate_source_root_digest=result.receipt.candidate_source_root_digest,
        replay_run_id=result.receipt.replay_run_id,
    )
    with pytest.raises(PermissionError, match="does not match"):
        verifier.verify_finalized(
            result.receipt.ticket_id,
            final_seal_root_digest=result.receipt_seal_root_digest,
            artifact_set_digest=result.receipt.artifact_set_digest,
            compilation_digest="0" * 64,
            candidate_source_root_digest=result.receipt.candidate_source_root_digest,
            replay_run_id=result.receipt.replay_run_id,
        )

    events = [
        json.loads(line)
        for line in fixture.replay_store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    attempt_events = [
        event for event in events if event["event_type"] == "replay.attempt.completed"
    ]
    assert len(attempt_events) == 2
    assert all(
        event["payload"]["candidateId"] == "candidate_mock_replay_1"
        and event["payload"]["originalRequestId"] == ORIGINAL_REQUEST_ID
        for event in attempt_events
    )
    with pytest.raises(PermissionError, match="already finalized"):
        fixture.authority.claimer().claim(
            fixture.ticket,
            expected_replay_run_id=fixture.replay_store.run_id,
            expected_candidate_source_root_digest=fixture.source_root_digest,
            expected_campaign_digest=replay_context_digest(
                fixture.campaign.model_dump(mode="json", by_alias=True)
            ),
            claimed_at=NOW,
        )


def test_reproducer_seals_deterministically_sorted_compilation_sets(tmp_path: Path) -> None:
    allowed_fields = {"simulation", *(f"optional_field_{number:02d}" for number in range(32))}
    fixture = _fixture(
        tmp_path,
        repetitions=1,
        allowed_argument_fields=allowed_fields,
    )

    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )
    compilation_payload = json.loads(
        (result.run_path / "replay/compilation.json").read_text(encoding="utf-8")
    )

    assert compilation_payload["contract"]["allowed_argument_fields"] == sorted(allowed_fields)
    assert result.receipt.compilation_digest == replay_context_digest(compilation_payload)


def test_verified_loader_ignores_mutated_in_memory_replay_result(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, vulnerable=False, repetitions=1)
    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )
    assert not result.artifact_set.outcome.supports_claim
    assert result.artifact_set.outcome.oracle_result is not None

    result.artifact_set.outcome.oracle_result.verdict = ReplayOracleVerdict.SUPPORTS
    assert result.artifact_set.outcome.supports_claim

    reloaded = load_verified_replay_result(
        fixture.replay_store.path,
        tickets=fixture.authority.verifier(),
    )
    assert not reloaded.artifact_set.outcome.supports_claim
    assert reloaded.receipt_seal_root_digest == result.receipt_seal_root_digest
    assert reloaded.verification.root_digest == result.verification.root_digest


def test_verified_loader_digests_legacy_wire_json_before_applying_defaults(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, vulnerable=False, repetitions=1)
    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )
    run_path = result.run_path
    compilation_path = run_path / "replay/compilation.json"
    receipt_path = run_path / "replay/verification-receipt.json"

    compilation_payload = json.loads(compilation_path.read_text(encoding="utf-8"))
    for section_name, default_fields in (
        ("validation_packet", ("purpose", "retest_context")),
        ("contract", ("purpose", "required_contradictions")),
        ("intent", ("purpose", "retest_context")),
        (
            "spec",
            ("purpose", "retest_context_digest", "required_contradictions"),
        ),
    ):
        section = compilation_payload[section_name]
        assert isinstance(section, dict)
        for field_name in default_fields:
            section.pop(field_name)
    binding = compilation_payload["spec"]["binding"]
    assert isinstance(binding, dict)
    binding.pop("purpose")
    binding.pop("context_run_id")
    compilation_path.write_text(
        json.dumps(compilation_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    legacy_wire_digest = replay_context_digest(compilation_payload)

    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_payload["compilation_digest"] = legacy_wire_digest
    _reseal_replay_artifacts(run_path, receipt_payload)

    verifier = RecordingReplayTicketVerifier(
        expected_compilation_digest=legacy_wire_digest,
    )
    reloaded = load_verified_replay_result(run_path, tickets=verifier)

    assert verifier.called
    assert reloaded.receipt.compilation_digest == legacy_wire_digest
    assert reloaded.artifact_set.validation_packet.purpose is ReplayPurpose.CONFIRMATION
    assert reloaded.artifact_set.contract.required_contradictions == 0
    assert reloaded.artifact_set.spec.binding.context_run_id is None


def test_verified_loader_accepts_legacy_compilation_set_order(
    tmp_path: Path,
) -> None:
    allowed_fields = {"simulation", *(f"optional_field_{number:02d}" for number in range(32))}
    fixture = _fixture(
        tmp_path,
        repetitions=1,
        allowed_argument_fields=allowed_fields,
    )
    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )
    run_path = result.run_path
    compilation_path = run_path / "replay/compilation.json"
    receipt_path = run_path / "replay/verification-receipt.json"
    compilation_payload = json.loads(compilation_path.read_text(encoding="utf-8"))
    ordered_fields = compilation_payload["contract"]["allowed_argument_fields"]
    assert ordered_fields == sorted(allowed_fields)
    compilation_payload["contract"]["allowed_argument_fields"] = list(reversed(ordered_fields))
    compilation_path.write_text(
        json.dumps(compilation_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    assert replay_context_digest(compilation_payload) != result.receipt.compilation_digest

    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    _reseal_replay_artifacts(run_path, receipt_payload)
    verifier = RecordingReplayTicketVerifier(
        expected_compilation_digest=result.receipt.compilation_digest,
    )

    reloaded = load_verified_replay_result(run_path, tickets=verifier)

    assert verifier.called
    assert reloaded.artifact_set.contract.allowed_argument_fields == allowed_fields


def test_verified_loader_accepts_legacy_missing_defaults_and_reversed_set_order(
    tmp_path: Path,
) -> None:
    allowed_fields = {"simulation", *(f"optional_field_{number:02d}" for number in range(49))}
    assert len(allowed_fields) == 50
    fixture = _fixture(
        tmp_path,
        repetitions=1,
        allowed_argument_fields=allowed_fields,
    )
    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )
    run_path = result.run_path
    compilation_path = run_path / "replay/compilation.json"
    receipt_path = run_path / "replay/verification-receipt.json"
    compilation_payload = json.loads(compilation_path.read_text(encoding="utf-8"))
    for section_name, default_fields in (
        ("validation_packet", ("purpose", "retest_context")),
        ("contract", ("purpose", "required_contradictions")),
        ("intent", ("purpose", "retest_context")),
        (
            "spec",
            ("purpose", "retest_context_digest", "required_contradictions"),
        ),
    ):
        section = compilation_payload[section_name]
        assert isinstance(section, dict)
        for field_name in default_fields:
            section.pop(field_name)
    binding = compilation_payload["spec"]["binding"]
    assert isinstance(binding, dict)
    binding.pop("purpose")
    binding.pop("context_run_id")

    ordered_fields = compilation_payload["contract"]["allowed_argument_fields"]
    assert ordered_fields == sorted(allowed_fields)
    legacy_receipt_digest = replay_context_digest(compilation_payload)
    compilation_payload["contract"]["allowed_argument_fields"] = list(reversed(ordered_fields))
    compilation_path.write_text(
        json.dumps(compilation_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    assert replay_context_digest(compilation_payload) != legacy_receipt_digest

    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_payload["compilation_digest"] = legacy_receipt_digest
    _reseal_replay_artifacts(run_path, receipt_payload)
    verifier = RecordingReplayTicketVerifier(
        expected_compilation_digest=legacy_receipt_digest,
    )

    reloaded = load_verified_replay_result(run_path, tickets=verifier)

    assert verifier.called
    assert reloaded.receipt.compilation_digest == legacy_receipt_digest
    assert reloaded.artifact_set.contract.allowed_argument_fields == allowed_fields


def test_verified_loader_rejects_resealed_semantic_compilation_tamper(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, repetitions=1)
    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )
    run_path = result.run_path
    compilation_path = run_path / "replay/compilation.json"
    receipt_path = run_path / "replay/verification-receipt.json"
    compilation_payload = json.loads(compilation_path.read_text(encoding="utf-8"))
    compilation_payload["contract"]["oracle_id"] = "test.substituted-oracle"
    compilation_path.write_text(
        json.dumps(compilation_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    _reseal_replay_artifacts(run_path, receipt_payload)
    verifier = RecordingReplayTicketVerifier(
        expected_compilation_digest=result.receipt.compilation_digest,
    )

    with pytest.raises(ValueError, match="compilation"):
        load_verified_replay_result(run_path, tickets=verifier)
    assert not verifier.called


def test_replay_ticket_claim_is_atomic_and_single_use(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    claimers = [fixture.authority.claimer(), fixture.authority.claimer()]
    campaign_digest = replay_context_digest(fixture.campaign.model_dump(mode="json", by_alias=True))

    def claim(index: int) -> str:
        try:
            claimed = claimers[index].claim(
                fixture.ticket,
                expected_replay_run_id=fixture.replay_store.run_id,
                expected_candidate_source_root_digest=fixture.source_root_digest,
                expected_campaign_digest=campaign_digest,
                claimed_at=NOW,
            )
            return claimed.ticket.ticket_id
        except PermissionError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, range(2)))

    assert results.count(fixture.ticket.ticket_id) == 1
    assert sum("already claimed" in result for result in results) == 1


def test_replay_ticket_rejects_unknown_or_changed_trusted_context(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    worker = NeverWorker()
    runtime = _runtime(
        fixture,
        worker=worker,
        oracle=ThresholdMockOracle(fixture.scenario),
    )
    changed = fixture.campaign.model_copy(
        update={
            "metadata": fixture.campaign.metadata.model_copy(
                update={"description": "substituted campaign context"}
            )
        }
    )
    with pytest.raises(PermissionError, match="context changed"):
        asyncio.run(
            runtime.reproduce(
                changed,
                fixture.ticket,
                candidate_source_root_digest=fixture.source_root_digest,
            )
        )
    assert worker.calls == 0
    assert not fixture.replay_store.events_path.exists()

    unknown = _fixture(tmp_path / "unknown")
    with pytest.raises(KeyError, match="unknown replay execution ticket"):
        asyncio.run(
            _runtime(
                unknown,
                worker=NeverWorker(),
                oracle=ThresholdMockOracle(unknown.scenario),
            ).reproduce(
                unknown.campaign,
                ReplayExecutionTicket("replay-ticket_untrusted"),
                candidate_source_root_digest=unknown.source_root_digest,
            )
        )


def test_reproducer_preserves_objective_contradiction_without_supporting_claim(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, vulnerable=False)
    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )

    assert result.artifact_set.outcome.execution_status is ReplayExecutionStatus.SUCCEEDED
    assert result.artifact_set.outcome.oracle_result is not None
    assert result.artifact_set.outcome.oracle_result.verdict is ReplayOracleVerdict.CONTRADICTS
    assert not result.artifact_set.outcome.supports_claim


@pytest.mark.parametrize(
    ("session_policy", "expected_reason"),
    [
        (ReplaySessionPolicy.FRESH_SESSION, ReplayRuntimeReason.MATERIALIZER_UNREGISTERED),
        (
            ReplaySessionPolicy.PRESERVE_SCENARIO_SESSION,
            ReplayRuntimeReason.SESSION_POLICY_UNSUPPORTED,
        ),
    ],
)
def test_reproducer_fails_closed_when_session_policy_cannot_be_materialized(
    tmp_path: Path,
    session_policy: ReplaySessionPolicy,
    expected_reason: ReplayRuntimeReason,
) -> None:
    fixture = _fixture(tmp_path, session_policy=session_policy)
    worker = NeverWorker()

    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=worker,
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )

    assert result.artifact_set.outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED
    assert worker.calls == 0
    run = json.loads((fixture.replay_store.path / "run.json").read_text(encoding="utf-8"))
    assert run["reason"] == expected_reason.value


def test_reproducer_fails_closed_for_missing_or_substituted_runtime_components(
    tmp_path: Path,
) -> None:
    missing = _fixture(tmp_path / "missing")
    never = NeverWorker()
    missing_result = _run(missing, _runtime(missing, worker=never, oracle=None))
    assert missing_result.artifact_set.outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED
    assert never.calls == 0

    substituted = _fixture(tmp_path / "substituted")
    never = NeverWorker()
    substituted_result = _run(
        substituted,
        _runtime(
            substituted,
            worker=never,
            oracle=ThresholdMockOracle(substituted.scenario),
            tool=VersionSubstitutingProbe(),
        ),
    )
    assert (
        substituted_result.artifact_set.outcome.execution_status
        is ReplayExecutionStatus.UNSUPPORTED
    )
    assert never.calls == 0


def test_reproducer_rejects_non_fresh_request_identity_without_dispatch(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    worker = NeverWorker()
    runtime = _runtime(
        fixture,
        worker=worker,
        oracle=ThresholdMockOracle(fixture.scenario),
    )
    runtime._request_id_factory = lambda _spec, _number: ORIGINAL_REQUEST_ID

    result = _run(fixture, runtime)

    assert result.artifact_set.outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED
    assert worker.calls == 0


def test_reproducer_rejects_path_unsafe_request_identity_without_dispatch(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    worker = NeverWorker()
    runtime = _runtime(
        fixture,
        worker=worker,
        oracle=ThresholdMockOracle(fixture.scenario),
    )
    runtime._request_id_factory = lambda _spec, _number: "../foreign/evidence"

    result = _run(fixture, runtime)

    assert result.artifact_set.outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED
    assert result.verification.seal_count == 2
    assert worker.calls == 0


def test_reproducer_preserves_completed_attempt_before_duplicate_request_identity(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    worker = CountingWorker()
    runtime = _runtime(
        fixture,
        worker=worker,
        oracle=ThresholdMockOracle(fixture.scenario),
    )
    runtime._request_id_factory = lambda _spec, _number: "tool_replay_duplicate"

    result = _run(fixture, runtime)

    outcome = result.artifact_set.outcome
    assert outcome.execution_status is ReplayExecutionStatus.FAILED
    assert outcome.replay_request_ids == ["tool_replay_duplicate"]
    assert outcome.evidence == ["evidence/tool_replay_duplicate.json"]
    assert len(outcome.attempts) == 1
    assert len(worker.jobs) == 1


def test_reproducer_distinguishes_target_unavailable_and_continues_transient_attempts(
    tmp_path: Path,
) -> None:
    unavailable = _fixture(tmp_path / "unavailable")
    unavailable_worker = UnavailableWorker()
    unavailable_result = _run(
        unavailable,
        _runtime(
            unavailable,
            worker=unavailable_worker,
            oracle=ThresholdMockOracle(unavailable.scenario),
        ),
    )
    assert (
        unavailable_result.artifact_set.outcome.execution_status
        is ReplayExecutionStatus.TARGET_UNAVAILABLE
    )
    assert unavailable_worker.calls == 1

    flaky = _fixture(tmp_path / "flaky")
    flaky_worker = FailThenSucceedWorker()
    flaky_result = _run(
        flaky,
        _runtime(
            flaky,
            worker=flaky_worker,
            oracle=ThresholdMockOracle(flaky.scenario),
        ),
    )
    assert flaky_result.artifact_set.outcome.execution_status is ReplayExecutionStatus.FAILED
    assert flaky_worker.calls == 2
    assert len(flaky_result.artifact_set.outcome.attempts) == 2


def test_reproducer_shares_campaign_budget_and_request_rate_ledger(tmp_path: Path) -> None:
    campaign = _campaign(request_limit=2)
    fixture = _fixture(tmp_path, campaign=campaign)
    budget = BudgetController(campaign.spec.budgets)
    budget.record_tool_call()
    rate_limits = RequestRateLimitLedger()
    assert rate_limits.reserve(campaign, NOW, request_cost=1) is None
    worker = CountingWorker()

    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=worker,
            oracle=ThresholdMockOracle(fixture.scenario),
            budget=budget,
            rate_limits=rate_limits,
        ),
    )

    assert result.artifact_set.outcome.execution_status is ReplayExecutionStatus.FAILED
    assert len(worker.jobs) == 1
    assert budget.tool_calls == 3
    assert result.artifact_set.outcome.attempts[-1].error is not None
    assert "rate limit" in result.artifact_set.outcome.attempts[-1].error


def test_reproducer_forbids_tool_authored_secret_requests(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, repetitions=1)
    worker = NeverWorker()
    secrets = SecretBroker(clock=lambda: NOW)
    secrets.register("provider/test", "must-not-be-leased")

    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=worker,
            oracle=ThresholdMockOracle(fixture.scenario),
            tool=SecretRequestingProbe(),
            secrets=secrets,
        ),
    )

    assert result.artifact_set.outcome.execution_status is ReplayExecutionStatus.FAILED
    assert worker.calls == 0
    assert secrets.snapshot() == []


def test_reproducer_preserves_failure_when_evidence_or_oracle_identity_is_substituted(
    tmp_path: Path,
) -> None:
    evidence = _fixture(tmp_path / "evidence")
    evidence_result = _run(
        evidence,
        _runtime(
            evidence,
            worker=CountingWorker(),
            oracle=ThresholdMockOracle(evidence.scenario),
            tool=IdentitySubstitutingProbe(),
        ),
    )
    assert evidence_result.artifact_set.outcome.execution_status is ReplayExecutionStatus.FAILED
    run = json.loads((evidence.replay_store.path / "run.json").read_text(encoding="utf-8"))
    assert run["reason"] == ReplayRuntimeReason.EVIDENCE_LINEAGE_INVALID.value

    oracle = _fixture(tmp_path / "oracle")
    oracle_result = _run(
        oracle,
        _runtime(
            oracle,
            worker=CountingWorker(),
            oracle=SubstitutingOracle(oracle.scenario),
        ),
    )
    assert oracle_result.artifact_set.outcome.execution_status is ReplayExecutionStatus.FAILED
    assert oracle_result.artifact_set.outcome.oracle_result is None


def test_reproducer_times_out_and_seals_without_additional_dispatch(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        campaign=_campaign(expires_at=NOW + timedelta(milliseconds=50)),
    )
    worker = HangingWorker()

    result = _run(
        fixture,
        _runtime(
            fixture,
            worker=worker,
            oracle=ThresholdMockOracle(fixture.scenario),
        ),
    )

    assert result.artifact_set.outcome.execution_status is ReplayExecutionStatus.TIMED_OUT
    assert worker.calls == 1
    assert verify_run_integrity(fixture.replay_store.path).seal_count == 2


def test_campaign_duration_bounds_replay_dispatch_and_oracle(tmp_path: Path) -> None:
    campaign = _campaign(duration_seconds=1)

    dispatch = _fixture(tmp_path / "dispatch", campaign=campaign, repetitions=1)
    dispatch_budget = BudgetController(campaign.spec.budgets)
    dispatch_budget.restore_usage(
        agent_count=0,
        tool_calls=1,
        model_calls=0,
        model_prompt_tokens=0,
        model_completion_tokens=0,
        cost_usd=0,
        elapsed_seconds=0.75,
    )
    dispatch_worker = HangingWorker()
    dispatch_result = _run(
        dispatch,
        _runtime(
            dispatch,
            worker=dispatch_worker,
            oracle=ThresholdMockOracle(dispatch.scenario),
            budget=dispatch_budget,
        ),
    )
    assert dispatch_result.artifact_set.outcome.execution_status is ReplayExecutionStatus.TIMED_OUT
    assert dispatch_worker.calls == 1

    oracle_fixture = _fixture(tmp_path / "oracle", campaign=campaign, repetitions=1)
    oracle_budget = BudgetController(campaign.spec.budgets)
    oracle_budget.restore_usage(
        agent_count=0,
        tool_calls=1,
        model_calls=0,
        model_prompt_tokens=0,
        model_completion_tokens=0,
        cost_usd=0,
        elapsed_seconds=0.75,
    )
    oracle = HangingOracle(oracle_fixture.scenario)
    oracle_result = _run(
        oracle_fixture,
        _runtime(
            oracle_fixture,
            worker=CountingWorker(),
            oracle=oracle,
            budget=oracle_budget,
        ),
    )
    assert oracle.started.is_set()
    assert oracle_result.artifact_set.outcome.execution_status is ReplayExecutionStatus.TIMED_OUT
    assert len(oracle_result.artifact_set.outcome.attempts) == 1
    assert oracle_result.artifact_set.outcome.oracle_result is None


def test_parent_cancellation_propagates_to_replay_child_and_seals_outcome(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    worker = HangingWorker()
    runtime = _runtime(
        fixture,
        worker=worker,
        oracle=ThresholdMockOracle(fixture.scenario),
    )
    parent = ExecutionCancellationContext()
    candidate_path = tmp_path / "candidate-parent-binding"
    candidate_path.mkdir()
    parent.bind_run(engine="candidate-runner", run_id="run_candidate_parent", path=candidate_path)

    async def exercise() -> None:
        task = asyncio.create_task(
            runtime.reproduce(
                fixture.campaign,
                fixture.ticket,
                candidate_source_root_digest=fixture.source_root_digest,
                cancellation=parent,
            )
        )
        await asyncio.wait_for(worker.started.wait(), timeout=1)
        parent.cancel(CancellationKind.RUN_CANCELLED, "operator cancelled parent Run")
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())

    artifact_set = json.loads(
        (fixture.replay_store.path / "replay" / "artifact-set.json").read_text(encoding="utf-8")
    )
    assert artifact_set["outcome"]["execution_status"] == "cancelled"
    assert worker.calls == 1
    assert verify_run_integrity(fixture.replay_store.path).seal_count == 2
    assert parent.binding is not None
    assert parent.binding.run_id == "run_candidate_parent"


def test_parent_cancellation_during_oracle_seals_outcome(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, repetitions=1)
    oracle = HangingOracle(fixture.scenario)
    runtime = _runtime(
        fixture,
        worker=CountingWorker(),
        oracle=oracle,
    )
    parent = ExecutionCancellationContext()

    async def exercise() -> None:
        task = asyncio.create_task(
            runtime.reproduce(
                fixture.campaign,
                fixture.ticket,
                candidate_source_root_digest=fixture.source_root_digest,
                cancellation=parent,
            )
        )
        await asyncio.wait_for(oracle.started.wait(), timeout=1)
        parent.cancel(CancellationKind.RUN_CANCELLED, "operator cancelled during Oracle")
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())

    artifact_set = json.loads(
        (fixture.replay_store.path / "replay" / "artifact-set.json").read_text(encoding="utf-8")
    )
    assert artifact_set["outcome"]["execution_status"] == "cancelled"
    assert len(artifact_set["outcome"]["attempts"]) == 1
    assert verify_run_integrity(fixture.replay_store.path).seal_count == 2
