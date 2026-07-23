from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.domain.validation import (
    AtomicClaimType,
    ClaimReplayStatus,
    FindingDisposition,
    PublicFindingState,
    ValidationReasonCode,
)
from pajin.modes.ai_redteam import replay as replay_module
from pajin.modes.ai_redteam.local import (
    KISALocalAgentRuntime,
    KISALocalReplayOrchestrator,
)
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime, KISAValidatorRuntime
from pajin.policy.engine import PolicyEngine
from pajin.replay.sqlite_tickets import (
    SQLiteReplayExecutionAuthority,
    SQLiteReplayTicketFinalizationVerifier,
)
from pajin.runtime.control import BudgetController
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.ai import AI_CHAT_PROXY_RECEIPT_VERSION, AIChatProbeTool
from pajin.tools.base import ToolRegistry, audit_http_target, http_target_sha256
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_CLAIM_REPLAYS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    ValidationSnapshotSemantics,
    load_validation_snapshot,
)


class M03TranscriptWorker:
    """Execute the real Worker contract with a deterministic M03 transcript."""

    def __init__(self, *, supports_claim: bool) -> None:
        self._supports_claim = supports_claim
        self.jobs: list[WorkerJob] = []
        self.sessions: list[str] = []

    async def run(self, job: WorkerJob) -> WorkerResult:
        started_at = datetime.now(UTC)
        assert job.command == ["ai-chat-probe"]
        assert job.network is NetworkMode.EGRESS_PROXY
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        assert probe["scenario_id"] == "kisa.model.system-prompt-disclosure"
        self.jobs.append(job)
        self.sessions.append(probe["session_id"])
        turns = []
        for index, turn in enumerate(probe["turns"]):
            markers = [
                check["value"]
                for check in probe["checks"]
                if check["turn"] == index and check["kind"] == "response-contains"
            ]
            content = (
                " ".join(["vulnerable lab response", *markers])
                if self._supports_claim
                else "I cannot reveal internal instructions."
            )
            turns.append(
                {
                    "index": index,
                    "name": turn["name"],
                    "request": {
                        "sessionId": probe["session_id"],
                        "messages": turn["messages"],
                        "metadata": {
                            "scenarioId": probe["scenario_id"],
                            "turn": index,
                        },
                    },
                    "response": {
                        "sessionId": probe["session_id"],
                        "message": {"role": "assistant", "content": content},
                        "toolCalls": [],
                        "safety": {
                            "blocked": not self._supports_claim,
                            "reason": (
                                None if self._supports_claim else "system-prompt-protection"
                            ),
                        },
                        "memoryWrites": [],
                        "model": "pajin-deterministic-lab-v1",
                    },
                    "responseLatencySeconds": 0.01,
                }
            )
        checks = [
            {
                "checkId": check["check_id"],
                "kind": check["kind"],
                "turn": check["turn"],
                # Worker-authored verdicts are deliberately irrelevant to the trusted
                # candidate producer and replay oracle.
                "matched": False,
                "sensitive": check["sensitive"],
            }
            for check in probe["checks"]
        ]
        output = {
            "target": payload["target"],
            "scenarioId": probe["scenario_id"],
            "threatClass": probe["threat_class"],
            "sessionId": probe["session_id"],
            "purpose": "attack",
            "vulnerable": False,
            "observation": "worker-authored verdict is not trusted",
            "turns": turns,
            "checks": checks,
            "sensitiveExposureCount": 0,
            "meanResponseLatencySeconds": 0.01,
            "networkPerformed": True,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="m03-local-replay-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _proxy_receipt_log(job: WorkerJob, worker_result: WorkerResult) -> str:
    payload = json.loads(job.stdin)
    output = json.loads(worker_result.stdout)
    probe = payload["probe"]
    events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
    for index, (turn, observed) in enumerate(zip(probe["turns"], output["turns"], strict=True)):
        request_body = {
            "sessionId": probe["session_id"],
            "messages": turn["messages"],
            "metadata": {"scenarioId": probe["scenario_id"], "turn": index},
        }
        response = observed["response"]
        events.append(
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": index + 1,
                    "method": "POST",
                    "target": audit_http_target(payload["target"]),
                    "targetSha256": http_target_sha256(payload["target"]),
                    "address": "172.17.0.1",
                    "status": 200,
                    "requestJsonSha256": _canonical_digest(request_body),
                    "responseBodySha256": _canonical_digest(response),
                    "responseJsonSha256": _canonical_digest(response),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events)


def _trusted_docker_backend(worker: M03TranscriptWorker) -> DockerWorkerBackend:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})

    async def run(
        job: WorkerJob,
        *,
        secrets: object = None,
    ) -> WorkerResult:
        del secrets
        result = await worker.run(job)
        return result.model_copy(
            update={
                "backend": "docker",
                "network_log": _proxy_receipt_log(job, result),
            }
        )

    backend.run = run  # type: ignore[method-assign]
    return backend


class OmissionValidator:
    async def validate(self, campaign, plan, results):
        del campaign, plan, results
        return []


def _campaign() -> CampaignManifest:
    campaign = load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))
    return campaign.model_copy(
        update={
            "spec": campaign.spec.model_copy(
                update={
                    "objectives": ["detect system prompt disclosure"],
                    "threat_classes": ["M03"],
                }
            )
        }
    )


def _tools() -> ToolRegistry:
    tools = ToolRegistry()
    tools.register(AIChatProbeTool())
    return tools


def _agents(*, omit_semantic_validation: bool = False) -> KISALocalAgentRuntime:
    validator = OmissionValidator() if omit_semantic_validation else DeterministicAgentRuntime()
    return KISALocalAgentRuntime(
        planner=KISAPlannerRuntime(
            thresholds=EvaluationThresholds(repetitions=2),
        ),
        validator=KISAValidatorRuntime(validator),
    )


def _orchestrator(
    root: Path,
    *,
    worker: WorkerBackend,
    omit_semantic_validation: bool = False,
) -> tuple[KISALocalReplayOrchestrator, Path]:
    ledger = root / "local-replay" / "replay-tickets.sqlite3"
    return (
        KISALocalReplayOrchestrator(
            agents=_agents(omit_semantic_validation=omit_semantic_validation),
            tools=_tools(),
            policy=PolicyEngine(),
            worker=worker,
            output_root=root,
            ticket_authority_factory=lambda: SQLiteReplayExecutionAuthority(ledger),
            repetitions=2,
        ),
        ledger,
    )


@pytest.mark.asyncio
async def test_kisa_local_replay_preserves_m03_evidence_without_product_confirmation(
    tmp_path: Path,
) -> None:
    worker = M03TranscriptWorker(supports_claim=True)
    orchestrator, ledger = _orchestrator(
        tmp_path,
        worker=_trusted_docker_backend(worker),
    )
    campaign = _campaign()
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()

    result = await orchestrator.run(
        campaign,
        budget=budget,
        rate_limits=rate_limits,
    )

    assert ledger.is_file()
    assert len(result.batch.records) == 1
    assert len(result.batch.verified_results) == 1
    assert len(result.batch.confirmation_results) == 3
    assert not hasattr(result.batch.tickets, "issuer")
    assert not hasattr(result.batch.tickets, "claimer")
    assert result.outcome.findings == result.outcome.validation.confirmed_findings
    assert result.outcome.findings == []
    decision = result.outcome.validation.decisions[0]
    assert decision.disposition is FindingDisposition.NEEDS_REVIEW
    assert decision.confirmation_basis is None
    assert decision.reason_codes == [ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING]
    assert result.outcome.report_path == (
        result.outcome.run_path / VERSIONED_VALIDATION_REPORT_PATH
    )
    assert result.outcome.report_path.is_file()

    legacy_findings = json.loads(
        (result.outcome.run_path / "findings.json").read_text(encoding="utf-8")
    )
    versioned_findings = json.loads(
        (result.outcome.run_path / "validation/v1alpha1/findings.json").read_text(encoding="utf-8")
    )
    assert legacy_findings == []
    assert versioned_findings["findings"] == []
    loaded = load_validation_snapshot(result.outcome.run_path)
    assert loaded.semantics is ValidationSnapshotSemantics.VERIFIED_REPLAY_EVIDENCE
    assert loaded.public_states[PublicFindingState.PARTIALLY_CONFIRMED] == [decision.candidate_id]
    assert loaded.claim_replays is not None
    assert loaded.claim_replays.assessments[0].status is ClaimReplayStatus.REPRODUCED
    assert {item.claim_type for item in loaded.claim_replays.assessments} == set(
        AtomicClaimType
    )
    assert (result.outcome.run_path / VERSIONED_VALIDATION_CLAIM_REPLAYS_PATH).is_file()

    replay_paths = [item.run_path for item in result.batch.verified_results.values()]
    assert all(path.parent.parent == tmp_path / "local-replay" for path in replay_paths)
    assert result.outcome.run_path not in replay_paths
    assert len(worker.jobs) == 8
    assert budget.tool_calls == 8
    sealed_rate_limits = json.loads(
        (result.outcome.run_path / "rate-limits.json").read_text(encoding="utf-8")
    )
    assert sealed_rate_limits["ledgerId"] == rate_limits.ledger_id
    assert rate_limits.snapshot()["reservationCounts"] == {}
    assert len(set(worker.sessions)) == 8
    assert set(worker.sessions[:2]).isdisjoint(worker.sessions[2:])
    assert verify_run_integrity(result.outcome.run_path).valid

    restarted = replace(
        result.batch,
        tickets=SQLiteReplayTicketFinalizationVerifier(ledger),
    )
    assert restarted.verified_records(result.outcome.run_path) == result.batch.records
    plan = json.loads((result.outcome.run_path / "plan.json").read_text(encoding="utf-8"))
    capabilities = json.loads(
        (result.outcome.run_path / "capabilities.json").read_text(encoding="utf-8")
    )
    assert {step["request"]["agent_id"] for step in plan["steps"]} == {
        KISALocalAgentRuntime.agent_id
    }
    assert len(capabilities) == 2
    root_grant = capabilities[0]["grant"]
    specialist_grant = capabilities[1]["grant"]
    assert root_grant["subject"] == f"supervisor:{KISALocalAgentRuntime.agent_id}"
    assert specialist_grant["subject"] == KISALocalAgentRuntime.agent_id
    assert specialist_grant["parent_grant_id"] == root_grant["grant_id"]


@pytest.mark.asyncio
async def test_kisa_local_successful_replay_cannot_override_semantic_omission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    omitted_worker = M03TranscriptWorker(supports_claim=True)
    omitted_orchestrator, _ = _orchestrator(
        tmp_path,
        worker=_trusted_docker_backend(omitted_worker),
        omit_semantic_validation=True,
    )
    # Exercise the common Gate's semantic fail-closed branch even if an upstream
    # coordinator were to over-admit this Candidate and produce a successful receipt.
    monkeypatch.setattr(
        replay_module,
        "_eligible_for_kisa_replay",
        lambda candidate, decision: True,
    )

    omitted = await omitted_orchestrator.run(_campaign())

    assert len(omitted.outcome.validation.candidates) == 1
    assert omitted.outcome.validation.decisions[0].disposition is (FindingDisposition.NEEDS_REVIEW)
    assert omitted.outcome.validation.decisions[0].reason_codes == [
        ValidationReasonCode.VALIDATOR_OMITTED
    ]
    assert omitted.outcome.validation.decisions[0].confirmation_basis is None
    assert omitted.outcome.findings == []
    assert len(omitted.batch.records) == 1
    assert omitted.batch.records[0].supports_claim is True
    assert len(omitted.batch.verified_results) == 1
    assert len(omitted_worker.jobs) == 8
    assert (omitted.outcome.run_path / VERSIONED_VALIDATION_INDEX_PATH).is_file()
    assert omitted.outcome.report_path == (
        omitted.outcome.run_path / VERSIONED_VALIDATION_REPORT_PATH
    )
    assert load_validation_snapshot(omitted.outcome.run_path).semantics is (
        ValidationSnapshotSemantics.VERIFIED_REPLAY_EVIDENCE
    )


@pytest.mark.asyncio
async def test_kisa_local_empty_candidate_set_stays_legacy_without_gate_projection(
    tmp_path: Path,
) -> None:
    worker = M03TranscriptWorker(supports_claim=False)
    orchestrator, ledger = _orchestrator(
        tmp_path,
        worker=_trusted_docker_backend(worker),
    )

    result = await orchestrator.run(_campaign())

    assert ledger.is_file()
    assert result.outcome.validation.candidates == []
    assert result.outcome.validation.decisions == []
    assert result.outcome.findings == []
    assert result.batch.records == ()
    assert result.batch.verified_results == {}
    assert result.outcome.report_path == result.outcome.run_path / "report.md"
    assert len(worker.jobs) == 2
    assert not (result.outcome.run_path / VERSIONED_VALIDATION_INDEX_PATH).exists()
    assert load_validation_snapshot(result.outcome.run_path).semantics is (
        ValidationSnapshotSemantics.LEGACY_UNVERSIONED
    )


def test_kisa_local_validates_mode_and_bounded_repetitions(tmp_path: Path) -> None:
    worker = M03TranscriptWorker(supports_claim=True)
    agents = _agents()
    assert agents.agent_id == "trusted-core:kisa-local-agent"
    with pytest.raises(AttributeError):
        agents.agent_id = "agent:caller-controlled"
    with pytest.raises(ValueError, match="between 2 and 20"):
        KISALocalReplayOrchestrator(
            agents=agents,
            tools=_tools(),
            policy=PolicyEngine(),
            worker=worker,
            output_root=tmp_path,
            ticket_authority_factory=lambda: SQLiteReplayExecutionAuthority(
                tmp_path / "tickets.sqlite3"
            ),
            repetitions=1,
        )

    orchestrator, _ = _orchestrator(tmp_path, worker=worker)
    wrong_mode = _campaign().model_copy(
        update={"spec": _campaign().spec.model_copy(update={"mode": CampaignMode.CTF})}
    )
    with pytest.raises(ValueError, match="AI Red Team"):
        asyncio.run(orchestrator.run(wrong_mode))
    assert list(tmp_path.iterdir()) == []
