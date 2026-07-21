from __future__ import annotations

import multiprocessing
import os
import re
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from queue import Empty
from threading import Barrier
from typing import Any

import pytest

from pajin.domain.models import (
    CampaignMode,
    CapabilityGrant,
    Finding,
    FindingSeverity,
    ToolRequest,
    ToolRiskTier,
)
from pajin.domain.replay import (
    CompiledReplaySpec,
    ModeReplayContract,
    ReplayBinding,
    ReplayCapabilityGrant,
    ReplayCompilation,
    ReplayIntent,
    ReplaySessionPolicy,
    ReplaySourceCapabilityReceipt,
    ValidationEvidenceExcerpt,
    ValidationPacket,
    replay_argument_digest,
    replay_evidence_digest,
    replay_request_digest,
    replay_source_capability_digest,
)
from pajin.domain.validation import CandidateFinding
from pajin.replay.sqlite_tickets import (
    SQLiteReplayExecutionAuthority,
    SQLiteReplayTicketFinalizationVerifier,
)
from pajin.replay.tickets import (
    ReplayExecutionAuthority,
    ReplayExecutionTicket,
    ReplayTicketClaimer,
    ReplayTicketContext,
    canonical_replay_compilation_bytes,
)

NOW = datetime(2026, 7, 16, 3, 0, tzinfo=UTC)
CLAIMED_AT = NOW + timedelta(seconds=1)
FINALIZED_AT = NOW + timedelta(seconds=2)
TARGET = "https://replay.example.invalid/probe"
TARGET_ID = "replay-target"
CAMPAIGN = "replay-ticket-tests"
SCENARIO_ID = "test.replay-ticket"
TOOL_ID = "mock.replay-probe"
THREAT_CLASS = "M01"
REQUEST_ID = "tool_original_ticket_1"
EVIDENCE = f"evidence/{REQUEST_ID}.json"
SOURCE_ROOT_DIGEST = "a" * 64
CAMPAIGN_DIGEST = "b" * 64
TOOL_SPEC_DIGEST = "c" * 64
SCENARIO_DIGEST = "d" * 64
FINAL_SEAL_ROOT_DIGEST = "e" * 64
ARTIFACT_SET_DIGEST = "f" * 64


@dataclass(frozen=True, slots=True)
class FrozenClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


@dataclass(frozen=True, slots=True)
class TicketCase:
    path: Path
    ticket: ReplayExecutionTicket
    compilation: ReplayCompilation
    context: ReplayTicketContext

    @property
    def compilation_digest(self) -> str:
        return sha256(canonical_replay_compilation_bytes(self.compilation)).hexdigest()

    @property
    def replay_run_id(self) -> str:
        return self.compilation.spec.binding.replay_run_id


def _compilation(
    *,
    replay_run_id: str = "run_replay_ticket_1",
    expires_at: datetime = NOW + timedelta(minutes=5),
) -> ReplayCompilation:
    request = ToolRequest(
        request_id=REQUEST_ID,
        agent_id="agent:specialist:ticket-test",
        tool_id=TOOL_ID,
        target=TARGET,
        method="POST",
        arguments={"probe": "bounded"},
    )
    finding = Finding(
        finding_id="finding_ticket_1",
        title="Replay ticket test finding",
        severity=FindingSeverity.LOW,
        threat_class=THREAT_CLASS,
        target=TARGET,
        summary="A bounded finding used only to construct a valid compilation.",
        reproduction=["Run the bounded replay probe."],
        evidence=[EVIDENCE],
        confidence=1,
    )
    candidate = CandidateFinding(
        candidate_id="candidate_ticket_1",
        claim=finding,
        source="trusted-core:test",
        source_agent_id="trusted-core:ticket-test",
        source_request_ids=[REQUEST_ID],
        created_at=NOW - timedelta(minutes=4),
    )
    packet = ValidationPacket(
        packet_id="validation-packet_ticket_1",
        candidate_run_id="run_candidate_ticket_1",
        candidate=candidate,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=SCENARIO_ID,
        target_id=TARGET_ID,
        target=TARGET,
        threat_class=THREAT_CLASS,
        original_request_ids=[REQUEST_ID],
        evidence=[
            ValidationEvidenceExcerpt(
                reference=EVIDENCE,
                sha256="1" * 64,
                excerpt="Redacted bounded replay evidence.",
            )
        ],
        semantic_support_required=False,
        replay_contract_id="replay-contract:ticket-test:v1",
        created_at=NOW - timedelta(minutes=3),
    )
    contract = ModeReplayContract(
        contract_id="replay-contract:ticket-test:v1",
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=SCENARIO_ID,
        tool_id=TOOL_ID,
        tool_version="1.0.0",
        method="POST",
        risk_tier=ToolRiskTier.T1,
        automatic=True,
        replay_safe=True,
        idempotent=True,
        session_policy=ReplaySessionPolicy.STATELESS,
        repetitions=1,
        required_successes=1,
        oracle_id="test.ticket-oracle",
        oracle_version="1.0.0",
        observation_schema="pajin.test/ticket-output/v1",
        semantic_support_required=False,
        allowed_argument_fields={"probe"},
    )
    intent = ReplayIntent(
        intent_id="replay-intent_ticket_1",
        replay_contract_id=contract.contract_id,
        candidate_id=candidate.candidate_id,
        candidate_run_id=packet.candidate_run_id,
        original_request_id=REQUEST_ID,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=SCENARIO_ID,
        threat_class=THREAT_CLASS,
        comparison_goals=["Compare the bounded replay observation."],
        rationale="The Candidate requires an independent restricted replay.",
        created_at=NOW - timedelta(minutes=2),
    )
    binding = ReplayBinding(
        candidate_id=candidate.candidate_id,
        campaign=CAMPAIGN,
        candidate_run_id=packet.candidate_run_id,
        replay_run_id=replay_run_id,
        original_request_id=REQUEST_ID,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=SCENARIO_ID,
        threat_class=THREAT_CLASS,
        tool_id=TOOL_ID,
        tool_version="1.0.0",
        target_id=TARGET_ID,
        target=TARGET,
    )
    source_root = CapabilityGrant(
        grant_id="grant_supervisor_ticket_1",
        subject="agent:supervisor:ticket-test",
        campaign=CAMPAIGN,
        tools={TOOL_ID},
        targets={TARGET},
        max_risk_tier=ToolRiskTier.T1,
        max_calls=10,
        expires_at=NOW + timedelta(hours=1),
        delegable=True,
        issued_at=NOW - timedelta(minutes=20),
        depth=0,
    )
    source_specialist = CapabilityGrant(
        grant_id="grant_specialist_ticket_1",
        parent_grant_id=source_root.grant_id,
        subject=request.agent_id,
        campaign=CAMPAIGN,
        tools={TOOL_ID},
        targets={TARGET},
        max_risk_tier=ToolRiskTier.T1,
        max_calls=1,
        expires_at=NOW + timedelta(minutes=30),
        issued_at=NOW - timedelta(minutes=10),
        depth=1,
    )
    source_capability = ReplaySourceCapabilityReceipt(
        request_id=request.request_id,
        lineage=[source_root, source_specialist],
        execution_started_at=NOW - timedelta(minutes=6),
        execution_finished_at=NOW - timedelta(minutes=5),
    )
    source_capability_digest = replay_source_capability_digest(source_capability)
    grant_id = f"grant_replay_{replay_run_id}"
    spec = CompiledReplaySpec(
        spec_id=f"replay-spec_{replay_run_id}",
        intent_id=intent.intent_id,
        contract_id=contract.contract_id,
        original_plan_step_id="step_ticket_1",
        binding=binding,
        method="POST",
        arguments=request.arguments,
        argument_digest=replay_argument_digest(request.arguments),
        original_request_digest=replay_request_digest(request),
        original_evidence_digest=replay_evidence_digest([EVIDENCE]),
        source_capability_digest=source_capability_digest,
        risk_tier=ToolRiskTier.T1,
        replay_safe=True,
        idempotent=True,
        session_policy=ReplaySessionPolicy.STATELESS,
        repetitions=1,
        required_successes=1,
        oracle_id=contract.oracle_id,
        oracle_version=contract.oracle_version,
        observation_schema=contract.observation_schema,
        semantic_support_required=False,
        grant_id=grant_id,
        max_calls=1,
        compiled_at=NOW,
        expires_at=expires_at,
    )
    grant = ReplayCapabilityGrant(
        grant_id=grant_id,
        subject=f"reproducer:{grant_id}",
        campaign=CAMPAIGN,
        tools={TOOL_ID},
        targets={TARGET},
        max_risk_tier=ToolRiskTier.T1,
        max_calls=1,
        expires_at=expires_at,
        issued_at=NOW,
        contract_id=contract.contract_id,
        candidate_id=candidate.candidate_id,
        candidate_run_id=packet.candidate_run_id,
        replay_run_id=replay_run_id,
        original_request_id=REQUEST_ID,
        original_grant_id="grant_specialist_ticket_1",
        source_capability_digest=source_capability_digest,
        original_subject=request.agent_id,
        tool_id=TOOL_ID,
        target=TARGET,
        repetitions=1,
    )
    return ReplayCompilation(
        validation_packet=packet,
        contract=contract,
        intent=intent,
        original_request=request,
        original_evidence=[EVIDENCE],
        source_capability=source_capability,
        spec=spec,
        grant=grant,
    )


def _context() -> ReplayTicketContext:
    return ReplayTicketContext(
        candidate_source_root_digest=SOURCE_ROOT_DIGEST,
        campaign_digest=CAMPAIGN_DIGEST,
        tool_spec_digest=TOOL_SPEC_DIGEST,
        scenario_digest=SCENARIO_DIGEST,
    )


def _issue(
    path: Path,
    *,
    replay_run_id: str = "run_replay_ticket_1",
    expires_at: datetime = NOW + timedelta(minutes=5),
) -> TicketCase:
    compilation = _compilation(replay_run_id=replay_run_id, expires_at=expires_at)
    context = _context()
    authority = SQLiteReplayExecutionAuthority(path, clock=FrozenClock(NOW))
    ticket = authority.issuer().issue_from_compiler(compilation, context=context)
    return TicketCase(
        path=path.resolve(),
        ticket=ticket,
        compilation=compilation,
        context=context,
    )


def _claim(
    case: TicketCase,
    *,
    now: datetime = CLAIMED_AT,
    claimed_at: datetime = CLAIMED_AT,
    replay_run_id: str | None = None,
    source_root_digest: str = SOURCE_ROOT_DIGEST,
    campaign_digest: str = CAMPAIGN_DIGEST,
) -> None:
    authority = SQLiteReplayExecutionAuthority(case.path, clock=FrozenClock(now))
    claimed = authority.claimer().claim(
        case.ticket,
        expected_replay_run_id=replay_run_id or case.replay_run_id,
        expected_candidate_source_root_digest=source_root_digest,
        expected_campaign_digest=campaign_digest,
        claimed_at=claimed_at,
    )
    assert claimed.compilation == case.compilation
    assert claimed.compilation_digest == case.compilation_digest
    assert claimed.context == case.context


def _finalize(
    case: TicketCase,
    *,
    now: datetime = FINALIZED_AT,
    finalized_at: datetime = FINALIZED_AT,
    final_seal_root_digest: str = FINAL_SEAL_ROOT_DIGEST,
    artifact_set_digest: str = ARTIFACT_SET_DIGEST,
) -> None:
    authority = SQLiteReplayExecutionAuthority(case.path, clock=FrozenClock(now))
    authority.claimer().finalize(
        case.ticket,
        final_seal_root_digest=final_seal_root_digest,
        artifact_set_digest=artifact_set_digest,
        finalized_at=finalized_at,
    )


def _verify(
    case: TicketCase,
    *,
    ticket_id: str | None = None,
    final_seal_root_digest: str = FINAL_SEAL_ROOT_DIGEST,
    artifact_set_digest: str = ARTIFACT_SET_DIGEST,
    compilation_digest: str | None = None,
    source_root_digest: str = SOURCE_ROOT_DIGEST,
    replay_run_id: str | None = None,
) -> None:
    SQLiteReplayTicketFinalizationVerifier(case.path).verify_finalized(
        ticket_id or case.ticket.ticket_id,
        final_seal_root_digest=final_seal_root_digest,
        artifact_set_digest=artifact_set_digest,
        compilation_digest=compilation_digest or case.compilation_digest,
        candidate_source_root_digest=source_root_digest,
        replay_run_id=replay_run_id or case.replay_run_id,
    )


def _finalized_case(
    path: Path,
    *,
    replay_run_id: str = "run_replay_ticket_1",
) -> TicketCase:
    case = _issue(path, replay_run_id=replay_run_id)
    _claim(case)
    _finalize(case)
    return case


def _process_claim(path: str, ticket_id: str, output: Any) -> None:
    try:
        authority = SQLiteReplayExecutionAuthority(
            Path(path),
            clock=FrozenClock(CLAIMED_AT),
        )
        authority.claimer().claim(
            ReplayExecutionTicket(ticket_id=ticket_id),
            expected_replay_run_id="run_replay_multiprocess",
            expected_candidate_source_root_digest=SOURCE_ROOT_DIGEST,
            expected_campaign_digest=CAMPAIGN_DIGEST,
            claimed_at=NOW - timedelta(days=1),
        )
    except PermissionError:
        output.put("rejected")
    except BaseException as exc:  # pragma: no cover - surfaced in the parent assertion
        output.put(f"error:{type(exc).__name__}")
    else:
        output.put("claimed")


def test_ticket_survives_reopen_for_claim_finalize_and_read_only_verify(
    tmp_path: Path,
) -> None:
    case = _issue(tmp_path / "state" / "replay-tickets.sqlite3")

    _claim(case)
    _finalize(case)
    _verify(case)

    with sqlite3.connect(case.path) as connection:
        state, event_count = connection.execute(
            """
            SELECT state, (
                SELECT COUNT(*) FROM replay_ticket_events WHERE ticket_id = ?
            ) FROM replay_tickets WHERE ticket_id = ?
            """,
            (case.ticket.ticket_id, case.ticket.ticket_id),
        ).fetchone()
    assert state == "finalized"
    assert event_count == 3


def test_durable_authority_ignores_caller_backdate_and_uses_trusted_clock_for_expiry(
    tmp_path: Path,
) -> None:
    case = _issue(
        tmp_path / "replay-tickets.sqlite3",
        expires_at=NOW + timedelta(minutes=5),
    )

    with pytest.raises(PermissionError):
        _claim(
            case,
            now=NOW + timedelta(minutes=6),
            claimed_at=NOW - timedelta(days=365),
        )

    with sqlite3.connect(case.path) as connection:
        state = connection.execute(
            "SELECT state FROM replay_tickets WHERE ticket_id = ?",
            (case.ticket.ticket_id,),
        ).fetchone()[0]
    assert state == "issued"


def test_unknown_issued_and_claimed_tickets_are_not_finalized(
    tmp_path: Path,
) -> None:
    case = _issue(tmp_path / "replay-tickets.sqlite3")
    unknown = ReplayExecutionTicket(ticket_id="replay-ticket_unknown")
    authority = SQLiteReplayExecutionAuthority(case.path, clock=FrozenClock(CLAIMED_AT))

    with pytest.raises(KeyError):
        authority.claimer().claim(
            unknown,
            expected_replay_run_id=case.replay_run_id,
            expected_candidate_source_root_digest=SOURCE_ROOT_DIGEST,
            expected_campaign_digest=CAMPAIGN_DIGEST,
            claimed_at=CLAIMED_AT,
        )
    with pytest.raises(PermissionError):
        _verify(case, ticket_id=unknown.ticket_id)
    with pytest.raises(PermissionError):
        _verify(case)

    _claim(case)

    with pytest.raises(PermissionError):
        _verify(case)


def test_claim_rejects_run_source_and_campaign_substitution_without_consuming_ticket(
    tmp_path: Path,
) -> None:
    case = _issue(tmp_path / "replay-tickets.sqlite3")

    for substitutions in (
        {"replay_run_id": "run_replay_foreign"},
        {"source_root_digest": "9" * 64},
        {"campaign_digest": "8" * 64},
    ):
        with pytest.raises(PermissionError):
            _claim(case, **substitutions)  # type: ignore[arg-type]

    _claim(case)


@pytest.mark.parametrize(
    "substitution",
    ["run", "source", "compilation", "final-seal", "artifact-set"],
)
def test_read_only_verifier_rejects_receipt_substitution(
    tmp_path: Path,
    substitution: str,
) -> None:
    case = _finalized_case(tmp_path / f"{substitution}.sqlite3")
    values: dict[str, str] = {}
    if substitution == "run":
        values["replay_run_id"] = "run_replay_foreign"
    elif substitution == "source":
        values["source_root_digest"] = "9" * 64
    elif substitution == "compilation":
        values["compilation_digest"] = "8" * 64
    elif substitution == "final-seal":
        values["final_seal_root_digest"] = "7" * 64
    else:
        values["artifact_set_digest"] = "6" * 64

    with pytest.raises(PermissionError):
        _verify(case, **values)  # type: ignore[arg-type]


def test_finalize_is_exactly_idempotent_and_rejects_different_artifacts(
    tmp_path: Path,
) -> None:
    case = _issue(tmp_path / "replay-tickets.sqlite3")
    _claim(case)
    _finalize(case)

    _finalize(
        case,
        now=FINALIZED_AT + timedelta(minutes=1),
        finalized_at=NOW - timedelta(days=1),
    )
    with pytest.raises(PermissionError):
        _finalize(case, final_seal_root_digest="7" * 64)
    with pytest.raises(PermissionError):
        _finalize(case, artifact_set_digest="6" * 64)

    with sqlite3.connect(case.path) as connection:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM replay_ticket_events WHERE ticket_id = ?",
            (case.ticket.ticket_id,),
        ).fetchone()[0]
    assert event_count == 3
    _verify(case)


def test_finalized_ticket_remains_verifiable_after_its_execution_expiry(
    tmp_path: Path,
) -> None:
    case = _issue(
        tmp_path / "replay-tickets.sqlite3",
        expires_at=NOW + timedelta(seconds=2),
    )
    _claim(case, now=NOW + timedelta(seconds=1))
    _finalize(case, now=NOW + timedelta(minutes=10))

    _verify(case)


def test_two_threads_can_claim_a_ticket_exactly_once(tmp_path: Path) -> None:
    case = _issue(tmp_path / "replay-tickets.sqlite3", replay_run_id="run_replay_threaded")
    claimers: list[ReplayTicketClaimer] = [
        SQLiteReplayExecutionAuthority(case.path, clock=FrozenClock(CLAIMED_AT)).claimer()
        for _ in range(2)
    ]
    barrier = Barrier(2)

    def attempt(claimer: ReplayTicketClaimer) -> str:
        barrier.wait()
        try:
            claimer.claim(
                case.ticket,
                expected_replay_run_id=case.replay_run_id,
                expected_candidate_source_root_digest=SOURCE_ROOT_DIGEST,
                expected_campaign_digest=CAMPAIGN_DIGEST,
                claimed_at=NOW - timedelta(days=1),
            )
        except PermissionError:
            return "rejected"
        return "claimed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, claimers))

    assert sorted(outcomes) == ["claimed", "rejected"]


@pytest.mark.skipif(os.name != "posix", reason="SQLite process race is exercised on POSIX")
def test_two_processes_can_claim_a_ticket_exactly_once(tmp_path: Path) -> None:
    case = _issue(
        tmp_path / "replay-tickets.sqlite3",
        replay_run_id="run_replay_multiprocess",
    )
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_process_claim,
            args=(str(case.path), case.ticket.ticket_id, output),
        )
        for _ in range(2)
    ]

    for process in processes:
        process.start()
    try:
        outcomes = [output.get(timeout=15) for _ in processes]
    except Empty:
        for process in processes:
            process.terminate()
        pytest.fail("concurrent replay ticket claim process did not report an outcome")
    finally:
        for process in processes:
            process.join(timeout=15)
        output.close()

    assert all(process.exitcode == 0 for process in processes)
    assert sorted(outcomes) == ["claimed", "rejected"]


def test_claimed_ticket_stays_consumed_after_claiming_authority_disappears(
    tmp_path: Path,
) -> None:
    case = _issue(tmp_path / "replay-tickets.sqlite3")
    _claim(case)

    with pytest.raises(PermissionError):
        _claim(case, now=CLAIMED_AT + timedelta(minutes=1))
    with pytest.raises(PermissionError):
        _verify(case)

    with sqlite3.connect(case.path) as connection:
        state, event_count = connection.execute(
            """
            SELECT state, (
                SELECT COUNT(*) FROM replay_ticket_events WHERE ticket_id = ?
            ) FROM replay_tickets WHERE ticket_id = ?
            """,
            (case.ticket.ticket_id, case.ticket.ticket_id),
        ).fetchone()
    assert state == "claimed"
    assert event_count == 2


def test_read_only_verifier_does_not_create_a_missing_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "missing-state" / "replay-tickets.sqlite3"
    verifier = SQLiteReplayTicketFinalizationVerifier(ledger)

    with pytest.raises(RuntimeError):
        verifier.verify_finalized(
            "replay-ticket_missing",
            final_seal_root_digest=FINAL_SEAL_ROOT_DIGEST,
            artifact_set_digest=ARTIFACT_SET_DIGEST,
            compilation_digest="1" * 64,
            candidate_source_root_digest=SOURCE_ROOT_DIGEST,
            replay_run_id="run_replay_missing",
        )

    assert not ledger.exists()
    assert not ledger.parent.exists()


@pytest.mark.parametrize("tamper", ["canonical", "context", "state", "event"])
def test_record_and_event_tampering_is_rejected(tmp_path: Path, tamper: str) -> None:
    case = _finalized_case(tmp_path / f"{tamper}.sqlite3")
    try:
        with sqlite3.connect(case.path) as connection:
            if tamper == "canonical":
                connection.execute(
                    "UPDATE replay_tickets SET canonical_compilation = ? WHERE ticket_id = ?",
                    (b"{}", case.ticket.ticket_id),
                )
            elif tamper == "context":
                connection.execute(
                    "UPDATE replay_tickets SET campaign_digest = ? WHERE ticket_id = ?",
                    ("9" * 64, case.ticket.ticket_id),
                )
            elif tamper == "state":
                connection.execute(
                    "UPDATE replay_tickets SET state = 'claimed' WHERE ticket_id = ?",
                    (case.ticket.ticket_id,),
                )
            else:
                connection.execute(
                    """
                    UPDATE replay_ticket_events SET occurred_at = ?
                    WHERE ticket_id = ? AND ordinal = 1
                    """,
                    ((NOW - timedelta(days=1)).isoformat(), case.ticket.ticket_id),
                )
    except sqlite3.DatabaseError:
        _verify(case)
        return

    with pytest.raises((PermissionError, RuntimeError)):
        _verify(case)


def test_same_replay_run_cannot_be_issued_twice(tmp_path: Path) -> None:
    ledger = tmp_path / "replay-tickets.sqlite3"
    case = _issue(ledger)
    authority = SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))

    with pytest.raises(PermissionError):
        authority.issuer().issue_from_compiler(case.compilation, context=case.context)


def test_process_local_same_replay_run_cannot_be_issued_twice() -> None:
    authority = ReplayExecutionAuthority()
    compilation = _compilation()
    context = _context()
    authority.issuer().issue_from_compiler(compilation, context=context)

    with pytest.raises(
        PermissionError,
        match="a replay execution ticket already exists for this Run",
    ):
        authority.issuer().issue_from_compiler(compilation, context=context)


def test_process_local_replay_run_issuance_is_atomic_across_threads() -> None:
    authority = ReplayExecutionAuthority()
    compilation = _compilation()
    context = _context()
    barrier = Barrier(2)

    def issue() -> str:
        barrier.wait()
        try:
            authority.issuer().issue_from_compiler(compilation, context=context)
        except PermissionError as exc:
            assert str(exc) == "a replay execution ticket already exists for this Run"
            return "rejected"
        return "issued"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: issue(), range(2)))

    assert sorted(outcomes) == ["issued", "rejected"]


def test_process_local_recovery_is_context_bound_and_idempotent() -> None:
    authority = ReplayExecutionAuthority()
    compilation = _compilation()
    context = _context()
    ticket = authority.issuer().issue_from_compiler(compilation, context=context)
    authority.claimer().claim(
        ticket,
        expected_replay_run_id=compilation.spec.binding.replay_run_id,
        expected_candidate_source_root_digest=context.candidate_source_root_digest,
        expected_campaign_digest=context.campaign_digest,
        claimed_at=CLAIMED_AT,
    )
    wrong_context = ReplayTicketContext(
        candidate_source_root_digest=context.candidate_source_root_digest,
        campaign_digest=context.campaign_digest,
        tool_spec_digest=context.tool_spec_digest,
        scenario_digest="0" * 64,
    )
    compilation_digest = sha256(canonical_replay_compilation_bytes(compilation)).hexdigest()

    with pytest.raises(PermissionError, match="recovery context"):
        authority.claimer().recover_finalization(
            ticket,
            final_seal_root_digest=FINAL_SEAL_ROOT_DIGEST,
            artifact_set_digest=ARTIFACT_SET_DIGEST,
            compilation_digest=compilation_digest,
            context=wrong_context,
            replay_run_id=compilation.spec.binding.replay_run_id,
            finalized_at=FINALIZED_AT,
        )

    for recovered_at in (FINALIZED_AT, FINALIZED_AT + timedelta(seconds=1)):
        authority.claimer().recover_finalization(
            ticket,
            final_seal_root_digest=FINAL_SEAL_ROOT_DIGEST,
            artifact_set_digest=ARTIFACT_SET_DIGEST,
            compilation_digest=compilation_digest,
            context=context,
            replay_run_id=compilation.spec.binding.replay_run_id,
            finalized_at=recovered_at,
        )
    authority.verifier().verify_finalized(
        ticket.ticket_id,
        final_seal_root_digest=FINAL_SEAL_ROOT_DIGEST,
        artifact_set_digest=ARTIFACT_SET_DIGEST,
        compilation_digest=compilation_digest,
        candidate_source_root_digest=context.candidate_source_root_digest,
        replay_run_id=compilation.spec.binding.replay_run_id,
    )


@pytest.mark.parametrize(
    ("transition", "expected_state", "expected_events"),
    [
        ("issue", None, 0),
        ("claim", "issued", 1),
        ("finalize", "claimed", 2),
    ],
)
def test_permission_hardening_failure_precedes_ticket_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
    expected_state: str | None,
    expected_events: int,
) -> None:
    ledger = tmp_path / "replay-tickets.sqlite3"
    case: TicketCase | None = None
    if transition == "issue":
        authority = SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))
    else:
        case = _issue(ledger)
        if transition == "finalize":
            _claim(case)
            authority = SQLiteReplayExecutionAuthority(
                ledger,
                clock=FrozenClock(FINALIZED_AT),
            )
        else:
            authority = SQLiteReplayExecutionAuthority(
                ledger,
                clock=FrozenClock(CLAIMED_AT),
            )

    def deny_chmod(_descriptor: int, _mode: int) -> None:
        raise PermissionError("chmod denied")

    monkeypatch.setattr(os, "fchmod", deny_chmod)
    with pytest.raises(PermissionError, match="chmod denied"):
        if transition == "issue":
            authority.issuer().issue_from_compiler(_compilation(), context=_context())
        elif transition == "claim":
            assert case is not None
            authority.claimer().claim(
                case.ticket,
                expected_replay_run_id=case.replay_run_id,
                expected_candidate_source_root_digest=SOURCE_ROOT_DIGEST,
                expected_campaign_digest=CAMPAIGN_DIGEST,
                claimed_at=CLAIMED_AT,
            )
        else:
            assert case is not None
            authority.claimer().finalize(
                case.ticket,
                final_seal_root_digest=FINAL_SEAL_ROOT_DIGEST,
                artifact_set_digest=ARTIFACT_SET_DIGEST,
                finalized_at=FINALIZED_AT,
            )

    with sqlite3.connect(ledger) as connection:
        row = connection.execute(
            """
            SELECT state, (
                SELECT COUNT(*) FROM replay_ticket_events WHERE ticket_id = replay_tickets.ticket_id
            ) FROM replay_tickets
            """
        ).fetchone()
    if expected_state is None:
        assert row is None
    else:
        assert row == (expected_state, expected_events)


def test_created_ledger_has_strict_unique_fk_index_and_append_only_schema(
    tmp_path: Path,
) -> None:
    case = _issue(tmp_path / "state" / "replay-tickets.sqlite3")

    with sqlite3.connect(case.path) as connection:
        connection.row_factory = sqlite3.Row
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        version = connection.execute(
            "SELECT value FROM replay_ticket_metadata WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert version == "1"
        table_rows = connection.execute("PRAGMA table_list").fetchall()
        strict_tables = {
            row["name"]
            for row in table_rows
            if row["name"] in {"replay_ticket_metadata", "replay_tickets", "replay_ticket_events"}
            and row["strict"] == 1
        }
        assert strict_tables == {
            "replay_ticket_metadata",
            "replay_tickets",
            "replay_ticket_events",
        }
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(replay_ticket_events)"
        ).fetchall()
        assert any(
            row["table"] == "replay_tickets"
            and row["from"] == "ticket_id"
            and row["to"] == "ticket_id"
            for row in foreign_keys
        )
        ticket_indexes = connection.execute("PRAGMA index_list(replay_tickets)").fetchall()
        assert any(row["unique"] == 1 for row in ticket_indexes)
        event_indexes = connection.execute("PRAGMA index_list(replay_ticket_events)").fetchall()
        assert any(row["unique"] == 1 for row in event_indexes)
        assert any(row["name"] == "replay_ticket_events_ticket_idx" for row in event_indexes)
        triggers = connection.execute(
            """
            SELECT sql FROM sqlite_schema
            WHERE type = 'trigger' AND tbl_name = 'replay_ticket_events'
            """
        ).fetchall()
        trigger_sql = "\n".join(str(row["sql"]).upper() for row in triggers)
        assert "UPDATE" in trigger_sql
        assert "DELETE" in trigger_sql


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_event_rows_reject_direct_update_and_delete(
    tmp_path: Path,
    operation: str,
) -> None:
    case = _issue(tmp_path / f"events-{operation}.sqlite3")
    connection = sqlite3.connect(case.path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            if operation == "update":
                connection.execute(
                    """
                    UPDATE replay_ticket_events SET occurred_at = occurred_at
                    WHERE ticket_id = ?
                    """,
                    (case.ticket.ticket_id,),
                )
            else:
                connection.execute(
                    "DELETE FROM replay_ticket_events WHERE ticket_id = ?",
                    (case.ticket.ticket_id,),
                )
    finally:
        connection.close()


@pytest.mark.parametrize("table", ["tickets", "events"])
@pytest.mark.parametrize("conflict_operation", ["replace", "upsert"])
def test_append_only_rows_reject_replace_and_upsert(
    tmp_path: Path,
    table: str,
    conflict_operation: str,
) -> None:
    case = _finalized_case(tmp_path / f"{table}-{conflict_operation}.sqlite3")
    with sqlite3.connect(case.path) as connection:
        if table == "tickets":
            before = connection.execute(
                "SELECT rowid FROM replay_tickets WHERE ticket_id = ?",
                (case.ticket.ticket_id,),
            ).fetchone()
            if conflict_operation == "replace":
                statement = """
                    INSERT OR REPLACE INTO replay_tickets
                    SELECT * FROM replay_tickets WHERE ticket_id = ?
                """
            else:
                statement = """
                    INSERT INTO replay_tickets
                    SELECT * FROM replay_tickets WHERE ticket_id = ?
                    ON CONFLICT(ticket_id) DO UPDATE SET state = excluded.state
                """
        else:
            before = connection.execute(
                """
                SELECT event_id FROM replay_ticket_events
                WHERE ticket_id = ? AND ordinal = 1
                """,
                (case.ticket.ticket_id,),
            ).fetchone()
            if conflict_operation == "replace":
                statement = """
                    INSERT OR REPLACE INTO replay_ticket_events
                    SELECT * FROM replay_ticket_events
                    WHERE ticket_id = ? AND ordinal = 1
                """
            else:
                statement = """
                    INSERT INTO replay_ticket_events
                    SELECT * FROM replay_ticket_events
                    WHERE ticket_id = ? AND ordinal = 1
                    ON CONFLICT(ticket_id, ordinal)
                    DO UPDATE SET occurred_at = excluded.occurred_at
                """

        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(statement, (case.ticket.ticket_id,))

        if table == "tickets":
            after = connection.execute(
                "SELECT rowid FROM replay_tickets WHERE ticket_id = ?",
                (case.ticket.ticket_id,),
            ).fetchone()
        else:
            after = connection.execute(
                """
                SELECT event_id FROM replay_ticket_events
                WHERE ticket_id = ? AND ordinal = 1
                """,
                (case.ticket.ticket_id,),
            ).fetchone()

    assert before == after
    _verify(case)


def test_ticket_rows_reject_explicit_rowid_replace_with_new_identity(tmp_path: Path) -> None:
    case = _finalized_case(tmp_path / "ticket-rowid-replace.sqlite3")
    with sqlite3.connect(case.path) as connection:
        before = connection.execute(
            "SELECT rowid, * FROM replay_tickets WHERE ticket_id = ?",
            (case.ticket.ticket_id,),
        ).fetchone()
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                """
                INSERT OR REPLACE INTO replay_tickets (
                    rowid, ticket_id, canonical_compilation, compilation_digest,
                    candidate_source_root_digest, campaign_digest, tool_spec_digest,
                    scenario_digest, replay_run_id, expires_at, state, issued_at,
                    claimed_at, finalized_at, final_seal_root_digest, artifact_set_digest,
                    issuance_digest, state_digest
                )
                SELECT
                    rowid, ticket_id || '_replacement', canonical_compilation,
                    compilation_digest, candidate_source_root_digest, campaign_digest,
                    tool_spec_digest, scenario_digest, replay_run_id || '_replacement',
                    expires_at, state, issued_at, claimed_at, finalized_at,
                    final_seal_root_digest, artifact_set_digest, issuance_digest, state_digest
                FROM replay_tickets WHERE ticket_id = ?
                """,
                (case.ticket.ticket_id,),
            )
        after = connection.execute(
            "SELECT rowid, * FROM replay_tickets WHERE ticket_id = ?",
            (case.ticket.ticket_id,),
        ).fetchone()

    assert before == after
    _verify(case)


def test_ticket_rows_reject_update_or_replace_rowid_collision(tmp_path: Path) -> None:
    ledger = tmp_path / "ticket-rowid-update-replace.sqlite3"
    first = _issue(ledger, replay_run_id="run_replay_rowid_first")
    second = _issue(ledger, replay_run_id="run_replay_rowid_second")

    with sqlite3.connect(ledger) as connection:
        before = connection.execute(
            "SELECT rowid, ticket_id, replay_run_id FROM replay_tickets ORDER BY rowid"
        ).fetchall()
        assert len(before) == 2
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute(
                "UPDATE OR REPLACE replay_tickets SET rowid = ? WHERE rowid = ?",
                (before[1][0], before[0][0]),
            )
        after = connection.execute(
            "SELECT rowid, ticket_id, replay_run_id FROM replay_tickets ORDER BY rowid"
        ).fetchall()

    assert before == after
    _claim(first)
    _claim(second)


def _rewrite_schema_sql(
    connection: sqlite3.Connection,
    *,
    object_name: str,
    pattern: str,
    replacement: str,
) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_schema WHERE name = ?",
        (object_name,),
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    changed, count = re.subn(pattern, replacement, row[0], count=1, flags=re.IGNORECASE)
    assert count == 1
    schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
    connection.execute("PRAGMA writable_schema = ON")
    try:
        connection.execute(
            "UPDATE sqlite_schema SET sql = ? WHERE name = ?",
            (changed, object_name),
        )
    finally:
        connection.execute("PRAGMA writable_schema = OFF")
    connection.execute(f"PRAGMA schema_version = {schema_version + 1}")


def _corrupt_schema(path: Path, corruption: str) -> None:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        if corruption == "metadata-version":
            connection.execute(
                "UPDATE replay_ticket_metadata SET value = '999' WHERE key = 'schema_version'"
            )
        elif corruption == "user-version":
            connection.execute("PRAGMA user_version = 999")
        elif corruption == "table":
            connection.execute("DROP TABLE replay_ticket_events")
        elif corruption == "index":
            connection.execute("DROP INDEX replay_ticket_events_ticket_idx")
        elif corruption == "foreign-key":
            _rewrite_schema_sql(
                connection,
                object_name="replay_ticket_events",
                pattern=r"\s+REFERENCES\s+replay_tickets\s*\(\s*ticket_id\s*\)",
                replacement="",
            )
        elif corruption == "unique":
            _rewrite_schema_sql(
                connection,
                object_name="replay_tickets",
                pattern=r"(replay_run_id\s+TEXT\s+NOT\s+NULL)\s+UNIQUE",
                replacement=r"\1",
            )
        elif corruption == "strict":
            _rewrite_schema_sql(
                connection,
                object_name="replay_tickets",
                pattern=r"\)\s*STRICT\s*$",
                replacement=")",
            )
        else:
            trigger = connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger' AND tbl_name = 'replay_ticket_events'
                ORDER BY name LIMIT 1
                """
            ).fetchone()
            assert trigger is not None
            trigger_name = str(trigger[0]).replace('"', '""')
            connection.execute(f'DROP TRIGGER "{trigger_name}"')
    finally:
        connection.close()


@pytest.mark.parametrize(
    "corruption",
    [
        "metadata-version",
        "user-version",
        "table",
        "index",
        "foreign-key",
        "unique",
        "strict",
        "append-only-trigger",
    ],
)
def test_schema_corruption_is_rejected(tmp_path: Path, corruption: str) -> None:
    ledger = tmp_path / f"{corruption}.sqlite3"
    SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))
    _corrupt_schema(ledger, corruption)

    with pytest.raises((RuntimeError, sqlite3.DatabaseError)):
        SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are not portable")
def test_new_state_directory_and_ledger_are_owner_only(tmp_path: Path) -> None:
    state_dir = tmp_path / "private-state"
    ledger = state_dir / "replay-tickets.sqlite3"

    SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))

    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW is a POSIX boundary")
def test_sqlite_authority_rejects_symlink_leaf_without_touching_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "private-state"
    state_dir.mkdir(mode=0o700)
    external = tmp_path / "external.sqlite3"
    external.write_bytes(b"do-not-touch")
    external.chmod(0o640)
    ledger = state_dir / "replay-tickets.sqlite3"
    ledger.symlink_to(external)

    with pytest.raises(RuntimeError, match="regular file"):
        SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))

    assert external.read_bytes() == b"do-not-touch"
    assert stat.S_IMODE(external.stat().st_mode) == 0o640


@pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW is a POSIX boundary")
def test_sqlite_authority_rejects_symlink_parent(tmp_path: Path) -> None:
    external_state = tmp_path / "external-state"
    external_state.mkdir(mode=0o700)
    linked_state = tmp_path / "linked-state"
    linked_state.symlink_to(external_state, target_is_directory=True)

    with pytest.raises(RuntimeError, match="regular directory"):
        SQLiteReplayExecutionAuthority(
            linked_state / "replay-tickets.sqlite3",
            clock=FrozenClock(NOW),
        )

    assert list(external_state.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="hard-link identity is a POSIX boundary")
def test_sqlite_authority_rejects_hard_linked_ledger(tmp_path: Path) -> None:
    state_dir = tmp_path / "private-state"
    state_dir.mkdir(mode=0o700)
    external = tmp_path / "external.sqlite3"
    external.write_bytes(b"do-not-touch")
    external.chmod(0o640)
    ledger = state_dir / "replay-tickets.sqlite3"
    os.link(external, ledger)

    with pytest.raises(RuntimeError, match="private regular file"):
        SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))

    assert external.read_bytes() == b"do-not-touch"
    assert stat.S_IMODE(external.stat().st_mode) == 0o640


@pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW is a POSIX boundary")
def test_sqlite_authority_rejects_symlink_journal(tmp_path: Path) -> None:
    state_dir = tmp_path / "private-state"
    ledger = state_dir / "replay-tickets.sqlite3"
    SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))
    external = tmp_path / "external-journal"
    external.write_bytes(b"do-not-touch")
    external.chmod(0o640)
    Path(f"{ledger}-journal").symlink_to(external)

    with pytest.raises(RuntimeError, match="journal is not a regular file"):
        SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))

    assert external.read_bytes() == b"do-not-touch"
    assert stat.S_IMODE(external.stat().st_mode) == 0o640


@pytest.mark.skipif(os.name != "posix", reason="directory identity is a POSIX boundary")
def test_sqlite_authority_detects_parent_directory_swap_before_schema_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "private-state"
    ledger = state_dir / "replay-tickets.sqlite3"
    SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))
    original_bytes = ledger.read_bytes()

    replacement = tmp_path / "replacement-state"
    replacement.mkdir(mode=0o700)
    replacement_ledger = replacement / ledger.name
    replacement_ledger.touch(mode=0o600)
    saved_state = tmp_path / "saved-state"
    real_connect = sqlite3.connect
    swapped = False

    def swap_parent_before_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped:
            swapped = True
            state_dir.rename(saved_state)
            replacement.rename(state_dir)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", swap_parent_before_connect)
    with pytest.raises(RuntimeError, match="changed while it was opened"):
        SQLiteReplayExecutionAuthority(ledger, clock=FrozenClock(NOW))

    assert (saved_state / ledger.name).read_bytes() == original_bytes
    assert ledger.read_bytes() == b""
