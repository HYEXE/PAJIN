from __future__ import annotations

import copy
import multiprocessing
import os
import pickle
import queue
import selectors
import signal
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from pajin.benchmark.effectiveness.docker import LocalModelRuntime
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.worker import DockerWorkerBackend
from pajin.skills.models import SkillRegistryRef
from pajin.web_assessment import analysis_live_claim_journal as journal_module
from pajin.web_assessment.analysis_capacity_v2 import SubprocessLlamaCppLiveMaterialization
from pajin.web_assessment.analysis_live_claim_journal import (
    DispatchStartedWebAnalysisLiveClaim,
    ReservedWebAnalysisLiveClaim,
    StartedWebAnalysisLiveClaim,
    WebAnalysisLiveClaimBinding,
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimJournalEntry,
    WebAnalysisLiveClaimJournalError,
    WebAnalysisLiveClaimPendingOutcome,
    WebAnalysisLiveClaimPhase,
    WebAnalysisLiveClaimTerminalDisposition,
    WebAnalysisOneCallAuthorizationCoordinate,
    build_web_analysis_live_claim_binding,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
)

NOW = datetime(2026, 9, 22, 3, 0, 0, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).parents[1]
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


class _StepClock:
    def __init__(self) -> None:
        self._tick = 0

    def __call__(self) -> datetime:
        value = NOW + timedelta(microseconds=self._tick)
        self._tick += 1
        return value


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _run_id(label: str) -> str:
    return f"run_20260922T030000Z_{_digest(label)[:8]}"


def _other_digest(value: str) -> str:
    replacement = "0" * 64
    return replacement if value != replacement else "1" * 64


def _admission(
    *,
    preparation_tag: str = "preparation-a",
    admission_tag: str = "admission-a",
) -> PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope:
    return PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(
        {
            "apiVersion": (
                "pajin.dev/prepared-compact-skill-bound-web-analysis-admission/v1alpha1"
            ),
            "kind": "PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope",
            "admissionId": "",
            "admissionDigest": "",
            "status": "prepared-request-admitted-not-authorized-no-dispatch",
            "preparationRunId": _run_id(f"preparation-run:{preparation_tag}"),
            "preparationRunRootDigest": _digest(f"preparation-root:{preparation_tag}"),
            "preparationDigest": _digest(f"preparation:{preparation_tag}"),
            "preparationIndexDigest": _digest(f"preparation-index:{preparation_tag}"),
            "liveRequestDigest": _digest(f"live-request:{admission_tag}"),
            "sourceRunId": _run_id("source-run"),
            "sourceRunRootDigest": _digest("source-root"),
            "skillRunId": _run_id("skill-run"),
            "skillRunRootDigest": _digest("skill-root"),
            "skillSnapshotDigest": _digest("skill-snapshot"),
            "registry": SkillRegistryRef(
                registryId="pajin.analysis-skills",
                registryVersion="1.0.0",
                registryDigest=_digest("skill-registry"),
            ),
            "selectionPolicyDigest": _digest("selection-policy"),
            "capacityRunId": _run_id("capacity-run"),
            "capacityRunRootDigest": _digest("capacity-root"),
            "capacityPinDigest": _digest("capacity-pin"),
            "capacityProofDigest": _digest("capacity-proof"),
            "modelMaterializationAttestationDigest": _digest("capacity-materialization"),
            "transportPinDigest": _digest("transport-pin"),
            "compactProjectionDigest": _digest("compact-projection"),
            "providerRegistrationDigest": _digest("provider-registration"),
            "providerChatRequestDigest": _digest("provider-chat-request"),
            "systemMessageDigest": _digest("system-message"),
            "userMessageDigest": _digest("user-message"),
            "responseSchemaDigest": _digest("response-schema"),
            "contextTokens": 4096,
            "promptTokens": 2048,
            "completionTokens": 1024,
            "totalTokens": 3072,
            "remainingTokens": 1024,
            "attempt": 1,
            "messageRoles": ("system", "user"),
            "toolsAllowed": False,
            "streamingAllowed": False,
            "authorizationPresented": False,
            "authorizationConsumed": False,
            "preparationClaimed": False,
            "liveModelMaterializationAttested": False,
            "modelInvocationAuthorized": False,
            "providerDispatchAuthorized": False,
            "targetRequestAuthorized": False,
            "executionAuthorized": False,
            "automaticRedispatchAuthorized": False,
        }
    )


def _authorization(tag: str = "authorization-a") -> WebAnalysisOneCallAuthorizationCoordinate:
    return WebAnalysisOneCallAuthorizationCoordinate(
        authorizationEnvelopeDigest=_digest(f"authorization-envelope:{tag}"),
        issuer="test.external-authorizer.invalid",
        keyId="test-signing-key-v1",
        nonce=f"test-nonce-{tag}-0123456789abcdef",
    )


def _binding(
    *,
    preparation_tag: str = "preparation-a",
    admission_tag: str = "admission-a",
    authorization_tag: str = "authorization-a",
) -> WebAnalysisLiveClaimBinding:
    return build_web_analysis_live_claim_binding(
        admission=_admission(preparation_tag=preparation_tag, admission_tag=admission_tag),
        authorization=_authorization(authorization_tag),
    )


def _journal(path: Path) -> WebAnalysisLiveClaimJournal:
    return WebAnalysisLiveClaimJournal(path, clock=_StepClock(), allow_create=True)


def _spawn_reserve(
    path: str,
    expected_store_id: str,
    binding_json: str,
    start: Any,
    ready: Any,
    output: Any,
) -> None:
    try:
        journal = WebAnalysisLiveClaimJournal(
            Path(path), expected_store_id=expected_store_id, allow_create=False
        )
        binding = WebAnalysisLiveClaimBinding.model_validate_json(binding_json)
        ready.put("ready")
        if not start.wait(timeout=15):
            output.put("error:start-timeout")
            return
        journal.reserve(binding)
    except WebAnalysisLiveClaimJournalError:
        output.put("rejected")
    except Exception as exc:  # pragma: no cover - surfaced by the parent assertion
        output.put(f"error:{type(exc).__name__}:{exc}")
    else:
        output.put("claimed")


def _terminate_processes(processes: list[Any]) -> None:
    for process in processes:
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        if process.is_alive():  # pragma: no cover - emergency cleanup only
            process.kill()
            process.join(timeout=5)


def test_schema_has_independent_single_column_preparation_and_authorization_unique_keys(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")

    with sqlite3.connect(journal.path) as connection:
        unique_columns = {
            tuple(
                str(column[2])
                for column in connection.execute(f"PRAGMA index_info('{index[1]!s}')")
            )
            for index in connection.execute("PRAGMA index_list('web_analysis_live_claims')")
            if index[2] == 1
        }

    assert ("preparation_identity",) in unique_columns
    assert ("authorization_identity",) in unique_columns
    assert ("preparation_identity", "authorization_identity") not in unique_columns


def test_creation_and_reopen_require_explicit_store_identity(tmp_path: Path) -> None:
    path = tmp_path / "live-claims.sqlite3"
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="requires its expected store"):
        WebAnalysisLiveClaimJournal(path)

    created = _journal(path)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match=r"existing.*expected store"):
        WebAnalysisLiveClaimJournal(path, allow_create=True)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="requires its expected store"):
        WebAnalysisLiveClaimJournal(path, allow_create=False)

    reopened = WebAnalysisLiveClaimJournal(
        path,
        expected_store_id=created.store_id,
        allow_create=False,
    )
    assert reopened.store_id == created.store_id


def test_exact_and_cross_identity_replays_are_all_rejected_without_partial_consumption(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    original = _binding()
    same_preparation_new_authorization = _binding(
        preparation_tag="preparation-a",
        admission_tag="admission-b",
        authorization_tag="authorization-b",
    )
    same_authorization_new_preparation = _binding(
        preparation_tag="preparation-b",
        admission_tag="admission-c",
        authorization_tag="authorization-a",
    )
    reserved = journal.reserve(original).entry

    for replay in (
        original,
        same_preparation_new_authorization,
        same_authorization_new_preparation,
    ):
        with pytest.raises(
            WebAnalysisLiveClaimJournalError,
            match="Preparation or authorization identity was already consumed",
        ):
            journal.reserve(replay)

    assert journal.inspect(original.claim_id) == reserved
    assert journal.inspect_preparation(original.preparation_identity) == reserved
    assert journal.inspect_authorization(original.authorization_identity) == reserved
    assert (
        journal.inspect_authorization(same_preparation_new_authorization.authorization_identity)
        is None
    )
    assert (
        journal.inspect_preparation(same_authorization_new_preparation.preparation_identity) is None
    )
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM web_analysis_live_claims").fetchone() == (
            1,
        )
        event_count = connection.execute(
            "SELECT COUNT(*) FROM web_analysis_live_claim_events"
        ).fetchone()
        assert event_count == (1,)


def test_four_phase_lifecycle_consumes_one_dispatch_slot_without_external_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_spies = (
        Mock(side_effect=AssertionError("live model materialization was called")),
        Mock(side_effect=AssertionError("Provider dispatch was called")),
        Mock(side_effect=AssertionError("target worker was created")),
        Mock(side_effect=AssertionError("legacy local model runtime was started")),
    )
    monkeypatch.setattr(SubprocessLlamaCppLiveMaterialization, "materialize", external_spies[0])
    monkeypatch.setattr(PolicyBoundProviderPort, "chat_bound", external_spies[1])
    monkeypatch.setattr(DockerWorkerBackend, "__init__", external_spies[2])
    monkeypatch.setattr(LocalModelRuntime, "start", external_spies[3])

    journal = _journal(tmp_path / "live-claims.sqlite3")
    binding = _binding()
    reserved_handle = journal.reserve(binding)
    reserved = reserved_handle.entry
    assert reserved.phase is WebAnalysisLiveClaimPhase.RESERVATION
    assert reserved.dispatch_count == 0
    assert len(reserved.event_digests) == 1

    started_handle = journal.begin_live(reserved_handle)
    started = started_handle.entry
    assert started.phase is WebAnalysisLiveClaimPhase.LIVE_START
    assert started.live_started_at is not None
    assert started.dispatch_count == 0
    assert len(started.event_digests) == 2
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        journal.begin_live(reserved_handle)

    dispatch_handle = journal.mark_dispatch_started(started_handle)
    dispatched = dispatch_handle.entry
    assert dispatched.phase is WebAnalysisLiveClaimPhase.LIVE_START
    assert dispatched.dispatch_count == 1
    assert dispatched.dispatch_started_at is not None
    assert len(dispatched.event_digests) == 3
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        journal.mark_dispatch_started(started_handle)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="cannot become not-dispatched"):
        journal.mark_pending_cleanup(
            dispatch_handle,
            outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
        )

    pending = journal.mark_pending_cleanup(
        dispatch_handle,
        outcome=WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED,
    )
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert pending.dispatch_count == 1
    assert pending.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert len(pending.event_digests) == 4

    terminal = journal.finalize_terminal(
        pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.SUCCESS,
        cleanup_result_digest=SHA_A,
        resource_absence_digest=SHA_B,
        terminal_receipt_digest=SHA_C,
    )
    assert terminal.phase is WebAnalysisLiveClaimPhase.TERMINAL
    assert terminal.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    assert terminal.dispatch_count == 1
    assert len(terminal.event_digests) == 5
    assert journal.inspect(binding.claim_id) == terminal
    assert journal.pending_cleanup_entries() == ()
    for spy in external_spies:
        spy.assert_not_called()


@pytest.mark.parametrize("race", ("same-pair", "same-preparation", "same-authorization"))
@pytest.mark.skipif(os.name != "posix", reason="spawned SQLite process race requires POSIX")
def test_two_spawned_processes_cannot_both_reserve_a_shared_identity(
    tmp_path: Path,
    race: str,
) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    first = _binding()
    if race == "same-pair":
        second = first
    elif race == "same-preparation":
        second = _binding(
            preparation_tag="preparation-a",
            admission_tag="admission-b",
            authorization_tag="authorization-b",
        )
    else:
        second = _binding(
            preparation_tag="preparation-b",
            admission_tag="admission-c",
            authorization_tag="authorization-a",
        )
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    ready = context.Queue()
    output = context.Queue()
    processes = [
        context.Process(
            target=_spawn_reserve,
            args=(
                str(journal.path),
                journal.store_id,
                binding.model_dump_json(by_alias=True),
                start,
                ready,
                output,
            ),
        )
        for binding in (first, second)
    ]

    for process in processes:
        process.start()
    try:
        assert [ready.get(timeout=20) for _ in processes] == ["ready", "ready"]
        start.set()
        outcomes = [output.get(timeout=20) for _ in processes]
    except queue.Empty:
        pytest.fail("spawned live-claim process did not report an outcome")
    finally:
        _terminate_processes(processes)
        ready.close()
        output.close()
        ready.join_thread()
        output.join_thread()

    assert all(process.exitcode == 0 for process in processes)
    assert sorted(outcomes) == ["claimed", "rejected"]
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM web_analysis_live_claims").fetchone() == (
            1,
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM web_analysis_live_claim_events"
        ).fetchone() == (1,)
    winner = journal.inspect_preparation(first.preparation_identity)
    if winner is None:
        winner = journal.inspect_preparation(second.preparation_identity)
    assert winner is not None
    assert winner.phase is WebAnalysisLiveClaimPhase.RESERVATION
    assert winner.dispatch_count == 0


@pytest.mark.skipif(os.name != "posix", reason="SIGKILL recovery requires POSIX")
def test_sigkill_after_committed_live_start_recovers_cleanup_only_and_never_redispatches(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    binding = _binding()
    script = """
import signal
import sys
from pathlib import Path
from pajin.web_assessment.analysis_live_claim_journal import (
    WebAnalysisLiveClaimBinding,
    WebAnalysisLiveClaimJournal,
)

journal = WebAnalysisLiveClaimJournal(
    Path(sys.argv[1]), expected_store_id=sys.argv[2], allow_create=False,
)
binding = WebAnalysisLiveClaimBinding.model_validate_json(sys.argv[3])
started = journal.begin_live(journal.reserve(binding))
print(started.entry.binding.claim_id, flush=True)
signal.pause()
"""
    environment = os.environ.copy()
    source_root = str(PROJECT_ROOT / "src")
    inherited_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root
        if not inherited_pythonpath
        else f"{source_root}{os.pathsep}{inherited_pythonpath}"
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(journal.path),
            journal.store_id,
            binding.model_dump_json(by_alias=True),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=20), "child did not commit live-start"
        assert process.stdout.readline().strip() == binding.claim_id
        process.kill()
        _stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)

    assert process.returncode == -signal.SIGKILL, stderr
    reopened = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
        allow_create=False,
        clock=_StepClock(),
    )
    before_recovery = reopened.inspect(binding.claim_id)
    assert before_recovery is not None
    assert before_recovery.phase is WebAnalysisLiveClaimPhase.LIVE_START
    assert before_recovery.dispatch_count == 0

    recovered = reopened.recover_pending_cleanup()
    assert len(recovered) == 1
    pending = recovered[0]
    assert type(pending) is WebAnalysisLiveClaimJournalEntry
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert pending.pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
    assert pending.dispatch_count == 0
    assert reopened.pending_cleanup_entries() == (pending,)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="already consumed"):
        reopened.reserve(binding)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="handle type is invalid"):
        reopened.begin_live(cast(Any, pending))

    terminal = reopened.finalize_terminal(
        pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=SHA_A,
        resource_absence_digest=SHA_B,
        terminal_receipt_digest=SHA_C,
    )
    assert terminal.phase is WebAnalysisLiveClaimPhase.TERMINAL
    second_reopen = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
        allow_create=False,
    )
    assert second_reopen.pending_cleanup_entries() == ()
    assert second_reopen.inspect(binding.claim_id) == terminal


def test_cleanup_failure_appends_evidence_but_keeps_claim_pending_and_non_reusable(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    binding = _binding()
    pending = journal.mark_pending_cleanup(
        journal.reserve(binding),
        outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
    )
    failure_digest = _digest("cleanup-failure")

    failed = journal.record_cleanup_failure(pending, failure_digest=failure_digest)

    assert failed.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert failed.pending_outcome is WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED
    assert failed.state_digest == pending.state_digest
    assert len(failed.event_digests) == len(pending.event_digests) + 1
    assert journal.pending_cleanup_entries() == (failed,)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="differs from durable state"):
        journal.record_cleanup_failure(pending, failure_digest=_digest("stale-cleanup"))
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="already consumed"):
        journal.reserve(binding)


@pytest.mark.parametrize("tamper", ("row", "schema", "event", "cross-field"))
def test_row_schema_and_event_tampering_all_fail_closed(tmp_path: Path, tamper: str) -> None:
    journal = _journal(tmp_path / f"live-claims-{tamper}.sqlite3")
    binding = _binding()
    reserved_handle = journal.reserve(binding)
    reserved = reserved_handle.entry
    pending: WebAnalysisLiveClaimJournalEntry | None = None
    if tamper == "cross-field":
        pending = journal.mark_pending_cleanup(
            reserved_handle,
            outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
        )

    with sqlite3.connect(journal.path) as connection:
        if tamper == "row":
            connection.execute("DROP TRIGGER web_analysis_live_claims_transition")
            connection.execute(
                "UPDATE web_analysis_live_claims SET state_digest = ? WHERE claim_id = ?",
                (_other_digest(reserved.state_digest), binding.claim_id),
            )
            connection.execute(journal_module._CLAIMS_TRANSITION_SQL)
        elif tamper == "event":
            connection.execute("DROP TRIGGER web_analysis_live_claim_events_no_update")
            connection.execute(
                "UPDATE web_analysis_live_claim_events SET event_digest = ? WHERE claim_id = ?",
                (_other_digest(reserved.event_digests[0]), binding.claim_id),
            )
            connection.execute(journal_module._EVENTS_NO_UPDATE_SQL)
        elif tamper == "cross-field":
            assert pending is not None
            assert pending.pending_cleanup_at is not None
            forged_digest = journal_module._event_digest(
                claim_id=binding.claim_id,
                ordinal=2,
                event_type="pending-cleanup",
                from_phase=WebAnalysisLiveClaimPhase.RESERVATION,
                to_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
                occurred_at=pending.pending_cleanup_at,
                pending_outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                terminal_disposition=WebAnalysisLiveClaimTerminalDisposition.FAILURE,
                evidence_digest=None,
                previous_event_digest=pending.event_digests[0],
            )
            connection.execute("DROP TRIGGER web_analysis_live_claim_events_no_update")
            connection.execute(
                """
                UPDATE web_analysis_live_claim_events
                SET terminal_disposition = ?, event_digest = ?
                WHERE claim_id = ? AND ordinal = 2
                """,
                (
                    WebAnalysisLiveClaimTerminalDisposition.FAILURE.value,
                    forged_digest,
                    binding.claim_id,
                ),
            )
            connection.execute(journal_module._EVENTS_NO_UPDATE_SQL)
        else:
            connection.execute("DROP INDEX web_analysis_live_claim_events_claim_idx")

    with pytest.raises(WebAnalysisLiveClaimJournalError):
        journal.inspect(binding.claim_id)


def test_open_journal_rejects_valid_database_path_substitution(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    binding = _binding()
    journal.reserve(binding)
    replacement = _journal(tmp_path / "replacement.sqlite3")
    assert replacement.store_id != journal.store_id

    os.replace(replacement.path, journal.path)

    with pytest.raises(WebAnalysisLiveClaimJournalError, match="opened store identity"):
        journal.reserve(binding)


def test_committed_write_rejects_valid_database_path_substitution_before_returning_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    binding = _binding()
    reserved = journal.reserve(binding)
    replacement = _journal(tmp_path / "replacement.sqlite3")
    replacement_store_id = replacement.store_id
    real_transaction = cast(Any, journal_module)._write_transaction_opened

    @contextmanager
    def replace_after_body(path: Path) -> Iterator[sqlite3.Connection]:
        with real_transaction(path) as connection:
            yield connection
            os.replace(replacement.path, path)

    with monkeypatch.context() as scoped:
        scoped.setattr(journal_module, "_write_transaction_opened", replace_after_body)
        with pytest.raises(
            WebAnalysisLiveClaimJournalError,
            match="changed during a committed transaction",
        ):
            journal.begin_live(reserved)

    with pytest.raises(WebAnalysisLiveClaimJournalError, match="opened store identity"):
        journal.inspect(binding.claim_id)
    authoritative = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=replacement_store_id,
        allow_create=False,
    )
    assert authoritative.inspect(binding.claim_id) is None
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        journal.begin_live(reserved)


def test_post_commit_reservation_error_is_recoverable_but_never_reissues_a_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    binding = _binding()
    real_transaction = cast(Any, journal_module)._write_transaction_opened

    @contextmanager
    def commit_then_raise(path: Path) -> Iterator[sqlite3.Connection]:
        with real_transaction(path) as connection:
            yield connection
        raise RuntimeError("injected post-commit uncertainty")

    with monkeypatch.context() as scoped:
        scoped.setattr(journal_module, "_write_transaction_opened", commit_then_raise)
        with pytest.raises(
            WebAnalysisLiveClaimJournalError,
            match="durable state requires recovery inspection",
        ):
            journal.reserve(binding)

    durable = journal.inspect_preparation(binding.preparation_identity)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.RESERVATION
    assert journal.inspect_authorization(binding.authorization_identity) == durable
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="already consumed"):
        journal.reserve(binding)
    recovered = journal.recover_pending_cleanup()
    assert len(recovered) == 1
    assert recovered[0].phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert recovered[0].pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN


@pytest.mark.parametrize("transition", ("begin-live", "dispatch", "pending-cleanup"))
@pytest.mark.parametrize("uncertainty", ("rollback", "committed"))
def test_transition_uncertainty_consumes_handle_before_database_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
    uncertainty: str,
) -> None:
    journal = _journal(tmp_path / f"live-claims-{transition}-{uncertainty}.sqlite3")
    binding = _binding()
    handle: Any = journal.reserve(binding)
    if transition == "dispatch":
        handle = journal.begin_live(handle)
    real_transaction = cast(Any, journal_module)._write_transaction_opened

    @contextmanager
    def uncertain_transaction(path: Path) -> Iterator[sqlite3.Connection]:
        if uncertainty == "rollback":
            with real_transaction(path) as connection:
                yield connection
                raise RuntimeError("injected pre-commit rollback")
        else:
            with real_transaction(path) as connection:
                yield connection
            raise RuntimeError("injected post-commit uncertainty")

    def perform_transition() -> object:
        if transition == "begin-live":
            return journal.begin_live(handle)
        if transition == "dispatch":
            return journal.mark_dispatch_started(handle)
        return journal.mark_pending_cleanup(
            handle,
            outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(journal_module, "_write_transaction_opened", uncertain_transaction)
        with pytest.raises(WebAnalysisLiveClaimJournalError, match="failed closed"):
            perform_transition()

    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        perform_transition()
    durable = journal.inspect(binding.claim_id)
    assert durable is not None
    if uncertainty == "committed" and transition == "pending-cleanup":
        assert durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
        assert durable.pending_outcome is WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED
    recovered = journal.recover_pending_cleanup()
    assert len(recovered) == 1
    assert recovered[0].phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert recovered[0].dispatch_count == int(
        uncertainty == "committed" and transition == "dispatch"
    )
    if uncertainty != "committed" or transition != "pending-cleanup":
        assert recovered[0].pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN


def test_claim_handles_cannot_be_copied_deepcopied_or_pickled(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "live-claims.sqlite3")
    reserved = journal.reserve(_binding())
    assert type(reserved) is ReservedWebAnalysisLiveClaim
    with pytest.raises(TypeError, match="only be issued"):
        ReservedWebAnalysisLiveClaim(reserved.entry, journal._authority)
    reopened = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
        allow_create=False,
    )
    audited = reopened.inspect(reserved.entry.binding.claim_id)
    assert audited is not None
    with pytest.raises(TypeError, match="only be issued"):
        ReservedWebAnalysisLiveClaim(audited, reopened._authority)
    forged = object.__new__(ReservedWebAnalysisLiveClaim)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="not journal-issued"):
        reopened.begin_live(forged)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(reserved)

    started = journal.begin_live(reserved)
    assert type(started) is StartedWebAnalysisLiveClaim
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(started)

    dispatch = journal.mark_dispatch_started(started)
    assert type(dispatch) is DispatchStartedWebAnalysisLiveClaim
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(dispatch)


def test_resource_owner_and_owned_names_cannot_be_injected(tmp_path: Path) -> None:
    binding = _binding()
    owner = binding.resources.resource_owner
    runtime = SubprocessLlamaCppLiveMaterialization(
        model_path=tmp_path / "model.gguf",
        resource_owner=owner,
    )
    assert runtime._owner == owner
    assert runtime._container_name == binding.resources.runtime_container_name
    assert runtime._seed_container_name == binding.resources.seed_container_name
    assert runtime._volume_name == binding.resources.volume_name
    assert runtime._network_name == binding.resources.network_name

    with pytest.raises(ValueError, match="resource owner is invalid"):
        SubprocessLlamaCppLiveMaterialization(
            model_path=tmp_path / "model.gguf",
            resource_owner="not-a-valid-owner",
        )

    wire = binding.model_dump(mode="python", by_alias=True)
    forged_owner = "f" * 32 if binding.resources.resource_owner != "f" * 32 else "e" * 32
    wire["claimId"] = ""
    wire["claimDigest"] = ""
    wire["resources"] = {
        "resourceOwner": forged_owner,
        "runtimeContainerName": f"pajin-web-analysis-live-{forged_owner}",
        "seedContainerName": f"pajin-web-analysis-live-seed-{forged_owner}",
        "volumeName": f"pajin-web-analysis-live-model-{forged_owner}",
        "networkName": f"pajin-web-analysis-live-network-{forged_owner}",
    }

    with pytest.raises(ValidationError, match="resource locator differs"):
        WebAnalysisLiveClaimBinding.model_validate(wire)
