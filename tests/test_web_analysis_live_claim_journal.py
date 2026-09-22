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
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier
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
    WebAnalysisLiveClaimGateDContext,
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


def _reserve_gate_d(
    journal: WebAnalysisLiveClaimJournal,
    binding: WebAnalysisLiveClaimBinding,
) -> ReservedWebAnalysisLiveClaim:
    return journal.reserve_with_gate_d_context(
        binding,
        initial_authorization_verification_digest=_digest("initial-authorization"),
        initial_authorization_evaluated_at=NOW - timedelta(seconds=1),
        initial_authorization_expires_at=NOW + timedelta(minutes=1),
    )


def _record_gate_d(
    journal: WebAnalysisLiveClaimJournal,
    started: StartedWebAnalysisLiveClaim,
    *,
    tag: str = "a",
) -> StartedWebAnalysisLiveClaim:
    binding = started.entry.binding
    return journal.record_gate_d_pre_dispatch_context(
        started,
        pre_dispatch_authorization_verification_digest=_digest(f"pre-dispatch-authorization:{tag}"),
        pre_dispatch_authorization_evaluated_at=NOW + timedelta(microseconds=1),
        pre_dispatch_authorization_expires_at=NOW + timedelta(minutes=1),
        provider_route_attestation_digest=_digest(f"provider-route-attestation:{tag}"),
        transport_execution_id=f"exec_{binding.resources.resource_owner}",
        lease_ids=(f"lease_{_digest(f'lease:{tag}')[:32]}",),
        worker_context_digest=_digest(f"worker-context:{tag}"),
        job_metadata_digest=_digest(f"job-metadata:{tag}"),
        transport_binding_digest=_digest(f"transport-binding:{tag}"),
    )


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


def _spawn_targeted_recovery(
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
        recovered = journal.recover_binding_pending_cleanup(binding)
    except Exception as exc:  # pragma: no cover - surfaced by the parent assertion
        output.put(f"error:{type(exc).__name__}:{exc}")
    else:
        output.put(recovered.model_dump_json(by_alias=True))


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


@pytest.mark.parametrize(
    ("starting_phase", "expected_dispatch_count"),
    (("reservation", 0), ("live-start", 0), ("dispatch-started", 1)),
)
def test_targeted_recovery_moves_only_exact_binding_and_is_idempotent(
    tmp_path: Path,
    starting_phase: str,
    expected_dispatch_count: int,
) -> None:
    journal = _journal(tmp_path / f"live-claims-targeted-{starting_phase}.sqlite3")
    target = _binding()
    other = _binding(
        preparation_tag="preparation-other",
        admission_tag="admission-other",
        authorization_tag="authorization-other",
    )
    target_handle: Any = journal.reserve(target)
    if starting_phase in {"live-start", "dispatch-started"}:
        target_handle = journal.begin_live(target_handle)
    if starting_phase == "dispatch-started":
        target_handle = journal.mark_dispatch_started(target_handle)
    target_before = target_handle.entry
    other_before = journal.reserve(other).entry

    recovered = journal.recover_binding_pending_cleanup(target)

    assert type(recovered) is WebAnalysisLiveClaimJournalEntry
    assert recovered.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert recovered.pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
    assert recovered.dispatch_count == expected_dispatch_count
    assert len(recovered.event_digests) == len(target_before.event_digests) + 1
    assert journal.inspect(other.claim_id) == other_before

    repeated = journal.recover_binding_pending_cleanup(target)
    assert repeated == recovered
    assert repeated.event_digests == recovered.event_digests
    assert journal.inspect(other.claim_id) == other_before

    def advance_stale_handle() -> object:
        if starting_phase == "reservation":
            return journal.begin_live(target_handle)
        if starting_phase == "live-start":
            return journal.mark_dispatch_started(target_handle)
        return journal.mark_pending_cleanup(
            target_handle,
            outcome=WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED,
        )

    with pytest.raises(WebAnalysisLiveClaimJournalError):
        advance_stale_handle()
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        advance_stale_handle()
    assert journal.inspect(target.claim_id) == recovered
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="handle type is invalid"):
        journal.begin_live(cast(Any, recovered))


@pytest.mark.parametrize(
    "outcome",
    (
        WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
        WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED,
        WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED,
    ),
)
def test_targeted_recovery_preserves_known_pending_outcomes(
    tmp_path: Path,
    outcome: WebAnalysisLiveClaimPendingOutcome,
) -> None:
    journal = _journal(tmp_path / f"live-claims-targeted-{outcome.value}.sqlite3")
    binding = _binding()
    handle: Any = journal.reserve(binding)
    if outcome is not WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED:
        handle = journal.mark_dispatch_started(journal.begin_live(handle))
    pending = journal.mark_pending_cleanup(handle, outcome=outcome)

    recovered = journal.recover_binding_pending_cleanup(binding)

    assert recovered == pending
    assert recovered.pending_outcome is outcome
    assert recovered.event_digests == pending.event_digests


def test_targeted_recovery_rejects_foreign_terminal_and_tampered_claims(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims-targeted-rejections.sqlite3")
    binding = _binding()
    reserved = journal.reserve(binding).entry
    foreign_bindings = (
        _binding(
            preparation_tag="preparation-foreign",
            admission_tag="admission-foreign",
            authorization_tag="authorization-foreign",
        ),
        _binding(
            preparation_tag="preparation-a",
            admission_tag="admission-new-authorization",
            authorization_tag="authorization-new",
        ),
        _binding(
            preparation_tag="preparation-new",
            admission_tag="admission-new-preparation",
            authorization_tag="authorization-a",
        ),
    )

    for foreign in foreign_bindings:
        with pytest.raises(WebAnalysisLiveClaimJournalError, match="was not found"):
            journal.recover_binding_pending_cleanup(foreign)
    assert journal.inspect(binding.claim_id) == reserved

    pending = journal.recover_binding_pending_cleanup(binding)
    terminal = journal.finalize_terminal(
        pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=SHA_A,
        resource_absence_digest=SHA_B,
        terminal_receipt_digest=SHA_C,
    )
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="Terminal live claim"):
        journal.recover_binding_pending_cleanup(binding)
    assert journal.inspect(binding.claim_id) == terminal

    tampered_binding = _binding(
        preparation_tag="preparation-tampered",
        admission_tag="admission-tampered",
        authorization_tag="authorization-tampered",
    )
    tampered = journal.reserve(tampered_binding).entry
    with sqlite3.connect(journal.path) as connection:
        connection.execute("DROP TRIGGER web_analysis_live_claims_transition")
        connection.execute(
            "UPDATE web_analysis_live_claims SET state_digest = ? WHERE claim_id = ?",
            (_other_digest(tampered.state_digest), tampered_binding.claim_id),
        )
        connection.execute(journal_module._CLAIMS_TRANSITION_SQL)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="integrity checks"):
        journal.recover_binding_pending_cleanup(tampered_binding)


@pytest.mark.parametrize("uncertainty", ("rollback", "committed"))
def test_targeted_recovery_uncertainty_is_retryable_without_touching_other_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    uncertainty: str,
) -> None:
    journal = _journal(tmp_path / f"live-claims-targeted-{uncertainty}.sqlite3")
    binding = _binding()
    dispatched = journal.mark_dispatch_started(journal.begin_live(journal.reserve(binding))).entry
    other = _binding(
        preparation_tag="preparation-other",
        admission_tag="admission-other",
        authorization_tag="authorization-other",
    )
    other_before = journal.reserve(other).entry
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

    with monkeypatch.context() as scoped:
        scoped.setattr(journal_module, "_write_transaction_opened", uncertain_transaction)
        with pytest.raises(WebAnalysisLiveClaimJournalError, match="failed closed"):
            journal.recover_binding_pending_cleanup(binding)

    durable = journal.inspect(binding.claim_id)
    assert durable is not None
    assert durable.phase is (
        WebAnalysisLiveClaimPhase.LIVE_START
        if uncertainty == "rollback"
        else WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    )
    assert durable.dispatch_count == 1
    assert journal.inspect(other.claim_id) == other_before

    recovered = journal.recover_binding_pending_cleanup(binding)
    assert recovered.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert recovered.pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
    assert recovered.dispatch_count == 1
    assert len(recovered.event_digests) == len(dispatched.event_digests) + 1
    assert journal.inspect(other.claim_id) == other_before


@pytest.mark.skipif(os.name != "posix", reason="spawned SQLite process race requires POSIX")
def test_two_processes_targeted_recovery_converge_without_touching_other_rows(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims-targeted-process-race.sqlite3")
    binding = _binding()
    started = journal.begin_live(journal.reserve(binding)).entry
    other = _binding(
        preparation_tag="preparation-other",
        admission_tag="admission-other",
        authorization_tag="authorization-other",
    )
    other_before = journal.reserve(other).entry
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    ready = context.Queue()
    output = context.Queue()
    processes = [
        context.Process(
            target=_spawn_targeted_recovery,
            args=(
                str(journal.path),
                journal.store_id,
                binding.model_dump_json(by_alias=True),
                start,
                ready,
                output,
            ),
        )
        for _ in range(2)
    ]

    for process in processes:
        process.start()
    try:
        assert [ready.get(timeout=20) for _ in processes] == ["ready", "ready"]
        start.set()
        raw_results = [output.get(timeout=20) for _ in processes]
    except queue.Empty:
        pytest.fail("spawned targeted-recovery process did not report an outcome")
    finally:
        _terminate_processes(processes)
        ready.close()
        output.close()
        ready.join_thread()
        output.join_thread()

    assert all(process.exitcode == 0 for process in processes)
    assert all(not result.startswith("error:") for result in raw_results)
    results = tuple(
        WebAnalysisLiveClaimJournalEntry.model_validate_json(item) for item in raw_results
    )
    assert results[0] == results[1]
    assert results[0].phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert results[0].pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
    assert results[0].dispatch_count == 0
    assert len(results[0].event_digests) == len(started.event_digests) + 1
    assert journal.inspect(binding.claim_id) == results[0]
    assert journal.inspect(other.claim_id) == other_before


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


def test_gate_d_context_is_atomic_audit_only_and_required_before_bound_dispatch(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims-gate-d.sqlite3")
    binding = _binding()
    reserved = _reserve_gate_d(journal, binding)

    initial = journal.inspect_gate_d_context(binding.claim_id)

    assert type(initial) is WebAnalysisLiveClaimGateDContext
    assert initial.claim_id == binding.claim_id
    assert initial.claim_digest == binding.claim_digest
    assert initial.initial_authorization_evaluated_at == "2026-09-22T02:59:59.000000Z"
    assert initial.initial_authorization_expires_at == "2026-09-22T03:01:00.000000Z"
    assert initial.pre_dispatch_authorization_verification_digest is None
    assert initial.provider_route_attestation_digest is None
    assert initial.lease_ids is None
    assert initial.model_invocation_authorized is False
    assert initial.provider_dispatch_authorized is False
    assert initial.target_request_authorized is False
    assert initial.execution_authorized is False
    assert initial.automatic_redispatch_authorized is False

    started = journal.begin_live(reserved)
    rebound = _record_gate_d(journal, started)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        journal.mark_dispatch_started(started)
    full = journal.inspect_gate_d_context(binding.claim_id)
    assert full is not None
    assert full.pre_dispatch_authorization_evaluated_at == "2026-09-22T03:00:00.000001Z"
    assert full.pre_dispatch_authorization_expires_at == "2026-09-22T03:01:00.000000Z"
    assert full.provider_route_attestation_digest == _digest("provider-route-attestation:a")
    assert full.transport_execution_id == f"exec_{binding.resources.resource_owner}"
    assert full.lease_ids == (f"lease_{_digest('lease:a')[:32]}",)
    dispatched = journal.mark_dispatch_started(rebound)
    assert dispatched.entry.dispatch_count == 1
    assert dispatched.entry.dispatch_started_at == "2026-09-22T03:00:00.000002Z"

    reopened = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
        allow_create=False,
    )
    assert reopened.inspect_gate_d_context(binding.claim_id) == full

    legacy = _binding(
        preparation_tag="legacy-preparation",
        admission_tag="legacy-admission",
        authorization_tag="legacy-authorization",
    )
    legacy_started = journal.begin_live(journal.reserve(legacy))
    assert journal.inspect_gate_d_context(legacy.claim_id) is None
    assert journal.mark_dispatch_started(legacy_started).entry.dispatch_count == 1

    incomplete_binding = _binding(
        preparation_tag="incomplete-preparation",
        admission_tag="incomplete-admission",
        authorization_tag="incomplete-authorization",
    )
    incomplete_started = journal.begin_live(_reserve_gate_d(journal, incomplete_binding))
    with pytest.raises(
        WebAnalysisLiveClaimJournalError,
        match="complete pre-dispatch context",
    ):
        journal.mark_dispatch_started(incomplete_started)
    incomplete = journal.inspect(incomplete_binding.claim_id)
    assert incomplete is not None
    assert incomplete.phase is WebAnalysisLiveClaimPhase.LIVE_START
    assert incomplete.dispatch_count == 0


def test_gate_d_context_rejects_partial_stale_and_noncanonical_evidence_without_consumption(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "live-claims-gate-d-validation.sqlite3")
    binding = _binding()
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="digest is invalid"):
        journal.reserve_with_gate_d_context(
            binding,
            initial_authorization_verification_digest="A" * 64,
            initial_authorization_evaluated_at=NOW - timedelta(seconds=1),
            initial_authorization_expires_at=NOW + timedelta(minutes=1),
        )
    assert journal.inspect(binding.claim_id) is None
    assert journal.inspect_gate_d_context(binding.claim_id) is None

    expired_binding = _binding(
        preparation_tag="expired-preparation",
        admission_tag="expired-admission",
        authorization_tag="expired-authorization",
    )
    expired_journal = _journal(tmp_path / "live-claims-gate-d-expired-reservation.sqlite3")
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="expired before reservation"):
        expired_journal.reserve_with_gate_d_context(
            expired_binding,
            initial_authorization_verification_digest=_digest("expired-initial"),
            initial_authorization_evaluated_at=NOW - timedelta(seconds=1),
            initial_authorization_expires_at=NOW,
        )
    assert expired_journal.inspect(expired_binding.claim_id) is None
    assert expired_journal.inspect_gate_d_context(expired_binding.claim_id) is None

    reserved = _reserve_gate_d(journal, binding)
    started = journal.begin_live(reserved)
    foreign_binding = _binding(
        preparation_tag="foreign-context-preparation",
        admission_tag="foreign-context-admission",
        authorization_tag="foreign-context-authorization",
    )
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="differs from the live claim"):
        journal.record_gate_d_pre_dispatch_context(
            started,
            pre_dispatch_authorization_verification_digest=_digest("foreign-context"),
            pre_dispatch_authorization_evaluated_at=NOW + timedelta(microseconds=1),
            pre_dispatch_authorization_expires_at=NOW + timedelta(minutes=1),
            provider_route_attestation_digest=_digest("foreign-provider-route"),
            transport_execution_id=f"exec_{foreign_binding.resources.resource_owner}",
            lease_ids=(f"lease_{SHA_A[:32]}",),
            worker_context_digest=SHA_A,
            job_metadata_digest=SHA_B,
            transport_binding_digest=SHA_C,
        )
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="tuple"):
        journal.record_gate_d_pre_dispatch_context(
            started,
            pre_dispatch_authorization_verification_digest=_digest("pre-dispatch"),
            pre_dispatch_authorization_evaluated_at=NOW + timedelta(microseconds=1),
            pre_dispatch_authorization_expires_at=NOW + timedelta(minutes=1),
            provider_route_attestation_digest=_digest("provider-route"),
            transport_execution_id=f"exec_{binding.resources.resource_owner}",
            lease_ids=cast(Any, [f"lease_{'a' * 32}"]),
            worker_context_digest=SHA_A,
            job_metadata_digest=SHA_B,
            transport_binding_digest=SHA_C,
        )
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="exactly one"):
        journal.record_gate_d_pre_dispatch_context(
            started,
            pre_dispatch_authorization_verification_digest=_digest("zero-lease"),
            pre_dispatch_authorization_evaluated_at=NOW + timedelta(microseconds=1),
            pre_dispatch_authorization_expires_at=NOW + timedelta(minutes=1),
            provider_route_attestation_digest=_digest("zero-lease-provider-route"),
            transport_execution_id=f"exec_{binding.resources.resource_owner}",
            lease_ids=(),
            worker_context_digest=SHA_A,
            job_metadata_digest=SHA_B,
            transport_binding_digest=SHA_C,
        )
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="digest is invalid"):
        journal.record_gate_d_pre_dispatch_context(
            started,
            pre_dispatch_authorization_verification_digest=_digest("pre-dispatch"),
            pre_dispatch_authorization_evaluated_at=NOW + timedelta(microseconds=1),
            pre_dispatch_authorization_expires_at=NOW + timedelta(minutes=1),
            provider_route_attestation_digest="A" * 64,
            transport_execution_id=f"exec_{binding.resources.resource_owner}",
            lease_ids=(f"lease_{SHA_A[:32]}",),
            worker_context_digest=SHA_A,
            job_metadata_digest=SHA_B,
            transport_binding_digest=SHA_C,
        )
    rebound = _record_gate_d(journal, started)
    assert type(rebound) is StartedWebAnalysisLiveClaim

    initial = WebAnalysisLiveClaimGateDContext(
        claimId=binding.claim_id,
        claimDigest=binding.claim_digest,
        initialAuthorizationVerificationDigest=_digest("initial"),
        initialAuthorizationEvaluatedAt="2026-09-22T03:00:00.000000Z",
        initialAuthorizationExpiresAt="2026-09-22T03:01:00.000000Z",
    )
    partial = initial.model_dump(mode="python", by_alias=True)
    partial["preDispatchAuthorizationVerificationDigest"] = _digest("pre-dispatch")
    partial["contextDigest"] = ""
    with pytest.raises(ValidationError, match="all present or all absent"):
        WebAnalysisLiveClaimGateDContext.model_validate(partial)

    copied_time = initial.model_dump(mode="python", by_alias=True)
    copied_time.update(
        {
            "preDispatchAuthorizationVerificationDigest": _digest("pre-dispatch"),
            "preDispatchAuthorizationEvaluatedAt": initial.initial_authorization_evaluated_at,
            "preDispatchAuthorizationExpiresAt": initial.initial_authorization_expires_at,
            "providerRouteAttestationDigest": _digest("provider-route"),
            "transportExecutionId": f"exec_{binding.resources.resource_owner}",
            "leaseIds": (f"lease_{SHA_A[:32]}",),
            "workerContextDigest": SHA_A,
            "jobMetadataDigest": SHA_B,
            "transportBindingDigest": SHA_C,
            "contextDigest": "",
        }
    )
    missing_route = dict(copied_time)
    missing_route.pop("providerRouteAttestationDigest")
    with pytest.raises(ValidationError, match="all present or all absent"):
        WebAnalysisLiveClaimGateDContext.model_validate(missing_route)
    with pytest.raises(ValidationError, match="must follow initial"):
        WebAnalysisLiveClaimGateDContext.model_validate(copied_time)

    mismatched_expiry = dict(copied_time)
    mismatched_expiry.update(
        {
            "preDispatchAuthorizationEvaluatedAt": "2026-09-22T03:00:00.000001Z",
            "preDispatchAuthorizationExpiresAt": "2026-09-22T03:02:00.000000Z",
            "contextDigest": "",
        }
    )
    with pytest.raises(ValidationError, match="expiry differs"):
        WebAnalysisLiveClaimGateDContext.model_validate(mismatched_expiry)

    stale_binding = _binding(
        preparation_tag="stale-preparation",
        admission_tag="stale-admission",
        authorization_tag="stale-authorization",
    )
    stale_started = journal.begin_live(_reserve_gate_d(journal, stale_binding))
    assert stale_started.entry.live_started_at is not None
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="predates live-start"):
        journal.record_gate_d_pre_dispatch_context(
            stale_started,
            pre_dispatch_authorization_verification_digest=_digest("stale-pre-dispatch"),
            pre_dispatch_authorization_evaluated_at=NOW,
            pre_dispatch_authorization_expires_at=NOW + timedelta(minutes=1),
            provider_route_attestation_digest=_digest("stale-provider-route"),
            transport_execution_id=f"exec_{stale_binding.resources.resource_owner}",
            lease_ids=(f"lease_{SHA_A[:32]}",),
            worker_context_digest=SHA_A,
            job_metadata_digest=SHA_B,
            transport_binding_digest=SHA_C,
        )
    assert journal.inspect_gate_d_context(stale_binding.claim_id) is not None


def test_gate_d_dispatch_marker_refuses_authorization_at_exact_expiry(
    tmp_path: Path,
) -> None:
    expiry = NOW + timedelta(microseconds=2)
    clock = Mock(side_effect=(NOW, NOW + timedelta(microseconds=1), expiry))
    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "live-claims-gate-d-expiry.sqlite3",
        clock=clock,
        allow_create=True,
    )
    binding = _binding()
    reserved = journal.reserve_with_gate_d_context(
        binding,
        initial_authorization_verification_digest=_digest("initial-expiry-bound"),
        initial_authorization_evaluated_at=NOW - timedelta(seconds=1),
        initial_authorization_expires_at=expiry,
    )
    started = journal.begin_live(reserved)
    rebound = journal.record_gate_d_pre_dispatch_context(
        started,
        pre_dispatch_authorization_verification_digest=_digest("pre-dispatch-expiry-bound"),
        pre_dispatch_authorization_evaluated_at=NOW + timedelta(microseconds=1),
        pre_dispatch_authorization_expires_at=expiry,
        provider_route_attestation_digest=_digest("expiry-provider-route"),
        transport_execution_id=f"exec_{binding.resources.resource_owner}",
        lease_ids=(f"lease_{SHA_A[:32]}",),
        worker_context_digest=SHA_A,
        job_metadata_digest=SHA_B,
        transport_binding_digest=SHA_C,
    )

    with pytest.raises(WebAnalysisLiveClaimJournalError, match="expired before dispatch marker"):
        journal.mark_dispatch_started(rebound)

    durable = journal.inspect(binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.LIVE_START
    assert durable.dispatch_count == 0
    assert durable.dispatch_started_at is None
    assert len(durable.event_digests) == 2
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        journal.mark_dispatch_started(rebound)

    with (
        sqlite3.connect(journal.path) as connection,
        pytest.raises(sqlite3.IntegrityError, match="invalid Web analysis live claim"),
    ):
        connection.execute(
            """
            UPDATE web_analysis_live_claims
            SET dispatch_started_at = ?, dispatch_count = 1
            WHERE claim_id = ?
            """,
            (
                expiry.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                binding.claim_id,
            ),
        )
    assert journal.inspect(binding.claim_id) == durable


def test_gate_d_pre_dispatch_commit_uncertainty_is_read_only_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = _journal(tmp_path / "live-claims-gate-d-uncertain.sqlite3")
    binding = _binding()
    started = journal.begin_live(_reserve_gate_d(journal, binding))
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
            match="durable state requires inspection",
        ):
            _record_gate_d(journal, started)

    durable_context = journal.inspect_gate_d_context(binding.claim_id)
    assert durable_context is not None
    assert durable_context.pre_dispatch_authorization_verification_digest == _digest(
        "pre-dispatch-authorization:a"
    )
    assert durable_context.provider_route_attestation_digest == _digest(
        "provider-route-attestation:a"
    )
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        _record_gate_d(journal, started)
    recovered = journal.recover_binding_pending_cleanup(binding)
    assert recovered.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert recovered.pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
    assert recovered.dispatch_count == 0
    assert journal.inspect_gate_d_context(binding.claim_id) == durable_context


def test_gate_d_pre_dispatch_rejects_foreign_handle_and_concurrent_double_cas(
    tmp_path: Path,
) -> None:
    first = _journal(tmp_path / "live-claims-gate-d-first.sqlite3")
    second = _journal(tmp_path / "live-claims-gate-d-second.sqlite3")
    first_binding = _binding()
    second_binding = _binding(
        preparation_tag="second-preparation",
        admission_tag="second-admission",
        authorization_tag="second-authorization",
    )
    first_started = first.begin_live(_reserve_gate_d(first, first_binding))
    second_started = second.begin_live(_reserve_gate_d(second, second_binding))

    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        first.record_gate_d_pre_dispatch_context(
            second_started,
            pre_dispatch_authorization_verification_digest=_digest("foreign"),
            pre_dispatch_authorization_evaluated_at=NOW + timedelta(microseconds=1),
            pre_dispatch_authorization_expires_at=NOW + timedelta(minutes=1),
            provider_route_attestation_digest=_digest("foreign-provider-route"),
            transport_execution_id=f"exec_{second_binding.resources.resource_owner}",
            lease_ids=(f"lease_{SHA_A[:32]}",),
            worker_context_digest=SHA_A,
            job_metadata_digest=SHA_B,
            transport_binding_digest=SHA_C,
        )
    assert first.inspect_gate_d_context(first_binding.claim_id) is not None
    assert second.inspect_gate_d_context(second_binding.claim_id) is not None

    barrier = Barrier(2)

    def race(tag: str) -> StartedWebAnalysisLiveClaim | WebAnalysisLiveClaimJournalError:
        barrier.wait(timeout=10)
        try:
            return _record_gate_d(first, first_started, tag=tag)
        except WebAnalysisLiveClaimJournalError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(race, ("first", "second")))

    winners = tuple(item for item in results if type(item) is StartedWebAnalysisLiveClaim)
    rejected = tuple(item for item in results if type(item) is WebAnalysisLiveClaimJournalError)
    assert len(winners) == 1
    assert len(rejected) == 1
    assert "foreign or consumed" in str(rejected[0])
    context = first.inspect_gate_d_context(first_binding.claim_id)
    assert context is not None
    assert context.pre_dispatch_authorization_verification_digest in {
        _digest("pre-dispatch-authorization:first"),
        _digest("pre-dispatch-authorization:second"),
    }
    assert (
        context.pre_dispatch_authorization_verification_digest,
        context.provider_route_attestation_digest,
    ) in {
        (
            _digest("pre-dispatch-authorization:first"),
            _digest("provider-route-attestation:first"),
        ),
        (
            _digest("pre-dispatch-authorization:second"),
            _digest("provider-route-attestation:second"),
        ),
    }
    assert first.mark_dispatch_started(winners[0]).entry.dispatch_count == 1


def test_gate_d_context_row_tampering_fails_closed(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "live-claims-gate-d-tamper.sqlite3")
    binding = _binding()
    started = journal.begin_live(_reserve_gate_d(journal, binding))
    _record_gate_d(journal, started)

    with sqlite3.connect(journal.path) as connection:
        connection.execute("DROP TRIGGER web_analysis_live_claim_gate_d_contexts_immutable")
        connection.execute("DROP TRIGGER web_analysis_live_claim_gate_d_contexts_transition")
        connection.execute(
            """
            UPDATE web_analysis_live_claim_gate_d_contexts
            SET initial_authorization_expires_at = ?,
                pre_dispatch_authorization_expires_at = ?
            WHERE claim_id = ?
            """,
            (
                "2026-09-22T03:02:00.000000Z",
                "2026-09-22T03:02:00.000000Z",
                binding.claim_id,
            ),
        )
        connection.execute(journal_module._GATE_D_CONTEXTS_IMMUTABLE_SQL)
        connection.execute(journal_module._GATE_D_CONTEXTS_TRANSITION_SQL)

    with pytest.raises(WebAnalysisLiveClaimJournalError, match="integrity checks"):
        journal.inspect_gate_d_context(binding.claim_id)


def test_schema_version_one_is_rejected_without_implicit_migration(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "live-claims-version-one.sqlite3")
    store_id = journal.store_id
    with sqlite3.connect(journal.path) as connection:
        connection.execute("DROP TRIGGER web_analysis_live_claim_metadata_no_update")
        connection.execute(
            "UPDATE web_analysis_live_claim_metadata SET value = '1' WHERE key = 'schema_version'"
        )
        connection.execute(
            "UPDATE web_analysis_live_claim_metadata SET value = ? WHERE key = 'schema_digest'",
            (SHA_A,),
        )
        connection.execute(journal_module._METADATA_NO_UPDATE_SQL)
        connection.execute("PRAGMA user_version = 1")

    with pytest.raises(
        WebAnalysisLiveClaimJournalError,
        match="connection or version differs",
    ):
        WebAnalysisLiveClaimJournal(
            journal.path,
            expected_store_id=store_id,
            allow_create=False,
        )

    with sqlite3.connect(journal.path) as connection:
        metadata = dict(
            connection.execute("SELECT key, value FROM web_analysis_live_claim_metadata")
        )
        user_version = connection.execute("PRAGMA user_version").fetchone()
    assert metadata["schema_version"] == "1"
    assert metadata["schema_digest"] == SHA_A
    assert user_version == (1,)
