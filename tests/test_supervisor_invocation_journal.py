from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.graph.projection import GraphSnapshotReason
from pajin.runtime.budget_state import BUDGET_SCHEMA_SQL, BUDGET_TABLE, BudgetPersistenceError
from pajin.runtime.control import BudgetController
from pajin.supervision import invocation_journal as journal_module
from pajin.supervision.checkpoint_scheduler import (
    SupervisorCheckpointSchedule,
    SupervisorCheckpointSchedulePublication,
    _checkpoint_key,
)
from pajin.supervision.invocation import (
    SupervisorDedicatedBudgetPolicy,
    SupervisorInvocationMessageBinding,
    SupervisorInvocationRequestBinding,
    SupervisorInvocationUsageBound,
    _request_schema_digest,
    _response_schema_digest,
)
from pajin.supervision.invocation_journal import (
    SupervisorBenchmarkRequestContext,
    SupervisorInvocationJournal,
    SupervisorInvocationJournalError,
    SupervisorInvocationJournalState,
    supervisor_stable_request_id,
)
from pajin.tools.ai import ChatRole

NOW = datetime(2026, 8, 5, 1, 2, 3, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SCHEDULE_RUN_ID = "run_20260805T010203Z_aaaaaaaa"
PROVIDER_RUN_ID = "run_20260805T010204Z_bbbbbbbb"
RECEIPT_PATH = "supervision/supervisor-invocation-receipt.json"


def _publication(tmp_path: Path) -> SupervisorCheckpointSchedulePublication:
    policy = SupervisorDedicatedBudgetPolicy(
        maxModelCalls=2,
        maxModelTokens=4_096,
        maxDurationSeconds=30,
        maxCostUsd=1.0,
    )
    request_binding = SupervisorInvocationRequestBinding(
        campaignDigest=SHA_A,
        modelBindingId=f"supervisor-model-binding:{SHA_B}",
        modelBindingDigest=SHA_B,
        providerModelDigest=SHA_C,
        configurationDigest=SHA_D,
        snapshotInputId=f"supervisor-snapshot-input:{SHA_A}",
        snapshotInputDigest=SHA_A,
        sourceSnapshotId=f"collaboration-snapshot:{SHA_B}",
        sourceSnapshotDigest=SHA_B,
        messages=(
            SupervisorInvocationMessageBinding(
                sequence=1,
                role=ChatRole.DEVELOPER,
                source="code-owned-developer",
                contentDigest=SHA_C,
                contentBytes=10,
                instructionAuthorized=True,
                targetTaintedUntrusted=False,
            ),
            SupervisorInvocationMessageBinding(
                sequence=2,
                role=ChatRole.USER,
                source="canonical-supervisor-snapshot-input",
                contentDigest=SHA_D,
                contentBytes=20,
                instructionAuthorized=False,
                targetTaintedUntrusted=True,
            ),
        ),
        requestSchemaDigest=_request_schema_digest(),
        responseSchemaDigest=_response_schema_digest(),
        requestDigest=SHA_C,
        usageBound=SupervisorInvocationUsageBound(
            promptTokens=100,
            completionTokens=200,
            totalTokens=300,
            costUsd=0.5,
            timeoutSeconds=30,
        ),
        dedicatedBudgetPolicyId=policy.policy_id,
        dedicatedBudgetPolicyDigest=policy.policy_digest,
    )
    graph_snapshot_id = f"graph-snapshot:{SHA_C}"
    checkpoint_key = _checkpoint_key(
        SHA_A,
        graph_snapshot_id,
        SHA_C,
        GraphSnapshotReason.CHECKPOINT,
    )
    schedule = SupervisorCheckpointSchedule(
        checkpointKey=checkpoint_key,
        plannedCallIndex=1,
        campaignDigest=SHA_A,
        graphSnapshotId=graph_snapshot_id,
        graphSnapshotDigest=SHA_C,
        graphSnapshotRevision=4,
        graphSnapshotReason=GraphSnapshotReason.CHECKPOINT,
        sourceSnapshotId=request_binding.source_snapshot_id,
        sourceSnapshotDigest=request_binding.source_snapshot_digest,
        snapshotInputId=request_binding.snapshot_input_id,
        snapshotInputDigest=request_binding.snapshot_input_digest,
        requestBinding=request_binding,
        requestBindingDigest=request_binding.request_binding_digest,
        dedicatedBudgetPolicy=policy,
        dedicatedBudgetPolicyDigest=policy.policy_digest,
    )
    return SupervisorCheckpointSchedulePublication(
        schedule=schedule,
        run_id=SCHEDULE_RUN_ID,
        root_digest=SHA_B,
        artifact_path="supervision/supervisor-checkpoint-schedule.json",
        artifact_sha256=SHA_C,
        run_path=tmp_path / SCHEDULE_RUN_ID,
    )


def _journal(tmp_path: Path) -> SupervisorInvocationJournal:
    return SupervisorInvocationJournal(
        tmp_path / "supervisor-invocations.sqlite3",
        clock=lambda: NOW,
        run_id_factory=lambda: PROVIDER_RUN_ID,
    )


def _request_context(publication: SupervisorCheckpointSchedulePublication):
    return SupervisorBenchmarkRequestContext(
        planApiVersion="pajin.dev/supervisor-benchmark-campaign-plan/v1alpha1",
        planKind="SupervisorBenchmarkCampaignPlan",
        planId=f"supervisor-benchmark-plan:{SHA_D}",
        planDigest=SHA_D,
        planRunId="run_20260805T010201Z_dddddddd",
        planRootDigest=SHA_A,
        planArtifactPath="supervision/supervisor-benchmark-campaign-plan.json",
        planArtifactSha256=SHA_B,
        manifestDigest=SHA_C,
        coordinateSetDigest=SHA_D,
        coordinateId=f"benchmark-coordinate:{SHA_A}",
        coordinateDigest=SHA_A,
        scheduleId=publication.schedule.schedule_id,
        scheduleDigest=publication.schedule.schedule_digest,
        scheduleRunId=publication.run_id,
        scheduleRootDigest=publication.root_digest,
    )


@pytest.mark.parametrize("run_bound", [False, True])
def test_claim_is_exact_idempotent_and_survives_reopen(tmp_path: Path, run_bound: bool) -> None:
    from pajin.supervision.run_binding import SupervisorRunBinding

    publication = _publication(tmp_path)
    journal = _journal(tmp_path)
    binding = SupervisorRunBinding(
        controlPlaneRunId="isolated-supervisor-run", campaignDigest=SHA_A,
        inputDigest=SHA_B, budgetMode="campaign-and-supervisor",
    ) if run_bound else None
    if binding is not None:
        journal = SupervisorInvocationJournal(
            journal.path, clock=lambda: NOW, run_id_factory=lambda: PROVIDER_RUN_ID,
            run_binding=binding,
        )

    first = journal.claim(publication)
    second = journal.claim(publication)
    reopened = SupervisorInvocationJournal(
        journal.path,
        clock=lambda: NOW,
        run_id_factory=lambda: "run_20260805T010205Z_cccccccc",
        run_binding=binding,
    )

    assert second == first
    assert reopened.claim(publication) == first
    assert reopened.inspect(first.intent.intent_id) == first
    assert first.state is SupervisorInvocationJournalState.INTENT_RECORDED
    assert first.intent.stable_request_id.startswith("supervisor_")
    assert len(first.intent.stable_request_id) == len("supervisor_") + 64
    assert first.intent.provider_run_id == PROVIDER_RUN_ID
    assert first.intent.receipt_path == RECEIPT_PATH
    assert first.dispatch_outcome_state == "not-started"
    assert first.redispatch_allowed is False
    assert first.dispatch_event_digest is None
    assert first.last_event_digest == first.event_digests[0]
    assert first.intent.api_version == "pajin.dev/supervisor-invocation-intent/v1alpha1"
    assert "requestContext" not in first.intent.model_dump(mode="json", by_alias=True)


def test_claim_context_binds_stable_request_and_rejects_context_equivocation(
    tmp_path: Path,
) -> None:
    publication = _publication(tmp_path)
    journal = _journal(tmp_path)
    context = _request_context(publication)

    entry = journal.claim(publication, request_context=context)

    assert entry.intent.stable_request_id == supervisor_stable_request_id(
        publication,
        request_context=context,
    )
    assert entry.intent.stable_request_id != supervisor_stable_request_id(publication)
    assert entry.intent.request_context == context
    assert entry.intent.api_version == "pajin.dev/supervisor-invocation-intent/v1alpha2"
    assert entry.intent.model_dump(mode="json", by_alias=True)["requestContext"] == (
        context.model_dump(mode="json", by_alias=True)
    )
    assert journal.claim(publication, request_context=context) == entry
    with pytest.raises(SupervisorInvocationJournalError, match="equivocation"):
        journal.claim(publication)
    foreign_raw = context.model_dump(mode="json", by_alias=True)
    foreign_raw["contextId"] = ""
    foreign_raw["contextDigest"] = ""
    foreign_raw["planDigest"] = "f" * 64
    foreign = SupervisorBenchmarkRequestContext.model_validate(foreign_raw)
    with pytest.raises(SupervisorInvocationJournalError, match="equivocation"):
        journal.claim(publication, request_context=foreign)
    with pytest.raises(SupervisorInvocationJournalError):
        journal.claim(publication, request_context="e" * 64)  # type: ignore[arg-type]


def test_same_checkpoint_publication_equivocation_is_rejected(tmp_path: Path) -> None:
    publication = _publication(tmp_path)
    journal = _journal(tmp_path)
    journal.claim(publication)

    forged = replace(publication, root_digest=SHA_D)

    with pytest.raises(SupervisorInvocationJournalError, match="equivocation"):
        journal.claim(forged)


def test_concurrent_begin_dispatch_has_one_winner_and_never_redispatches(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    entry = journal.claim(_publication(tmp_path))

    def begin() -> object:
        try:
            return journal.begin_dispatch(entry)
        except SupervisorInvocationJournalError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _: begin(), range(2)))

    winners = [item for item in results if not isinstance(item, Exception)]
    losers = [item for item in results if isinstance(item, Exception)]
    assert len(winners) == 1
    assert len(losers) == 1
    started = journal.inspect(entry.intent.intent_id)
    assert started.state is SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    assert started.dispatch_outcome_state == "outcome-unknown"
    assert started.manual_review_required is True
    assert started.redispatch_allowed is False
    assert started.dispatch_event_digest == started.event_digests[1]
    with pytest.raises(SupervisorInvocationJournalError, match="redispatch denied"):
        journal.begin_dispatch(started)


def test_terminal_success_is_exact_idempotent_and_rejects_anchor_equivocation(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    started = journal.begin_dispatch(journal.claim(_publication(tmp_path)))

    terminal = journal.finalize_success(
        started,
        final_root_digest=SHA_C,
        receipt_path=RECEIPT_PATH,
        receipt_sha256=SHA_D,
    )
    exact_retry = journal.finalize_success(
        started,
        final_root_digest=SHA_C,
        receipt_path=RECEIPT_PATH,
        receipt_sha256=SHA_D,
    )

    assert exact_retry == terminal
    assert terminal.state is SupervisorInvocationJournalState.TERMINAL_SUCCESS
    assert terminal.dispatch_outcome_state == "terminal-success"
    assert terminal.final_root_digest == SHA_C
    assert terminal.receipt_path == RECEIPT_PATH
    assert terminal.receipt_sha256 == SHA_D
    assert terminal.manual_review_required is False
    assert terminal.redispatch_allowed is False
    assert len(terminal.event_digests) == 3
    with pytest.raises(SupervisorInvocationJournalError, match="different receipt"):
        journal.finalize_success(
            terminal,
            final_root_digest=SHA_A,
            receipt_path=RECEIPT_PATH,
            receipt_sha256=SHA_D,
        )


def test_inspection_rejects_forged_state_row(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    entry = journal.claim(_publication(tmp_path))
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE supervisor_invocation_intents SET state_digest = ? WHERE intent_id = ?",
            ("0" * 64, entry.intent.intent_id),
        )

    with pytest.raises(SupervisorInvocationJournalError):
        journal.inspect(entry.intent.intent_id)


def test_inspection_rejects_schema_and_event_tampering(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    entry = journal.claim(_publication(tmp_path))
    with sqlite3.connect(journal.path) as connection:
        connection.execute("DROP TRIGGER supervisor_invocation_events_no_update")
        connection.execute(
            "UPDATE supervisor_invocation_events SET event_digest = ? WHERE intent_id = ?",
            ("0" * 64, entry.intent.intent_id),
        )

    with pytest.raises(SupervisorInvocationJournalError):
        journal.inspect(entry.intent.intent_id)


def test_immutable_intent_and_append_only_events_are_database_enforced(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    entry = journal.claim(_publication(tmp_path))
    with sqlite3.connect(journal.path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="intent is immutable"):
            connection.execute(
                "UPDATE supervisor_invocation_intents SET schedule_digest = ? WHERE intent_id = ?",
                (SHA_D, entry.intent.intent_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="events are append-only"):
            connection.execute(
                "DELETE FROM supervisor_invocation_events WHERE intent_id = ?",
                (entry.intent.intent_id,),
            )


def _remove_budget_schema(path: Path, *, legacy: bool) -> None:
    """Build an exact pre-budget fixture or an incomplete current schema."""

    with sqlite3.connect(path) as connection:
        for kind, name in BUDGET_SCHEMA_SQL:
            if kind == "trigger":
                connection.execute(f"DROP TRIGGER {name}")
        connection.execute(f"DROP TABLE {BUDGET_TABLE}")
        if legacy:
            connection.execute("DROP TRIGGER supervisor_invocation_metadata_no_update")
            connection.executemany(
                "UPDATE supervisor_invocation_metadata SET value=? WHERE key=?",
                [("1", "schema_version"), (journal_module._V1_SCHEMA_DIGEST, "schema_digest")],
            )
            connection.execute("PRAGMA user_version=1")
            connection.execute(journal_module._METADATA_NO_UPDATE_SQL)


@pytest.mark.parametrize("has_history", [False, True])
def test_exact_legacy_journal_migration_preserves_history_without_inventing_usage(
    tmp_path: Path, has_history: bool
) -> None:
    from pajin.domain.models import Budgets

    journal = _journal(tmp_path)
    publication = _publication(tmp_path)
    entry = journal.claim(publication) if has_history else None
    _remove_budget_schema(journal.path, legacy=True)

    reopened = _journal(tmp_path)
    campaign, dedicated = BudgetController(Budgets()), BudgetController(Budgets())
    arguments = dict(
        campaign_digest=publication.schedule.campaign_digest,
        policy_digest=publication.schedule.dedicated_budget_policy_digest,
        campaign=campaign,
        dedicated=dedicated,
    )
    if has_history:
        assert entry is not None
        assert reopened.inspect(entry.intent.intent_id) == entry
        assert reopened.checkpoint_entry(publication.schedule.checkpoint_key) == entry
        with pytest.raises(BudgetPersistenceError, match="no budget checkpoint"):
            reopened.bind_budgets(**arguments)
        with pytest.raises(BudgetPersistenceError):
            campaign.reserve_tool_usage()
    else:
        reopened.bind_budgets(**arguments)
        campaign.reserve_tool_usage()
        assert campaign.tool_calls == 1
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        count = connection.execute(f"SELECT count(*) FROM {BUDGET_TABLE}").fetchone()[0]
    assert count == (0 if has_history else 3)


@pytest.mark.parametrize("legacy", [False, True])
def test_missing_current_budget_table_and_corrupt_legacy_history_are_not_repaired(
    tmp_path: Path, legacy: bool
) -> None:
    journal = _journal(tmp_path)
    entry = journal.claim(_publication(tmp_path))
    _remove_budget_schema(journal.path, legacy=legacy)
    if legacy:
        with sqlite3.connect(journal.path) as connection:
            connection.execute(
                "UPDATE supervisor_invocation_intents SET state_digest=? WHERE intent_id=?",
                ("0" * 64, entry.intent.intent_id),
            )

    with pytest.raises(SupervisorInvocationJournalError):
        _journal(tmp_path)

    with sqlite3.connect(journal.path) as connection:
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name=?", (BUDGET_TABLE,)
            ).fetchone()
            is None
        )
