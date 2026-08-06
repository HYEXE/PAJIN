from __future__ import annotations

import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Literal

import pytest
from pydantic import ValidationError

from pajin.domain.models import ToolRiskTier
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
)
from pajin.graph.approval_batch import (
    ActionApprovalBatchAuthorization,
    ActionApprovalBatchCancellation,
    ActionApprovalBatchCompletion,
    ActionApprovalBatchEnvelope,
    ActionApprovalBatchError,
    ActionApprovalBatchItemState,
    ActionApprovalBatchState,
    GraphApprovedActionBatchDispatcher,
    SQLiteActionApprovalBatchJournal,
)
from pajin.graph.authority import ActionPermit, RegisteredActionCapability
from pajin.graph.cleanup import ActionCleanupReservation
from pajin.graph.sqlite_store import SQLiteGraphStore
from tests.test_graph_action_approval_store import (
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    NOW,
    _action_proposal,
    _approval,
    _approved_authority,
    _InputAuthority,
    _seed,
)
from tests.test_graph_action_permit import (
    NOW as REVERSIBLE_NOW,
)
from tests.test_graph_action_permit import (
    _action_proposal as _reversible_proposal,
)
from tests.test_graph_action_permit import (
    _approved_reversible_authority,
    _cleanup_capability,
    _cleanup_reservation_request,
    _reversible_approval,
    _reversible_envelope,
)
from tests.test_graph_action_permit import (
    _seed as _reversible_seed,
)


class _BatchInputAuthority:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.calls = 0
        self.fail_on_call = fail_on_call

    def verify_action_approval_batch(self, batch: ActionApprovalBatchEnvelope) -> None:
        self.calls += 1
        assert batch.max_actions == len(batch.approvals)
        if self.calls == self.fail_on_call:
            raise RuntimeError("batch issuer changed")


class _CompletionAuthority:
    def __init__(
        self,
        *,
        reject: bool = False,
        fail_on_call: int | None = None,
    ) -> None:
        self.calls = 0
        self.reject = reject
        self.fail_on_call = fail_on_call

    def verify_action_approval_batch_completion(
        self,
        batch: ActionApprovalBatchEnvelope,
        approval: ActionApprovalEnvelope,
        authorization: ActionApprovalBatchAuthorization,
        completion: ActionApprovalBatchCompletion,
    ) -> None:
        self.calls += 1
        permit = (
            authorization.action.permit
            if isinstance(authorization, ActionApprovalAuthorization)
            else authorization.reversible.action.permit
        )
        assert completion.batch_id == batch.batch_id
        assert completion.approval_id == approval.approval_id
        assert completion.permit_id == permit.permit_id
        assert completion.receipt_id == authorization.receipt.receipt_id
        if not isinstance(authorization, ActionApprovalAuthorization):
            reservation = authorization.reversible.cleanup_reservation
            assert completion.cleanup_reservation_id == reservation.cleanup_reservation_id
            assert completion.cleanup_reservation_digest == reservation.cleanup_reservation_digest
            assert completion.restored_state_evidence_digest is not None
        if self.reject or self.calls == self.fail_on_call:
            raise RuntimeError("completion evidence rejected")


class _CancellationAuthority:
    def __init__(self, *, reject: bool = False) -> None:
        self.calls = 0
        self.reject = reject

    def verify_action_approval_batch_cancellation(
        self,
        batch: ActionApprovalBatchEnvelope,
        cancellation: ActionApprovalBatchCancellation,
    ) -> None:
        self.calls += 1
        assert cancellation.batch_id == batch.batch_id
        if self.reject:
            raise RuntimeError("cancellation rejected")


def _batch(
    tmp_path: Path,
    *,
    input_authority: _BatchInputAuthority | None = None,
    completion_authority: _CompletionAuthority | None = None,
    cancellation_authority: _CancellationAuthority | None = None,
) -> tuple[
    SQLiteGraphStore,
    RegisteredActionCapability,
    ActionApprovalBatchEnvelope,
    SQLiteActionApprovalBatchJournal,
]:
    store, decision, capability, envelope, _first_proposal, first_approval = _seed(
        tmp_path / "graph.sqlite3"
    )
    second_proposal = _action_proposal(
        envelope,
        capability,
        decision,
        request_id="tool_approval_store_second",
    )
    second_approval = _approval(envelope, second_proposal, decision)
    batch = ActionApprovalBatchEnvelope(
        maxActions=2,
        issuer=first_approval.issuer,
        campaignId=first_approval.campaign_id,
        campaignDigest=first_approval.campaign_digest,
        runId=first_approval.run_id,
        approvals=(first_approval, second_approval),
        approvedAt=first_approval.approved_at,
        notBefore=first_approval.not_before,
        expiresAt=first_approval.expires_at,
    )
    journal = SQLiteActionApprovalBatchJournal(
        tmp_path / "approval-batch.sqlite3",
        input_authority=input_authority or _BatchInputAuthority(),
        completion_authority=completion_authority or _CompletionAuthority(),
        cancellation_authority=cancellation_authority or _CancellationAuthority(),
        clock=lambda: NOW + timedelta(seconds=9),
    )
    return store, capability, batch, journal


def _completion(
    batch: ActionApprovalBatchEnvelope,
    ordinal: int,
    permit: ActionPermit,
    receipt: ActionApprovalConsumptionReceipt,
    *,
    outcome: Literal["succeeded", "failed"] = "succeeded",
    source: Literal["worker-completion", "manual-reconciliation"] = "worker-completion",
    evidence_digest: str = DIGEST_A,
    cleanup_reservation: ActionCleanupReservation | None = None,
    restored_state_evidence_digest: str | None = None,
) -> ActionApprovalBatchCompletion:
    return ActionApprovalBatchCompletion(
        batchId=batch.batch_id,
        batchDigest=batch.batch_digest,
        itemOrdinal=ordinal,
        approvalId=batch.approvals[ordinal - 1].approval_id,
        approvalDigest=batch.approvals[ordinal - 1].approval_digest,
        permitId=permit.permit_id,
        permitDigest=permit.permit_digest,
        receiptId=receipt.receipt_id,
        receiptDigest=receipt.receipt_digest,
        cleanupReservationId=(
            cleanup_reservation.cleanup_reservation_id if cleanup_reservation is not None else None
        ),
        cleanupReservationDigest=(
            cleanup_reservation.cleanup_reservation_digest
            if cleanup_reservation is not None
            else None
        ),
        restoredStateEvidenceDigest=restored_state_evidence_digest,
        outcome=outcome,
        source=source,
        evidenceDigest=evidence_digest,
        completedAt=NOW + timedelta(seconds=10),
    )


def _reversible_batch(
    tmp_path: Path,
    *,
    completion_authority: _CompletionAuthority | None = None,
) -> tuple[
    SQLiteGraphStore,
    RegisteredActionCapability,
    RegisteredActionCapability,
    ActionApprovalBatchEnvelope,
    SQLiteActionApprovalBatchJournal,
]:
    store, _, decision, action, _, _ = _reversible_seed(
        tmp_path / "reversible-graph.sqlite3",
        risk_tier=ToolRiskTier.T2,
    )
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup)
    first_proposal = _reversible_proposal(envelope, action, decision)
    second_proposal = _reversible_proposal(
        envelope,
        action,
        decision,
        request_id="tool_action_permit_second",
    )
    first_approval = _reversible_approval(envelope, first_proposal, decision)
    second_approval = _reversible_approval(envelope, second_proposal, decision)
    cleanup_requests = (
        _cleanup_reservation_request(envelope, first_proposal, cleanup),
        _cleanup_reservation_request(envelope, second_proposal, cleanup),
    )
    batch = ActionApprovalBatchEnvelope(
        maxActions=2,
        issuer=first_approval.issuer,
        campaignId=first_approval.campaign_id,
        campaignDigest=first_approval.campaign_digest,
        runId=first_approval.run_id,
        approvals=(first_approval, second_approval),
        cleanupRequests=cleanup_requests,
        approvedAt=first_approval.approved_at,
        notBefore=first_approval.not_before,
        expiresAt=first_approval.expires_at,
    )
    journal = SQLiteActionApprovalBatchJournal(
        tmp_path / "reversible-approval-batch.sqlite3",
        input_authority=_BatchInputAuthority(),
        completion_authority=completion_authority or _CompletionAuthority(),
        cancellation_authority=_CancellationAuthority(),
        clock=lambda: REVERSIBLE_NOW + timedelta(seconds=9),
    )
    return store, action, cleanup, batch, journal


def _cancellation(
    batch: ActionApprovalBatchEnvelope,
    *ordinals: int,
) -> ActionApprovalBatchCancellation:
    return ActionApprovalBatchCancellation(
        batchId=batch.batch_id,
        batchDigest=batch.batch_digest,
        itemOrdinals=ordinals,
        reasonDigest=DIGEST_C,
        cancelledAt=NOW + timedelta(seconds=9),
    )


def test_batch_model_is_bounded_ordered_and_content_addressed(tmp_path: Path) -> None:
    _, _, batch, _ = _batch(tmp_path)

    assert batch.mode == "batch"
    assert batch.asynchronous is True
    assert batch.batch_id == f"action-approval-batch_{batch.batch_digest}"
    assert batch.approval_at(1) == batch.approvals[0]

    raw = batch.model_dump(mode="json", by_alias=True)
    raw["maxActions"] = True
    with pytest.raises(ValidationError, match="JSON integer"):
        ActionApprovalBatchEnvelope.model_validate(raw)

    raw = batch.model_dump(mode="json", by_alias=True)
    raw["approvals"] = [raw["approvals"][0], raw["approvals"][0]]
    raw.pop("batchId")
    raw.pop("batchDigest")
    with pytest.raises(ValidationError, match="duplicate action"):
        ActionApprovalBatchEnvelope.model_validate(raw)

    raw = batch.model_dump(mode="json", by_alias=True)
    raw.pop("batchId")
    raw.pop("batchDigest")
    raw["approvals"][0].pop("approvalId")
    raw["approvals"][0].pop("approvalDigest")
    raw["approvals"][0]["sideEffectClass"] = "reversible-write"
    raw["approvals"][0]["cleanupRequired"] = True
    with pytest.raises(ValidationError, match="requires one cleanup reservation request"):
        ActionApprovalBatchEnvelope.model_validate(raw)

    with pytest.raises(TypeError, match="completion authority"):
        SQLiteActionApprovalBatchJournal(
            tmp_path / "invalid-authority.sqlite3",
            input_authority=_BatchInputAuthority(),
            completion_authority=object(),  # type: ignore[arg-type]
            cancellation_authority=_CancellationAuthority(),
        )


def test_journal_registration_is_durable_exact_and_post_verified(tmp_path: Path) -> None:
    store, _, batch, journal = _batch(tmp_path)
    publication = journal.register(batch)

    assert publication.state is ActionApprovalBatchState.PENDING
    assert [item.state for item in publication.items] == [
        ActionApprovalBatchItemState.PENDING,
        ActionApprovalBatchItemState.PENDING,
    ]
    reopened = SQLiteActionApprovalBatchJournal(
        journal.path,
        input_authority=_BatchInputAuthority(),
        completion_authority=_CompletionAuthority(),
        cancellation_authority=_CancellationAuthority(),
        clock=lambda: NOW + timedelta(seconds=9),
    )
    assert reopened.register(batch) == publication

    failing_path = tmp_path / "post-verify.sqlite3"
    failing = SQLiteActionApprovalBatchJournal(
        failing_path,
        input_authority=_BatchInputAuthority(fail_on_call=2),
        completion_authority=_CompletionAuthority(),
        cancellation_authority=_CancellationAuthority(),
        clock=lambda: NOW + timedelta(seconds=9),
    )
    with pytest.raises(ActionApprovalBatchError, match="input authority"):
        failing.register(batch)
    with sqlite3.connect(failing_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM action_approval_batches").fetchone()
    assert count == (0,)
    del store


def test_concurrent_batch_item_claim_has_one_durable_winner(tmp_path: Path) -> None:
    _, _, batch, journal = _batch(tmp_path)
    journal.register(batch)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: journal.claim(batch, 1), range(2)))

    assert sum(newly_claimed for _, newly_claimed in results) == 1
    assert all(item.state is ActionApprovalBatchItemState.CLAIM_STARTED for item, _ in results)
    assert journal.item(batch.batch_id, 1).state is ActionApprovalBatchItemState.CLAIM_STARTED


@pytest.mark.asyncio
async def test_async_batch_success_is_terminal_and_never_redispatches(tmp_path: Path) -> None:
    completion_authority = _CompletionAuthority()
    store, capability, batch, journal = _batch(
        tmp_path,
        completion_authority=completion_authority,
    )
    authority = _approved_authority(store, capability)
    dispatcher = GraphApprovedActionBatchDispatcher(authority, journal)
    calls = 0

    async def consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> ActionApprovalBatchCompletion:
        nonlocal calls
        calls += 1
        return _completion(batch, 1, permit, receipt)

    first = await dispatcher.dispatch_item_once(
        batch,
        1,
        consumer,
    )
    retry = await dispatcher.dispatch_item_once(
        batch,
        1,
        consumer,
    )

    assert calls == 1
    assert first.dispatched is True
    assert first.item.state is ActionApprovalBatchItemState.TERMINAL_SUCCEEDED
    assert retry.dispatched is False
    assert retry.authorization is None
    assert retry.item == first.item
    assert completion_authority.calls == 2


@pytest.mark.asyncio
async def test_unknown_outcome_requires_authenticated_manual_reconciliation(
    tmp_path: Path,
) -> None:
    completion_authority = _CompletionAuthority()
    store, capability, batch, journal = _batch(
        tmp_path,
        completion_authority=completion_authority,
    )
    authority = _approved_authority(store, capability)
    dispatcher = GraphApprovedActionBatchDispatcher(authority, journal)
    calls = 0

    async def failing_consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> ActionApprovalBatchCompletion:
        nonlocal calls
        calls += 1
        raise RuntimeError("transport closed after dispatch")

    with pytest.raises(ActionApprovalBatchError, match="outcome is unknown"):
        await dispatcher.dispatch_item_once(
            batch,
            1,
            failing_consumer,
        )
    publication = journal.publication(batch.batch_id)
    assert publication.state is ActionApprovalBatchState.MANUAL_REVIEW_REQUIRED
    assert publication.manual_review_required is True
    assert publication.items[0].permit_id is not None

    retry = await dispatcher.dispatch_item_once(
        batch,
        1,
        failing_consumer,
    )
    assert retry.dispatched is False
    assert calls == 1

    approval = batch.approvals[0]
    authorization = authority.authorize_for_dispatch(
        approval.mission_envelope,
        approval.proposal,
        approval.graph_decision,
        approval,
    )
    assert authorization.action.newly_consumed is False
    completion = _completion(
        batch,
        1,
        authorization.action.permit,
        authorization.receipt,
        outcome="failed",
        source="manual-reconciliation",
        evidence_digest=DIGEST_B,
    )
    completion_authority.reject = True
    with pytest.raises(ActionApprovalBatchError, match="completion authority"):
        journal.finalize(
            batch,
            1,
            authorization,
            completion,
        )
    completion_authority.reject = False
    reconciled = journal.finalize(
        batch,
        1,
        authorization,
        completion,
    )
    assert reconciled.items[0].state is ActionApprovalBatchItemState.TERMINAL_FAILED
    assert reconciled.items[0].completion == completion
    assert reconciled.state is ActionApprovalBatchState.ACTIVE


@pytest.mark.asyncio
async def test_task_cancellation_leaves_unknown_item_nonredispatchable(tmp_path: Path) -> None:
    store, capability, batch, journal = _batch(tmp_path)
    dispatcher = GraphApprovedActionBatchDispatcher(
        _approved_authority(store, capability),
        journal,
    )
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> ActionApprovalBatchCompletion:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return _completion(batch, 1, permit, receipt)

    task = asyncio.create_task(dispatcher.dispatch_item_once(batch, 1, consumer))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    unknown = journal.item(batch.batch_id, 1)
    assert unknown.state is ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    retry = await dispatcher.dispatch_item_once(batch, 1, consumer)
    assert retry.dispatched is False
    assert retry.item == unknown
    assert calls == 1


@pytest.mark.asyncio
async def test_completion_post_verifier_drift_rolls_back_terminal_state(
    tmp_path: Path,
) -> None:
    completion_authority = _CompletionAuthority(fail_on_call=2)
    store, capability, batch, journal = _batch(
        tmp_path,
        completion_authority=completion_authority,
    )
    dispatcher = GraphApprovedActionBatchDispatcher(
        _approved_authority(store, capability),
        journal,
    )
    calls = 0

    async def consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> ActionApprovalBatchCompletion:
        nonlocal calls
        calls += 1
        return _completion(batch, 1, permit, receipt)

    with pytest.raises(ActionApprovalBatchError, match="completion authority"):
        await dispatcher.dispatch_item_once(batch, 1, consumer)

    current = journal.item(batch.batch_id, 1)
    assert current.state is ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    assert current.completion is None
    retry = await dispatcher.dispatch_item_once(batch, 1, consumer)
    assert retry.dispatched is False
    assert calls == 1


@pytest.mark.asyncio
async def test_pre_dispatch_authority_failure_can_resume_without_duplicate_claim(
    tmp_path: Path,
) -> None:
    store, capability, batch, journal = _batch(tmp_path)
    authority = _approved_authority(
        store,
        capability,
        input_authority=_InputAuthority(fail_on_call=1),
    )
    dispatcher = GraphApprovedActionBatchDispatcher(authority, journal)
    calls = 0

    async def consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> ActionApprovalBatchCompletion:
        nonlocal calls
        calls += 1
        return _completion(batch, 1, permit, receipt)

    with pytest.raises(ActionApprovalBatchError, match="outcome is unknown"):
        await dispatcher.dispatch_item_once(
            batch,
            1,
            consumer,
        )
    claim_started = journal.publication(batch.batch_id)
    assert claim_started.manual_review_required is True
    assert claim_started.items[0].state is ActionApprovalBatchItemState.CLAIM_STARTED
    assert claim_started.items[0].permit_id is None

    recovered = await dispatcher.dispatch_item_once(
        batch,
        1,
        consumer,
    )
    assert recovered.dispatched is True
    assert recovered.item.state is ActionApprovalBatchItemState.TERMINAL_SUCCEEDED
    assert calls == 1


def test_reversible_batch_rejects_missing_and_cross_item_cleanup_requests(
    tmp_path: Path,
) -> None:
    _, _, _, batch, _ = _reversible_batch(tmp_path)
    raw = batch.model_dump(mode="json", by_alias=True)
    raw.pop("batchId")
    raw.pop("batchDigest")
    raw["cleanupRequests"] = [raw["cleanupRequests"][1], raw["cleanupRequests"][0]]
    with pytest.raises(ValidationError, match="cleanup request lineage differs"):
        ActionApprovalBatchEnvelope.model_validate(raw)

    raw = batch.model_dump(mode="json", by_alias=True)
    raw.pop("batchId")
    raw.pop("batchDigest")
    raw["cleanupRequests"][0] = None
    with pytest.raises(ValidationError, match="requires one cleanup reservation request"):
        ActionApprovalBatchEnvelope.model_validate(raw)


@pytest.mark.asyncio
async def test_reversible_batch_binds_cleanup_hold_and_restored_state_once(
    tmp_path: Path,
) -> None:
    completion_authority = _CompletionAuthority()
    store, action, cleanup, batch, journal = _reversible_batch(
        tmp_path,
        completion_authority=completion_authority,
    )
    reversible_authority = _approved_reversible_authority(store, action, cleanup)
    dispatcher = GraphApprovedActionBatchDispatcher(
        None,
        journal,
        reversible_authority=reversible_authority,
    )
    calls = 0

    async def consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
        reservation: ActionCleanupReservation,
    ) -> ActionApprovalBatchCompletion:
        nonlocal calls
        calls += 1
        return _completion(
            batch,
            1,
            permit,
            receipt,
            cleanup_reservation=reservation,
            restored_state_evidence_digest=DIGEST_B,
        )

    first = await dispatcher.dispatch_reversible_item_once(batch, 1, consumer)
    retry = await dispatcher.dispatch_reversible_item_once(batch, 1, consumer)

    assert first.dispatched is True
    assert first.item.state is ActionApprovalBatchItemState.TERMINAL_SUCCEEDED
    assert first.item.cleanup_reservation is not None
    assert first.item.completion is not None
    assert first.item.completion.restored_state_evidence_digest == DIGEST_B
    assert retry.dispatched is False
    assert retry.item == first.item
    assert calls == 1
    assert completion_authority.calls == 2
    assert store.permit_store.cleanup_reservations() == (first.item.cleanup_reservation,)
    reopened = SQLiteActionApprovalBatchJournal(
        journal.path,
        input_authority=_BatchInputAuthority(),
        completion_authority=_CompletionAuthority(),
        cancellation_authority=_CancellationAuthority(),
        clock=lambda: REVERSIBLE_NOW + timedelta(seconds=9),
    )
    assert reopened.item(batch.batch_id, 1) == first.item

    async def no_write_consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
    ) -> ActionApprovalBatchCompletion:
        raise AssertionError((permit, receipt))

    with pytest.raises(ActionApprovalBatchError, match="cleanup-bound dispatcher"):
        await dispatcher.dispatch_item_once(batch, 2, no_write_consumer)
    assert journal.item(batch.batch_id, 2).state is ActionApprovalBatchItemState.PENDING
    cancelled = journal.cancel_pending(
        batch,
        ActionApprovalBatchCancellation(
            batchId=batch.batch_id,
            batchDigest=batch.batch_digest,
            itemOrdinals=(2,),
            reasonDigest=DIGEST_C,
            cancelledAt=REVERSIBLE_NOW + timedelta(seconds=9),
        ),
    )
    assert cancelled.state is ActionApprovalBatchState.TERMINAL_PARTIAL
    assert cancelled.items[1].state is ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH
    assert store.permit_store.cleanup_reservations() == (first.item.cleanup_reservation,)


@pytest.mark.asyncio
async def test_reversible_unknown_requires_exact_restored_state_reconciliation(
    tmp_path: Path,
) -> None:
    store, action, cleanup, batch, journal = _reversible_batch(tmp_path)
    reversible_authority = _approved_reversible_authority(store, action, cleanup)
    dispatcher = GraphApprovedActionBatchDispatcher(
        None,
        journal,
        reversible_authority=reversible_authority,
    )
    calls = 0

    async def failing_consumer(
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
        reservation: ActionCleanupReservation,
    ) -> ActionApprovalBatchCompletion:
        nonlocal calls
        calls += 1
        raise RuntimeError((permit, receipt, reservation))

    with pytest.raises(ActionApprovalBatchError, match="outcome is unknown"):
        await dispatcher.dispatch_reversible_item_once(batch, 1, failing_consumer)
    unknown = journal.item(batch.batch_id, 1)
    assert unknown.state is ActionApprovalBatchItemState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    assert unknown.cleanup_reservation is not None

    retry = await dispatcher.dispatch_reversible_item_once(batch, 1, failing_consumer)
    assert retry.dispatched is False
    assert calls == 1

    approval = batch.approvals[0]
    cleanup_request = batch.cleanup_requests[0]
    assert cleanup_request is not None
    authorization = reversible_authority.authorize_for_dispatch(
        approval.mission_envelope,
        approval.proposal,
        approval.graph_decision,
        approval,
        cleanup_request,
    )
    reservation = authorization.reversible.cleanup_reservation
    with pytest.raises(ValidationError, match="cleanup evidence is partial"):
        _completion(
            batch,
            1,
            authorization.reversible.action.permit,
            authorization.receipt,
            source="manual-reconciliation",
            cleanup_reservation=reservation,
        )

    completion = _completion(
        batch,
        1,
        authorization.reversible.action.permit,
        authorization.receipt,
        outcome="failed",
        source="manual-reconciliation",
        cleanup_reservation=reservation,
        restored_state_evidence_digest=DIGEST_C,
    )
    forged_raw = completion.model_dump(mode="json", by_alias=True)
    forged_raw.pop("completionId")
    forged_raw.pop("completionDigest")
    forged_raw["cleanupReservationId"] = f"action-cleanup-reservation_{DIGEST_C}"
    forged = ActionApprovalBatchCompletion.model_validate(forged_raw)
    with pytest.raises(ActionApprovalBatchError, match="completion differs"):
        journal.finalize(batch, 1, authorization, forged)

    reconciled = journal.finalize(batch, 1, authorization, completion)
    assert reconciled.items[0].state is ActionApprovalBatchItemState.TERMINAL_FAILED
    assert reconciled.items[0].cleanup_reservation == reservation
    assert reconciled.items[0].completion == completion


def test_partial_cancellation_is_atomic_and_cannot_cancel_claimed_item(tmp_path: Path) -> None:
    authority = _CancellationAuthority()
    _, _, batch, journal = _batch(tmp_path, cancellation_authority=authority)
    journal.register(batch)
    journal.claim(batch, 1)

    with pytest.raises(ActionApprovalBatchError, match="claimed item"):
        journal.cancel_pending(
            batch,
            _cancellation(batch, 1, 2),
        )
    assert journal.item(batch.batch_id, 2).state is ActionApprovalBatchItemState.PENDING

    publication = journal.cancel_pending(
        batch,
        _cancellation(batch, 2),
    )
    assert publication.state is ActionApprovalBatchState.MANUAL_REVIEW_REQUIRED
    assert publication.items[1].state is ActionApprovalBatchItemState.CANCELLED_BEFORE_DISPATCH
    assert authority.calls == 3


def test_journal_schema_and_authority_rows_resist_direct_mutation(tmp_path: Path) -> None:
    _, _, batch, journal = _batch(tmp_path)
    journal.register(batch)

    with sqlite3.connect(journal.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE action_approval_batches SET campaign_id = ? WHERE batch_id = ?",
                ("foreign-campaign", batch.batch_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="state transition"):
            connection.execute(
                """
                UPDATE action_approval_batch_items SET state = 'terminal-succeeded'
                WHERE batch_id = ? AND item_ordinal = 1
                """,
                (batch.batch_id,),
            )
