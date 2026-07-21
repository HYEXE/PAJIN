"""Run cancellation and approval/lease expiration transactions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from pajin.control_plane.claim_service import ControlPlaneClaimService
from pajin.control_plane.collaborator_hooks import ControlPlaneTransactionHooks
from pajin.control_plane.database import (
    ApprovalRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    JobRecord,
    ReplayBatchRecord,
    ReplayBudgetAccountRecord,
    ReplayBudgetReservationRecord,
    ReplayItemRecord,
    ReplayRateAccountRecord,
    ReplayRateReservationRecord,
    ReplayTicketRecord,
    RunRecord,
)
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.models import (
    ApprovalIntent,
    ApprovalState,
    CancelRunRequest,
    CancelRunView,
    InternalJobKind,
    JobState,
    ReplayBatchState,
    ReplayItemState,
    ReplayTicketState,
    RunState,
)
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.security import CheckpointSigner
from pajin.control_plane.view_mapper import ControlPlaneViewMapper

_CANCELLABLE_RUN_STATES = frozenset(
    {
        RunState.QUEUED.value,
        RunState.RUNNING.value,
        RunState.AWAITING_APPROVAL.value,
    }
)
_CANCELLABLE_JOB_STATES = frozenset({JobState.QUEUED.value, JobState.LEASED.value})
_REVOCABLE_APPROVAL_STATES = frozenset({ApprovalState.PENDING.value, ApprovalState.APPROVED.value})
_INTERNAL_REPLAY_KIND = InternalJobKind.REPLAY.value
_ACTIVE_REPLAY_TICKET_STATES = frozenset(
    {ReplayTicketState.ISSUED.value, ReplayTicketState.CLAIMED.value}
)
_TERMINAL_REPLAY_ITEM_STATES = frozenset(
    {
        ReplayItemState.GATED.value,
        ReplayItemState.FAILED.value,
        ReplayItemState.CANCELLED.value,
    }
)


@dataclass(frozen=True, slots=True)
class LifecycleServiceHooks:
    """Shared clock and append-only audit writers."""

    transaction: ControlPlaneTransactionHooks


@dataclass(slots=True)
class _ReplayCancellationGraph:
    """Replay cancellation rows locked in canonical graph order."""

    jobs: list[JobRecord]
    tickets: list[ReplayTicketRecord]
    items: list[ReplayItemRecord]
    batch: ReplayBatchRecord
    run: RunRecord
    current_item: ReplayItemRecord
    jobs_by_id: dict[str, JobRecord]
    items_by_id: dict[str, ReplayItemRecord]
    retry_authority_cancel: bool


@dataclass(slots=True)
class _ExpiredLeaseGraph:
    """Expirable Jobs and their rows after canonical table-by-table locking."""

    jobs: list[JobRecord]
    tickets_by_job_id: dict[str, ReplayTicketRecord]
    items_by_id: dict[str, ReplayItemRecord]
    batches_by_id: dict[str, ReplayBatchRecord]
    runs_by_id: dict[str, RunRecord]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class ControlPlaneLifecycleService:
    """Own cancellation and opportunistic expiration lock graphs."""

    def __init__(
        self,
        repository: ControlPlaneRepository,
        signer: CheckpointSigner,
        records: ControlPlaneRecords,
        views: ControlPlaneViewMapper,
        claims: ControlPlaneClaimService,
        hooks: LifecycleServiceHooks,
    ) -> None:
        self.repository = repository
        self.signer = signer
        self._records = records
        self._views = views
        self._claims = claims
        self._hooks = hooks

    def cancel_run(
        self,
        run_id: str,
        request: CancelRunRequest,
        *,
        actor: str,
    ) -> CancelRunView:
        with self.repository.transaction() as session:
            replay_item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.replay_run_id == run_id)
            )
            if replay_item is not None:
                return self._cancel_replay_run(
                    session,
                    replay_item,
                    request=request,
                    actor=actor,
                )
            jobs_by_id = {job.job_id: job for job in self._lock_cancellable_jobs(session, run_id)}
            approvals = self._lock_revocable_approvals(session, run_id)
            # Resume locks its Approval before it inserts a continuation Job. Re-read Jobs after
            # acquiring Approval locks so a continuation created while cancellation was waiting
            # cannot escape the same transaction.
            jobs_by_id.update(
                {job.job_id: job for job in self._lock_cancellable_jobs(session, run_id)}
            )
            run = self._records.run(session, run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                return CancelRunView(
                    run=self._views.run(run),
                    applied=False,
                    cancelled_job_ids=[],
                    revoked_approval_ids=[],
                )
            if run.state not in _CANCELLABLE_RUN_STATES:
                raise StateConflict(f"run in {run.state} state cannot be cancelled")

            now = self._hooks.transaction.clock()
            cancelled_job_ids: list[str] = []
            for job in sorted(jobs_by_id.values(), key=lambda item: item.job_id):
                previous_lease_owner = job.lease_owner
                self._cancel_job(job, now=now)
                cancelled_job_ids.append(job.job_id)
                self._hooks.transaction.event_writer(
                    session,
                    run,
                    "job.cancelled",
                    actor,
                    {
                        "jobId": job.job_id,
                        "previousLeaseOwner": previous_lease_owner,
                        "reason": request.reason,
                    },
                )

            revoked_approval_ids: list[str] = []
            for approval in approvals:
                approval.state = ApprovalState.REVOKED.value
                revoked_approval_ids.append(approval.approval_id)
                self._hooks.transaction.event_writer(
                    session,
                    run,
                    "approval.revoked",
                    actor,
                    {
                        "approvalId": approval.approval_id,
                        "checkpointId": approval.checkpoint_id,
                        "reason": request.reason,
                    },
                )

            self.cancel_run_record(
                session,
                run,
                actor=actor,
                now=now,
                reason=request.reason,
                cause="operator-request",
                extra={
                    "cancelledJobIds": cancelled_job_ids,
                    "revokedApprovalIds": revoked_approval_ids,
                },
            )
            return CancelRunView(
                run=self._views.run(run),
                applied=True,
                cancelled_job_ids=cancelled_job_ids,
                revoked_approval_ids=revoked_approval_ids,
            )

    def requeue_expired(self, *, actor: str) -> int:
        now = self._hooks.transaction.clock()
        # Approval expiry has a different global lock order from Job lease expiry.
        # Keep each graph atomic without holding Approval/Run locks while acquiring Jobs.
        with self.repository.transaction() as session:
            self._expire_due_approvals(session, now=now, actor=actor)
        with self.repository.transaction() as session:
            return self.expire_leases(session, now=now, actor=actor)

    def _expire_due_approvals(self, session: Session, *, now: datetime, actor: str) -> int:
        checkpoint_ids = list(
            session.scalars(
                select(ApprovalRecord.checkpoint_id)
                .where(
                    ApprovalRecord.state.in_(_REVOCABLE_APPROVAL_STATES),
                    ApprovalRecord.expires_at <= now,
                )
                .order_by(ApprovalRecord.checkpoint_id)
            ).all()
        )
        if not checkpoint_ids:
            return 0

        checkpoints = list(
            session.scalars(
                select(CheckpointRecord)
                .where(CheckpointRecord.checkpoint_id.in_(checkpoint_ids))
                .order_by(CheckpointRecord.checkpoint_id)
                .with_for_update()
            ).all()
        )
        checkpoints_by_id = {checkpoint.checkpoint_id: checkpoint for checkpoint in checkpoints}
        if set(checkpoint_ids).difference(checkpoints_by_id):
            raise StateConflict("expirable approval exists without its checkpoint")

        approvals = list(
            session.scalars(
                select(ApprovalRecord)
                .where(
                    ApprovalRecord.checkpoint_id.in_(checkpoint_ids),
                    ApprovalRecord.state.in_(_REVOCABLE_APPROVAL_STATES),
                    ApprovalRecord.expires_at <= now,
                )
                .order_by(ApprovalRecord.approval_id)
                .with_for_update()
            ).all()
        )
        run_ids = sorted({approval.run_id for approval in approvals})
        runs = list(
            session.scalars(
                select(RunRecord)
                .where(RunRecord.run_id.in_(run_ids))
                .order_by(RunRecord.run_id)
                .with_for_update()
            ).all()
        )
        runs_by_id = {run.run_id: run for run in runs}
        if set(run_ids).difference(runs_by_id):
            raise StateConflict("expirable approval exists without its Run")

        for approval in approvals:
            checkpoint = checkpoints_by_id[approval.checkpoint_id]
            run = runs_by_id[approval.run_id]
            if checkpoint.run_id != run.run_id:
                raise StateConflict("expirable approval checkpoint ownership is inconsistent")
            self.require_run_state(run, RunState.AWAITING_APPROVAL)
            self.require_current_checkpoint(run, checkpoint.checkpoint_id)
            self.verify_checkpoint(checkpoint)
            intent = self._views.checkpoint_intent(checkpoint)
            if not self.approval_matches_intent(approval, intent):
                raise StateConflict("approval fields do not match signed checkpoint intent")
            self.expire_approval(session, approval, run, actor=actor, now=now)
        return len(approvals)

    def expire_leases(self, session: Session, *, now: datetime, actor: str) -> int:
        graph = self._lock_expired_lease_graph(session, now=now)
        return sum(
            self._expire_locked_job(session, graph, job, now=now, actor=actor) for job in graph.jobs
        )

    def _lock_expired_lease_graph(
        self,
        session: Session,
        *,
        now: datetime,
    ) -> _ExpiredLeaseGraph:
        jobs = self._lock_expirable_jobs(session, now=now)
        replay_jobs = [job for job in jobs if job.kind == _INTERNAL_REPLAY_KIND]
        tickets_by_job_id, items_by_id, batches_by_id = self._lock_expirable_replay_rows(
            session,
            replay_jobs,
        )
        runs_by_id = self._lock_expirable_runs(session, jobs)
        self._prelock_replay_capacity(session, list(tickets_by_job_id.values()))
        return _ExpiredLeaseGraph(
            jobs=jobs,
            tickets_by_job_id=tickets_by_job_id,
            items_by_id=items_by_id,
            batches_by_id=batches_by_id,
            runs_by_id=runs_by_id,
        )

    def _lock_expirable_jobs(self, session: Session, *, now: datetime) -> list[JobRecord]:
        expired_issued_replay_jobs = select(ReplayTicketRecord.job_id).where(
            ReplayTicketRecord.state == ReplayTicketState.ISSUED.value,
            ReplayTicketRecord.expires_at <= now,
        )
        statement = (
            select(JobRecord)
            .where(
                or_(
                    and_(
                        JobRecord.state == JobState.LEASED.value,
                        or_(
                            JobRecord.lease_expires_at <= now,
                            JobRecord.lease_deadline_at <= now,
                        ),
                    ),
                    and_(
                        JobRecord.kind == _INTERNAL_REPLAY_KIND,
                        JobRecord.state == JobState.QUEUED.value,
                        JobRecord.job_id.in_(expired_issued_replay_jobs),
                    ),
                )
            )
            .order_by(JobRecord.job_id)
        )
        if self.repository.dialect_name == "postgresql":
            statement = statement.with_for_update(skip_locked=True)
        return list(session.scalars(statement).all())

    def _lock_expirable_replay_rows(
        self,
        session: Session,
        replay_jobs: list[JobRecord],
    ) -> tuple[
        dict[str, ReplayTicketRecord],
        dict[str, ReplayItemRecord],
        dict[str, ReplayBatchRecord],
    ]:
        # Do not lazily walk each Replay graph. Concurrent SKIP LOCKED sweepers can
        # partition sibling Jobs from multiple batches; per-Job traversal would then
        # let each transaction hold one batch while waiting for the other. Pre-lock
        # every selected graph table-by-table in the canonical global order instead:
        # Job (above) -> ticket -> item -> batch -> Run -> budget account ->
        # rate account -> budget reservations -> rate reservations.
        tickets_by_job_id: dict[str, ReplayTicketRecord] = {}
        items_by_id: dict[str, ReplayItemRecord] = {}
        batches_by_id: dict[str, ReplayBatchRecord] = {}
        if not replay_jobs:
            return tickets_by_job_id, items_by_id, batches_by_id
        replay_job_ids = sorted(job.job_id for job in replay_jobs)
        tickets = list(
            session.scalars(
                select(ReplayTicketRecord)
                .where(ReplayTicketRecord.job_id.in_(replay_job_ids))
                .order_by(ReplayTicketRecord.ticket_id)
                .with_for_update()
            ).all()
        )
        tickets_by_job_id = {ticket.job_id: ticket for ticket in tickets}
        if set(replay_job_ids).difference(tickets_by_job_id):
            raise StateConflict("internal Replay Job exists without its ticket")

        item_ids = sorted({ticket.item_id for ticket in tickets})
        items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.item_id.in_(item_ids))
                .order_by(ReplayItemRecord.item_id)
                .with_for_update()
            ).all()
        )
        items_by_id = {item.item_id: item for item in items}
        if set(item_ids).difference(items_by_id):
            raise StateConflict("Replay ticket exists without its item")

        batch_ids = sorted({ticket.batch_id for ticket in tickets})
        batches = list(
            session.scalars(
                select(ReplayBatchRecord)
                .where(ReplayBatchRecord.batch_id.in_(batch_ids))
                .order_by(ReplayBatchRecord.batch_id)
                .with_for_update()
            ).all()
        )
        batches_by_id = {batch.batch_id: batch for batch in batches}
        if set(batch_ids).difference(batches_by_id):
            raise StateConflict("Replay item exists without its batch")
        return tickets_by_job_id, items_by_id, batches_by_id

    def _lock_expirable_runs(
        self,
        session: Session,
        jobs: list[JobRecord],
    ) -> dict[str, RunRecord]:
        run_ids = sorted({job.run_id for job in jobs})
        runs = (
            list(
                session.scalars(
                    select(RunRecord)
                    .where(RunRecord.run_id.in_(run_ids))
                    .order_by(RunRecord.run_id)
                    .with_for_update()
                ).all()
            )
            if run_ids
            else []
        )
        runs_by_id = {run.run_id: run for run in runs}
        if set(run_ids).difference(runs_by_id):
            raise StateConflict("leased Job exists without its Run")
        return runs_by_id

    @staticmethod
    def _prelock_replay_capacity(
        session: Session,
        tickets: list[ReplayTicketRecord],
    ) -> None:
        """Lock every selected capacity graph by table and primary-key order."""

        if not tickets:
            return
        budget_reservation_ids = sorted({ticket.budget_reservation_id for ticket in tickets})
        rate_reservation_ids = sorted({ticket.rate_reservation_id for ticket in tickets})
        budget_bindings = session.execute(
            select(
                ReplayBudgetReservationRecord.budget_reservation_id,
                ReplayBudgetReservationRecord.budget_account_id,
            ).where(ReplayBudgetReservationRecord.budget_reservation_id.in_(budget_reservation_ids))
        ).all()
        rate_bindings = session.execute(
            select(
                ReplayRateReservationRecord.rate_reservation_id,
                ReplayRateReservationRecord.rate_account_id,
            ).where(ReplayRateReservationRecord.rate_reservation_id.in_(rate_reservation_ids))
        ).all()
        if set(budget_reservation_ids).difference(row[0] for row in budget_bindings) or set(
            rate_reservation_ids
        ).difference(row[0] for row in rate_bindings):
            raise StateConflict("internal Replay Job authority reservation is incomplete")

        budget_account_ids = sorted({row[1] for row in budget_bindings})
        rate_account_ids = sorted({row[1] for row in rate_bindings})
        budget_accounts = list(
            session.scalars(
                select(ReplayBudgetAccountRecord)
                .where(ReplayBudgetAccountRecord.budget_account_id.in_(budget_account_ids))
                .order_by(ReplayBudgetAccountRecord.budget_account_id)
                .with_for_update()
            ).all()
        )
        rate_accounts = list(
            session.scalars(
                select(ReplayRateAccountRecord)
                .where(ReplayRateAccountRecord.rate_account_id.in_(rate_account_ids))
                .order_by(ReplayRateAccountRecord.rate_account_id)
                .with_for_update()
            ).all()
        )
        if set(budget_account_ids).difference(
            account.budget_account_id for account in budget_accounts
        ) or set(rate_account_ids).difference(account.rate_account_id for account in rate_accounts):
            raise StateConflict("internal Replay Job authority account is missing")

        locked_budget_reservation_ids = set(
            session.scalars(
                select(ReplayBudgetReservationRecord.budget_reservation_id)
                .where(ReplayBudgetReservationRecord.budget_account_id.in_(budget_account_ids))
                .order_by(ReplayBudgetReservationRecord.budget_reservation_id)
                .with_for_update()
            ).all()
        )
        locked_rate_reservation_ids = set(
            session.scalars(
                select(ReplayRateReservationRecord.rate_reservation_id)
                .where(ReplayRateReservationRecord.rate_account_id.in_(rate_account_ids))
                .order_by(ReplayRateReservationRecord.rate_reservation_id)
                .with_for_update()
            ).all()
        )
        if set(budget_reservation_ids).difference(locked_budget_reservation_ids) or set(
            rate_reservation_ids
        ).difference(locked_rate_reservation_ids):
            raise StateConflict("internal Replay Job reservation account binding changed")

    def _expire_locked_job(
        self,
        session: Session,
        graph: _ExpiredLeaseGraph,
        job: JobRecord,
        *,
        now: datetime,
        actor: str,
    ) -> int:
        run = graph.runs_by_id[job.run_id]
        if job.kind != _INTERNAL_REPLAY_KIND:
            return self._expire_generic_job(session, job, run, actor=actor)
        ticket = graph.tickets_by_job_id[job.job_id]
        item = graph.items_by_id[ticket.item_id]
        batch = graph.batches_by_id[ticket.batch_id]
        return self._expire_replay_job(
            session,
            job,
            ticket,
            item,
            batch,
            run,
            now=now,
            actor=actor,
        )

    def _expire_replay_job(
        self,
        session: Session,
        job: JobRecord,
        ticket: ReplayTicketRecord,
        item: ReplayItemRecord,
        batch: ReplayBatchRecord,
        run: RunRecord,
        *,
        now: datetime,
        actor: str,
    ) -> int:
        self._claims.verify_replay_binding(session, job, ticket, item, batch)
        transition_time = self._hooks.transaction.clock()
        if job.state == JobState.QUEUED.value:
            if not (
                run.state == RunState.QUEUED.value
                and batch.state == ReplayBatchState.RUNNING.value
                and item.state == ReplayItemState.QUEUED.value
                and ticket.state == ReplayTicketState.ISSUED.value
                and _aware(ticket.expires_at) <= now
            ):
                raise StateConflict("expired issued Replay authority graph is inconsistent")
            self._claims.terminate_replay_attempt(
                session,
                job=job,
                ticket=ticket,
                item=item,
                batch=batch,
                run=run,
                actor=actor,
                now=transition_time,
                reason="Replay ticket expired before claim",
                retryable=True,
                event_type="replay.ticket.expired-before-claim",
            )
            return 1
        if run.state == RunState.CANCELLED.value or batch.state == ReplayBatchState.CANCELLED.value:
            self._reap_cancelled_replay_lease(
                session,
                job,
                ticket,
                item,
                batch,
                run,
                actor=actor,
                now=transition_time,
            )
            return 0
        self.require_run_state(run, RunState.RUNNING)
        if ticket.state != ReplayTicketState.CLAIMED.value:
            raise StateConflict("leased Replay Job does not own a claimed ticket")
        if item.state != ReplayItemState.RUNNING.value:
            raise StateConflict("leased Replay Job does not own a running item")
        self._claims.terminate_replay_attempt(
            session,
            job=job,
            ticket=ticket,
            item=item,
            batch=batch,
            run=run,
            actor=actor,
            now=transition_time,
            reason="Replay lease expired",
            retryable=True,
            event_type="replay.ticket.lease-expired",
        )
        return 1

    def _reap_cancelled_replay_lease(
        self,
        session: Session,
        job: JobRecord,
        ticket: ReplayTicketRecord,
        item: ReplayItemRecord,
        batch: ReplayBatchRecord,
        run: RunRecord,
        *,
        actor: str,
        now: datetime,
    ) -> None:
        self._claims.abandon_replay_ticket(
            ticket,
            now=now,
            reason="cancelled Replay lease was reaped",
        )
        self._claims.release_replay_reservations(session, ticket, batch, now=now)
        self._cancel_job(job, now=now)
        item.state = ReplayItemState.CANCELLED.value
        item.updated_at = now
        self._hooks.transaction.replay_event_writer(
            session,
            batch,
            "replay.ticket.abandoned",
            actor,
            {"reason": ticket.abandon_reason},
            item=item,
            ticket=ticket,
            job=job,
            run_id=run.run_id,
        )

    def _expire_generic_job(
        self,
        session: Session,
        job: JobRecord,
        run: RunRecord,
        *,
        actor: str,
    ) -> int:
        transition_time = self._hooks.transaction.clock()
        if run.state == RunState.CANCELLED.value:
            self._cancel_job(job, now=transition_time)
            self._hooks.transaction.event_writer(
                session,
                run,
                "job.cancelled",
                actor,
                {"jobId": job.job_id, "reason": "cancelled run lease was reaped"},
            )
            return 0
        self.require_run_state(run, RunState.RUNNING)
        job.lease_owner = None
        job.lease_token_hash = None
        job.lease_expires_at = None
        job.lease_deadline_at = None
        job.heartbeat_at = None
        job.heartbeat_event_at = None
        job.updated_at = transition_time
        if job.attempts < job.max_attempts:
            job.state = JobState.QUEUED.value
            job.available_at = transition_time
            run.state = RunState.QUEUED.value
            event_type = "job.lease-expired-requeued"
        else:
            job.state = JobState.DEAD_LETTER.value
            run.state = RunState.FAILED.value
            event_type = "job.lease-expired-dead-lettered"
        run.updated_at = transition_time
        self._hooks.transaction.event_writer(
            session,
            run,
            event_type,
            actor,
            {"jobId": job.job_id, "attempt": job.attempts},
        )
        return 1

    def _cancel_replay_run(
        self,
        session: Session,
        replay_item_hint: ReplayItemRecord,
        *,
        request: CancelRunRequest,
        actor: str,
    ) -> CancelRunView:
        """Cancel under the canonical Replay graph then capacity-layer lock order."""

        graph = self._lock_replay_cancellation_graph(session, replay_item_hint)
        if graph.current_item.state == ReplayItemState.CANCELLED.value:
            return CancelRunView(
                run=self._views.run(graph.run),
                applied=False,
                cancelled_job_ids=[],
                revoked_approval_ids=[],
            )

        self._require_replay_cancellation_authority(session, graph)
        now = self._hooks.transaction.clock()
        cancelled_job_ids = self._cancel_replay_jobs(
            session,
            graph,
            actor=actor,
            reason=request.reason,
            now=now,
        )
        self._abandon_replay_cancellation_tickets(
            session,
            graph,
            actor=actor,
            reason=request.reason,
            now=now,
        )
        self._complete_replay_cancellation(
            session,
            graph,
            actor=actor,
            reason=request.reason,
            cancelled_job_ids=cancelled_job_ids,
            now=now,
        )
        return CancelRunView(
            run=self._views.run(graph.run),
            applied=True,
            cancelled_job_ids=cancelled_job_ids,
            revoked_approval_ids=[],
        )

    def _lock_replay_cancellation_graph(
        self,
        session: Session,
        replay_item_hint: ReplayItemRecord,
    ) -> _ReplayCancellationGraph:
        jobs = self._lock_cancellable_jobs(session, replay_item_hint.replay_run_id)
        tickets = list(
            session.scalars(
                select(ReplayTicketRecord)
                .where(ReplayTicketRecord.item_id == replay_item_hint.item_id)
                .order_by(ReplayTicketRecord.ticket_id)
                .with_for_update()
            ).all()
        )
        items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == replay_item_hint.batch_id)
                .order_by(ReplayItemRecord.item_id)
                .with_for_update()
            ).all()
        )
        batch = self._records.replay_batch(session, replay_item_hint.batch_id, lock=True)
        run = self._records.run(session, replay_item_hint.replay_run_id, lock=True)
        jobs_by_id = {job.job_id: job for job in jobs}
        items_by_id = {item.item_id: item for item in items}
        current_item = items_by_id.get(replay_item_hint.item_id)
        if current_item is None:
            raise StateConflict("Replay item disappeared during cancellation")
        if current_item.batch_id != batch.batch_id or current_item.replay_run_id != run.run_id:
            raise StateConflict("Replay item cancellation authority changed concurrently")
        return _ReplayCancellationGraph(
            jobs=jobs,
            tickets=tickets,
            items=items,
            batch=batch,
            run=run,
            current_item=current_item,
            jobs_by_id=jobs_by_id,
            items_by_id=items_by_id,
            retry_authority_cancel=(
                current_item.state == ReplayItemState.RETRY_PENDING.value
                and run.state == RunState.FAILED.value
            ),
        )

    def _require_replay_cancellation_authority(
        self,
        session: Session,
        graph: _ReplayCancellationGraph,
    ) -> None:
        if graph.run.state == RunState.CANCELLED.value:
            raise StateConflict("cancelled Replay Run still owns active item authority")
        if graph.run.state not in _CANCELLABLE_RUN_STATES and not graph.retry_authority_cancel:
            raise StateConflict(f"run in {graph.run.state} state cannot be cancelled")
        if graph.current_item.state in _TERMINAL_REPLAY_ITEM_STATES:
            raise StateConflict(
                f"Replay item in {graph.current_item.state} state cannot be cancelled"
            )
        if graph.batch.state in {
            ReplayBatchState.COMPLETED.value,
            ReplayBatchState.FAILED.value,
            ReplayBatchState.CANCELLED.value,
        }:
            raise StateConflict(f"Replay batch in {graph.batch.state} state cannot be cancelled")

        for ticket in graph.tickets:
            if ticket.state not in _ACTIVE_REPLAY_TICKET_STATES:
                continue
            item = graph.items_by_id.get(ticket.item_id)
            job = graph.jobs_by_id.get(ticket.job_id)
            if item is None or job is None:
                raise StateConflict("active Replay ticket authority graph is incomplete")
            self._claims.verify_replay_binding(session, job, ticket, item, graph.batch)

    def _cancel_replay_jobs(
        self,
        session: Session,
        graph: _ReplayCancellationGraph,
        *,
        actor: str,
        reason: str,
        now: datetime,
    ) -> list[str]:
        cancelled_job_ids: list[str] = []
        for job in graph.jobs:
            if job.kind != _INTERNAL_REPLAY_KIND:
                raise StateConflict("Replay batch owns a non-Replay active Job")
            previous_lease_owner = job.lease_owner
            self._cancel_job(job, now=now)
            cancelled_job_ids.append(job.job_id)
            if job.run_id != graph.run.run_id:
                raise StateConflict("Replay Job belongs to an unexpected Run")
            self._hooks.transaction.event_writer(
                session,
                graph.run,
                "job.cancelled",
                actor,
                {
                    "jobId": job.job_id,
                    "previousLeaseOwner": previous_lease_owner,
                    "reason": reason,
                    "replayBatchId": graph.batch.batch_id,
                },
            )
        return cancelled_job_ids

    def _abandon_replay_cancellation_tickets(
        self,
        session: Session,
        graph: _ReplayCancellationGraph,
        *,
        actor: str,
        reason: str,
        now: datetime,
    ) -> None:
        for ticket in graph.tickets:
            item = graph.items_by_id.get(ticket.item_id)
            if item is None:
                raise StateConflict("Replay ticket exists without its item")
            if ticket.state not in _ACTIVE_REPLAY_TICKET_STATES:
                continue
            self._claims.abandon_replay_ticket(
                ticket,
                now=now,
                reason="Replay item cancelled by operator",
            )
            self._claims.release_replay_reservations(
                session,
                ticket,
                graph.batch,
                now=now,
            )
            self._hooks.transaction.replay_event_writer(
                session,
                graph.batch,
                "replay.ticket.abandoned",
                actor,
                {"reason": reason},
                item=item,
                ticket=ticket,
                job=graph.jobs_by_id.get(ticket.job_id),
                run_id=ticket.replay_run_id,
            )

    def _complete_replay_cancellation(
        self,
        session: Session,
        graph: _ReplayCancellationGraph,
        *,
        actor: str,
        reason: str,
        cancelled_job_ids: list[str],
        now: datetime,
    ) -> None:
        graph.current_item.state = ReplayItemState.CANCELLED.value
        graph.current_item.updated_at = now
        graph.batch.updated_at = now
        graph.batch.cas_version += 1
        if graph.batch.cancellation_reason is None:
            graph.batch.cancellation_reason = reason
            graph.batch.cancelled_at = now
        terminal_batch_state = self._claims.refresh_terminal_replay_batch_state(
            graph.batch,
            graph.items,
            now=now,
        )
        batch_cancelled = terminal_batch_state == ReplayBatchState.CANCELLED.value

        if graph.retry_authority_cancel:
            # The expired one-shot attempt is immutable terminal history. Cancelling
            # retry authority fences future attempts without rewriting its failed Run.
            self._hooks.transaction.event_writer(
                session,
                graph.run,
                "run.replay-retry-authority-cancelled",
                actor,
                {
                    "reason": reason,
                    "replayBatchId": graph.batch.batch_id,
                    "replayItemId": graph.current_item.item_id,
                },
            )
        else:
            self.cancel_run_record(
                session,
                graph.run,
                actor=actor,
                now=now,
                reason=reason,
                cause="replay-item-cancelled",
                extra={
                    "replayBatchId": graph.batch.batch_id,
                    "replayItemId": graph.current_item.item_id,
                },
            )
        self._hooks.transaction.replay_event_writer(
            session,
            graph.batch,
            "replay.batch.cancelled" if batch_cancelled else "replay.item.cancelled",
            actor,
            {
                "reason": reason,
                "cancelledJobIds": cancelled_job_ids,
                "batchCancelled": batch_cancelled,
            },
            item=graph.current_item,
            run_id=graph.run.run_id,
        )

    def _lock_cancellable_jobs(self, session: Session, run_id: str) -> list[JobRecord]:
        statement = (
            select(JobRecord)
            .where(
                JobRecord.run_id == run_id,
                JobRecord.state.in_(_CANCELLABLE_JOB_STATES),
            )
            .order_by(JobRecord.job_id)
            .with_for_update()
        )
        return list(session.scalars(statement).all())

    def _lock_revocable_approvals(self, session: Session, run_id: str) -> list[ApprovalRecord]:
        statement = (
            select(ApprovalRecord)
            .where(
                ApprovalRecord.run_id == run_id,
                ApprovalRecord.state.in_(_REVOCABLE_APPROVAL_STATES),
            )
            .order_by(ApprovalRecord.approval_id)
            .with_for_update()
        )
        return list(session.scalars(statement).all())

    @staticmethod
    def _cancel_job(job: JobRecord, *, now: datetime) -> None:
        job.state = JobState.CANCELLED.value
        job.lease_owner = None
        job.lease_token_hash = None
        job.lease_expires_at = None
        job.lease_deadline_at = None
        job.heartbeat_at = None
        job.heartbeat_event_at = None
        job.updated_at = now

    def cancel_run_record(
        self,
        session: Session,
        run: RunRecord,
        *,
        actor: str,
        now: datetime,
        reason: str,
        cause: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if run.state == RunState.CANCELLED.value:
            return
        if run.state not in _CANCELLABLE_RUN_STATES:
            raise StateConflict(f"run in {run.state} state cannot be cancelled")
        run.state = RunState.CANCELLED.value
        run.updated_at = now
        self._hooks.transaction.event_writer(
            session,
            run,
            "run.cancelled",
            actor,
            {"cause": cause, "reason": reason, **(extra or {})},
        )

    def expire_approval(
        self,
        session: Session,
        approval: ApprovalRecord,
        run: RunRecord,
        *,
        actor: str,
        now: datetime,
    ) -> None:
        approval.state = ApprovalState.EXPIRED.value
        self._hooks.transaction.event_writer(
            session,
            run,
            "approval.expired",
            actor,
            {
                "approvalId": approval.approval_id,
                "checkpointId": approval.checkpoint_id,
                "expiredAt": approval.expires_at.isoformat(),
            },
        )
        self.cancel_run_record(
            session,
            run,
            actor=actor,
            now=now,
            reason="approval expired before it could be consumed",
            cause="approval-expired",
            extra={"approvalId": approval.approval_id},
        )

    @staticmethod
    def require_run_state(run: RunRecord, expected: RunState) -> None:
        if run.state == expected.value:
            return
        if run.state == RunState.CANCELLED.value:
            raise StateConflict("run has been cancelled")
        raise StateConflict(f"run must be {expected.value}, not {run.state}")

    @staticmethod
    def require_current_checkpoint(run: RunRecord, checkpoint_id: str) -> None:
        if run.current_checkpoint_id != checkpoint_id:
            raise StateConflict("checkpoint is not the Run's current approval boundary")

    def verify_checkpoint(self, checkpoint: CheckpointRecord) -> None:
        self.signer.verify(
            checkpoint_id=checkpoint.checkpoint_id,
            run_id=checkpoint.run_id,
            sequence=checkpoint.sequence,
            schema_version=checkpoint.schema_version,
            payload=checkpoint.payload,
            payload_sha256=checkpoint.payload_sha256,
            signature=checkpoint.signature,
            key_id=checkpoint.key_id,
        )

    @staticmethod
    def approval_matches_intent(approval: ApprovalRecord, intent: ApprovalIntent) -> bool:
        return (
            approval.call_fingerprint == intent.call_fingerprint
            and approval.tool_id == intent.tool_id
            and approval.target == intent.target
            and approval.risk_tier == int(intent.risk_tier)
            and _aware(approval.expires_at) == intent.expires_at
        )
