"""Generic and Replay Job claim/lease transactions."""

from __future__ import annotations

import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Protocol

from sqlalchemy import Select, func, select, update
from sqlalchemy.orm import Session

from pajin.control_plane.artifacts import (
    ArtifactNotFound,
    ArtifactRepositoryError,
    ManagedArtifactRepository,
    ManagedArtifactSnapshot,
)
from pajin.control_plane.collaborator_hooks import ControlPlaneTransactionHooks
from pajin.control_plane.database import (
    MAX_JOB_LEASE_LIFETIME_SECONDS,
    ArtifactRecord,
    ControlPlaneRepository,
    JobRecord,
    ReplayBatchRecord,
    ReplayBudgetAccountRecord,
    ReplayBudgetReservationRecord,
    ReplayCompilationRecord,
    ReplayExecutionContextRecord,
    ReplayItemRecord,
    ReplayRateAccountRecord,
    ReplayRateReservationRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
    RunRecord,
)
from pajin.control_plane.errors import (
    LeaseRejected,
    ReplayExecutorRejected,
    ResourceNotFound,
    RunCancelled,
    StateConflict,
)
from pajin.control_plane.models import (
    ArtifactLocator,
    ArtifactRef,
    ClaimedJob,
    ClaimJobRequest,
    InternalJobKind,
    JobKind,
    JobState,
    JobView,
    LeaseRequest,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayExecutionContext,
    ReplayFinalizeRequest,
    ReplayItemState,
    ReplayJobPayload,
    ReplayLeaseRequest,
    ReplayRateAccountAuthority,
    ReplayRateLimitSnapshot,
    ReplayTicketState,
    ReplayToolPermitRequest,
    RunState,
    job_submission_authority_digest,
)
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.replay_authority import (
    ReplayBindingAuthority,
    replay_rate_reservation_lifecycle_exact,
    require_exact_replay_account_permit_consumption,
    require_exact_replay_binding,
    require_exact_replay_budget_ledger,
    require_exact_replay_permit_ledger,
    require_exact_replay_rate_account,
    trusted_replay_compilation,
    trusted_replay_execution_context,
)
from pajin.control_plane.security import token_digest
from pajin.control_plane.view_mapper import ControlPlaneViewMapper
from pajin.replay.tickets import replay_context_digest
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import VerifiedRunSnapshot

MIN_JOB_HEARTBEAT_EVENT_INTERVAL_SECONDS = 60
_MAX_REPLAY_RATE_LIMIT_SNAPSHOT_BYTES = 1 * 1024 * 1024
_MAX_REPLAY_RATE_LIMIT_SNAPSHOT_DEPTH = 8
_MAX_REPLAY_RATE_LIMIT_SNAPSHOT_NODES = 4_096
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


class LeaseSweeper(Protocol):
    """Expire due leases before a new claim transaction selects work."""

    def __call__(self, session: Session, *, now: datetime, actor: str) -> int: ...


class VerifiedRunArtifactsLoader(Protocol):
    """Load a bounded set of artifacts from one verified sealed Run."""

    def __call__(
        self,
        run_path: Path,
        *,
        requests: Mapping[str, int],
        expected_run_id: str | None = None,
    ) -> VerifiedRunSnapshot: ...


@dataclass(frozen=True, slots=True)
class ClaimServiceHooks:
    """Service-owned transaction primitives required by claim operations."""

    transaction: ControlPlaneTransactionHooks
    lease_sweeper: LeaseSweeper
    artifact_loader: VerifiedRunArtifactsLoader


@dataclass(slots=True)
class LockedReplayAttempt:
    """One Replay Job graph loaded in the canonical Job-to-capacity lock order."""

    job: JobRecord
    ticket: ReplayTicketRecord
    item: ReplayItemRecord
    batch: ReplayBatchRecord
    run: RunRecord
    authority: ReplayBindingAuthority


@dataclass(slots=True)
class LockedReplayCapacity:
    """One ticket's accounts and complete reservation ledgers under lock."""

    budget_account: ReplayBudgetAccountRecord
    rate_account: ReplayRateAccountRecord
    budget_reservation: ReplayBudgetReservationRecord
    rate_reservation: ReplayRateReservationRecord
    budget_reservations: list[ReplayBudgetReservationRecord]
    rate_reservations: list[ReplayRateReservationRecord]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class ControlPlaneClaimService:
    """Own Job claim, lease heartbeat, and Replay fencing transactions."""

    def __init__(
        self,
        repository: ControlPlaneRepository,
        records: ControlPlaneRecords,
        views: ControlPlaneViewMapper,
        artifact_repository: ManagedArtifactRepository | None,
        replay_executor_profiles: Mapping[str, frozenset[str]],
        hooks: ClaimServiceHooks,
    ) -> None:
        self.repository = repository
        self._records = records
        self._views = views
        self._artifact_repository = artifact_repository
        self._replay_executor_profiles = dict(replay_executor_profiles)
        self._hooks = hooks

    def claim_job(self, request: ClaimJobRequest, *, actor: str) -> ClaimedJob | None:
        requested_kinds = [
            kind.value if isinstance(kind, JobKind) else str(kind) for kind in request.kinds
        ]
        if _INTERNAL_REPLAY_KIND in requested_kinds:
            raise StateConflict("internal Replay Jobs require the trusted Replay claim service")
        public_kinds = {kind.value for kind in JobKind}
        if not requested_kinds or not set(requested_kinds).issubset(public_kinds):
            raise StateConflict("generic claim accepts only public Job kinds")
        sweep_time = self._hooks.transaction.clock()
        # Keep opportunistic cleanup outside the claim transaction. A sweep locks
        # Job -> Replay graph -> Run; acquiring another queued Job afterwards would
        # invert that global order and can deadlock concurrent PostgreSQL claimers.
        with self.repository.transaction() as session:
            self._hooks.lease_sweeper(session, now=sweep_time, actor=actor)
        claim_time = self._hooks.transaction.clock()
        with self.repository.transaction() as session:
            statement: Select[tuple[JobRecord]] = (
                select(JobRecord)
                .where(
                    JobRecord.state == JobState.QUEUED.value,
                    JobRecord.available_at <= claim_time,
                    JobRecord.kind.in_(requested_kinds),
                )
                .order_by(JobRecord.priority.desc(), JobRecord.created_at, JobRecord.job_id)
                .limit(1)
            )
            if self.repository.dialect_name == "postgresql":
                statement = statement.with_for_update(skip_locked=True)
            else:
                statement = statement.with_for_update()
            job = session.scalar(statement)
            if job is None:
                return None
            self._require_job_submission_authority(job)
            run = self._records.run(session, job.run_id, lock=True)
            now = self._hooks.transaction.clock()
            if run.state == RunState.CANCELLED.value:
                self._cancel_job(job, now=now)
                self._hooks.transaction.event_writer(
                    session,
                    run,
                    "job.cancelled",
                    actor,
                    {"jobId": job.job_id, "reason": "run was already cancelled"},
                )
                return None
            self._require_run_state(run, RunState.QUEUED)
            lease_token = secrets.token_urlsafe(32)
            lease_deadline_at = now + timedelta(seconds=MAX_JOB_LEASE_LIFETIME_SECONDS)
            lease_expires_at = min(
                now + timedelta(seconds=request.lease_seconds),
                lease_deadline_at,
            )
            job.state = JobState.LEASED.value
            job.lease_owner = request.worker_id
            job.lease_token_hash = self._generic_lease_token_digest(actor, lease_token)
            job.lease_expires_at = lease_expires_at
            job.lease_deadline_at = lease_deadline_at
            job.heartbeat_at = now
            job.heartbeat_event_at = None
            job.attempts += 1
            job.updated_at = now
            run.state = RunState.RUNNING.value
            run.updated_at = now
            self._hooks.transaction.event_writer(
                session,
                run,
                "job.claimed",
                actor,
                {
                    "jobId": job.job_id,
                    "workerId": request.worker_id,
                    "attempt": job.attempts,
                    "leaseExpiresAt": job.lease_expires_at.isoformat(),
                },
            )
            return ClaimedJob(job=self._views.job(job), lease_token=lease_token)

    def claim_replay_job(
        self,
        request: ReplayClaimRequest,
        *,
        actor: str,
    ) -> ReplayExecutionClaimView | None:
        """Burn exactly one issued Replay ticket while leasing its one-shot Job."""

        self.require_replay_executor_profile(actor, request.executor_profile)
        sweep_time = self._hooks.transaction.clock()
        # The cleanup transaction must commit before claim starts. Besides avoiding
        # SQLite reader-to-writer upgrade deadlocks, this keeps PostgreSQL claimers
        # from returning to a Job lock after they already locked Replay dependants.
        with self.repository.transaction() as session:
            self._hooks.lease_sweeper(session, now=sweep_time, actor=actor)
        with self.repository.transaction() as session:
            lease_token = secrets.token_urlsafe(32)
            lease_hash = token_digest(lease_token)
            claim_started_at = self._hooks.transaction.clock()
            job = self._acquire_replay_job_for_claim(
                session,
                actor=actor,
                lease_hash=lease_hash,
                lease_seconds=request.lease_seconds,
                now=claim_started_at,
            )
            if job is None:
                return None
            self._require_job_submission_authority(job)

            ticket = self._records.replay_ticket_for_job(session, job.job_id, lock=True)
            item = self._records.replay_item(session, ticket.item_id, lock=True)
            batch = self._records.replay_batch(session, ticket.batch_id, lock=True)
            run = self._records.run(session, job.run_id, lock=True)
            authority = self.verify_replay_binding(session, job, ticket, item, batch)
            attempt = LockedReplayAttempt(
                job=job,
                ticket=ticket,
                item=item,
                batch=batch,
                run=run,
                authority=authority,
            )
            if request.executor_profile != authority.execution_context.required_executor_profile:
                raise ReplayExecutorRejected(
                    "Replay Job requires a different registered executor profile"
                )
            now = self._hooks.transaction.clock()
            if self._cancel_replay_claim_if_needed(session, attempt, actor=actor, now=now):
                return None
            self._require_claimable_replay_attempt(attempt)
            if _aware(attempt.ticket.expires_at) <= now:
                self.terminate_replay_attempt(
                    session,
                    job=attempt.job,
                    ticket=attempt.ticket,
                    item=attempt.item,
                    batch=attempt.batch,
                    run=attempt.run,
                    actor=actor,
                    now=now,
                    reason="Replay ticket expired before claim",
                    retryable=True,
                    event_type="replay.ticket.expired-before-claim",
                )
                return None
            return self._burn_replay_claim(
                session,
                attempt,
                request=request,
                actor=actor,
                lease_token=lease_token,
                lease_hash=lease_hash,
                now=now,
            )

    def _acquire_replay_job_for_claim(
        self,
        session: Session,
        *,
        actor: str,
        lease_hash: str,
        lease_seconds: int,
        now: datetime,
    ) -> JobRecord | None:
        claimable = (
            JobRecord.kind == _INTERNAL_REPLAY_KIND,
            JobRecord.state == JobState.QUEUED.value,
            JobRecord.available_at <= now,
            JobRecord.attempts == 0,
            JobRecord.max_attempts == 1,
            JobRecord.lease_owner.is_(None),
            JobRecord.lease_token_hash.is_(None),
            JobRecord.lease_expires_at.is_(None),
            JobRecord.lease_deadline_at.is_(None),
            JobRecord.heartbeat_at.is_(None),
            JobRecord.heartbeat_event_at.is_(None),
        )
        if self.repository.dialect_name == "sqlite":
            candidate = (
                select(JobRecord.job_id)
                .where(*claimable)
                .order_by(JobRecord.priority.desc(), JobRecord.created_at, JobRecord.job_id)
                .limit(1)
                .scalar_subquery()
            )
            claimed_job_id = session.scalar(
                update(JobRecord)
                .where(JobRecord.job_id == candidate, *claimable)
                .values(
                    state=JobState.LEASED.value,
                    lease_owner=actor,
                    lease_token_hash=lease_hash,
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                    lease_deadline_at=now + timedelta(seconds=MAX_JOB_LEASE_LIFETIME_SECONDS),
                    heartbeat_at=now,
                    heartbeat_event_at=None,
                    attempts=1,
                    updated_at=now,
                )
                .returning(JobRecord.job_id)
            )
            return (
                self._records.job(session, claimed_job_id) if claimed_job_id is not None else None
            )
        statement: Select[tuple[JobRecord]] = (
            select(JobRecord)
            .where(*claimable)
            .order_by(JobRecord.priority.desc(), JobRecord.created_at, JobRecord.job_id)
            .limit(1)
        )
        if self.repository.dialect_name == "postgresql":
            statement = statement.with_for_update(skip_locked=True)
        else:
            statement = statement.with_for_update()
        return session.scalar(statement)

    def _cancel_replay_claim_if_needed(
        self,
        session: Session,
        attempt: LockedReplayAttempt,
        *,
        actor: str,
        now: datetime,
    ) -> bool:
        if not (
            attempt.run.state == RunState.CANCELLED.value
            or attempt.batch.state == ReplayBatchState.CANCELLED.value
            or attempt.item.state == ReplayItemState.CANCELLED.value
        ):
            return False
        self.abandon_replay_ticket(
            attempt.ticket,
            now=now,
            reason="replay authority was cancelled before claim",
        )
        self.release_replay_reservations(
            session,
            attempt.ticket,
            attempt.batch,
            now=now,
        )
        self._cancel_job(attempt.job, now=now)
        attempt.item.state = ReplayItemState.CANCELLED.value
        attempt.item.updated_at = now
        self._hooks.transaction.replay_event_writer(
            session,
            attempt.batch,
            "replay.ticket.abandoned",
            actor,
            {"reason": attempt.ticket.abandon_reason},
            item=attempt.item,
            ticket=attempt.ticket,
            job=attempt.job,
            run_id=attempt.run.run_id,
        )
        return True

    def _require_claimable_replay_attempt(self, attempt: LockedReplayAttempt) -> None:
        self._require_run_state(attempt.run, RunState.QUEUED)
        if attempt.batch.state != ReplayBatchState.RUNNING.value:
            raise StateConflict(f"Replay batch in {attempt.batch.state} state cannot be claimed")
        if attempt.item.state != ReplayItemState.QUEUED.value:
            raise StateConflict(f"Replay item in {attempt.item.state} state cannot be claimed")
        if attempt.ticket.state != ReplayTicketState.ISSUED.value:
            raise StateConflict(f"Replay ticket is already {attempt.ticket.state}")
        expected_attempts = 1 if self.repository.dialect_name == "sqlite" else 0
        if attempt.job.attempts != expected_attempts or attempt.job.max_attempts != 1:
            raise StateConflict("internal Replay Job attempt authority is inconsistent")

    def _burn_replay_claim(
        self,
        session: Session,
        attempt: LockedReplayAttempt,
        *,
        request: ReplayClaimRequest,
        actor: str,
        lease_token: str,
        lease_hash: str,
        now: datetime,
    ) -> ReplayExecutionClaimView:
        # expires_at is the unclaimed issuance deadline. Once the ticket is
        # atomically burned, the claimed authority is governed by its lease.
        lease_deadline_at = min(
            now + timedelta(seconds=MAX_JOB_LEASE_LIFETIME_SECONDS),
            _aware(attempt.authority.compilation.spec.expires_at),
            _aware(attempt.authority.compilation.grant.expires_at),
        )
        if lease_deadline_at <= now:
            raise StateConflict("Replay compilation authority expired during claim")
        lease_expires_at = min(
            now + timedelta(seconds=request.lease_seconds),
            lease_deadline_at,
        )
        attempt.job.state = JobState.LEASED.value
        attempt.job.lease_owner = actor
        attempt.job.lease_token_hash = lease_hash
        attempt.job.lease_expires_at = lease_expires_at
        attempt.job.lease_deadline_at = lease_deadline_at
        attempt.job.heartbeat_at = now
        attempt.job.heartbeat_event_at = None
        attempt.job.attempts = 1
        attempt.job.updated_at = now
        claimed_ticket_id = session.scalar(
            update(ReplayTicketRecord)
            .where(
                ReplayTicketRecord.ticket_id == attempt.ticket.ticket_id,
                ReplayTicketRecord.state == ReplayTicketState.ISSUED.value,
                ReplayTicketRecord.claim_principal.is_(None),
                ReplayTicketRecord.executor_profile.is_(None),
                ReplayTicketRecord.lease_token_hash.is_(None),
                ReplayTicketRecord.claimed_at.is_(None),
                ReplayTicketRecord.lease_expires_at.is_(None),
            )
            .values(
                state=ReplayTicketState.CLAIMED.value,
                executor_profile=request.executor_profile,
                claim_principal=actor,
                lease_token_hash=lease_hash,
                claimed_at=now,
                lease_expires_at=lease_expires_at,
                updated_at=now,
            )
            .returning(ReplayTicketRecord.ticket_id)
        )
        if claimed_ticket_id != attempt.ticket.ticket_id:
            raise StateConflict("Replay ticket claim authority changed concurrently")
        session.refresh(attempt.ticket)
        attempt.item.state = ReplayItemState.RUNNING.value
        attempt.item.updated_at = now
        attempt.run.state = RunState.RUNNING.value
        attempt.run.updated_at = now
        self._hooks.transaction.event_writer(
            session,
            attempt.run,
            "job.claimed",
            actor,
            {
                "jobId": attempt.job.job_id,
                "workerId": actor,
                "attempt": attempt.job.attempts,
                "leaseExpiresAt": lease_expires_at.isoformat(),
                "replayTicketId": attempt.ticket.ticket_id,
                "fencingValue": attempt.ticket.fencing_value,
            },
        )
        self._hooks.transaction.replay_event_writer(
            session,
            attempt.batch,
            "replay.ticket.claimed",
            actor,
            {
                "attempt": attempt.ticket.attempt_number,
                "fencingValue": attempt.ticket.fencing_value,
                "executorProfile": request.executor_profile,
                "leaseExpiresAt": lease_expires_at.isoformat(),
            },
            item=attempt.item,
            ticket=attempt.ticket,
            job=attempt.job,
            run_id=attempt.run.run_id,
        )
        return self._views.replay_claim(
            job=attempt.job,
            batch=attempt.batch,
            item=attempt.item,
            ticket=attempt.ticket,
            compilation=attempt.authority.compilation,
            execution_context=attempt.authority.execution_context,
            execution_context_digest=attempt.authority.execution_context_record.context_digest,
            lease_token=lease_token,
        )

    def heartbeat_replay_job(
        self,
        job_id: str,
        request: ReplayLeaseRequest,
        *,
        actor: str,
    ) -> ReplayExecutionClaimView:
        """Extend only the exact principal/token/ticket/fence Replay lease."""

        self.require_replay_executor_profile(actor, request.executor_profile)
        expired = False
        result: ReplayExecutionClaimView | None = None
        with self.repository.transaction() as session:
            job = self._records.job(session, job_id, lock=True)
            if job.kind != _INTERNAL_REPLAY_KIND:
                raise StateConflict("Job is not an internal Replay Job")
            ticket = self._records.replay_ticket_for_job(session, job.job_id, lock=True)
            item = self._records.replay_item(session, ticket.item_id, lock=True)
            batch = self._records.replay_batch(session, ticket.batch_id, lock=True)
            run = self._records.run(session, job.run_id, lock=True)
            authority = self.verify_replay_binding(session, job, ticket, item, batch)
            if (
                run.state == RunState.CANCELLED.value
                or batch.state == ReplayBatchState.CANCELLED.value
                or item.state == ReplayItemState.CANCELLED.value
            ):
                raise RunCancelled("run has been cancelled")
            observed_now = self._hooks.transaction.clock()
            now = max(
                observed_now,
                _aware(job.heartbeat_at) if job.heartbeat_at is not None else observed_now,
            )
            self.require_replay_lease_identity(
                job,
                ticket,
                request=request,
                actor=actor,
            )
            lease_deadline = min(
                _aware(job.lease_expires_at) if job.lease_expires_at else now,
                _aware(ticket.lease_expires_at) if ticket.lease_expires_at else now,
                _aware(job.lease_deadline_at) if job.lease_deadline_at else now,
            )
            if lease_deadline <= now:
                self.terminate_replay_attempt(
                    session,
                    job=job,
                    ticket=ticket,
                    item=item,
                    batch=batch,
                    run=run,
                    actor=actor,
                    now=now,
                    reason="Replay lease expired",
                    retryable=True,
                    event_type="replay.ticket.lease-expired",
                )
                expired = True
            else:
                self._require_run_state(run, RunState.RUNNING)
                if batch.state != ReplayBatchState.RUNNING.value:
                    raise LeaseRejected("Replay batch is not running")
                if item.state != ReplayItemState.RUNNING.value:
                    raise LeaseRejected("Replay item is not running")
                if ticket.state != ReplayTicketState.CLAIMED.value:
                    raise LeaseRejected("Replay ticket is not claimed")
                if job.lease_deadline_at is None:
                    raise LeaseRejected("Replay job lease has expired")
                hard_deadline = _aware(job.lease_deadline_at)
                lease_expires_at = min(
                    now + timedelta(seconds=request.lease_seconds),
                    hard_deadline,
                )
                job.heartbeat_at = now
                job.lease_expires_at = lease_expires_at
                job.updated_at = now
                ticket.lease_expires_at = lease_expires_at
                ticket.updated_at = now
                if self._heartbeat_event_is_due(job, now=now):
                    job.heartbeat_event_at = now
                    self._hooks.transaction.event_writer(
                        session,
                        run,
                        "job.heartbeat",
                        actor,
                        {
                            "jobId": job.job_id,
                            "leaseExpiresAt": lease_expires_at.isoformat(),
                            "replayTicketId": ticket.ticket_id,
                            "fencingValue": ticket.fencing_value,
                        },
                    )
                    self._hooks.transaction.replay_event_writer(
                        session,
                        batch,
                        "replay.ticket.heartbeat",
                        actor,
                        {
                            "fencingValue": ticket.fencing_value,
                            "leaseExpiresAt": lease_expires_at.isoformat(),
                        },
                        item=item,
                        ticket=ticket,
                        job=job,
                        run_id=run.run_id,
                    )
                result = self._views.replay_claim(
                    job=job,
                    batch=batch,
                    item=item,
                    ticket=ticket,
                    compilation=authority.compilation,
                    execution_context=authority.execution_context,
                    execution_context_digest=(authority.execution_context_record.context_digest),
                    lease_token=request.lease_token,
                )
        if expired:
            raise LeaseRejected("Replay job lease has expired")
        if result is None:
            raise RuntimeError("Replay heartbeat did not produce a result")
        return result

    def heartbeat(self, job_id: str, request: LeaseRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._records.job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job requires the Replay heartbeat service")
            run = self._records.run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                # Keep this message deliberately generic. The operator's cancellation
                # reason is audit data and must not be disclosed to Worker credentials.
                raise RunCancelled("run has been cancelled")
            self._require_run_state(run, RunState.RUNNING)
            observed_now = self._hooks.transaction.clock()
            now = max(
                observed_now,
                _aware(job.heartbeat_at) if job.heartbeat_at is not None else observed_now,
            )
            self.require_active_lease(
                job,
                request.worker_id,
                request.lease_token,
                now,
                actor=actor,
            )
            if job.lease_deadline_at is None:
                raise LeaseRejected("job lease has expired")
            hard_deadline = _aware(job.lease_deadline_at)
            job.heartbeat_at = now
            job.lease_expires_at = min(
                now + timedelta(seconds=request.lease_seconds),
                hard_deadline,
            )
            job.updated_at = now
            if self._heartbeat_event_is_due(job, now=now):
                job.heartbeat_event_at = now
                self._hooks.transaction.event_writer(
                    session,
                    run,
                    "job.heartbeat",
                    actor,
                    {
                        "jobId": job.job_id,
                        "leaseExpiresAt": job.lease_expires_at.isoformat(),
                    },
                )
            return self._views.job(job)

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

    @staticmethod
    def _require_run_state(run: RunRecord, expected: RunState) -> None:
        if run.state == expected.value:
            return
        if run.state == RunState.CANCELLED.value:
            raise StateConflict("run has been cancelled")
        raise StateConflict(f"run must be {expected.value}, not {run.state}")

    @staticmethod
    def _require_job_submission_authority(job: JobRecord) -> None:
        """Fail closed before dispatch when immutable Job authority has drifted."""

        try:
            expected = job_submission_authority_digest(
                job_id=job.job_id,
                run_id=job.run_id,
                job_kind=job.kind,
                payload=job.payload,
                max_attempts=job.max_attempts,
                idempotency_key=job.idempotency_key,
            )
        except (TypeError, ValueError) as exc:
            raise StateConflict("Job submission authority is invalid") from exc
        stored = job.submission_authority_digest
        if not isinstance(stored, str) or not hmac.compare_digest(stored, expected):
            raise StateConflict("Job submission authority integrity check failed")

    @staticmethod
    def _generic_lease_token_digest(actor: str, token: str) -> str:
        material = json.dumps(
            {"actor": actor, "token": token},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return sha256(b"pajin.generic-lease.v1\x00" + material).hexdigest()

    @classmethod
    def require_lease_identity(
        cls,
        job: JobRecord,
        worker_id: str,
        token: str,
        *,
        actor: str,
    ) -> None:
        if job.lease_owner != worker_id or job.lease_token_hash is None:
            raise LeaseRejected("job lease is not owned by this worker")
        actor_bound_digest = cls._generic_lease_token_digest(actor, token)
        # Accept only already-persisted pre-binding leases during their bounded rollout
        # lifetime. Newly issued leases always use the actor-bound digest above.
        legacy_digest = token_digest(token)
        if not (
            hmac.compare_digest(job.lease_token_hash, actor_bound_digest)
            or hmac.compare_digest(job.lease_token_hash, legacy_digest)
        ):
            raise LeaseRejected("job lease token is invalid")

    @classmethod
    def require_active_lease(
        cls,
        job: JobRecord,
        worker_id: str,
        token: str,
        now: datetime,
        *,
        actor: str,
    ) -> None:
        cls.require_lease_identity(job, worker_id, token, actor=actor)
        if job.state != JobState.LEASED.value:
            raise LeaseRejected("job is not actively leased")
        if job.lease_expires_at is None or job.lease_deadline_at is None:
            raise LeaseRejected("job lease has expired")
        lease_expires_at = _aware(job.lease_expires_at)
        lease_deadline_at = _aware(job.lease_deadline_at)
        if (
            lease_expires_at <= now
            or lease_deadline_at <= now
            or lease_expires_at > lease_deadline_at
        ):
            raise LeaseRejected("job lease has expired")

    @staticmethod
    def _heartbeat_event_is_due(job: JobRecord, *, now: datetime) -> bool:
        if job.heartbeat_event_at is None:
            return True
        return (
            _aware(job.heartbeat_event_at)
            + timedelta(seconds=MIN_JOB_HEARTBEAT_EVENT_INTERVAL_SECONDS)
            <= now
        )

    def _trusted_replay_rate_authority(
        self,
        session: Session,
        *,
        batch: ReplayBatchRecord,
        execution_context: ReplayExecutionContext,
    ) -> ReplayRateAccountAuthority:
        """Reconstruct rate authority without changing the persisted v7 Job payload.

        The managed repository is resolved both before and after reading one exact,
        bounded, integrity-bound ledger snapshot. A legacy issued Job can therefore
        be checked against its source without a payload rewrite. The request cap comes
        from the independently sealed execution context Campaign.
        """

        repository = self._require_artifact_repository()
        source = self._views.replay_source(batch)
        locator = ArtifactLocator(
            artifact_id=source.artifact_id,
            repository_version=source.repository_version,
        )
        artifact = self._records.artifact(session, locator)
        self._require_artifact_snapshot(
            artifact,
            source,
            storage_key=artifact.storage_key,
        )
        storage_key = artifact.storage_key
        snapshot = self._resolve_managed_artifact(
            repository,
            source,
            expected_storage_key=storage_key,
        )
        try:
            verified = self._hooks.artifact_loader(
                snapshot.path,
                requests={
                    "rate-limits.json": _MAX_REPLAY_RATE_LIMIT_SNAPSHOT_BYTES,
                },
                expected_run_id=source.run_id,
            )
            if verified.verification.root_digest != source.integrity_root_digest:
                raise ValueError("sealed Replay rate-limit snapshot changed its Run root")
            raw_rate_limits = parse_strict_json_bytes(
                verified.artifact_bytes("rate-limits.json"),
                label="sealed Replay rate-limit snapshot",
                max_bytes=_MAX_REPLAY_RATE_LIMIT_SNAPSHOT_BYTES,
                max_depth=_MAX_REPLAY_RATE_LIMIT_SNAPSHOT_DEPTH,
                max_nodes=_MAX_REPLAY_RATE_LIMIT_SNAPSHOT_NODES,
            )
            if not isinstance(raw_rate_limits, dict):
                raise ValueError("sealed Replay rate-limit snapshot must be an object")
            rate_limits = ReplayRateLimitSnapshot.model_validate(raw_rate_limits)
            authority = ReplayRateAccountAuthority(
                rate_limits_digest=replay_context_digest(rate_limits),
                ledger_id=rate_limits.ledger_id,
                max_requests_per_minute=(
                    execution_context.campaign.spec.rules_of_engagement.max_requests_per_minute
                ),
                observed_request_units=rate_limits.reservation_counts.get(
                    execution_context.campaign.metadata.name,
                    0,
                ),
                observed_at=_aware(artifact.created_at),
                window_seconds=60,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise StateConflict(
                "managed source Replay rate authority failed reverification"
            ) from exc
        self._resolve_managed_artifact(
            repository,
            source,
            expected_storage_key=storage_key,
        )
        return authority

    def verify_replay_binding(
        self,
        session: Session,
        job: JobRecord,
        ticket: ReplayTicketRecord,
        item: ReplayItemRecord,
        batch: ReplayBatchRecord,
    ) -> ReplayBindingAuthority:
        try:
            payload = ReplayJobPayload.model_validate(job.payload)
        except ValueError as exc:
            raise StateConflict("internal Replay Job payload is not canonical") from exc
        compilation = session.get(ReplayCompilationRecord, ticket.compilation_id)
        execution_context_record = session.scalar(
            select(ReplayExecutionContextRecord).where(
                ReplayExecutionContextRecord.compilation_id == ticket.compilation_id
            )
        )
        budget_account_id = session.scalar(
            select(ReplayBudgetReservationRecord.budget_account_id).where(
                ReplayBudgetReservationRecord.budget_reservation_id == ticket.budget_reservation_id
            )
        )
        rate_account_id = session.scalar(
            select(ReplayRateReservationRecord.rate_account_id).where(
                ReplayRateReservationRecord.rate_reservation_id == ticket.rate_reservation_id
            )
        )
        if (
            compilation is None
            or execution_context_record is None
            or budget_account_id is None
            or rate_account_id is None
        ):
            raise StateConflict("internal Replay Job authority reservation is incomplete")
        budget_account = session.scalar(
            select(ReplayBudgetAccountRecord)
            .where(ReplayBudgetAccountRecord.budget_account_id == budget_account_id)
            .with_for_update()
        )
        rate_account = session.scalar(
            select(ReplayRateAccountRecord)
            .where(ReplayRateAccountRecord.rate_account_id == rate_account_id)
            .with_for_update()
        )
        if budget_account is None or rate_account is None:
            raise StateConflict("internal Replay Job authority account is missing")
        budget_reservations = list(
            session.scalars(
                select(ReplayBudgetReservationRecord)
                .where(
                    ReplayBudgetReservationRecord.budget_account_id
                    == budget_account.budget_account_id
                )
                .order_by(ReplayBudgetReservationRecord.budget_reservation_id)
                .with_for_update()
            ).all()
        )
        budget_reservation = next(
            (
                reservation
                for reservation in budget_reservations
                if reservation.budget_reservation_id == ticket.budget_reservation_id
            ),
            None,
        )
        rate_reservations = list(
            session.scalars(
                select(ReplayRateReservationRecord)
                .where(ReplayRateReservationRecord.rate_account_id == rate_account.rate_account_id)
                .order_by(ReplayRateReservationRecord.rate_reservation_id)
                .with_for_update()
            ).all()
        )
        rate_reservation = next(
            (
                reservation
                for reservation in rate_reservations
                if reservation.rate_reservation_id == ticket.rate_reservation_id
            ),
            None,
        )
        if budget_reservation is None or rate_reservation is None:
            raise StateConflict("internal Replay Job reservation account binding changed")
        require_exact_replay_budget_ledger(
            budget_account,
            budget_reservations,
        )
        if any(
            not replay_rate_reservation_lifecycle_exact(reservation)
            for reservation in rate_reservations
        ):
            raise StateConflict("durable Replay rate reservation ledger is inconsistent")
        require_exact_replay_account_permit_consumption(
            session,
            budget_reservations=budget_reservations,
            rate_reservations=rate_reservations,
        )
        trusted = trusted_replay_compilation(compilation)
        execution_context = trusted_replay_execution_context(execution_context_record)
        rate_authority = self._trusted_replay_rate_authority(
            session,
            batch=batch,
            execution_context=execution_context,
        )
        require_exact_replay_rate_account(rate_account, batch, rate_authority)
        permits = list(
            session.scalars(
                select(ReplayToolPermitRecord)
                .where(ReplayToolPermitRecord.ticket_id == ticket.ticket_id)
                .order_by(ReplayToolPermitRecord.call_ordinal)
            ).all()
        )
        require_exact_replay_permit_ledger(
            permits,
            job=job,
            ticket=ticket,
            item=item,
            batch=batch,
            compilation=compilation,
            trusted=trusted,
            budget_reservation=budget_reservation,
            rate_reservation=rate_reservation,
            rate_window_seconds=rate_account.window_seconds,
        )
        authority = ReplayBindingAuthority(
            payload=payload,
            compilation_record=compilation,
            compilation=trusted,
            execution_context_record=execution_context_record,
            execution_context=execution_context,
            budget_account=budget_account,
            rate_account=rate_account,
            budget_reservation=budget_reservation,
            rate_reservation=rate_reservation,
            budget_reservations=budget_reservations,
            rate_reservations=rate_reservations,
            permits=permits,
        )
        require_exact_replay_binding(
            job,
            ticket,
            item,
            batch,
            authority,
            source=self._views.replay_source(batch),
        )
        return authority

    def require_replay_executor_profile(self, actor: str, executor_profile: str) -> None:
        allowed = self._replay_executor_profiles.get(actor, frozenset())
        if executor_profile not in allowed:
            raise ReplayExecutorRejected(
                "authenticated Worker principal is not registered for this Replay executor"
            )

    @staticmethod
    def require_replay_lease_identity(
        job: JobRecord,
        ticket: ReplayTicketRecord,
        *,
        request: ReplayLeaseRequest | ReplayToolPermitRequest | ReplayFinalizeRequest,
        actor: str,
    ) -> None:
        if (
            request.ticket_id != ticket.ticket_id
            or request.fencing_value != ticket.fencing_value
            or request.executor_profile != ticket.executor_profile
            or actor != ticket.claim_principal
            or actor != job.lease_owner
        ):
            raise LeaseRejected("Replay lease identity or fencing value does not match")
        if (
            job.state != JobState.LEASED.value
            or ticket.state != ReplayTicketState.CLAIMED.value
            or job.lease_token_hash is None
            or ticket.lease_token_hash is None
            or job.heartbeat_at is None
            or job.lease_deadline_at is None
        ):
            raise LeaseRejected("Replay job is not actively leased")
        supplied_digest = token_digest(request.lease_token)
        if not (
            hmac.compare_digest(job.lease_token_hash, supplied_digest)
            and hmac.compare_digest(ticket.lease_token_hash, supplied_digest)
            and hmac.compare_digest(job.lease_token_hash, ticket.lease_token_hash)
        ):
            raise LeaseRejected("Replay lease token is invalid")
        if (
            job.lease_expires_at is None
            or ticket.lease_expires_at is None
            or _aware(job.lease_expires_at) != _aware(ticket.lease_expires_at)
            or _aware(job.lease_expires_at) > _aware(job.lease_deadline_at)
        ):
            raise LeaseRejected("Replay Job and ticket lease deadlines do not match")

    @staticmethod
    def abandon_replay_ticket(
        ticket: ReplayTicketRecord,
        *,
        now: datetime,
        reason: str,
    ) -> None:
        if ticket.state not in _ACTIVE_REPLAY_TICKET_STATES:
            raise StateConflict(f"Replay ticket in {ticket.state} state cannot be abandoned")
        bounded_reason = reason.strip()[:2_000]
        if not bounded_reason:
            raise ValueError("Replay ticket abandonment reason must not be blank")
        ticket.state = ReplayTicketState.ABANDONED.value
        ticket.abandoned_at = now
        ticket.abandon_reason = bounded_reason
        ticket.updated_at = now

    def release_replay_reservations(
        self,
        session: Session,
        ticket: ReplayTicketRecord,
        batch: ReplayBatchRecord,
        *,
        now: datetime,
    ) -> None:
        """Release only the definitely unconsumed remainder of one exact attempt.

        Account IDs are discovered without retaining ORM rows, then both accounts
        are locked before any reservation. This preserves the same capacity-layer
        order used by issuance and prevents account/reservation lock inversion.
        """

        capacity = self._lock_replay_capacity_for_release(session, ticket)
        self._require_releasable_replay_capacity(
            session,
            ticket,
            batch,
            capacity,
        )
        self._release_replay_budget_capacity(capacity, now=now)
        self._release_replay_rate_capacity(capacity, now=now)
        require_exact_replay_budget_ledger(
            capacity.budget_account,
            capacity.budget_reservations,
        )

    def _lock_replay_capacity_for_release(
        self,
        session: Session,
        ticket: ReplayTicketRecord,
    ) -> LockedReplayCapacity:
        budget_account_id = session.scalar(
            select(ReplayBudgetReservationRecord.budget_account_id).where(
                ReplayBudgetReservationRecord.budget_reservation_id == ticket.budget_reservation_id
            )
        )
        rate_account_id = session.scalar(
            select(ReplayRateReservationRecord.rate_account_id).where(
                ReplayRateReservationRecord.rate_reservation_id == ticket.rate_reservation_id
            )
        )
        if budget_account_id is None or rate_account_id is None:
            raise StateConflict("Replay ticket reservation disappeared during release")
        budget_account = session.scalar(
            select(ReplayBudgetAccountRecord)
            .where(ReplayBudgetAccountRecord.budget_account_id == budget_account_id)
            .with_for_update()
        )
        rate_account = session.scalar(
            select(ReplayRateAccountRecord)
            .where(ReplayRateAccountRecord.rate_account_id == rate_account_id)
            .with_for_update()
        )
        if budget_account is None or rate_account is None:
            raise StateConflict("Replay reservation account disappeared during release")

        budget_reservations = list(
            session.scalars(
                select(ReplayBudgetReservationRecord)
                .where(
                    ReplayBudgetReservationRecord.budget_account_id
                    == budget_account.budget_account_id
                )
                .order_by(ReplayBudgetReservationRecord.budget_reservation_id)
                .with_for_update()
            ).all()
        )
        budget = next(
            (
                reservation
                for reservation in budget_reservations
                if reservation.budget_reservation_id == ticket.budget_reservation_id
            ),
            None,
        )
        rate_reservations = list(
            session.scalars(
                select(ReplayRateReservationRecord)
                .where(ReplayRateReservationRecord.rate_account_id == rate_account.rate_account_id)
                .order_by(ReplayRateReservationRecord.rate_reservation_id)
                .with_for_update()
            ).all()
        )
        rate = next(
            (
                reservation
                for reservation in rate_reservations
                if reservation.rate_reservation_id == ticket.rate_reservation_id
            ),
            None,
        )
        if budget is None or rate is None:
            raise StateConflict("Replay ticket reservation account changed before release")
        return LockedReplayCapacity(
            budget_account=budget_account,
            rate_account=rate_account,
            budget_reservation=budget,
            rate_reservation=rate,
            budget_reservations=budget_reservations,
            rate_reservations=rate_reservations,
        )

    def _require_releasable_replay_capacity(
        self,
        session: Session,
        ticket: ReplayTicketRecord,
        batch: ReplayBatchRecord,
        capacity: LockedReplayCapacity,
    ) -> None:
        require_exact_replay_budget_ledger(
            capacity.budget_account,
            capacity.budget_reservations,
        )
        if any(
            not replay_rate_reservation_lifecycle_exact(reservation)
            for reservation in capacity.rate_reservations
        ):
            raise StateConflict("durable Replay rate reservation ledger is inconsistent")
        require_exact_replay_account_permit_consumption(
            session,
            budget_reservations=capacity.budget_reservations,
            rate_reservations=capacity.rate_reservations,
        )
        budget = capacity.budget_reservation
        rate = capacity.rate_reservation
        budget_account = capacity.budget_account
        rate_account = capacity.rate_account
        if not (
            ticket.batch_id == batch.batch_id
            and ticket.source_root_digest == batch.source_root_digest
            and budget.budget_account_id == budget_account.budget_account_id
            and budget.batch_id == ticket.batch_id
            and budget.item_id == ticket.item_id
            and budget.attempt_number == ticket.attempt_number
            and budget.compilation_id == ticket.compilation_id
            and rate.rate_account_id == rate_account.rate_account_id
            and rate.batch_id == ticket.batch_id
            and rate.item_id == ticket.item_id
            and rate.attempt_number == ticket.attempt_number
            and rate.compilation_id == ticket.compilation_id
            and budget_account.source_run_id == batch.source_run_id
            and budget_account.source_root_digest == batch.source_root_digest
            and budget_account.campaign_name == batch.campaign_name
            and rate_account.source_run_id == batch.source_run_id
            and rate_account.source_root_digest == batch.source_root_digest
            and rate_account.campaign_name == batch.campaign_name
        ):
            raise StateConflict("Replay ticket reservation binding changed before release")

    @staticmethod
    def _release_replay_budget_capacity(
        capacity: LockedReplayCapacity,
        *,
        now: datetime,
    ) -> None:
        reservation = capacity.budget_reservation
        account = capacity.budget_account
        remaining = (
            reservation.total_calls - reservation.consumed_calls - reservation.released_calls
        )
        if remaining < 0 or account.reserved_calls < remaining:
            raise StateConflict("Replay budget reservation counters are inconsistent")
        if remaining:
            reservation.released_calls += remaining
            reservation.state = "released"
            reservation.released_at = now
            reservation.updated_at = now
            account.reserved_calls -= remaining
            account.released_calls += remaining
            account.cas_version += 1
            account.updated_at = now
        elif reservation.state == "active" and (
            reservation.consumed_calls == reservation.total_calls
        ):
            reservation.state = "consumed"
            reservation.updated_at = now

    @staticmethod
    def _release_replay_rate_capacity(
        capacity: LockedReplayCapacity,
        *,
        now: datetime,
    ) -> None:
        reservation = capacity.rate_reservation
        account = capacity.rate_account
        remaining = (
            reservation.total_request_units
            - reservation.consumed_request_units
            - reservation.released_request_units
        )
        if remaining < 0:
            raise StateConflict("Replay rate reservation counters are inconsistent")
        if remaining:
            reservation.released_request_units += remaining
            reservation.state = "released"
            reservation.released_at = now
            reservation.updated_at = now
            account.cas_version += 1
            account.updated_at = now
        elif reservation.state == "active" and (
            reservation.consumed_request_units == reservation.total_request_units
        ):
            reservation.state = "consumed"
            reservation.updated_at = now

    @staticmethod
    def refresh_terminal_replay_batch_state(
        batch: ReplayBatchRecord,
        items: list[ReplayItemRecord],
        *,
        now: datetime,
    ) -> str | None:
        """Resolve a terminal batch solely from its final item-state set.

        Cancellation has precedence over failure so the same terminal item set
        always produces the same aggregate regardless of transition order.
        """

        item_states = {item.state for item in items}
        if not item_states or any(
            state not in _TERMINAL_REPLAY_ITEM_STATES for state in item_states
        ):
            return None
        if ReplayItemState.CANCELLED.value in item_states:
            resolved = ReplayBatchState.CANCELLED.value
            if batch.cancellation_reason is None:
                batch.cancellation_reason = "one or more Replay items were cancelled"
                batch.cancelled_at = now
        elif ReplayItemState.FAILED.value in item_states:
            resolved = ReplayBatchState.FAILED.value
        else:
            resolved = ReplayBatchState.COMPLETED.value
        batch.state = resolved
        batch.updated_at = now
        return resolved

    def terminate_replay_attempt(
        self,
        session: Session,
        *,
        job: JobRecord,
        ticket: ReplayTicketRecord,
        item: ReplayItemRecord,
        batch: ReplayBatchRecord,
        run: RunRecord,
        actor: str,
        now: datetime,
        reason: str,
        retryable: bool,
        event_type: str,
    ) -> None:
        self.abandon_replay_ticket(ticket, now=now, reason=reason)
        self.release_replay_reservations(session, ticket, batch, now=now)
        job.state = JobState.FAILED.value
        job.error = reason[:2_000]
        job.result = None
        job.lease_owner = None
        job.lease_token_hash = None
        job.lease_expires_at = None
        job.lease_deadline_at = None
        job.heartbeat_at = None
        job.heartbeat_event_at = None
        job.updated_at = now
        issued_permit_count = int(
            session.scalar(
                select(func.count())
                .select_from(ReplayToolPermitRecord)
                .where(ReplayToolPermitRecord.ticket_id == ticket.ticket_id)
            )
            or 0
        )
        # Once a permit exists, the Control Plane cannot know whether the external
        # side effect happened before a crash or lost response. Automatic replay
        # would risk duplicating it, so the attempt fails closed and is never retried.
        retry_pending = retryable and issued_permit_count == 0 and item.attempts < item.max_attempts
        item.state = (
            ReplayItemState.RETRY_PENDING.value if retry_pending else ReplayItemState.FAILED.value
        )
        item.updated_at = now
        run.state = RunState.FAILED.value
        run.updated_at = now
        batch.updated_at = now
        batch.cas_version += 1
        batch_items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch.batch_id)
                .order_by(ReplayItemRecord.ordinal, ReplayItemRecord.item_id)
            ).all()
        )
        self.refresh_terminal_replay_batch_state(batch, batch_items, now=now)
        self._hooks.transaction.event_writer(
            session,
            run,
            "job.replay-attempt-abandoned",
            actor,
            {
                "jobId": job.job_id,
                "replayTicketId": ticket.ticket_id,
                "attempt": ticket.attempt_number,
                "fencingValue": ticket.fencing_value,
                "retryPending": retry_pending,
                "issuedPermitCount": issued_permit_count,
                "sideEffectsUncertain": issued_permit_count > 0,
                "reason": reason,
            },
        )
        self._hooks.transaction.replay_event_writer(
            session,
            batch,
            event_type,
            actor,
            {
                "reason": reason,
                "attempt": ticket.attempt_number,
                "fencingValue": ticket.fencing_value,
                "retryPending": retry_pending,
                "issuedPermitCount": issued_permit_count,
                "sideEffectsUncertain": issued_permit_count > 0,
            },
            item=item,
            ticket=ticket,
            job=job,
            run_id=run.run_id,
        )

    def _require_artifact_repository(self) -> ManagedArtifactRepository:
        if self._artifact_repository is None:
            raise StateConflict("managed Artifact repository is not configured")
        return self._artifact_repository

    @staticmethod
    def _require_artifact_snapshot(
        record: ArtifactRecord,
        ref: ArtifactRef,
        *,
        storage_key: str,
    ) -> None:
        if ControlPlaneViewMapper.artifact(record) != ref or record.storage_key != storage_key:
            raise StateConflict("managed Artifact metadata changed during verification")

    @staticmethod
    def _resolve_managed_artifact(
        repository: ManagedArtifactRepository,
        ref: ArtifactRef,
        *,
        expected_storage_key: str,
    ) -> ManagedArtifactSnapshot:
        try:
            snapshot = repository.resolve(ref)
        except ArtifactNotFound as exc:
            raise ResourceNotFound("managed source Artifact not found") from exc
        except ArtifactRepositoryError as exc:
            raise StateConflict("managed source Artifact failed reverification") from exc
        if snapshot.ref != ref or snapshot.storage_key != expected_storage_key:
            raise StateConflict("managed source Artifact resolution was substituted")
        return snapshot
