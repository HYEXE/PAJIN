"""Transactional Control Plane application service."""

from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import Select, and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, load_only

from pajin.control_plane.database import (
    ApprovalRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
    RunRecord,
    utc_now,
)
from pajin.control_plane.models import (
    ApprovalIntent,
    ApprovalState,
    ApprovalView,
    AuditEventView,
    CancelRunRequest,
    CancelRunView,
    CheckpointCreationView,
    CheckpointView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    DecideApprovalRequest,
    FailJobRequest,
    JobState,
    JobView,
    LeaseRequest,
    ResumeView,
    RunListView,
    RunState,
    RunSummaryView,
    RunView,
    SubmissionView,
    SubmitRunRequest,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.domain.models import ToolRiskTier


class ControlPlaneError(RuntimeError):
    """Base class for expected Control Plane errors."""


class ResourceNotFound(ControlPlaneError):
    pass


class StateConflict(ControlPlaneError):
    pass


class LeaseRejected(ControlPlaneError):
    pass


_CANCELLABLE_RUN_STATES = frozenset(
    {
        RunState.QUEUED.value,
        RunState.RUNNING.value,
        RunState.AWAITING_APPROVAL.value,
    }
)
_CANCELLABLE_JOB_STATES = frozenset({JobState.QUEUED.value, JobState.LEASED.value})
_REVOCABLE_APPROVAL_STATES = frozenset(
    {ApprovalState.PENDING.value, ApprovalState.APPROVED.value}
)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class ControlPlaneService:
    """Coordinate durable state transitions under database transactions."""

    def __init__(self, repository: ControlPlaneRepository, signer: CheckpointSigner) -> None:
        self.repository = repository
        self.signer = signer

    def submit_run(self, request: SubmitRunRequest, *, actor: str) -> SubmissionView:
        try:
            with self.repository.transaction() as session:
                existing = session.scalar(
                    select(RunRecord).where(RunRecord.submission_key == request.idempotency_key)
                )
                if existing is not None:
                    return self._existing_submission(session, existing)
                now = utc_now()
                run = RunRecord(
                    run_id=f"run_{uuid4().hex}",
                    campaign_name=request.campaign_name,
                    state=RunState.QUEUED.value,
                    input=request.input,
                    submission_key=request.idempotency_key,
                    current_checkpoint_id=None,
                    created_at=now,
                    updated_at=now,
                )
                job = JobRecord(
                    job_id=f"job_{uuid4().hex}",
                    run_id=run.run_id,
                    kind=request.job_kind.value,
                    state=JobState.QUEUED.value,
                    payload={"input": request.input},
                    priority=0,
                    attempts=0,
                    max_attempts=request.max_attempts,
                    idempotency_key=f"submission:{request.idempotency_key}",
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    heartbeat_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
                )
                session.add(run)
                session.flush()
                session.add(job)
                session.flush()
                self._event(
                    session,
                    run,
                    "run.submitted",
                    actor,
                    {
                        "campaignName": request.campaign_name,
                        "jobId": job.job_id,
                        "jobKind": request.job_kind.value,
                    },
                )
                return SubmissionView(
                    run=self._run_view(run), job=self._job_view(job), created=True
                )
        except IntegrityError:
            with self.repository.transaction() as session:
                existing = session.scalar(
                    select(RunRecord).where(RunRecord.submission_key == request.idempotency_key)
                )
                if existing is None:
                    raise
                return self._existing_submission(session, existing)

    def get_run(self, run_id: str) -> RunView:
        with self.repository.transaction() as session:
            return self._run_view(self._run(session, run_id))

    def list_runs(
        self,
        *,
        state: RunState | None,
        limit: int,
        offset: int,
    ) -> RunListView:
        with self.repository.transaction() as session:
            filters = () if state is None else (RunRecord.state == state.value,)
            total = session.scalar(select(func.count()).select_from(RunRecord).where(*filters))
            records = session.scalars(
                select(RunRecord)
                .options(
                    load_only(
                        RunRecord.run_id,
                        RunRecord.campaign_name,
                        RunRecord.state,
                        RunRecord.current_checkpoint_id,
                        RunRecord.created_at,
                        RunRecord.updated_at,
                    )
                )
                .where(*filters)
                .order_by(RunRecord.updated_at.desc(), RunRecord.run_id.desc())
                .offset(offset)
                .limit(limit)
            ).all()
            return RunListView(
                items=[self._run_summary_view(record) for record in records],
                total=int(total or 0),
                limit=limit,
                offset=offset,
            )

    def get_current_approval(self, run_id: str) -> ApprovalView | None:
        with self.repository.transaction() as session:
            row = session.execute(
                select(
                    RunRecord.state,
                    RunRecord.current_checkpoint_id,
                    CheckpointRecord,
                    ApprovalRecord,
                )
                .select_from(RunRecord)
                .outerjoin(
                    CheckpointRecord,
                    and_(
                        CheckpointRecord.checkpoint_id == RunRecord.current_checkpoint_id,
                        CheckpointRecord.run_id == RunRecord.run_id,
                    ),
                )
                .outerjoin(
                    ApprovalRecord,
                    and_(
                        ApprovalRecord.checkpoint_id == CheckpointRecord.checkpoint_id,
                        ApprovalRecord.run_id == RunRecord.run_id,
                    ),
                )
                .where(RunRecord.run_id == run_id)
            ).one_or_none()
            if row is None:
                raise ResourceNotFound("run not found")
            run_state, checkpoint_id, checkpoint, approval = row
            if checkpoint_id is None:
                if run_state == RunState.AWAITING_APPROVAL.value:
                    raise StateConflict("awaiting-approval Run has no current checkpoint")
                return None
            if run_state not in {
                RunState.AWAITING_APPROVAL.value,
                RunState.CANCELLED.value,
            }:
                raise StateConflict(f"run in {run_state} state cannot have a current checkpoint")
            if checkpoint is None or approval is None:
                raise StateConflict("current checkpoint ownership is inconsistent")
            self._verify_checkpoint(checkpoint)
            intent = self._checkpoint_intent(checkpoint)
            if not self._approval_matches_intent(approval, intent):
                raise StateConflict("approval fields do not match signed checkpoint intent")
            allowed_states = (
                {ApprovalState.PENDING.value, ApprovalState.APPROVED.value}
                if run_state == RunState.AWAITING_APPROVAL.value
                else {
                    ApprovalState.DENIED.value,
                    ApprovalState.EXPIRED.value,
                    ApprovalState.REVOKED.value,
                }
            )
            if approval.state not in allowed_states:
                raise StateConflict("approval state does not match the Run lifecycle")
            return self._approval_view(approval)

    def cancel_run(
        self,
        run_id: str,
        request: CancelRunRequest,
        *,
        actor: str,
    ) -> CancelRunView:
        with self.repository.transaction() as session:
            jobs_by_id = {
                job.job_id: job for job in self._lock_cancellable_jobs(session, run_id)
            }
            approvals = self._lock_revocable_approvals(session, run_id)
            # Resume locks its Approval before it inserts a continuation Job. Re-read Jobs after
            # acquiring Approval locks so a continuation created while cancellation was waiting
            # cannot escape the same transaction.
            jobs_by_id.update(
                {
                    job.job_id: job
                    for job in self._lock_cancellable_jobs(session, run_id)
                }
            )
            run = self._run(session, run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                return CancelRunView(
                    run=self._run_view(run),
                    applied=False,
                    cancelled_job_ids=[],
                    revoked_approval_ids=[],
                )
            if run.state not in _CANCELLABLE_RUN_STATES:
                raise StateConflict(f"run in {run.state} state cannot be cancelled")

            now = utc_now()
            cancelled_job_ids: list[str] = []
            for job in sorted(jobs_by_id.values(), key=lambda item: item.job_id):
                previous_lease_owner = job.lease_owner
                self._cancel_job(job, now=now)
                cancelled_job_ids.append(job.job_id)
                self._event(
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
                self._event(
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

            self._cancel_run_record(
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
                run=self._run_view(run),
                applied=True,
                cancelled_job_ids=cancelled_job_ids,
                revoked_approval_ids=revoked_approval_ids,
            )

    def get_job(self, job_id: str) -> JobView:
        with self.repository.transaction() as session:
            return self._job_view(self._job(session, job_id))

    def list_events(self, run_id: str) -> list[AuditEventView]:
        with self.repository.transaction() as session:
            self._run(session, run_id)
            records = session.scalars(
                select(EventRecord)
                .where(EventRecord.run_id == run_id)
                .order_by(EventRecord.sequence)
            ).all()
            return [self._event_view(record) for record in records]

    def claim_job(self, request: ClaimJobRequest, *, actor: str) -> ClaimedJob | None:
        sweep_time = utc_now()
        with self.repository.transaction() as session:
            self._expire_leases(session, now=sweep_time, actor=actor)
            statement: Select[tuple[JobRecord]] = (
                select(JobRecord)
                .where(
                    JobRecord.state == JobState.QUEUED.value,
                    JobRecord.available_at <= sweep_time,
                    JobRecord.kind.in_(request.kinds),
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
            run = self._run(session, job.run_id, lock=True)
            now = utc_now()
            if run.state == RunState.CANCELLED.value:
                self._cancel_job(job, now=now)
                self._event(
                    session,
                    run,
                    "job.cancelled",
                    actor,
                    {"jobId": job.job_id, "reason": "run was already cancelled"},
                )
                return None
            self._require_run_state(run, RunState.QUEUED)
            lease_token = secrets.token_urlsafe(32)
            job.state = JobState.LEASED.value
            job.lease_owner = request.worker_id
            job.lease_token_hash = token_digest(lease_token)
            job.lease_expires_at = now + timedelta(seconds=request.lease_seconds)
            job.heartbeat_at = now
            job.attempts += 1
            job.updated_at = now
            run.state = RunState.RUNNING.value
            run.updated_at = now
            self._event(
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
            return ClaimedJob(job=self._job_view(job), lease_token=lease_token)

    def heartbeat(self, job_id: str, request: LeaseRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            run = self._run(session, job.run_id, lock=True)
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=request.lease_seconds)
            job.updated_at = now
            self._event(
                session,
                run,
                "job.heartbeat",
                actor,
                {"jobId": job.job_id, "leaseExpiresAt": job.lease_expires_at.isoformat()},
            )
            return self._job_view(job)

    def complete_job(self, job_id: str, request: CompleteJobRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            run = self._run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                raise StateConflict("run has been cancelled")
            self._require_lease_identity(job, request.worker_id, request.lease_token)
            if job.state == JobState.SUCCEEDED.value:
                return self._job_view(job)
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            job.state = JobState.SUCCEEDED.value
            job.result = request.result
            job.error = None
            job.lease_expires_at = None
            job.updated_at = now
            run.state = RunState.COMPLETED.value
            run.updated_at = now
            self._event(session, run, "job.completed", actor, {"jobId": job.job_id})
            self._event(session, run, "run.completed", actor, {"jobId": job.job_id})
            return self._job_view(job)

    def fail_job(self, job_id: str, request: FailJobRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            run = self._run(session, job.run_id, lock=True)
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            job.error = request.error
            job.lease_owner = None
            job.lease_token_hash = None
            job.lease_expires_at = None
            job.heartbeat_at = None
            job.updated_at = now
            if request.retryable and job.attempts < job.max_attempts:
                job.state = JobState.QUEUED.value
                job.available_at = now
                run.state = RunState.QUEUED.value
                event_type = "job.requeued"
            else:
                job.state = (
                    JobState.DEAD_LETTER.value
                    if job.attempts >= job.max_attempts
                    else JobState.FAILED.value
                )
                run.state = RunState.FAILED.value
                event_type = "job.failed"
            run.updated_at = now
            self._event(
                session,
                run,
                event_type,
                actor,
                {"jobId": job.job_id, "error": request.error, "attempt": job.attempts},
            )
            return self._job_view(job)

    def create_checkpoint(
        self,
        job_id: str,
        request: CreateCheckpointRequest,
        *,
        actor: str,
    ) -> CheckpointCreationView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            run = self._run(session, job.run_id, lock=True)
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            if request.pending_intent.expires_at <= now:
                raise StateConflict("approval intent is already expired")
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            current_sequence = session.scalar(
                select(func.max(CheckpointRecord.sequence)).where(
                    CheckpointRecord.run_id == run.run_id
                )
            )
            sequence = int(current_sequence or 0) + 1
            checkpoint_id = f"checkpoint_{uuid4().hex}"
            payload = {
                "state": request.state,
                "pendingIntent": request.pending_intent.model_dump(mode="json"),
                "job": {"kind": job.kind, "maxAttempts": job.max_attempts},
            }
            signed = self.signer.sign(
                checkpoint_id=checkpoint_id,
                run_id=run.run_id,
                sequence=sequence,
                schema_version=1,
                payload=payload,
            )
            checkpoint = CheckpointRecord(
                checkpoint_id=checkpoint_id,
                run_id=run.run_id,
                sequence=sequence,
                schema_version=1,
                payload=payload,
                payload_sha256=signed.payload_sha256,
                signature=signed.signature,
                key_id=signed.key_id,
                created_at=now,
                claimed_at=None,
                claimed_by=None,
                continuation_job_id=None,
            )
            approval = ApprovalRecord(
                approval_id=f"approval_{uuid4().hex}",
                run_id=run.run_id,
                checkpoint_id=checkpoint_id,
                call_fingerprint=request.pending_intent.call_fingerprint,
                tool_id=request.pending_intent.tool_id,
                target=request.pending_intent.target,
                risk_tier=int(request.pending_intent.risk_tier),
                state=ApprovalState.PENDING.value,
                requested_by=actor,
                requested_at=now,
                expires_at=request.pending_intent.expires_at,
                decided_by=None,
                decided_at=None,
                decision_reason=None,
                consumed_by=None,
                consumed_at=None,
            )
            session.add(checkpoint)
            session.flush()
            session.add(approval)
            job.state = JobState.SUCCEEDED.value
            job.result = {"checkpointId": checkpoint_id, "awaitingApproval": True}
            job.lease_expires_at = None
            job.updated_at = now
            run.state = RunState.AWAITING_APPROVAL.value
            run.current_checkpoint_id = checkpoint_id
            run.updated_at = now
            self._event(
                session,
                run,
                "checkpoint.created",
                actor,
                {
                    "checkpointId": checkpoint_id,
                    "sequence": sequence,
                    "payloadSha256": signed.payload_sha256,
                },
            )
            self._event(
                session,
                run,
                "approval.requested",
                actor,
                {
                    "approvalId": approval.approval_id,
                    "checkpointId": checkpoint_id,
                    "riskTier": int(request.pending_intent.risk_tier),
                    "callFingerprint": request.pending_intent.call_fingerprint,
                },
            )
            return CheckpointCreationView(
                checkpoint=self._checkpoint_view(checkpoint),
                approval=self._approval_view(approval),
            )

    def decide_approval(
        self,
        approval_id: str,
        request: DecideApprovalRequest,
        *,
        actor: str,
    ) -> ApprovalView:
        expired = False
        view: ApprovalView | None = None
        with self.repository.transaction() as session:
            approval_reference = self._approval(session, approval_id)
            checkpoint = self._checkpoint(
                session, approval_reference.checkpoint_id, lock=True
            )
            approval = self._approval(session, approval_id, lock=True)
            if (
                approval.checkpoint_id != checkpoint.checkpoint_id
                or approval.run_id != checkpoint.run_id
            ):
                raise StateConflict("approval does not belong to its signed checkpoint")
            run = self._run(session, approval.run_id, lock=True)
            if approval.state != ApprovalState.PENDING.value:
                raise StateConflict("approval has already been decided")
            self._require_run_state(run, RunState.AWAITING_APPROVAL)
            self._require_current_checkpoint(run, approval.checkpoint_id)
            self._verify_checkpoint(checkpoint)
            intent = self._checkpoint_intent(checkpoint)
            if not self._approval_matches_intent(approval, intent):
                raise StateConflict("approval fields do not match signed checkpoint intent")
            if approval.requested_by == actor:
                raise StateConflict("approval requester cannot decide their own request")
            now = utc_now()
            if _aware(approval.expires_at) <= now:
                self._expire_approval(session, approval, run, actor=actor, now=now)
                expired = True
            else:
                approval.state = (
                    ApprovalState.APPROVED.value
                    if request.approve
                    else ApprovalState.DENIED.value
                )
                approval.decided_by = actor
                approval.decided_at = now
                approval.decision_reason = request.reason
                run.updated_at = now
                self._event(
                    session,
                    run,
                    "approval.approved" if request.approve else "approval.denied",
                    actor,
                    {
                        "approvalId": approval.approval_id,
                        "checkpointId": approval.checkpoint_id,
                        "reason": request.reason,
                    },
                )
                if not request.approve:
                    self._cancel_run_record(
                        session,
                        run,
                        actor=actor,
                        now=now,
                        reason=request.reason,
                        cause="approval-denied",
                        extra={"approvalId": approval.approval_id},
                    )
                view = self._approval_view(approval)
        if expired:
            raise StateConflict("approval request has expired")
        if view is None:
            raise RuntimeError("approval decision did not produce a view")
        return view

    def resume_checkpoint(
        self,
        checkpoint_id: str,
        approval_id: str,
        *,
        actor: str,
    ) -> ResumeView:
        expired = False
        result: ResumeView | None = None
        with self.repository.transaction() as session:
            checkpoint = self._checkpoint(session, checkpoint_id, lock=True)
            approval = self._approval(session, approval_id, lock=True)
            if (
                approval.checkpoint_id != checkpoint.checkpoint_id
                or approval.run_id != checkpoint.run_id
            ):
                raise StateConflict("approval does not authorize this checkpoint")
            run = self._run(session, checkpoint.run_id, lock=True)
            self._verify_checkpoint(checkpoint)
            self._require_run_state(run, RunState.AWAITING_APPROVAL)
            self._require_current_checkpoint(run, checkpoint.checkpoint_id)
            if checkpoint.claimed_at is not None:
                raise StateConflict("checkpoint has already been claimed")
            if approval.state != ApprovalState.APPROVED.value:
                raise StateConflict("checkpoint requires an active approved decision")
            now = utc_now()
            if _aware(approval.expires_at) <= now:
                self._expire_approval(session, approval, run, actor=actor, now=now)
                expired = True
            else:
                intent = self._checkpoint_intent(checkpoint)
                if not self._approval_matches_intent(approval, intent):
                    raise StateConflict("approval fields do not match signed checkpoint intent")
                raw_job_context = checkpoint.payload.get("job", {})
                job_context = raw_job_context if isinstance(raw_job_context, dict) else {}
                continuation_kind = str(job_context.get("kind", "campaign"))
                continuation_max_attempts = int(job_context.get("maxAttempts", 3))
                job = JobRecord(
                    job_id=f"job_{uuid4().hex}",
                    run_id=run.run_id,
                    kind=continuation_kind,
                    state=JobState.QUEUED.value,
                    payload={
                        "resumeFromCheckpointId": checkpoint.checkpoint_id,
                        "state": checkpoint.payload["state"],
                        "approvalId": approval.approval_id,
                        "approval": {
                            "callFingerprint": approval.call_fingerprint,
                            "toolId": approval.tool_id,
                            "target": approval.target,
                            "riskTier": approval.risk_tier,
                            "approvedBy": approval.decided_by,
                            "approvedAt": (
                                approval.decided_at.isoformat() if approval.decided_at else None
                            ),
                            "expiresAt": approval.expires_at.isoformat(),
                        },
                    },
                    priority=10,
                    attempts=0,
                    max_attempts=continuation_max_attempts,
                    idempotency_key=f"resume:{checkpoint.checkpoint_id}",
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    heartbeat_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
                )
                session.add(job)
                session.flush()
                checkpoint.claimed_at = now
                checkpoint.claimed_by = actor
                checkpoint.continuation_job_id = job.job_id
                approval.state = ApprovalState.CONSUMED.value
                approval.consumed_by = actor
                approval.consumed_at = now
                run.state = RunState.QUEUED.value
                run.current_checkpoint_id = None
                run.updated_at = now
                self._event(
                    session,
                    run,
                    "checkpoint.claimed",
                    actor,
                    {
                        "checkpointId": checkpoint.checkpoint_id,
                        "approvalId": approval.approval_id,
                        "continuationJobId": job.job_id,
                    },
                )
                result = ResumeView(
                    run=self._run_view(run),
                    job=self._job_view(job),
                    checkpoint=self._checkpoint_view(checkpoint),
                    approval=self._approval_view(approval),
                )
        if expired:
            raise StateConflict("approval has expired")
        if result is None:
            raise RuntimeError("checkpoint resume did not produce a result")
        return result

    def requeue_expired(self, *, actor: str) -> int:
        with self.repository.transaction() as session:
            return self._expire_leases(session, now=utc_now(), actor=actor)

    def _expire_leases(self, session: Session, *, now: datetime, actor: str) -> int:
        statement = select(JobRecord).where(
            JobRecord.state == JobState.LEASED.value,
            JobRecord.lease_expires_at <= now,
        )
        if self.repository.dialect_name == "postgresql":
            statement = statement.with_for_update(skip_locked=True)
        jobs = session.scalars(statement).all()
        requeued_or_dead_lettered = 0
        for job in jobs:
            run = self._run(session, job.run_id, lock=True)
            transition_time = utc_now()
            if run.state == RunState.CANCELLED.value:
                self._cancel_job(job, now=transition_time)
                self._event(
                    session,
                    run,
                    "job.cancelled",
                    actor,
                    {"jobId": job.job_id, "reason": "cancelled run lease was reaped"},
                )
                continue
            self._require_run_state(run, RunState.RUNNING)
            job.lease_owner = None
            job.lease_token_hash = None
            job.lease_expires_at = None
            job.heartbeat_at = None
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
            requeued_or_dead_lettered += 1
            self._event(
                session,
                run,
                event_type,
                actor,
                {"jobId": job.job_id, "attempt": job.attempts},
            )
        return requeued_or_dead_lettered

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

    def _lock_revocable_approvals(
        self, session: Session, run_id: str
    ) -> list[ApprovalRecord]:
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
        job.heartbeat_at = None
        job.updated_at = now

    def _cancel_run_record(
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
        self._event(
            session,
            run,
            "run.cancelled",
            actor,
            {"cause": cause, "reason": reason, **(extra or {})},
        )

    def _expire_approval(
        self,
        session: Session,
        approval: ApprovalRecord,
        run: RunRecord,
        *,
        actor: str,
        now: datetime,
    ) -> None:
        approval.state = ApprovalState.EXPIRED.value
        self._event(
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
        self._cancel_run_record(
            session,
            run,
            actor=actor,
            now=now,
            reason="approval expired before it could be consumed",
            cause="approval-expired",
            extra={"approvalId": approval.approval_id},
        )

    @staticmethod
    def _require_run_state(run: RunRecord, expected: RunState) -> None:
        if run.state == expected.value:
            return
        if run.state == RunState.CANCELLED.value:
            raise StateConflict("run has been cancelled")
        raise StateConflict(f"run must be {expected.value}, not {run.state}")

    @staticmethod
    def _require_current_checkpoint(run: RunRecord, checkpoint_id: str) -> None:
        if run.current_checkpoint_id != checkpoint_id:
            raise StateConflict("checkpoint is not the Run's current approval boundary")

    @staticmethod
    def _require_lease_identity(job: JobRecord, worker_id: str, token: str) -> None:
        if job.lease_owner != worker_id or job.lease_token_hash is None:
            raise LeaseRejected("job lease is not owned by this worker")
        if not hmac.compare_digest(job.lease_token_hash, token_digest(token)):
            raise LeaseRejected("job lease token is invalid")

    @classmethod
    def _require_active_lease(
        cls, job: JobRecord, worker_id: str, token: str, now: datetime
    ) -> None:
        cls._require_lease_identity(job, worker_id, token)
        if job.state != JobState.LEASED.value:
            raise LeaseRejected("job is not actively leased")
        if job.lease_expires_at is None or _aware(job.lease_expires_at) <= now:
            raise LeaseRejected("job lease has expired")

    def _verify_checkpoint(self, checkpoint: CheckpointRecord) -> None:
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
    def _checkpoint_intent(checkpoint: CheckpointRecord) -> ApprovalIntent:
        value = checkpoint.payload.get("pendingIntent")
        if not isinstance(value, dict):
            raise StateConflict("signed checkpoint does not contain an approval intent")
        return ApprovalIntent.model_validate(value)

    @staticmethod
    def _approval_matches_intent(approval: ApprovalRecord, intent: ApprovalIntent) -> bool:
        return (
            approval.call_fingerprint == intent.call_fingerprint
            and approval.tool_id == intent.tool_id
            and approval.target == intent.target
            and approval.risk_tier == int(intent.risk_tier)
            and _aware(approval.expires_at) == intent.expires_at
        )

    def _existing_submission(self, session: Session, run: RunRecord) -> SubmissionView:
        job = session.scalar(
            select(JobRecord).where(JobRecord.idempotency_key == f"submission:{run.submission_key}")
        )
        if job is None:
            raise StateConflict("idempotent run exists without its initial job")
        return SubmissionView(run=self._run_view(run), job=self._job_view(job), created=False)

    @staticmethod
    def _run(session: Session, run_id: str, *, lock: bool = False) -> RunRecord:
        statement = select(RunRecord).where(RunRecord.run_id == run_id)
        if lock:
            statement = statement.with_for_update()
        run = session.scalar(statement)
        if run is None:
            raise ResourceNotFound("run not found")
        return run

    @staticmethod
    def _job(session: Session, job_id: str, *, lock: bool = False) -> JobRecord:
        statement = select(JobRecord).where(JobRecord.job_id == job_id)
        if lock:
            statement = statement.with_for_update()
        job = session.scalar(statement)
        if job is None:
            raise ResourceNotFound("job not found")
        return job

    @staticmethod
    def _checkpoint(
        session: Session, checkpoint_id: str, *, lock: bool = False
    ) -> CheckpointRecord:
        statement = select(CheckpointRecord).where(CheckpointRecord.checkpoint_id == checkpoint_id)
        if lock:
            statement = statement.with_for_update()
        checkpoint = session.scalar(statement)
        if checkpoint is None:
            raise ResourceNotFound("checkpoint not found")
        return checkpoint

    @staticmethod
    def _approval(session: Session, approval_id: str, *, lock: bool = False) -> ApprovalRecord:
        statement = select(ApprovalRecord).where(ApprovalRecord.approval_id == approval_id)
        if lock:
            statement = statement.with_for_update()
        approval = session.scalar(statement)
        if approval is None:
            raise ResourceNotFound("approval not found")
        return approval

    def _event(
        self,
        session: Session,
        run: RunRecord,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> EventRecord:
        event = EventRecord(
            event_id=f"event_{uuid4().hex}",
            run_id=run.run_id,
            sequence=self.repository.next_event_sequence(session, run.run_id),
            event_type=event_type,
            actor=actor,
            payload=payload,
            occurred_at=utc_now(),
        )
        session.add(event)
        session.flush()
        return event

    @staticmethod
    def _run_view(record: RunRecord) -> RunView:
        return RunView(
            run_id=record.run_id,
            campaign_name=record.campaign_name,
            state=RunState(record.state),
            input=record.input,
            current_checkpoint_id=record.current_checkpoint_id,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _run_summary_view(record: RunRecord) -> RunSummaryView:
        return RunSummaryView(
            run_id=record.run_id,
            campaign_name=record.campaign_name,
            state=RunState(record.state),
            current_checkpoint_id=record.current_checkpoint_id,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _job_view(record: JobRecord) -> JobView:
        return JobView(
            job_id=record.job_id,
            run_id=record.run_id,
            kind=record.kind,
            state=JobState(record.state),
            payload=record.payload,
            priority=record.priority,
            attempts=record.attempts,
            max_attempts=record.max_attempts,
            available_at=_aware(record.available_at),
            lease_owner=record.lease_owner,
            lease_expires_at=(_aware(record.lease_expires_at) if record.lease_expires_at else None),
            heartbeat_at=_aware(record.heartbeat_at) if record.heartbeat_at else None,
            result=record.result,
            error=record.error,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _checkpoint_view(record: CheckpointRecord) -> CheckpointView:
        state = record.payload.get("state")
        return CheckpointView(
            checkpoint_id=record.checkpoint_id,
            run_id=record.run_id,
            sequence=record.sequence,
            schema_version=record.schema_version,
            state=state if isinstance(state, dict) else {},
            pending_intent=ControlPlaneService._checkpoint_intent(record),
            payload_sha256=record.payload_sha256,
            signature=record.signature,
            key_id=record.key_id,
            created_at=_aware(record.created_at),
            claimed_at=_aware(record.claimed_at) if record.claimed_at else None,
            claimed_by=record.claimed_by,
            continuation_job_id=record.continuation_job_id,
        )

    @staticmethod
    def _approval_view(record: ApprovalRecord) -> ApprovalView:
        return ApprovalView(
            approval_id=record.approval_id,
            run_id=record.run_id,
            checkpoint_id=record.checkpoint_id,
            intent=ApprovalIntent(
                call_fingerprint=record.call_fingerprint,
                tool_id=record.tool_id,
                target=record.target,
                risk_tier=ToolRiskTier(record.risk_tier),
                expires_at=_aware(record.expires_at),
            ),
            state=ApprovalState(record.state),
            requested_by=record.requested_by,
            requested_at=_aware(record.requested_at),
            decided_by=record.decided_by,
            decided_at=_aware(record.decided_at) if record.decided_at else None,
            decision_reason=record.decision_reason,
            consumed_by=record.consumed_by,
            consumed_at=_aware(record.consumed_at) if record.consumed_at else None,
        )

    @staticmethod
    def _event_view(record: EventRecord) -> AuditEventView:
        return AuditEventView(
            event_id=record.event_id,
            run_id=record.run_id,
            sequence=record.sequence,
            event_type=record.event_type,
            actor=record.actor,
            payload=record.payload,
            occurred_at=_aware(record.occurred_at),
        )
