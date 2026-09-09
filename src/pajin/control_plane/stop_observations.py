"""Lease-bound cancellation observations, separate from execution authority."""

from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from pajin.control_plane.claim_service import ControlPlaneClaimService
from pajin.control_plane.collaborator_hooks import ControlPlaneTransactionHooks
from pajin.control_plane.database import (
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
    RunRecord,
)
from pajin.control_plane.errors import AuthorizationDenied, StateConflict
from pajin.control_plane.models import (
    InternalJobKind,
    JobState,
    RunState,
    canonical_control_plane_json,
)
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.security import token_digest
from pajin.domain.models import StrictModel
from pajin.runtime.control import (
    CancellationCleanupStatus,
    CancellationKind,
    ExecutionCancellationSnapshot,
)

STOP_FENCE_EVENT = "job.stop-fenced"
STOP_OBSERVATION_EVENT = "worker.stop-observed"
_Identifier = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_Digest = Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")]
_EventId = Annotated[str, Field(strict=True, pattern=r"^event_[a-f0-9]{32}$")]


def _digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + canonical_control_plane_json(value)).hexdigest()


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class _StopModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid", populate_by_name=True, frozen=True, revalidate_instances="always"
    )


class JobStopFence(_StopModel):
    api_version: Literal["pajin.dev/job-stop-fence/v1"] = Field(
        default="pajin.dev/job-stop-fence/v1", alias="apiVersion"
    )
    run_id: _Identifier = Field(alias="runId")
    job_id: _Identifier = Field(alias="jobId")
    job_kind: _Identifier = Field(alias="jobKind")
    worker_id: _Identifier = Field(alias="workerId")
    lease_proof_commitment: _Digest = Field(alias="leaseProofCommitment")
    fence_digest: str = Field(default="", alias="fenceDigest")

    @model_validator(mode="after")
    def bind_digest(self) -> Self:
        digest = _digest(
            "pajin.job-stop-fence/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"fence_digest"}),
        )
        if self.fence_digest and self.fence_digest != digest:
            raise ValueError("Job stop fence digest differs")
        object.__setattr__(self, "fence_digest", digest)
        return self


def _lease_proof(*, job_id: str, run_id: str, worker_id: str, lease_hash: str) -> str:
    return _digest(
        "pajin.job-stop-lease-proof/v1",
        {
            "jobId": job_id,
            "runId": run_id,
            "workerId": worker_id,
            "leaseHash": lease_hash,
        },
    )


def record_job_stop_fence(
    session: Session,
    run: RunRecord,
    job: JobRecord,
    *,
    actor: str,
    hooks: ControlPlaneTransactionHooks,
) -> None:
    """Record a non-renewable proof before cancellation erases the active lease."""

    if job.state != JobState.LEASED.value or not job.lease_owner or not job.lease_token_hash:
        return
    if run.run_id != job.run_id:
        raise StateConflict("Job stop fence belongs to another Run")
    fence = JobStopFence(
        runId=run.run_id,
        jobId=job.job_id,
        jobKind=job.kind,
        workerId=job.lease_owner,
        leaseProofCommitment=_lease_proof(
            job_id=job.job_id,
            run_id=run.run_id,
            worker_id=job.lease_owner,
            lease_hash=job.lease_token_hash,
        ),
    )
    hooks.event_writer(
        session, run, STOP_FENCE_EVENT, actor, fence.model_dump(mode="json", by_alias=True)
    )


class WorkerStopReport(_StopModel):
    api_version: Literal["pajin.dev/worker-stop-report/v1"] = Field(
        default="pajin.dev/worker-stop-report/v1", alias="apiVersion"
    )
    kind: Literal[CancellationKind.RUN_CANCELLED]
    cleanup_status: CancellationCleanupStatus = Field(alias="cleanupStatus")
    observed_at: datetime = Field(alias="observedAt")
    forced_at: datetime | None = Field(default=None, alias="forcedAt")
    cleanup_completed_at: datetime | None = Field(default=None, alias="cleanupCompletedAt")
    executor_drained_at: datetime | None = Field(default=None, alias="executorDrainedAt")
    engine: _Identifier | None = None
    engine_run_id: _Identifier | None = Field(default=None, alias="engineRunId")
    resource_cleanup_verified: Literal[False] = Field(
        default=False, alias="resourceCleanupVerified"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    resume_authorized: Literal[False] = Field(default=False, alias="resumeAuthorized")

    @field_validator(
        "resource_cleanup_verified", "execution_authorized", "resume_authorized", mode="before"
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("a Worker stop report cannot grant authority or attest resources")
        return value

    @field_validator("observed_at", "forced_at", "cleanup_completed_at", "executor_drained_at")
    @classmethod
    def require_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("Worker stop timestamps must use UTC")
        return value

    @model_validator(mode="after")
    def require_consistent_report(self) -> Self:
        completed = self.cleanup_status in {
            CancellationCleanupStatus.CLEANUP_COMPLETED,
            CancellationCleanupStatus.QUIESCED,
        }
        if completed and self.cleanup_completed_at is None:
            raise ValueError("completed cleanup requires its observed timestamp")
        if (
            self.cleanup_status
            in {CancellationCleanupStatus.EXECUTOR_DRAINED, CancellationCleanupStatus.QUIESCED}
            and self.executor_drained_at is None
        ):
            raise ValueError("drained execution requires its observed timestamp")
        if (self.engine is None) != (self.engine_run_id is None):
            raise ValueError("Worker stop engine binding is partial")
        for value in (self.forced_at, self.cleanup_completed_at, self.executor_drained_at):
            if value is not None and value < self.observed_at:
                raise ValueError("Worker stop timestamps precede cancellation")
        return self

    @classmethod
    def from_snapshot(cls, snapshot: ExecutionCancellationSnapshot) -> WorkerStopReport:
        if snapshot.kind is not CancellationKind.RUN_CANCELLED:
            raise ValueError("Only Run cancellation has a Control Plane stop fence")
        return cls(
            kind=snapshot.kind,
            cleanupStatus=snapshot.cleanup_status,
            observedAt=snapshot.observed_at,
            forcedAt=snapshot.forced_at,
            cleanupCompletedAt=snapshot.cleanup_completed_at,
            executorDrainedAt=snapshot.executor_drained_at,
            engine=snapshot.engine,
            engineRunId=snapshot.engine_run_id,
        )


class WorkerStopObservationRequest(_StopModel):
    worker_id: _Identifier = Field(alias="workerId")
    lease_token: str = Field(alias="leaseToken", strict=True, min_length=32, max_length=300)
    report: WorkerStopReport


class WorkerStopObservation(_StopModel):
    api_version: Literal["pajin.dev/worker-stop-observation/v1"] = Field(
        default="pajin.dev/worker-stop-observation/v1", alias="apiVersion"
    )
    run_id: _Identifier = Field(alias="runId")
    job_id: _Identifier = Field(alias="jobId")
    worker_id: _Identifier = Field(alias="workerId")
    principal: _Identifier
    fence_event_id: _EventId = Field(alias="fenceEventId")
    fence_digest: _Digest = Field(alias="fenceDigest")
    report: WorkerStopReport
    observation_digest: str = Field(default="", alias="observationDigest")

    @model_validator(mode="after")
    def bind_digest(self) -> Self:
        digest = _digest(
            "pajin.worker-stop-observation/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"observation_digest"}),
        )
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("Worker stop observation digest differs")
        object.__setattr__(self, "observation_digest", digest)
        return self


def _job_events(session: Session, run_id: str, job_id: str, event_type: str) -> list[EventRecord]:
    return list(
        session.scalars(
            select(EventRecord)
            .where(
                EventRecord.run_id == run_id,
                EventRecord.event_type == event_type,
                EventRecord.payload["jobId"].as_string() == job_id,
            )
            .order_by(EventRecord.sequence)
            .limit(2)
        )
    )


def load_job_stop_fence(session: Session, job: JobRecord) -> tuple[EventRecord, JobStopFence]:
    rows = _job_events(session, job.run_id, job.job_id, STOP_FENCE_EVENT)
    if len(rows) != 1:
        raise StateConflict("Job has no unique cancellation fence")
    row = rows[0]
    try:
        fence = JobStopFence.model_validate(row.payload)
        if fence.model_dump(mode="json", by_alias=True) != row.payload:
            raise ValueError("Job stop fence is not canonical")
        if (fence.run_id, fence.job_id, fence.job_kind) != (job.run_id, job.job_id, job.kind):
            raise ValueError("Job stop fence identity differs")
    except (ValueError, TypeError) as exc:
        raise StateConflict("Stored Job stop fence is not integrity-valid") from exc
    return row, fence


def load_stop_observation(row: EventRecord) -> WorkerStopObservation:
    try:
        observation = WorkerStopObservation.model_validate(row.payload)
        if observation.model_dump(mode="json", by_alias=True) != row.payload:
            raise ValueError("Worker stop observation is not canonical")
        if row.run_id != observation.run_id or row.actor != observation.principal:
            raise ValueError("Worker stop event identity differs")
        return observation
    except (ValueError, TypeError) as exc:
        raise StateConflict("Stored Worker stop observation is not integrity-valid") from exc


class StopObservationService:
    def __init__(
        self, repository: ControlPlaneRepository, hooks: ControlPlaneTransactionHooks
    ) -> None:
        self._repository = repository
        self._hooks = hooks

    def record(
        self,
        job_id: str,
        request: WorkerStopObservationRequest,
        *,
        actor: str,
        replay: bool = False,
    ) -> WorkerStopObservation:
        request = WorkerStopObservationRequest.model_validate(request.model_dump(mode="python"))
        with self._repository.transaction() as session:
            job = ControlPlaneRecords.job(session, job_id, lock=True)
            run = ControlPlaneRecords.run(session, job.run_id, lock=True)
            if (job.kind == InternalJobKind.REPLAY.value) != replay:
                raise AuthorizationDenied("Worker route does not own this Job kind")
            if job.state != JobState.CANCELLED.value or run.state != RunState.CANCELLED.value:
                raise StateConflict("Worker stop observations require a cancelled Run and Job")
            fence_row, fence = load_job_stop_fence(session, job)
            self._authorize(fence, request, actor=actor, replay=replay)
            proposed = WorkerStopObservation(
                runId=job.run_id,
                jobId=job.job_id,
                workerId=request.worker_id,
                principal=actor,
                fenceEventId=fence_row.event_id,
                fenceDigest=fence.fence_digest,
                report=request.report,
            )
            previous = _job_events(session, job.run_id, job.job_id, STOP_OBSERVATION_EVENT)
            if previous:
                if len(previous) != 1 or load_stop_observation(previous[0]) != proposed:
                    raise StateConflict("Worker stop observation contradicts the recorded report")
                return proposed
            now = self._hooks.clock()
            times = (
                request.report.observed_at,
                request.report.forced_at,
                request.report.cleanup_completed_at,
                request.report.executor_drained_at,
            )
            if any(value is not None and value > now + timedelta(seconds=30) for value in times):
                raise StateConflict("Worker stop report is ahead of the trusted clock")
            if request.report.observed_at < _aware(fence_row.occurred_at) - timedelta(seconds=30):
                raise StateConflict("Worker stop report predates its cancellation fence")
            self._hooks.event_writer(
                session,
                run,
                STOP_OBSERVATION_EVENT,
                actor,
                proposed.model_dump(mode="json", by_alias=True),
            )
            return proposed

    @staticmethod
    def _authorize(
        fence: JobStopFence,
        request: WorkerStopObservationRequest,
        *,
        actor: str,
        replay: bool,
    ) -> None:
        if request.worker_id != fence.worker_id or (replay and actor != fence.worker_id):
            raise AuthorizationDenied("Worker does not own the cancelled lease")
        hashes: tuple[str, ...] = (token_digest(request.lease_token),)
        if not replay:
            hashes += (
                ControlPlaneClaimService._generic_lease_token_digest(actor, request.lease_token),
            )
        if not any(
            hmac.compare_digest(
                fence.lease_proof_commitment,
                _lease_proof(
                    job_id=fence.job_id,
                    run_id=fence.run_id,
                    worker_id=fence.worker_id,
                    lease_hash=value,
                ),
            )
            for value in hashes
        ):
            raise AuthorizationDenied("Worker stop lease proof is invalid")
