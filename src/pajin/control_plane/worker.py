"""Lease-aware PAJIN Control Plane Worker daemon."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, ValidationError, model_validator

from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneLeaseLost,
    ControlPlaneLocalLeaseDeadlineExceeded,
    ControlPlaneProtocolError,
    ControlPlaneTransientError,
)
from pajin.control_plane.error_safety import (
    control_plane_cancellation_reason,
    control_plane_status_diagnostic,
)
from pajin.control_plane.executors import (
    ApprovalCheckpointExecution,
    CompletedExecution,
    ExecutionOutcome,
    ExecutorRegistry,
    PermanentExecutionError,
    TransientExecutionError,
)
from pajin.control_plane.lease_deadline import MonotonicLeaseDeadline
from pajin.control_plane.models import (
    ApprovalState,
    CheckpointCreationView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    FailJobRequest,
    JobKind,
    JobState,
    JobView,
    LeaseRequest,
)
from pajin.control_plane.status_file import write_status_file
from pajin.control_plane.worker_lifecycle import (
    FinalizationMessages,
    LeaseDaemonLifecycle,
    encode_status,
    validate_lifecycle_timing,
)
from pajin.domain.models import StrictModel
from pajin.runtime.control import (
    CancellationKind,
    ExecutionCancellationContext,
    ExecutionCancellationSnapshot,
)
from pajin.runtime.error_safety import audit_safe_exception_type

WorkerDaemonState = Literal[
    "starting",
    "idle",
    "running",
    "fatal",
    "lease-lost",
    "degraded",
    "stopped",
    "cancelled",
]


class WorkerQuiescenceError(RuntimeError):
    """Raised when a trusted operation does not stop within its bounded cleanup window."""


class WorkerControlPlanePort(Protocol):
    async def claim(self, request: ClaimJobRequest) -> ClaimedJob | None: ...

    async def heartbeat(self, job_id: str, request: LeaseRequest) -> JobView: ...

    async def complete(self, job_id: str, request: CompleteJobRequest) -> JobView: ...

    async def fail(self, job_id: str, request: FailJobRequest) -> JobView: ...

    async def checkpoint(
        self, job_id: str, request: CreateCheckpointRequest
    ) -> CheckpointCreationView: ...


class WorkerDaemonConfig(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    kinds: list[JobKind] = Field(min_length=1, max_length=20)
    lease_seconds: int = Field(default=15, ge=5, le=300)
    heartbeat_seconds: float = Field(default=5, ge=0.05, le=120)
    long_poll_seconds: int = Field(default=10, ge=0, le=20)
    idle_delay_seconds: float = Field(default=0.2, ge=0.05, le=10)
    retry_base_seconds: float = Field(default=0.25, ge=0.05, le=10)
    retry_max_seconds: float = Field(default=5, ge=0.1, le=60)
    finalize_attempts: int = Field(default=3, ge=1, le=10)
    cancellation_grace_seconds: float = Field(default=2, ge=0.05, le=30)
    cancellation_force_seconds: float = Field(default=5, ge=0.05, le=30)
    status_path: Path | None = None

    @model_validator(mode="after")
    def heartbeat_precedes_expiry(self) -> WorkerDaemonConfig:
        validate_lifecycle_timing(self, owner="Worker")
        if len(self.kinds) != len(set(self.kinds)):
            raise ValueError("Worker Job kinds must be unique")
        return self


class WorkerDaemonStatus(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    state: WorkerDaemonState
    active_job_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    handled_jobs: int = Field(default=0, ge=0)
    last_contact_at: datetime
    last_error: str | None = Field(default=None, max_length=500)
    last_cancellation: ExecutionCancellationSnapshot | None = None


class WorkerDaemon:
    """Claim one Job at a time and retain its lease through durable finalization."""

    def __init__(
        self,
        *,
        client: WorkerControlPlanePort,
        executors: ExecutorRegistry,
        config: WorkerDaemonConfig,
    ) -> None:
        unsupported = set(config.kinds) - set(executors.kinds)
        if unsupported:
            raise ValueError(
                f"Worker configured with unregistered Job kinds: {sorted(unsupported)}"
            )
        self._client = client
        self._executors = executors
        self._config = config
        self._handled_jobs = 0
        self._last_cancellation: ExecutionCancellationSnapshot | None = None
        self._lifecycle = LeaseDaemonLifecycle(
            timing=config,
            owner="Worker",
            status=lambda state, error: self._status(state, error=error),
            record_cancellation=self._record_cancellation,
            quiescence_error=WorkerQuiescenceError,
        )

    async def run_forever(self, stop: asyncio.Event) -> None:
        await self._lifecycle.run_forever(
            stop,
            self.run_once,
            diagnostic_stage="worker-control-plane",
        )

    async def run_once(self) -> bool:
        self._lifecycle.require_active()
        claimed = await self._client.claim(
            ClaimJobRequest(
                worker_id=self._config.worker_id,
                kinds=self._config.kinds,
                lease_seconds=self._config.lease_seconds,
                wait_seconds=self._config.long_poll_seconds,
            )
        )
        claim_received_at = asyncio.get_running_loop().time()
        self._lifecycle.require_active()
        if claimed is not None:
            # The transport is an injected boundary and may retain the object it
            # returned.  Take daemon ownership before yielding again so later
            # transport-side mutation cannot retarget execution or finalization.
            claimed = claimed.model_copy(deep=True)
        self._status("idle" if claimed is None else "running", claimed=claimed)
        if claimed is None:
            return False
        try:
            lease_deadline = MonotonicLeaseDeadline.from_server_timestamps(
                lease_expires_at=claimed.job.lease_expires_at,
                lease_reference_at=claimed.job.heartbeat_at,
                requested_lease_seconds=self._config.lease_seconds,
                observed_at=claim_received_at,
            )
            await self._process_claim(claimed, lease_deadline=lease_deadline)
        except ControlPlaneAuthenticationError:
            self._status(
                "fatal",
                error="Control Plane authentication rejected",
            )
            raise
        except ControlPlaneProtocolError as exc:
            self._status(
                "fatal",
                error=control_plane_status_diagnostic(
                    exc,
                    stage="worker-control-plane-protocol",
                ),
            )
            raise
        except ControlPlaneLeaseLost as exc:
            self._status(
                "lease-lost",
                error=control_plane_status_diagnostic(
                    exc,
                    stage="worker-control-plane-lease",
                ),
            )
            raise
        except ControlPlaneTransientError as exc:
            self._status(
                "degraded",
                error=control_plane_status_diagnostic(
                    exc,
                    stage="worker-control-plane-transport",
                ),
            )
            raise
        self._handled_jobs += 1
        self._status("idle")
        return True

    async def _process_claim(
        self,
        claimed: ClaimedJob,
        *,
        lease_deadline: MonotonicLeaseDeadline,
    ) -> None:
        lease_deadline.require_active()
        cancellation = ExecutionCancellationContext(
            job_id=claimed.job.job_id,
            control_plane_run_id=claimed.job.run_id,
        )
        heartbeat = asyncio.create_task(
            self._heartbeat_loop(claimed, lease_deadline=lease_deadline)
        )
        execution: asyncio.Task[ExecutionOutcome | FailJobRequest] | None = None
        finalize: asyncio.Task[None] | None = None
        try:
            execution = asyncio.create_task(
                self._execution_action(claimed, cancellation=cancellation)
            )
            action = await self._lifecycle.await_with_heartbeat(
                execution,
                heartbeat,
                cancellation=cancellation,
                finalization_operation="Job finalization",
                heartbeat_stopped="heartbeat loop stopped unexpectedly",
            )
            lease_deadline.require_active()
            finalize = asyncio.create_task(self._finalize(claimed, action))
            await self._lifecycle.await_finalization_with_heartbeat(
                finalize,
                heartbeat,
                lease_deadline=lease_deadline,
                messages=FinalizationMessages(
                    operation="Job finalization",
                    heartbeat_stopped=(
                        "heartbeat loop stopped unexpectedly during Job finalization"
                    ),
                    local_deadline=(
                        "local lease deadline elapsed during Job finalization reconciliation"
                    ),
                ),
            )
            lease_deadline.require_active()
        except ControlPlaneLeaseLost as exc:
            cancellation.cancel(
                self._lifecycle.cancellation_kind(exc),
                control_plane_cancellation_reason(exc),
            )
            if cancellation.active and (execution is None or execution.done()):
                cancellation.mark_executor_drained()
                self._last_cancellation = cancellation.snapshot()
            raise
        except asyncio.CancelledError:
            cancellation.cancel(
                CancellationKind.DAEMON_SHUTDOWN,
                "Worker daemon execution was cancelled",
            )
            if execution is not None and not execution.done():
                await self._lifecycle.stop_execution(execution, cancellation)
            else:
                if finalize is not None and not finalize.done():
                    await self._lifecycle.cancel_and_drain(
                        finalize,
                        operation="Job finalization",
                    )
                cancellation.mark_executor_drained()
                self._last_cancellation = cancellation.snapshot()
            self._status("cancelled", error=cancellation.snapshot().reason)
            raise
        finally:
            await self._lifecycle.drain_claim_tasks((execution, finalize, heartbeat))

    async def _execution_action(
        self,
        claimed: ClaimedJob,
        *,
        cancellation: ExecutionCancellationContext,
    ) -> ExecutionOutcome | FailJobRequest:
        try:
            outcome = await self._executors.execute(
                claimed.job,
                cancellation=cancellation,
            )
            return self._validated_owned_execution_outcome(claimed, outcome)
        except ValidationError:
            return FailJobRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                error="permanent executor rejection: payload validation failed",
                retryable=False,
            )
        except (PermanentExecutionError, ValueError) as exc:
            return FailJobRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                error=f"permanent executor rejection: {audit_safe_exception_type(exc)}",
                retryable=False,
            )
        except TransientExecutionError as exc:
            return FailJobRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                error=f"transient executor failure: {audit_safe_exception_type(exc)}",
                retryable=True,
            )
        except Exception as exc:
            return FailJobRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                error=f"unexpected executor failure: {audit_safe_exception_type(exc)}",
                retryable=True,
            )

    def _validated_owned_execution_outcome(
        self,
        claimed: ClaimedJob,
        outcome: object,
    ) -> ExecutionOutcome:
        if isinstance(outcome, CompletedExecution):
            CompleteJobRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                result=outcome.result,
            )
        elif isinstance(outcome, ApprovalCheckpointExecution):
            CreateCheckpointRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                state=outcome.state,
                pending_intent=outcome.pending_intent,
            )
        else:
            raise PermanentExecutionError("trusted executor returned an unsupported outcome type")
        # Adapters are injected collaborators and can retain the model they
        # return. Validation and this deep copy run without yielding, so a
        # scheduled adapter-side mutation cannot alter durable finalization.
        return outcome.model_copy(deep=True)

    async def _finalize(
        self,
        claimed: ClaimedJob,
        action: ExecutionOutcome | FailJobRequest,
    ) -> None:
        async def operation() -> JobView | CheckpointCreationView:
            if isinstance(action, CompletedExecution):
                return await self._client.complete(
                    claimed.job.job_id,
                    CompleteJobRequest(
                        worker_id=self._config.worker_id,
                        lease_token=claimed.lease_token,
                        result=action.result,
                    ),
                )
            if isinstance(action, ApprovalCheckpointExecution):
                return await self._client.checkpoint(
                    claimed.job.job_id,
                    CreateCheckpointRequest(
                        worker_id=self._config.worker_id,
                        lease_token=claimed.lease_token,
                        state=action.state,
                        pending_intent=action.pending_intent,
                    ),
                )
            return await self._client.fail(claimed.job.job_id, action)

        async def validated_operation() -> JobView | CheckpointCreationView:
            response = await operation()
            self._validate_finalization_response(claimed, action, response)
            return response

        await self._lifecycle.finalize_with_retry(validated_operation)

    @classmethod
    def _validate_finalization_response(
        cls,
        claimed: ClaimedJob,
        action: ExecutionOutcome | FailJobRequest,
        response: JobView | CheckpointCreationView,
    ) -> None:
        if isinstance(action, ApprovalCheckpointExecution):
            if not isinstance(response, CheckpointCreationView):
                raise ControlPlaneProtocolError(
                    "Worker checkpoint finalization returned the wrong response type"
                )
            cls._validate_checkpoint_finalization(claimed, action, response)
            return
        if not isinstance(response, JobView):
            raise ControlPlaneProtocolError(
                "Worker Job finalization returned the wrong response type"
            )
        cls._validate_job_finalization(claimed, action, response)

    @staticmethod
    def _validate_job_finalization(
        claimed: ClaimedJob,
        action: CompletedExecution | FailJobRequest,
        response: JobView,
    ) -> None:
        original = claimed.job
        immutable_fields = (
            "job_id",
            "run_id",
            "kind",
            "payload",
            "priority",
            "attempts",
            "max_attempts",
            "created_at",
        )
        if any(
            getattr(response, field_name) != getattr(original, field_name)
            for field_name in immutable_fields
        ):
            raise ControlPlaneProtocolError(
                "Worker finalization response changed immutable Job authority"
            )
        if isinstance(action, CompletedExecution):
            valid_terminal_state = (
                response.state is JobState.SUCCEEDED
                and response.result == action.result
                and response.error is None
                and response.lease_expires_at is None
            )
        else:
            if action.retryable and original.attempts < original.max_attempts:
                expected_state = JobState.QUEUED
            elif original.attempts >= original.max_attempts:
                expected_state = JobState.DEAD_LETTER
            else:
                expected_state = JobState.FAILED
            valid_terminal_state = (
                response.state is expected_state
                and response.result == original.result
                and response.error == action.error
                and response.lease_owner is None
                and response.lease_expires_at is None
                and response.heartbeat_at is None
            )
        if not valid_terminal_state:
            raise ControlPlaneProtocolError(
                "Worker finalization response does not attest the requested outcome"
            )

    @staticmethod
    def _validate_checkpoint_finalization(
        claimed: ClaimedJob,
        action: ApprovalCheckpointExecution,
        response: CheckpointCreationView,
    ) -> None:
        checkpoint = response.checkpoint
        approval = response.approval
        if not (
            checkpoint.run_id == claimed.job.run_id
            and checkpoint.state == action.state
            and checkpoint.pending_intent == action.pending_intent
            and checkpoint.sequence >= 1
            and checkpoint.schema_version == 1
            and checkpoint.claimed_at is None
            and checkpoint.claimed_by is None
            and checkpoint.continuation_job_id is None
            and approval.run_id == claimed.job.run_id
            and approval.checkpoint_id == checkpoint.checkpoint_id
            and approval.intent == action.pending_intent
            and approval.state is ApprovalState.PENDING
            and approval.decided_by is None
            and approval.decided_at is None
            and approval.consumed_by is None
            and approval.consumed_at is None
        ):
            raise ControlPlaneProtocolError(
                "Worker checkpoint response differs from the claimed authority"
            )

    async def _heartbeat_loop(
        self,
        claimed: ClaimedJob,
        *,
        lease_deadline: MonotonicLeaseDeadline,
    ) -> None:
        current = claimed.job
        while True:
            self._lifecycle.require_active()
            request_started_at = asyncio.get_running_loop().time()
            lease_deadline.require_active()
            try:
                async with asyncio.timeout_at(lease_deadline.expires_at):
                    refreshed = await self._client.heartbeat(
                        claimed.job.job_id,
                        LeaseRequest(
                            worker_id=self._config.worker_id,
                            lease_token=claimed.lease_token,
                            lease_seconds=self._config.lease_seconds,
                        ),
                    )
                self._lifecycle.require_active()
            except TimeoutError as exc:
                if lease_deadline.remaining() <= 0:
                    raise ControlPlaneLocalLeaseDeadlineExceeded(
                        "local lease deadline elapsed while heartbeat was unavailable"
                    ) from exc
                raise
            self._validate_heartbeat_job(current, refreshed)
            lease_deadline.renew_from_server_timestamps(
                lease_expires_at=refreshed.lease_expires_at,
                lease_reference_at=refreshed.heartbeat_at,
                requested_lease_seconds=self._config.lease_seconds,
                request_started_at=request_started_at,
            )
            current = refreshed
            self._status("running", claimed=claimed)
            await lease_deadline.wait_for_renewal_interval(self._config.heartbeat_seconds)

    @staticmethod
    def _validate_heartbeat_job(previous: JobView, refreshed: JobView) -> None:
        expected = previous.model_copy(
            update={
                "lease_expires_at": refreshed.lease_expires_at,
                "heartbeat_at": refreshed.heartbeat_at,
                "updated_at": refreshed.updated_at,
            }
        )
        if refreshed != expected or refreshed.state is not JobState.LEASED:
            raise ControlPlaneProtocolError(
                "Worker heartbeat response changed immutable Job authority"
            )

    def _record_cancellation(self, snapshot: ExecutionCancellationSnapshot) -> None:
        self._last_cancellation = snapshot

    def _status(
        self,
        state: WorkerDaemonState,
        *,
        claimed: ClaimedJob | None = None,
        error: str | None = None,
    ) -> None:
        lifecycle = getattr(self, "_lifecycle", None)
        if lifecycle is not None:
            if state == "fatal":
                lifecycle.fence()
            elif lifecycle.fenced:
                return
        path = self._config.status_path
        if path is None:
            return
        status = WorkerDaemonStatus(
            worker_id=self._config.worker_id,
            state=state,
            active_job_id=claimed.job.job_id if claimed else None,
            handled_jobs=self._handled_jobs,
            last_contact_at=datetime.now(UTC),
            last_error=error[:500] if error else None,
            last_cancellation=self._last_cancellation,
        )
        payload = encode_status(status)
        self._write_status(path, payload)

    @staticmethod
    def _write_status(path: Path, payload: str) -> None:
        write_status_file(path, payload, owner_label="Worker")
