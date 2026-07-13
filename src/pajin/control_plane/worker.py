"""Lease-aware PAJIN Control Plane Worker daemon."""

from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, TypeVar

from pydantic import Field, ValidationError, model_validator

from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneLeaseLost,
    ControlPlaneTransientError,
)
from pajin.control_plane.executors import (
    ApprovalCheckpointExecution,
    CompletedExecution,
    ExecutionOutcome,
    ExecutorRegistry,
    PermanentExecutionError,
    TransientExecutionError,
)
from pajin.control_plane.models import (
    CheckpointCreationView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    FailJobRequest,
    JobView,
    LeaseRequest,
)
from pajin.domain.models import StrictModel

T = TypeVar("T")


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
    kinds: list[str] = Field(min_length=1, max_length=20)
    lease_seconds: int = Field(default=15, ge=5, le=300)
    heartbeat_seconds: float = Field(default=5, ge=0.05, le=120)
    long_poll_seconds: int = Field(default=10, ge=0, le=20)
    idle_delay_seconds: float = Field(default=0.2, ge=0.05, le=10)
    retry_base_seconds: float = Field(default=0.25, ge=0.05, le=10)
    retry_max_seconds: float = Field(default=5, ge=0.1, le=60)
    finalize_attempts: int = Field(default=3, ge=1, le=10)
    status_path: Path | None = None

    @model_validator(mode="after")
    def heartbeat_precedes_expiry(self) -> WorkerDaemonConfig:
        if self.heartbeat_seconds >= self.lease_seconds / 2:
            raise ValueError("heartbeat interval must be less than half the lease duration")
        if len(self.kinds) != len(set(self.kinds)):
            raise ValueError("Worker Job kinds must be unique")
        return self


class WorkerDaemonStatus(StrictModel):
    worker_id: str
    state: str
    active_job_id: str | None = None
    handled_jobs: int = 0
    last_contact_at: datetime
    last_error: str | None = None


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

    async def run_forever(self, stop: asyncio.Event) -> None:
        backoff = self._config.retry_base_seconds
        self._status("starting")
        while not stop.is_set():
            try:
                handled = await self.run_once()
                backoff = self._config.retry_base_seconds
                if not handled:
                    await self._wait_or_stop(stop, self._config.idle_delay_seconds)
            except ControlPlaneAuthenticationError:
                self._status("fatal", error="Control Plane authentication rejected")
                raise
            except ControlPlaneLeaseLost as exc:
                self._status("lease-lost", error=str(exc))
            except ControlPlaneTransientError as exc:
                self._status("degraded", error=str(exc))
                await self._wait_or_stop(stop, backoff)
                backoff = min(backoff * 2, self._config.retry_max_seconds)
        self._status("stopped")

    async def run_once(self) -> bool:
        claimed = await self._client.claim(
            ClaimJobRequest(
                worker_id=self._config.worker_id,
                kinds=self._config.kinds,
                lease_seconds=self._config.lease_seconds,
                wait_seconds=self._config.long_poll_seconds,
            )
        )
        self._status("idle" if claimed is None else "running", claimed=claimed)
        if claimed is None:
            return False
        await self._process_claim(claimed)
        self._handled_jobs += 1
        self._status("idle")
        return True

    async def _process_claim(self, claimed: ClaimedJob) -> None:
        heartbeat = asyncio.create_task(self._heartbeat_loop(claimed))
        try:
            execution = asyncio.create_task(self._execution_action(claimed))
            action = await self._await_with_heartbeat(execution, heartbeat)
            finalize = asyncio.create_task(self._finalize(claimed, action))
            await self._await_with_heartbeat(finalize, heartbeat)
        finally:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)

    async def _execution_action(self, claimed: ClaimedJob) -> ExecutionOutcome | FailJobRequest:
        try:
            return await self._executors.execute(claimed.job)
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
                error=f"permanent executor rejection: {type(exc).__name__}",
                retryable=False,
            )
        except TransientExecutionError as exc:
            return FailJobRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                error=f"transient executor failure: {type(exc).__name__}",
                retryable=True,
            )
        except Exception as exc:
            return FailJobRequest(
                worker_id=self._config.worker_id,
                lease_token=claimed.lease_token,
                error=f"unexpected executor failure: {type(exc).__name__}",
                retryable=True,
            )

    async def _finalize(
        self,
        claimed: ClaimedJob,
        action: ExecutionOutcome | FailJobRequest,
    ) -> None:
        async def operation() -> object:
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

        delay = self._config.retry_base_seconds
        for attempt in range(1, self._config.finalize_attempts + 1):
            try:
                await operation()
                return
            except ControlPlaneTransientError:
                if attempt == self._config.finalize_attempts:
                    raise
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._config.retry_max_seconds)

    async def _heartbeat_loop(self, claimed: ClaimedJob) -> None:
        while True:
            await asyncio.sleep(self._config.heartbeat_seconds)
            await self._client.heartbeat(
                claimed.job.job_id,
                LeaseRequest(
                    worker_id=self._config.worker_id,
                    lease_token=claimed.lease_token,
                    lease_seconds=self._config.lease_seconds,
                ),
            )
            self._status("running", claimed=claimed)

    @staticmethod
    async def _await_with_heartbeat(
        operation: asyncio.Task[T],
        heartbeat: asyncio.Task[None],
    ) -> T:
        done, _pending = await asyncio.wait(
            {operation, heartbeat}, return_when=asyncio.FIRST_COMPLETED
        )
        if heartbeat in done:
            operation.cancel()
            await asyncio.gather(operation, return_exceptions=True)
            exception = heartbeat.exception()
            if exception is None:
                raise ControlPlaneLeaseLost("heartbeat loop stopped unexpectedly")
            raise exception
        return operation.result()

    async def _wait_or_stop(self, stop: asyncio.Event, seconds: float) -> None:
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=seconds)

    def _status(
        self,
        state: str,
        *,
        claimed: ClaimedJob | None = None,
        error: str | None = None,
    ) -> None:
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
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(status.model_dump_json(), encoding="utf-8")
        os.replace(temporary, path)
