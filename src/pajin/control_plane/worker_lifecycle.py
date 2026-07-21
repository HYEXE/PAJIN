"""Shared, authority-neutral lifecycle primitives for leased daemons.

This module deliberately knows nothing about ordinary Job payloads or Replay
tickets.  It only owns the mechanics that must remain identical for every
leased daemon: bounded shutdown, heartbeat fencing, finalization
reconciliation, transient retry, and loop backoff.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Literal, Protocol, TypeVar

from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneLeaseLost,
    ControlPlaneLocalLeaseDeadlineExceeded,
    ControlPlaneProtocolError,
    ControlPlaneRunCancelled,
    ControlPlaneTransientError,
)
from pajin.control_plane.error_safety import (
    control_plane_cancellation_reason,
    control_plane_status_diagnostic,
)
from pajin.control_plane.lease_deadline import MonotonicLeaseDeadline
from pajin.domain.models import StrictModel
from pajin.runtime.control import (
    CancellationKind,
    ExecutionCancellationContext,
    ExecutionCancellationSnapshot,
)

T = TypeVar("T")
LifecycleState = Literal["starting", "fatal", "lease-lost", "degraded", "stopped"]


class LeaseDaemonFencedError(RuntimeError):
    """Raised when code attempts work after fatal daemon authority revocation."""


class LifecycleTiming(Protocol):
    """Configuration fields required by the authority-neutral lifecycle."""

    heartbeat_seconds: float
    lease_seconds: int
    idle_delay_seconds: float
    retry_base_seconds: float
    retry_max_seconds: float
    finalize_attempts: int
    cancellation_grace_seconds: float
    cancellation_force_seconds: float


@dataclass(frozen=True, slots=True)
class FinalizationMessages:
    """Daemon-specific diagnostics without daemon-specific authority logic."""

    operation: str
    heartbeat_stopped: str
    local_deadline: str


StatusCallback = Callable[[LifecycleState, str | None], None]
CancellationCallback = Callable[[ExecutionCancellationSnapshot], None]


def validate_lifecycle_timing(config: LifecycleTiming, *, owner: str) -> None:
    """Validate timing invariants shared by ordinary and Replay workers."""

    if config.heartbeat_seconds >= config.lease_seconds / 2:
        raise ValueError(f"{owner} heartbeat interval must be less than half the lease duration")
    if config.retry_base_seconds > config.retry_max_seconds:
        raise ValueError(f"{owner} retry base cannot exceed its maximum")
    if config.cancellation_grace_seconds >= config.cancellation_force_seconds:
        raise ValueError(f"{owner} cancellation grace must be shorter than the forced drain bound")


def encode_status(status: StrictModel) -> str:
    """Serialize a strict daemon status without NaN or presentation whitespace."""

    return json.dumps(
        status.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


class LeaseDaemonLifecycle:
    """Reusable concurrency mechanics for a single-claim leased daemon.

    Callers retain claim validation, heartbeat request construction, execution,
    and terminal-response validation.  The lifecycle only coordinates tasks and
    enforces bounded quiescence.
    """

    def __init__(
        self,
        *,
        timing: LifecycleTiming,
        owner: str,
        status: StatusCallback,
        record_cancellation: CancellationCallback,
        quiescence_error: type[RuntimeError],
    ) -> None:
        self._timing = timing
        self._owner = owner
        self._status = status
        self._record_cancellation = record_cancellation
        self._quiescence_error = quiescence_error
        self._fenced = False

    @property
    def fenced(self) -> bool:
        """Whether a fatal lifecycle failure permanently revoked this daemon."""

        return self._fenced

    def require_active(self) -> None:
        """Stop a cancellation-suppressing collaborator after authority revocation."""

        if self._fenced:
            raise LeaseDaemonFencedError(f"{self._owner} lifecycle has been fenced")

    def fence(self) -> None:
        """Permanently revoke this daemon after an unrecoverable failure."""

        self._fenced = True

    def _set_status(self, state: LifecycleState, error: str | None = None) -> None:
        if state == "fatal":
            self.fence()
        self._status(state, error)

    async def run_forever(
        self,
        stop: asyncio.Event,
        run_once: Callable[[], Awaitable[bool]],
        *,
        diagnostic_stage: str,
    ) -> None:
        """Run one claim at a time with shared transport backoff semantics."""

        backoff = self._timing.retry_base_seconds
        self._set_status("starting")
        while not stop.is_set():
            try:
                handled = await self.run_once_or_stop(stop, run_once)
                if handled is None:
                    break
                backoff = self._timing.retry_base_seconds
                if not handled:
                    await self.wait_or_stop(stop, self._timing.idle_delay_seconds)
            except ControlPlaneAuthenticationError:
                self._set_status("fatal", "Control Plane authentication rejected")
                raise
            except ControlPlaneProtocolError as exc:
                self._set_status(
                    "fatal",
                    control_plane_status_diagnostic(
                        exc,
                        stage=f"{diagnostic_stage}-protocol",
                    ),
                )
                raise
            except ControlPlaneLeaseLost as exc:
                self._set_status(
                    "lease-lost",
                    control_plane_status_diagnostic(
                        exc,
                        stage=f"{diagnostic_stage}-lease",
                    ),
                )
            except ControlPlaneTransientError as exc:
                self._set_status(
                    "degraded",
                    control_plane_status_diagnostic(
                        exc,
                        stage=f"{diagnostic_stage}-transport",
                    ),
                )
                await self.wait_or_stop(stop, backoff)
                backoff = min(backoff * 2, self._timing.retry_max_seconds)
        self._set_status("stopped")

    async def run_once_or_stop(
        self,
        stop: asyncio.Event,
        run_once: Callable[[], Awaitable[bool]],
    ) -> bool | None:
        """Race a claim cycle against shutdown and drain both sides boundedly."""

        async def invoke() -> bool:
            return await run_once()

        operation: asyncio.Task[bool] = asyncio.create_task(invoke())
        stop_wait = asyncio.create_task(stop.wait())
        try:
            done, _pending = await asyncio.wait(
                {operation, stop_wait},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if stop_wait in done:
                if not operation.done():
                    await self.cancel_and_drain(
                        operation,
                        operation=f"{self._owner} claim cycle",
                    )
                else:
                    result = (await asyncio.gather(operation, return_exceptions=True))[0]
                    if isinstance(result, BaseException) and not isinstance(
                        result,
                        asyncio.CancelledError,
                    ):
                        raise result
                return None
            stop_wait.cancel()
            await asyncio.gather(stop_wait, return_exceptions=True)
            return operation.result()
        except asyncio.CancelledError:
            stop_wait.cancel()
            # Retrieve the waiter asynchronously, but quiesce the claim cycle
            # first.  Awaiting the already-cancelled waiter here used to leave
            # ``operation`` attached if a second cancellation arrived in that
            # small window.
            stop_wait.add_done_callback(self._consume_task_result)
            if not operation.done():
                await self.cancel_and_drain(
                    operation,
                    operation=f"{self._owner} claim cycle",
                )
            else:
                self._consume_task_result(operation)
            raise

    async def finalize_with_retry(
        self,
        operation: Callable[[], Awaitable[T]],
    ) -> T:
        """Retry an idempotent finalization only for transient transport faults."""

        delay = self._timing.retry_base_seconds
        for attempt in range(1, self._timing.finalize_attempts + 1):
            try:
                return await operation()
            except ControlPlaneTransientError:
                if attempt == self._timing.finalize_attempts:
                    raise
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._timing.retry_max_seconds)
        raise AssertionError("bounded finalization retry loop did not return")

    async def await_with_heartbeat(
        self,
        operation: asyncio.Task[T],
        heartbeat: asyncio.Task[None],
        *,
        cancellation: ExecutionCancellationContext | None,
        finalization_operation: str,
        heartbeat_stopped: str,
    ) -> T:
        """Fence an operation immediately when its heartbeat authority ends."""

        done, _pending = await asyncio.wait(
            {operation, heartbeat},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if heartbeat in done:
            try:
                exception = heartbeat.exception()
            except asyncio.CancelledError:
                exception = None
            if exception is None:
                exception = ControlPlaneProtocolError(heartbeat_stopped)
            if cancellation is not None:
                cancellation.cancel(
                    self.cancellation_kind(exception),
                    control_plane_cancellation_reason(exception),
                )
                await self.stop_execution(
                    operation,
                    cancellation,
                    force_immediately=isinstance(
                        exception,
                        ControlPlaneLocalLeaseDeadlineExceeded,
                    ),
                )
            else:
                await self.cancel_and_drain(
                    operation,
                    operation=finalization_operation,
                )
            raise exception
        return operation.result()

    async def await_finalization_with_heartbeat(
        self,
        operation: asyncio.Task[T],
        heartbeat: asyncio.Task[None],
        *,
        lease_deadline: MonotonicLeaseDeadline,
        messages: FinalizationMessages,
    ) -> T:
        """Reconcile an idempotent finalization without crossing the local lease."""

        done, _pending = await asyncio.wait(
            {operation, heartbeat},
            return_when=asyncio.FIRST_COMPLETED,
        )
        heartbeat_error: BaseException | None = None
        if heartbeat in done:
            try:
                heartbeat_error = heartbeat.exception()
            except asyncio.CancelledError:
                heartbeat_error = None
        if isinstance(heartbeat_error, ControlPlaneLocalLeaseDeadlineExceeded):
            if operation not in done:
                await self.cancel_and_drain(
                    operation,
                    operation=f"{messages.operation} after local lease expiry",
                )
            raise heartbeat_error
        # A validated terminal response wins over a concurrent heartbeat that
        # merely observes the terminal state.  Local deadline expiry above wins
        # even when both tasks finish in the same scheduler turn.
        if operation in done:
            return operation.result()
        if heartbeat_error is None:
            heartbeat_error = ControlPlaneProtocolError(messages.heartbeat_stopped)

        reconciliation_seconds = min(
            self._timing.cancellation_force_seconds,
            max(0.0, lease_deadline.remaining()),
        )
        done, _pending = await asyncio.wait({operation}, timeout=reconciliation_seconds)
        if operation in done:
            return operation.result()
        if lease_deadline.remaining() <= 0:
            await self.cancel_and_drain(
                operation,
                operation=f"{messages.operation} at local lease deadline",
            )
            raise ControlPlaneLocalLeaseDeadlineExceeded(
                messages.local_deadline
            ) from heartbeat_error
        await self.cancel_and_drain(
            operation,
            operation=f"{messages.operation} reconciliation",
        )
        raise heartbeat_error

    async def stop_execution(
        self,
        operation: asyncio.Task[object],
        cancellation: ExecutionCancellationContext,
        *,
        force_immediately: bool = False,
    ) -> None:
        """Give a trusted executor a grace period, then enforce a hard bound."""

        done: set[asyncio.Task[object]] = set()
        interrupted = False
        if not force_immediately:
            done, _pending, wait_interrupted = await self._wait_owned_tasks(
                {operation},
                timeout=self._timing.cancellation_grace_seconds,
            )
            interrupted = interrupted or wait_interrupted
        if operation not in done and not operation.done():
            cancellation.mark_forced()
            operation.cancel()
            done, _pending, wait_interrupted = await self._wait_owned_tasks(
                {operation},
                timeout=self._timing.cancellation_force_seconds,
            )
            interrupted = interrupted or wait_interrupted
        if not operation.done():
            error = (
                f"trusted {self._owner} executor did not quiesce within its cancellation deadline"
            )
            cancellation.mark_incomplete(error)
            self._record_cancellation(cancellation.snapshot())
            self._set_status("fatal", error)
            raise self._quiescence_error(error)
        self._consume_task_result(operation)
        cancellation.mark_executor_drained()
        self._record_cancellation(cancellation.snapshot())
        if interrupted:
            raise asyncio.CancelledError

    async def cancel_and_drain(
        self,
        operation_task: asyncio.Task[object],
        *,
        operation: str,
    ) -> None:
        """Cancel an internal task and prove that it stopped within the hard bound."""

        operation_task.cancel()
        done, _pending, interrupted = await self._wait_owned_tasks(
            {operation_task},
            timeout=self._timing.cancellation_force_seconds,
        )
        if operation_task not in done:
            error = f"{operation} did not stop within its cancellation deadline"
            self._set_status("fatal", error)
            operation_task.add_done_callback(self._consume_task_result)
            raise self._quiescence_error(error)
        self._consume_task_result(operation_task)
        if interrupted:
            raise asyncio.CancelledError

    async def drain_claim_tasks(
        self,
        tasks: tuple[asyncio.Task[object] | None, ...],
    ) -> None:
        """Bound final cleanup, including a transport that suppresses cancellation."""

        present = {task for task in tasks if task is not None}
        if not present:
            return
        for task in present:
            if not task.done():
                task.cancel()
        done, pending, interrupted = await self._wait_owned_tasks(
            present,
            timeout=self._timing.cancellation_force_seconds,
        )
        for task in done:
            self._consume_task_result(task)
        if pending:
            error = f"{self._owner} claim tasks did not quiesce within the cleanup deadline"
            self._set_status("fatal", error)
            for task in pending:
                task.add_done_callback(self._consume_task_result)
            raise self._quiescence_error(error)
        if interrupted:
            raise asyncio.CancelledError

    @staticmethod
    async def _wait_owned_tasks(
        tasks: set[asyncio.Task[object]],
        *,
        timeout: float,
    ) -> tuple[set[asyncio.Task[object]], set[asyncio.Task[object]], bool]:
        """Keep a bounded cleanup wait alive across repeated caller cancellation."""

        waiter = asyncio.create_task(asyncio.wait(tasks, timeout=timeout))
        interrupted = False
        while not waiter.done():
            try:
                await asyncio.shield(waiter)
            except asyncio.CancelledError:
                # A second SIGTERM/task cancellation must not detach resources
                # whose quiescence this lifecycle owns.  Preserve cancellation
                # and re-raise it only after the bounded proof finishes.
                interrupted = True
        done, pending = waiter.result()
        return done, pending, interrupted

    @staticmethod
    def _consume_task_result(task: asyncio.Task[object]) -> None:
        """Retrieve a late fenced task result to avoid unhandled-task warnings."""

        with suppress(BaseException):
            task.result()

    @staticmethod
    def cancellation_kind(exception: BaseException) -> CancellationKind:
        if isinstance(exception, ControlPlaneRunCancelled):
            return CancellationKind.RUN_CANCELLED
        if isinstance(exception, ControlPlaneLeaseLost):
            return CancellationKind.LEASE_LOST
        return CancellationKind.HEARTBEAT_UNAVAILABLE

    @staticmethod
    async def wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=seconds)
