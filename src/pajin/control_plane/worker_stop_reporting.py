"""Bounded reporting of an already-observed cancellation; no execution authority."""

from __future__ import annotations

import asyncio
from typing import Literal, Protocol

from pajin.control_plane.stop_observations import (
    WorkerStopObservation,
    WorkerStopObservationRequest,
    WorkerStopReport,
)
from pajin.runtime.control import CancellationKind, ExecutionCancellationContext

StopReportingStatus = Literal["not-requested", "recorded", "failed"]


class WorkerStopReporter(Protocol):
    async def observe_worker_stop(
        self,
        job_id: str,
        request: WorkerStopObservationRequest,
        *,
        replay: bool = False,
    ) -> WorkerStopObservation: ...


async def publish_worker_stop(
    reporter: WorkerStopReporter | None,
    cancellation: ExecutionCancellationContext,
    *,
    job_id: str,
    worker_id: str,
    lease_token: str,
    replay: bool = False,
) -> StopReportingStatus:
    if reporter is None or not cancellation.active:
        return "not-requested"
    snapshot = cancellation.snapshot()
    if snapshot.kind is not CancellationKind.RUN_CANCELLED:
        return "not-requested"
    try:
        request = WorkerStopObservationRequest(
            workerId=worker_id,
            leaseToken=lease_token,
            report=WorkerStopReport.from_snapshot(snapshot),
        )
        async with asyncio.timeout(5):
            result = await reporter.observe_worker_stop(job_id, request, replay=replay)
        if (
            result.job_id != job_id
            or result.run_id != snapshot.control_plane_run_id
            or result.worker_id != worker_id
            or result.report != request.report
        ):
            return "failed"
        return "recorded"
    except Exception:
        # The caller retains its cancellation/quiescence error. The local status
        # explicitly records missing delivery without leaking transport credentials.
        return "failed"
