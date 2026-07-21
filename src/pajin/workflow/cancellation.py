"""Tamper-evident local receipts for cooperative execution cancellation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable

from pydantic import Field

from pajin.domain.models import StrictModel
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    CancellationKind,
    ExecutionCancellationContext,
    ExecutionCancellationSnapshot,
)
from pajin.runtime.store import RunStore


class LocalCancellationReceipt(StrictModel):
    """Evidence bounded to resources owned by the current PAJIN process."""

    api_version: str = Field(
        default="pajin.dev/local-cancellation-receipt/v1",
        alias="apiVersion",
    )
    cancellation: ExecutionCancellationSnapshot
    quiescence_scope: str = Field(default="owned-async-stack", alias="quiescenceScope")
    resource_cleanup_attested: bool = Field(
        default=False,
        alias="resourceCleanupAttested",
    )
    external_side_effects_reverted: bool = Field(
        default=False,
        alias="externalSideEffectsReverted",
    )
    control_plane_attested: bool = Field(default=False, alias="controlPlaneAttested")


async def await_with_cancellation[T](
    operation: Awaitable[T],
    cancellation: ExecutionCancellationContext | None,
) -> T:
    """Cancel and drain an owned operation when its cooperative context activates."""

    operation_task = asyncio.ensure_future(operation)
    if cancellation is None:
        return await operation_task
    if cancellation.active:
        snapshot = cancellation.snapshot()
        operation_task.cancel()
        await asyncio.gather(operation_task, return_exceptions=True)
        raise asyncio.CancelledError(snapshot.reason)
    cancellation_task = asyncio.create_task(cancellation.wait())
    try:
        done, _pending = await asyncio.wait(
            {operation_task, cancellation_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancellation_task in done:
            operation_task.cancel()
            await asyncio.gather(operation_task, return_exceptions=True)
            raise asyncio.CancelledError(cancellation_task.result().reason)
        cancellation_task.cancel()
        await asyncio.gather(cancellation_task, return_exceptions=True)
        return operation_task.result()
    except asyncio.CancelledError:
        for task in (operation_task, cancellation_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(operation_task, cancellation_task, return_exceptions=True)
        raise


async def await_with_campaign_deadline[T](
    operation: Awaitable[T],
    budget: BudgetController,
    cancellation: ExecutionCancellationContext | None = None,
) -> T:
    """Bound and drain one owned operation by both cancellation and Campaign time.

    ``BudgetController`` checks performed before dispatch do not stop an operation that
    blocks after dispatch.  The timeout context cancels ``await_with_cancellation``;
    that helper in turn cancels and drains the owned operation and cancellation waiter
    before this function reports the Campaign budget failure.
    """

    operation_task = asyncio.ensure_future(operation)
    try:
        budget.check_duration()
    except BudgetExceeded:
        operation_task.cancel()
        await asyncio.gather(operation_task, return_exceptions=True)
        raise
    timeout = asyncio.timeout(budget.remaining_seconds)
    try:
        async with timeout:
            return await await_with_cancellation(operation_task, cancellation)
    except TimeoutError as exc:
        if not timeout.expired():
            raise
        raise BudgetExceeded("maximum campaign duration exceeded") from exc


def ensure_cancellation_context(
    cancellation: ExecutionCancellationContext | None,
    *,
    engine: str,
    store: RunStore,
) -> ExecutionCancellationContext:
    context = cancellation or ExecutionCancellationContext()
    if not context.active:
        context.cancel(
            CancellationKind.CALLER_CANCELLED,
            "execution task was cancelled",
        )
    context.bind_run(engine=engine, run_id=store.run_id, path=store.path)
    return context


def record_engine_cleanup(
    store: RunStore,
    cancellation: ExecutionCancellationContext,
) -> str:
    """Record engine cleanup; the trusted executor records final quiescence separately."""

    observed = cancellation.snapshot()
    store.append_event(
        "execution.cancellation-observed",
        {
            "kind": observed.kind.value,
            "reason": observed.reason,
            "observedAt": observed.observed_at,
        },
    )
    cancellation.mark_cleanup_completed()
    receipt = LocalCancellationReceipt(cancellation=cancellation.snapshot())
    relative = store.write_json(
        "cancellation.json",
        receipt.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "execution.cleanup-completed",
        {
            "receipt": relative,
            "scope": receipt.quiescence_scope,
            "resourceCleanupAttested": receipt.resource_cleanup_attested,
            "externalSideEffectsReverted": receipt.external_side_effects_reverted,
        },
    )
    return relative


def seal_executor_quiescence(cancellation: ExecutionCancellationContext) -> bool:
    """Append a second seal after a trusted executor's owned stack has unwound."""

    binding = cancellation.binding
    if binding is None or not cancellation.active:
        return False
    cancellation.mark_executor_drained()
    if (binding.path / "quiescence.json").exists():
        return False
    store = RunStore(binding.run_id, binding.path)
    receipt = LocalCancellationReceipt(cancellation=cancellation.snapshot())
    relative = store.write_json(
        "quiescence.json",
        receipt.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "execution.quiesced",
        {
            "receipt": relative,
            "scope": receipt.quiescence_scope,
            "resourceCleanupAttested": receipt.resource_cleanup_attested,
            "controlPlaneAttested": receipt.control_plane_attested,
        },
    )
    store.seal()
    return True
