"""Atomic budget accounting inside an existing trusted SQLite journal."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import TYPE_CHECKING
from uuid import uuid4

from pajin.runtime.budget_state import (
    BUDGET_TABLE,
    BudgetCheckpoint,
    BudgetPersistenceError,
    BudgetScope,
    BudgetUsage,
    budget_checkpoint_bytes,
    parse_budget_checkpoint,
)

if TYPE_CHECKING:
    from pajin.runtime.control import BudgetController


@dataclass
class BudgetAccountBinding:
    ledger: DurableBudgetLedger
    controller: BudgetController
    checkpoint: BudgetCheckpoint

    def require_usable(self) -> None:
        if self.ledger.failed or self.controller._accounting_failed:
            raise BudgetPersistenceError("budget persistence is uncertain; reopen verified state")
        if self.controller.budgets != self.checkpoint.scope.limits:
            raise BudgetPersistenceError("bound budget configuration has changed")


def _usage(controller: BudgetController) -> BudgetUsage:
    return BudgetUsage(
        agent_count=controller.agent_count,
        tool_calls=controller.tool_calls,
        model_calls=controller.model_calls,
        model_prompt_tokens=controller.model_prompt_tokens,
        model_completion_tokens=controller.model_completion_tokens,
        cost_usd=controller.cost_usd,
        elapsed_seconds=controller.elapsed_seconds,
    )


def _require_pristine(controller: BudgetController) -> None:
    if (
        controller._model_usage_reservations
        or controller._tool_usage_reservations
        or any(
            value != 0
            for name, value in _usage(controller).model_dump().items()
            if name != "elapsed_seconds"
        )
        or controller._elapsed_offset_seconds != 0
    ):
        raise BudgetPersistenceError("persisted usage requires an unused replacement controller")


def _restore(controller: BudgetController, usage: BudgetUsage, *, elapsed: float) -> None:
    controller.restore_usage(
        agent_count=usage.agent_count,
        tool_calls=usage.tool_calls,
        model_calls=usage.model_calls,
        model_prompt_tokens=usage.model_prompt_tokens,
        model_completion_tokens=usage.model_completion_tokens,
        cost_usd=usage.cost_usd,
        elapsed_seconds=elapsed,
    )


def _read_row(row: sqlite3.Row) -> BudgetCheckpoint:
    if type(row["payload"]) is not str:
        raise BudgetPersistenceError("budget checkpoint payload is not text")
    checkpoint = parse_budget_checkpoint(row["payload"])
    if (
        row["scope_id"] != checkpoint.scope.scope_id
        or type(row["revision"]) is not int
        or row["revision"] != checkpoint.revision
        or row["checkpoint_digest"] != checkpoint.checkpoint_digest
    ):
        raise BudgetPersistenceError("budget checkpoint index differs from its payload")
    return checkpoint


def _latest(connection: sqlite3.Connection, scope_id: str) -> BudgetCheckpoint | None:
    row = connection.execute(
        f"SELECT * FROM {BUDGET_TABLE} WHERE scope_id = ? ORDER BY revision DESC LIMIT 1",
        (scope_id,),
    ).fetchone()
    return None if row is None else _read_row(row)


def _verified_history(
    connection: sqlite3.Connection, scope: BudgetScope
) -> BudgetCheckpoint | None:
    previous: BudgetCheckpoint | None = None
    for row in connection.execute(
        f"SELECT * FROM {BUDGET_TABLE} WHERE scope_id = ? ORDER BY revision", (scope.scope_id,)
    ):
        checkpoint = _read_row(row)
        if checkpoint.scope != scope:
            raise BudgetPersistenceError("persisted budget scope or policy has changed")
        if (
            checkpoint.revision != (1 if previous is None else previous.revision + 1)
            or checkpoint.previous_digest
            != (None if previous is None else previous.checkpoint_digest)
            or (
                previous is not None
                and (
                    checkpoint.origin_at != previous.origin_at
                    or checkpoint.recorded_at < previous.recorded_at
                    or checkpoint.usage.elapsed_seconds < previous.usage.elapsed_seconds
                )
            )
        ):
            raise BudgetPersistenceError("budget checkpoint history is incomplete or inconsistent")
        previous = checkpoint
    return previous


def _insert(connection: sqlite3.Connection, checkpoint: BudgetCheckpoint) -> None:
    connection.execute(
        f"INSERT INTO {BUDGET_TABLE} (scope_id, revision, checkpoint_digest, payload) "
        "VALUES (?, ?, ?, ?)",
        (
            checkpoint.scope.scope_id,
            checkpoint.revision,
            checkpoint.checkpoint_digest,
            budget_checkpoint_bytes(checkpoint).decode("utf-8"),
        ),
    )


class DurableBudgetLedger:
    """Serialize conservative usage and fence superseded in-memory owners.

    The journal owner supplies the schema-validated transaction and legacy-state
    admission check. It must keep this ledger with the invocation claims it governs.
    """

    def __init__(
        self,
        *,
        transaction: Callable[[], AbstractContextManager[sqlite3.Connection]],
        may_initialize: Callable[[sqlite3.Connection, str], bool],
        clock: Callable[[], datetime],
    ) -> None:
        self._transaction = transaction
        self._may_initialize = may_initialize
        self._clock = clock
        self._owner = uuid4().hex
        self._lock = RLock()
        self._bindings: dict[str, BudgetAccountBinding] = {}
        self._changing: frozenset[str] = frozenset()
        self.failed = False

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise BudgetPersistenceError("budget clock must use UTC")
        return now.astimezone(UTC)

    def bind_pair(
        self,
        *,
        campaign_digest: str,
        policy_digest: str,
        campaign: BudgetController,
        dedicated: BudgetController,
    ) -> None:
        from pajin.runtime.control import BudgetController

        if type(campaign) is not BudgetController or type(dedicated) is not BudgetController:
            raise BudgetPersistenceError("durable budgets require the code-owned controllers")
        if campaign is dedicated:
            raise BudgetPersistenceError("durable dual budgets require distinct controllers")
        pairs = (
            (
                campaign,
                BudgetScope(
                    campaign_digest=campaign_digest,
                    role="campaign",
                    policy_digest=None,
                    limits=campaign.budgets,
                ),
            ),
            (
                dedicated,
                BudgetScope(
                    campaign_digest=campaign_digest,
                    role="supervisor",
                    policy_digest=policy_digest,
                    limits=dedicated.budgets,
                ),
            ),
        )
        self._bind_accounts(campaign_digest, pairs)

    def bind_campaign(self, *, campaign_digest: str, campaign: BudgetController) -> None:
        """Bind a complete Campaign-only scope without inventing a Supervisor allowance."""
        from pajin.runtime.control import BudgetController

        if type(campaign) is not BudgetController:
            raise BudgetPersistenceError("durable budgets require the code-owned controllers")
        self._bind_accounts(campaign_digest, ((campaign, BudgetScope(
            campaign_digest=campaign_digest, role="campaign", policy_digest=None,
            limits=campaign.budgets,
        )),))

    def _bind_accounts(
        self,
        campaign_digest: str,
        pairs: tuple[tuple[BudgetController, BudgetScope], ...],
    ) -> None:
        controllers = tuple(controller for controller, _ in pairs)
        if any(controller._accounting_failed for controller in controllers):
            raise BudgetPersistenceError("failed accounting requires fresh replacement controllers")
        with self._lock, ExitStack() as locks:
            for controller in sorted(controllers, key=id):
                locks.enter_context(controller._usage_lock)
            if self._already_bound(pairs):
                with self._transaction() as connection:
                    self._require_current(connection, self._require_bindings(controllers))
                return
            pending: list[tuple[BudgetController, BudgetCheckpoint, BudgetController | None]] = []
            try:
                with self._transaction() as connection:
                    now = self._now()
                    previous = tuple(_verified_history(connection, scope) for _, scope in pairs)
                    if any(item is None for item in previous) and any(
                        item is not None for item in previous
                    ):
                        raise BudgetPersistenceError(
                            "one side of the durable budget pair is missing"
                        )
                    if previous[0] is None and not self._may_initialize(
                        connection, campaign_digest
                    ):
                        raise BudgetPersistenceError(
                            "existing invocation history has no budget checkpoint"
                        )
                    for (controller, scope), saved in zip(pairs, previous, strict=True):
                        pending.append(self._prepare_binding(controller, scope, saved, now))
                    for _, checkpoint, _ in pending:
                        _insert(connection, checkpoint)
                for controller, checkpoint, restored in pending:
                    if restored is not None:
                        _restore(controller, _usage(restored), elapsed=restored.elapsed_seconds)
                    binding = BudgetAccountBinding(self, controller, checkpoint)
                    controller._persistence = binding
                    self._bindings[checkpoint.scope.scope_id] = binding
            except BaseException:
                self.failed = True
                for controller in controllers:
                    controller._accounting_failed = True
                raise

    def _already_bound(self, pairs: tuple[tuple[BudgetController, BudgetScope], ...]) -> bool:
        if self.failed:
            raise BudgetPersistenceError("budget persistence is uncertain; reopen verified state")
        existing = tuple(controller._persistence for controller, _ in pairs)
        if all(binding is None for binding in existing):
            if any(scope.scope_id in self._bindings for _, scope in pairs):
                raise BudgetPersistenceError("budget scope is already bound to another controller")
            return False
        for (controller, scope), binding in zip(pairs, existing, strict=True):
            if (
                binding is None
                or binding.ledger is not self
                or binding.controller is not controller
                or binding.checkpoint.scope != scope
            ):
                raise BudgetPersistenceError(
                    "budget controller belongs to a different journal or scope"
                )
            binding.require_usable()
        return True

    def _prepare_binding(
        self,
        controller: BudgetController,
        scope: BudgetScope,
        saved: BudgetCheckpoint | None,
        now: datetime,
    ) -> tuple[BudgetController, BudgetCheckpoint, BudgetController | None]:
        from pajin.runtime.control import BudgetController

        restored: BudgetController | None = None
        if controller._model_usage_reservations or controller._tool_usage_reservations:
            raise BudgetPersistenceError("cannot adopt a controller with an in-flight reservation")
        if saved is None:
            usage = _usage(controller)
            controller.check_duration()
            origin = now - timedelta(seconds=usage.elapsed_seconds)
        else:
            _require_pristine(controller)
            if now < saved.recorded_at:
                raise BudgetPersistenceError("budget recovery clock moved backwards")
            elapsed = max(saved.usage.elapsed_seconds, (now - saved.origin_at).total_seconds())
            restored = BudgetController(scope.limits)
            _restore(restored, saved.usage, elapsed=elapsed)
            usage = _usage(restored)
            origin = saved.origin_at
        checkpoint = BudgetCheckpoint(
            scope=scope,
            revision=1 if saved is None else saved.revision + 1,
            previous_digest=None if saved is None else saved.checkpoint_digest,
            owner_id=self._owner,
            origin_at=origin,
            recorded_at=now,
            usage=usage,
        )
        return controller, checkpoint, restored

    @contextmanager
    def change(self, controllers: tuple[BudgetController, ...]) -> Iterator[None]:
        with self._lock, ExitStack() as locks:
            for controller in sorted(controllers, key=id):
                locks.enter_context(controller._usage_lock)
            bindings = self._require_bindings(controllers)
            identities = frozenset(binding.checkpoint.scope.scope_id for binding in bindings)
            if self._changing:
                if not identities <= self._changing:
                    raise BudgetPersistenceError("nested budget mutation escapes its atomic scope")
                yield
                return
            body_error: BaseException | None = None
            updated: list[tuple[BudgetAccountBinding, BudgetCheckpoint]] = []
            try:
                with self._transaction() as connection:
                    self._require_current(connection, bindings)
                    self._changing = identities
                    try:
                        yield
                    except BaseException as exc:
                        # Preserve the existing conservative exception semantics (for
                        # example an over-bound settlement consumes its full reservation).
                        body_error = exc
                    finally:
                        self._changing = frozenset()
                    now = self._now()
                    for binding in bindings:
                        saved = binding.checkpoint
                        usage = _usage(binding.controller)
                        if (
                            now < saved.recorded_at
                            or usage.elapsed_seconds < saved.usage.elapsed_seconds
                        ):
                            raise BudgetPersistenceError("budget accounting clock moved backwards")
                        checkpoint = BudgetCheckpoint(
                            scope=saved.scope,
                            revision=saved.revision + 1,
                            previous_digest=saved.checkpoint_digest,
                            owner_id=self._owner,
                            origin_at=saved.origin_at,
                            recorded_at=now,
                            usage=usage,
                        )
                        _insert(connection, checkpoint)
                        updated.append((binding, checkpoint))
            except BaseException:
                self.failed = True
                raise
            for binding, checkpoint in updated:
                binding.checkpoint = checkpoint
            if body_error is not None:
                raise body_error

    def _require_bindings(
        self, controllers: tuple[BudgetController, ...]
    ) -> tuple[BudgetAccountBinding, ...]:
        bindings: list[BudgetAccountBinding] = []
        for controller in controllers:
            binding = controller._persistence
            if (
                binding is None
                or binding.ledger is not self
                or binding.controller is not controller
            ):
                raise BudgetPersistenceError("atomic budget accounting has an unbound participant")
            binding.require_usable()
            bindings.append(binding)
        return tuple(bindings)

    def _require_current(
        self, connection: sqlite3.Connection, bindings: tuple[BudgetAccountBinding, ...]
    ) -> None:
        for binding in bindings:
            current = _latest(connection, binding.checkpoint.scope.scope_id)
            if current != binding.checkpoint or current.owner_id != self._owner:
                raise BudgetPersistenceError("budget owner or checkpoint was superseded")


@contextmanager
def budget_change(*controllers: BudgetController) -> Iterator[None]:
    if any(controller._accounting_failed for controller in controllers):
        raise BudgetPersistenceError("budget accounting failed; dispatch is fenced")
    bindings = tuple(controller._persistence for controller in controllers)
    if all(binding is None for binding in bindings):
        yield
        return
    ledger = next(binding.ledger for binding in bindings if binding is not None)
    with ledger.change(controllers):
        yield
