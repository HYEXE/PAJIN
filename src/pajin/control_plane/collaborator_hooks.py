"""Shared transaction hooks for Control Plane service collaborators."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy.orm import Session

from pajin.control_plane.database import (
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayEventRecord,
    ReplayItemRecord,
    ReplayTicketRecord,
    RunRecord,
)

type EventWriter = Callable[[Session, RunRecord, str, str, dict[str, Any]], EventRecord]


class ReplayEventWriter(Protocol):
    """Write one bounded Replay event with its optional authority context."""

    def __call__(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        *,
        item: ReplayItemRecord | None = None,
        ticket: ReplayTicketRecord | None = None,
        job: JobRecord | None = None,
        run_id: str | None = None,
    ) -> ReplayEventRecord: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneTransactionHooks:
    """Service-owned clock and append-only audit writers."""

    clock: Callable[[], datetime]
    event_writer: EventWriter
    replay_event_writer: ReplayEventWriter
