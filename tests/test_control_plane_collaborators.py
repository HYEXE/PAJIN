from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.orm import Session

import pajin.control_plane.service as service_module
from pajin.control_plane.claim_service import ControlPlaneClaimService
from pajin.control_plane.database import ControlPlaneRepository
from pajin.control_plane.errors import ResourceNotFound, StateConflict
from pajin.control_plane.lifecycle_service import ControlPlaneLifecycleService
from pajin.control_plane.models import (
    CancelRunRequest,
    ClaimJobRequest,
    LeaseRequest,
    ReplayClaimRequest,
    ReplayLeaseRequest,
)
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.replay_issuance import ReplayIssuanceService
from pajin.control_plane.replay_reads import ReplayReadService
from pajin.control_plane.security import CheckpointSigner
from pajin.control_plane.service import ControlPlaneService
from pajin.control_plane.view_mapper import ControlPlaneViewMapper


class _ReadRepository:
    def __init__(self) -> None:
        self.sessions: list[object] = []

    @contextmanager
    def read_transaction(self) -> Iterator[object]:
        session = object()
        self.sessions.append(session)
        yield session


class _ReplayRecords:
    @staticmethod
    def replay_batch(session: object, record_id: str) -> SimpleNamespace:
        return SimpleNamespace(kind="batch", session=session, batch_id=record_id)

    @staticmethod
    def replay_item(session: object, record_id: str) -> tuple[str, object, str]:
        return ("item", session, record_id)

    @staticmethod
    def replay_ticket(session: object, record_id: str) -> tuple[str, object, str]:
        return ("ticket", session, record_id)

    @staticmethod
    def replay_retest_source(
        session: object,
        record_id: str,
    ) -> None:
        return None


class _ReplayViews:
    @staticmethod
    def replay_batch(
        record: object,
        *,
        retest_artifact: object | None = None,
    ) -> tuple[str, object]:
        assert retest_artifact is None
        return ("batch-view", record)

    @staticmethod
    def replay_item(record: object) -> tuple[str, object]:
        return ("item-view", record)

    @staticmethod
    def replay_ticket(record: object) -> tuple[str, object]:
        return ("ticket-view", record)


def test_service_keeps_stable_error_reexports() -> None:
    assert service_module.ResourceNotFound is ResourceNotFound
    assert service_module.StateConflict is StateConflict


def test_replay_read_collaborator_owns_one_read_transaction_per_view() -> None:
    repository = _ReadRepository()
    reads = ReplayReadService(
        cast(ControlPlaneRepository, repository),
        cast(ControlPlaneRecords, _ReplayRecords()),
        cast(ControlPlaneViewMapper, _ReplayViews()),
    )

    batch = reads.get_batch("batch-1")
    item = reads.get_item("item-1")
    ticket = reads.get_ticket("ticket-1")

    assert batch == (
        "batch-view",
        SimpleNamespace(kind="batch", session=repository.sessions[0], batch_id="batch-1"),
    )
    assert item == ("item-view", ("item", repository.sessions[1], "item-1"))
    assert ticket == ("ticket-view", ("ticket", repository.sessions[2], "ticket-1"))
    assert len(repository.sessions) == 3


def test_public_replay_read_facade_delegates_without_changing_results() -> None:
    expected = {
        "batch": object(),
        "finalization": object(),
        "item": object(),
        "ticket": object(),
    }
    reads = SimpleNamespace(
        get_batch=lambda _record_id: expected["batch"],
        get_finalization=lambda _record_id: expected["finalization"],
        get_item=lambda _record_id: expected["item"],
        get_ticket=lambda _record_id: expected["ticket"],
    )
    service = object.__new__(ControlPlaneService)
    service._replay_reads = cast(ReplayReadService, reads)

    assert service.get_replay_batch("batch-1") is expected["batch"]
    assert service.get_replay_finalization("ticket-1") is expected["finalization"]
    assert service.get_replay_item("item-1") is expected["item"]
    assert service.get_replay_ticket("ticket-1") is expected["ticket"]


def test_public_claim_facade_delegates_without_changing_results() -> None:
    expected = {
        "claim": object(),
        "replay-claim": object(),
        "replay-heartbeat": object(),
        "heartbeat": object(),
    }
    claims = SimpleNamespace(
        claim_job=lambda _request, *, actor: (actor, expected["claim"]),
        claim_replay_job=lambda _request, *, actor: (actor, expected["replay-claim"]),
        heartbeat_replay_job=lambda job_id, _request, *, actor: (
            job_id,
            actor,
            expected["replay-heartbeat"],
        ),
        heartbeat=lambda job_id, _request, *, actor: (
            job_id,
            actor,
            expected["heartbeat"],
        ),
    )
    service = object.__new__(ControlPlaneService)
    service._claims = cast(ControlPlaneClaimService, claims)

    claim = service.claim_job(cast(ClaimJobRequest, object()), actor="worker")
    replay_claim = service.claim_replay_job(
        cast(ReplayClaimRequest, object()),
        actor="replay-worker",
    )
    replay_heartbeat = service.heartbeat_replay_job(
        "job-1",
        cast(ReplayLeaseRequest, object()),
        actor="replay-worker",
    )
    heartbeat = service.heartbeat(
        "job-2",
        cast(LeaseRequest, object()),
        actor="worker",
    )

    assert claim == ("worker", expected["claim"])
    assert replay_claim == ("replay-worker", expected["replay-claim"])
    assert replay_heartbeat == ("job-1", "replay-worker", expected["replay-heartbeat"])
    assert heartbeat == ("job-2", "worker", expected["heartbeat"])


def test_replay_claim_facade_issues_pending_retry_before_second_claim() -> None:
    expected_claim = object()
    claim_results = iter([None, expected_claim])
    claim_calls: list[str] = []
    issuance_calls: list[str] = []
    claims = SimpleNamespace(
        claim_replay_job=lambda _request, *, actor: (
            claim_calls.append(actor),
            next(claim_results),
        )[1]
    )
    issuance = SimpleNamespace(
        issue_pending_replay_retries=lambda *, actor: (
            issuance_calls.append(actor),
            1,
        )[1]
    )
    service = object.__new__(ControlPlaneService)
    service._claims = cast(ControlPlaneClaimService, claims)
    service._replay_issuance = cast(ReplayIssuanceService, issuance)

    claimed = service.claim_replay_job(
        cast(ReplayClaimRequest, object()),
        actor="replay-worker",
    )

    assert claimed is expected_claim
    assert claim_calls == ["replay-worker", "replay-worker"]
    assert issuance_calls == ["control-plane:replay-retry"]


def test_transaction_collaborators_share_clock_and_audit_hooks() -> None:
    service = ControlPlaneService(
        cast(ControlPlaneRepository, SimpleNamespace()),
        cast(CheckpointSigner, SimpleNamespace()),
    )

    transaction_hooks = service._claims._hooks.transaction
    assert transaction_hooks is service._replay_issuance._hooks.transaction
    assert transaction_hooks is service._lifecycle._hooks.transaction


def test_public_lifecycle_facade_delegates_without_changing_results() -> None:
    expected_cancel = object()
    lifecycle = SimpleNamespace(
        cancel_run=lambda run_id, _request, *, actor: (run_id, actor, expected_cancel),
        requeue_expired=lambda *, actor: (actor, 7),
    )
    service = object.__new__(ControlPlaneService)
    service._lifecycle = cast(ControlPlaneLifecycleService, lifecycle)

    cancelled = service.cancel_run(
        "run-1",
        cast(CancelRunRequest, object()),
        actor="operator",
    )

    assert cancelled == ("run-1", "operator", expected_cancel)
    assert service.requeue_expired(actor="reaper") == ("reaper", 7)


def test_record_collaborator_preserves_missing_resource_error() -> None:
    session = cast(Session, SimpleNamespace(scalar=lambda _statement: None))

    with pytest.raises(ResourceNotFound, match="run not found"):
        ControlPlaneRecords.run(session, "run-missing")

    with pytest.raises(ResourceNotFound, match="Replay ticket not found"):
        ControlPlaneRecords.replay_ticket(session, "ticket-missing")
