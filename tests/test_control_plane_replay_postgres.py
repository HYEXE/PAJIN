from __future__ import annotations

import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import select, text, update

from pajin.control_plane.database import (
    CURRENT_SCHEMA_VERSION,
    ControlPlaneRepository,
    JobRecord,
    ReplayEventRecord,
    ReplayItemRecord,
    ReplayTicketRecord,
    RunRecord,
    SchemaInitializationError,
    _validate_append_only_trigger,
    _validate_current_schema,
)
from pajin.control_plane.models import (
    ArtifactRef,
    CreateReplayBatchRequest,
    InternalJobKind,
    JobState,
    ReplayBatchItemInput,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayItemState,
    ReplayTicketState,
    RunState,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.control_plane.service import ControlPlaneService
from pajin.domain.models import CampaignMode
from pajin.domain.replay import ReplayPurpose

POSTGRES_URL = os.environ.get("PAJIN_TEST_POSTGRES_URL")
EXECUTOR_PROFILE = "kisa-exact-v1"
WORKER_A = "postgres-replay-worker-a"
WORKER_B = "postgres-replay-worker-b"
pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="set PAJIN_TEST_POSTGRES_URL to an isolated PAJIN PostgreSQL test database",
)


def _service() -> tuple[ControlPlaneRepository, ControlPlaneService]:
    assert POSTGRES_URL is not None
    repository = ControlPlaneRepository(POSTGRES_URL)
    repository.initialize()
    signer = CheckpointSigner(
        active_key_id="postgres-replay-v1",
        keys={"postgres-replay-v1": b"postgres-replay-signing-key-at-least-32-bytes"},
    )
    return repository, ControlPlaneService(
        repository,
        signer,
        replay_executor_profiles={
            WORKER_A: frozenset({EXECUTOR_PROFILE}),
            WORKER_B: frozenset({EXECUTOR_PROFILE}),
        },
    )


def _seed_batch(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    suffix: str,
    *,
    item_count: int = 1,
    required_attempts: int = 2,
    max_attempts: int = 3,
) -> str:
    source_run_id = f"run_source_{suffix}"
    now = datetime.now(UTC)
    with repository.transaction() as session:
        session.add(
            RunRecord(
                run_id=source_run_id,
                campaign_name="postgres-replay",
                state=RunState.COMPLETED.value,
                input={"sealedSource": True, "suffix": suffix},
                submission_key=f"postgres-replay-source-{suffix}",
                current_checkpoint_id=None,
                created_at=now,
                updated_at=now,
            )
        )
    source = ArtifactRef(
        artifact_id=f"artifact_{suffix}",
        repository_version=1,
        media_type="application/vnd.pajin.run+tar",
        schema_kind="pajin.run.v1",
        byte_length=4_096,
        content_digest=sha256(f"content:{suffix}".encode()).hexdigest(),
        run_id=source_run_id,
        integrity_root_digest=sha256(f"root:{suffix}".encode()).hexdigest(),
        created_by="postgres-replay-admission",
    )
    created = service.create_replay_batch(
        CreateReplayBatchRequest(
            campaign_name="postgres-replay",
            source=source,
            mode=CampaignMode.AI_REDTEAM,
            purpose=ReplayPurpose.CONFIRMATION,
            policy_version="policy-v1",
            idempotency_key=f"postgres-replay-batch-{suffix}",
            items=[
                ReplayBatchItemInput(
                    candidate_id=f"candidate-{suffix}-{ordinal}",
                    candidate_digest=sha256(
                        f"candidate:{suffix}:{ordinal}".encode()
                    ).hexdigest(),
                    contract_digest=sha256(
                        f"contract:{suffix}:{ordinal}".encode()
                    ).hexdigest(),
                    compilation_digest=sha256(
                        f"compilation:{suffix}:{ordinal}".encode()
                    ).hexdigest(),
                    grant_digest=sha256(
                        f"grant:{suffix}:{ordinal}".encode()
                    ).hexdigest(),
                    required_attempts=required_attempts,
                    max_attempts=max_attempts,
                )
                for ordinal in range(item_count)
            ],
        ),
        actor="postgres-replay-admission",
    )
    return created.batch_id


def test_postgres_replay_claim_has_exactly_one_winner_and_atomic_ticket_binding() -> None:
    repository_a, service_a = _service()
    repository_b, service_b = _service()
    suffix = uuid4().hex
    try:
        assert repository_a.schema_version() == CURRENT_SCHEMA_VERSION
        expected_batch_id = _seed_batch(repository_a, service_a, suffix)
        barrier = Barrier(2)

        def claim(service: ControlPlaneService, actor: str):
            barrier.wait()
            return service.claim_replay_job(
                ReplayClaimRequest(
                    executor_profile=EXECUTOR_PROFILE,
                    lease_seconds=30,
                ),
                actor=actor,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(claim, service_a, WORKER_A)
            second = pool.submit(claim, service_b, WORKER_B)
            results = [first.result(timeout=15), second.result(timeout=15)]

        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        winner = winners[0]
        assert winner.batch.batch_id == expected_batch_id
        assert winner.ticket.claimed_by in {WORKER_A, WORKER_B}
        assert winner.job.lease_owner == winner.ticket.claimed_by
        assert winner.ticket.attempt == winner.item.attempts == 1
        assert winner.ticket.fencing_value == 1

        with repository_a.transaction() as session:
            job = session.get(JobRecord, winner.job.job_id)
            ticket = session.get(ReplayTicketRecord, winner.ticket.ticket_id)
            item = session.get(ReplayItemRecord, winner.item.item_id)
            assert job is not None and ticket is not None and item is not None
            lease_digest = token_digest(winner.lease_token)
            assert job.kind == InternalJobKind.REPLAY.value
            assert job.state == JobState.LEASED.value
            assert job.attempts == 1
            assert job.lease_owner == winner.ticket.claimed_by
            assert job.lease_token_hash == lease_digest
            assert ticket.state == ReplayTicketState.CLAIMED.value
            assert ticket.claim_principal == winner.ticket.claimed_by
            assert ticket.lease_token_hash == lease_digest
            assert ticket.job_id == job.job_id
            assert ticket.replay_run_id == job.run_id == item.replay_run_id
            assert ticket.item_id == item.item_id
            assert ticket.attempt_number == item.attempts == 1
            assert ticket.fencing_value == 1
            assert item.state == ReplayItemState.RUNNING.value
    finally:
        repository_b.close()
        repository_a.close()


def test_postgres_expired_replay_sweepers_prelock_shared_batches_in_global_order() -> None:
    repository_a, service_a = _service()
    repository_b, service_b = _service()
    batch_ids: list[str] = []
    allocation: tuple[str, str, list[str], list[str]] | None = None
    try:
        # Find two two-item batches whose random Job IDs permit opposite lazy
        # traversal orders. The explicit row locks below then deterministically
        # reproduce the old X -> Y / Y -> X reaper partition.
        for _ in range(8):
            suffix = uuid4().hex
            batch_ids.append(
                _seed_batch(
                    repository_a,
                    service_a,
                    suffix,
                    item_count=2,
                    required_attempts=1,
                    max_attempts=1,
                )
            )
            if len(batch_ids) < 2:
                continue
            with repository_a.transaction() as session:
                rows = session.execute(
                    select(JobRecord.job_id, ReplayTicketRecord.batch_id)
                    .join(ReplayTicketRecord, ReplayTicketRecord.job_id == JobRecord.job_id)
                    .where(ReplayTicketRecord.batch_id.in_(batch_ids))
                ).all()
            jobs_by_batch = {
                batch_id: sorted(
                    job_id for job_id, row_batch_id in rows if row_batch_id == batch_id
                )
                for batch_id in batch_ids
            }
            for left_index, left_batch_id in enumerate(batch_ids):
                for right_batch_id in batch_ids[left_index + 1 :]:
                    left_jobs = jobs_by_batch[left_batch_id]
                    right_jobs = jobs_by_batch[right_batch_id]
                    for left_a in left_jobs:
                        left_b = next(job_id for job_id in left_jobs if job_id != left_a)
                        for right_a in right_jobs:
                            right_b = next(job_id for job_id in right_jobs if job_id != right_a)
                            if (left_a < right_a) != (left_b < right_b):
                                allocation = (
                                    left_batch_id,
                                    right_batch_id,
                                    [left_a, right_a],
                                    [left_b, right_b],
                                )
                                break
                        if allocation is not None:
                            break
                    if allocation is not None:
                        break
                if allocation is not None:
                    break
            if allocation is not None:
                break
        assert allocation is not None, "failed to construct crossed Replay Job ordering"

        for _ in range(2 * len(batch_ids)):
            claimed = service_a.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=300),
                actor=WORKER_A,
            )
            assert claimed is not None
            assert claimed.batch.batch_id in batch_ids

        left_batch_id, right_batch_id, worker_a_jobs, worker_b_jobs = allocation
        selected_job_ids = worker_a_jobs + worker_b_jobs
        expired_at = datetime.now(UTC) - timedelta(seconds=1)
        with repository_a.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id.in_(selected_job_ids))
                .values(lease_expires_at=expired_at)
            )
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.job_id.in_(selected_job_ids))
                .values(lease_expires_at=expired_at)
            )
            selected_ticket_ids = list(
                session.scalars(
                    select(ReplayTicketRecord.ticket_id).where(
                        ReplayTicketRecord.job_id.in_(selected_job_ids)
                    )
                ).all()
            )

        barrier = Barrier(2)
        transition_time = datetime.now(UTC)

        def reap_owned_partition(
            repository: ControlPlaneRepository,
            service: ControlPlaneService,
            owned_job_ids: list[str],
            actor: str,
        ) -> int:
            with repository.transaction() as session:
                session.execute(text("SET LOCAL lock_timeout = '5s'"))
                locked_job_ids = list(
                    session.scalars(
                        select(JobRecord.job_id)
                        .where(JobRecord.job_id.in_(owned_job_ids))
                        .order_by(JobRecord.job_id)
                        .with_for_update()
                    ).all()
                )
                assert set(locked_job_ids) == set(owned_job_ids)
                barrier.wait(timeout=10)
                return service._expire_leases(
                    session,
                    now=transition_time,
                    actor=actor,
                )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(
                reap_owned_partition,
                repository_a,
                service_a,
                worker_a_jobs,
                WORKER_A,
            )
            second = pool.submit(
                reap_owned_partition,
                repository_b,
                service_b,
                worker_b_jobs,
                WORKER_B,
            )
            counts = [first.result(timeout=15), second.result(timeout=15)]

        assert counts == [2, 2]
        assert service_a.requeue_expired(actor="postgres-replay-reaper") == 0
        with repository_a.transaction() as session:
            jobs = list(
                session.scalars(
                    select(JobRecord).where(JobRecord.job_id.in_(selected_job_ids))
                ).all()
            )
            tickets = list(
                session.scalars(
                    select(ReplayTicketRecord).where(
                        ReplayTicketRecord.ticket_id.in_(selected_ticket_ids)
                    )
                ).all()
            )
            items = list(
                session.scalars(
                    select(ReplayItemRecord).where(
                        ReplayItemRecord.batch_id.in_([left_batch_id, right_batch_id])
                    )
                ).all()
            )
            expiry_events = list(
                session.scalars(
                    select(ReplayEventRecord).where(
                        ReplayEventRecord.ticket_id.in_(selected_ticket_ids),
                        ReplayEventRecord.event_type == "replay.ticket.lease-expired",
                    )
                ).all()
            )
        assert all(job.state == JobState.FAILED.value for job in jobs)
        assert all(ticket.state == ReplayTicketState.ABANDONED.value for ticket in tickets)
        assert all(item.state == ReplayItemState.FAILED.value for item in items)
        assert Counter(event.ticket_id for event in expiry_events) == Counter(selected_ticket_ids)
        assert service_a.get_replay_batch(left_batch_id).state is ReplayBatchState.FAILED
        assert service_a.get_replay_batch(right_batch_id).state is ReplayBatchState.FAILED
    finally:
        repository_b.close()
        repository_a.close()


def test_postgres_schema_fence_rejects_append_only_trigger_catalog_drift() -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                _validate_append_only_trigger(connection, "cp_replay_events")
                connection.execute(
                    text(
                        "ALTER TABLE cp_replay_events DISABLE TRIGGER "
                        "cp_replay_events_append_only"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="append-only trigger"):
                    _validate_append_only_trigger(connection, "cp_replay_events")
            finally:
                transaction.rollback()

        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        "DROP TRIGGER cp_replay_events_append_only "
                        "ON cp_replay_events"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER cp_replay_events_append_only "
                        "BEFORE UPDATE OF event_type ON cp_replay_events "
                        "FOR EACH ROW EXECUTE FUNCTION "
                        "pajin_cp_reject_replay_event_mutation()"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="append-only trigger"):
                    _validate_append_only_trigger(connection, "cp_replay_events")
            finally:
                transaction.rollback()

        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        "CREATE OR REPLACE FUNCTION "
                        "pajin_cp_reject_replay_event_mutation() RETURNS trigger "
                        "LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END; $$"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="append-only trigger"):
                    _validate_append_only_trigger(connection, "cp_replay_events")
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("table_name", "operation"),
    [
        ("cp_replay_events", "INSERT"),
        ("cp_replay_batches", "UPDATE"),
    ],
)
def test_postgres_schema_fence_rejects_unmanaged_user_trigger_inventory(
    table_name: str,
    operation: str,
) -> None:
    repository, _service_instance = _service()
    trigger_name = f"{table_name}_unmanaged"
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        f"CREATE TRIGGER {trigger_name} "
                        f"BEFORE {operation} ON {table_name} "
                        "FOR EACH ROW EXECUTE FUNCTION "
                        "pajin_cp_reject_replay_event_mutation()"
                    )
                )
                with pytest.raises(
                    SchemaInitializationError, match="user trigger inventory"
                ):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize("table_name", ["cp_replay_events", "cp_replay_batches"])
def test_postgres_schema_fence_rejects_unmanaged_rewrite_rule_inventory(
    table_name: str,
) -> None:
    repository, _service_instance = _service()
    rule_name = f"{table_name}_suppress_insert"
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        f"CREATE RULE {rule_name} AS ON INSERT TO {table_name} "
                        "DO INSTEAD NOTHING"
                    )
                )
                with pytest.raises(
                    SchemaInitializationError, match="rewrite rule inventory"
                ):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


def test_postgres_schema_fence_rejects_managed_table_inheritance_edges() -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        "CREATE TABLE pajin_test_audit_shadow () "
                        "INHERITS (cp_events)"
                    )
                )
                with pytest.raises(
                    SchemaInitializationError, match="inheritance inventory"
                ):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize("table_name", ["cp_events", "cp_replay_events"])
def test_postgres_schema_fence_rejects_unlogged_managed_audit_tables(
    table_name: str,
) -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text(f"ALTER TABLE {table_name} SET UNLOGGED"))
                with pytest.raises(
                    SchemaInitializationError, match="relation persistence"
                ):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()


@pytest.mark.parametrize("constraint_option", ["NOT VALID", "NO INHERIT"])
def test_postgres_schema_fence_rejects_unmanaged_check_catalog_flags(
    constraint_option: str,
) -> None:
    repository, _service_instance = _service()
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text(
                        "ALTER TABLE cp_replay_batches DROP CONSTRAINT "
                        "ck_cp_replay_batches_cas_version"
                    )
                )
                connection.execute(
                    text(
                        "ALTER TABLE cp_replay_batches ADD CONSTRAINT "
                        "ck_cp_replay_batches_cas_version "
                        f"CHECK (cas_version > 0) {constraint_option}"
                    )
                )
                with pytest.raises(SchemaInitializationError, match="unmanaged"):
                    _validate_current_schema(connection)
            finally:
                transaction.rollback()
    finally:
        repository.close()
