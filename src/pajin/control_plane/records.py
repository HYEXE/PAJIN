"""Canonical Control Plane record lookup collaborator."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from pajin.control_plane.database import (
    ApprovalRecord,
    ArtifactRecord,
    CheckpointRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayClaimBindingRecord,
    ReplayFinalizationRecord,
    ReplayItemRecord,
    ReplayProjectionRecord,
    ReplayRetestSourceRecord,
    ReplayTicketRecord,
    RunRecord,
)
from pajin.control_plane.errors import ResourceNotFound, StateConflict
from pajin.control_plane.models import ArtifactLocator


class ControlPlaneRecords:
    """Load one canonical row shape and apply stable missing-authority errors."""

    @staticmethod
    def run(session: Session, run_id: str, *, lock: bool = False) -> RunRecord:
        statement = select(RunRecord).where(RunRecord.run_id == run_id)
        if lock:
            statement = statement.with_for_update()
        run = session.scalar(statement)
        if run is None:
            raise ResourceNotFound("run not found")
        return run

    @staticmethod
    def artifact(
        session: Session,
        locator: ArtifactLocator,
        *,
        lock: bool = False,
    ) -> ArtifactRecord:
        statement = select(ArtifactRecord).where(
            ArtifactRecord.artifact_id == locator.artifact_id,
            ArtifactRecord.repository_version == locator.repository_version,
        )
        if lock:
            statement = statement.with_for_update()
        artifact = session.scalar(statement)
        if artifact is None:
            raise ResourceNotFound("managed source Artifact not found")
        return artifact

    @staticmethod
    def artifact_by_idempotency_key(
        session: Session,
        idempotency_key: str,
        *,
        lock: bool = False,
    ) -> ArtifactRecord | None:
        statement = select(ArtifactRecord).where(ArtifactRecord.idempotency_key == idempotency_key)
        if lock:
            statement = statement.with_for_update()
        return session.scalar(statement)

    @staticmethod
    def job(session: Session, job_id: str, *, lock: bool = False) -> JobRecord:
        statement = select(JobRecord).where(JobRecord.job_id == job_id)
        if lock:
            statement = statement.with_for_update()
        job = session.scalar(statement)
        if job is None:
            raise ResourceNotFound("job not found")
        return job

    @staticmethod
    def replay_batch(
        session: Session,
        batch_id: str,
        *,
        lock: bool = False,
    ) -> ReplayBatchRecord:
        statement = select(ReplayBatchRecord).where(ReplayBatchRecord.batch_id == batch_id)
        if lock:
            statement = statement.with_for_update()
        batch = session.scalar(statement)
        if batch is None:
            raise ResourceNotFound("Replay batch not found")
        return batch

    @staticmethod
    def replay_retest_source(
        session: Session,
        batch_id: str,
        *,
        lock: bool = False,
    ) -> ReplayRetestSourceRecord | None:
        statement = select(ReplayRetestSourceRecord).where(
            ReplayRetestSourceRecord.batch_id == batch_id
        )
        if lock:
            statement = statement.with_for_update()
        return session.scalar(statement)

    @staticmethod
    def replay_item(
        session: Session,
        item_id: str,
        *,
        lock: bool = False,
    ) -> ReplayItemRecord:
        statement = select(ReplayItemRecord).where(ReplayItemRecord.item_id == item_id)
        if lock:
            statement = statement.with_for_update()
        item = session.scalar(statement)
        if item is None:
            raise ResourceNotFound("Replay item not found")
        return item

    @staticmethod
    def replay_claim_binding(
        session: Session,
        item_id: str,
        *,
        lock: bool = False,
    ) -> ReplayClaimBindingRecord | None:
        statement = select(ReplayClaimBindingRecord).where(
            ReplayClaimBindingRecord.item_id == item_id
        )
        if lock:
            statement = statement.with_for_update()
        return session.scalar(statement)

    @staticmethod
    def replay_ticket(
        session: Session,
        ticket_id: str,
        *,
        lock: bool = False,
    ) -> ReplayTicketRecord:
        statement = select(ReplayTicketRecord).where(ReplayTicketRecord.ticket_id == ticket_id)
        if lock:
            statement = statement.with_for_update()
        ticket = session.scalar(statement)
        if ticket is None:
            raise ResourceNotFound("Replay ticket not found")
        return ticket

    @staticmethod
    def replay_ticket_for_job(
        session: Session,
        job_id: str,
        *,
        lock: bool = False,
    ) -> ReplayTicketRecord:
        statement = select(ReplayTicketRecord).where(ReplayTicketRecord.job_id == job_id)
        if lock:
            statement = statement.with_for_update()
        ticket = session.scalar(statement)
        if ticket is None:
            raise StateConflict("internal Replay Job exists without its ticket")
        return ticket

    @staticmethod
    def replay_finalization_for_ticket(
        session: Session,
        ticket_id: str,
        *,
        lock: bool = False,
    ) -> ReplayFinalizationRecord | None:
        statement = select(ReplayFinalizationRecord).where(
            ReplayFinalizationRecord.ticket_id == ticket_id
        )
        if lock:
            statement = statement.with_for_update()
        return session.scalar(statement)

    @staticmethod
    def replay_projection_for_batch(
        session: Session,
        batch_id: str,
        *,
        lock: bool = False,
    ) -> ReplayProjectionRecord | None:
        statement = select(ReplayProjectionRecord).where(
            ReplayProjectionRecord.batch_id == batch_id
        )
        if lock:
            statement = statement.with_for_update()
        return session.scalar(statement)

    @staticmethod
    def checkpoint(
        session: Session,
        checkpoint_id: str,
        *,
        lock: bool = False,
    ) -> CheckpointRecord:
        statement = select(CheckpointRecord).where(CheckpointRecord.checkpoint_id == checkpoint_id)
        if lock:
            statement = statement.with_for_update()
        checkpoint = session.scalar(statement)
        if checkpoint is None:
            raise ResourceNotFound("checkpoint not found")
        return checkpoint

    @staticmethod
    def approval(
        session: Session,
        approval_id: str,
        *,
        lock: bool = False,
    ) -> ApprovalRecord:
        statement = select(ApprovalRecord).where(ApprovalRecord.approval_id == approval_id)
        if lock:
            statement = statement.with_for_update()
        approval = session.scalar(statement)
        if approval is None:
            raise ResourceNotFound("approval not found")
        return approval

    @staticmethod
    def approval_for_checkpoint(
        session: Session,
        checkpoint_id: str,
        *,
        lock: bool = False,
    ) -> ApprovalRecord:
        statement = select(ApprovalRecord).where(ApprovalRecord.checkpoint_id == checkpoint_id)
        if lock:
            statement = statement.with_for_update()
        approval = session.scalar(statement)
        if approval is None:
            raise StateConflict("current checkpoint exists without its approval")
        return approval
