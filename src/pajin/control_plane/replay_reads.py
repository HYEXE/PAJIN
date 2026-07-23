"""Read-only Replay application collaborator behind the public service facade."""

from __future__ import annotations

from sqlalchemy.orm import Session

from pajin.control_plane.database import ArtifactRecord, ControlPlaneRepository, ReplayBatchRecord
from pajin.control_plane.models import (
    ArtifactLocator,
    ReplayBatchView,
    ReplayFinalizationView,
    ReplayItemView,
    ReplayProjectionView,
    ReplayTicketView,
)
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.view_mapper import ControlPlaneViewMapper


class ReplayReadService:
    """Own Replay read transactions and record-to-view composition."""

    def __init__(
        self,
        repository: ControlPlaneRepository,
        records: ControlPlaneRecords,
        views: ControlPlaneViewMapper,
    ) -> None:
        self._repository = repository
        self._records = records
        self._views = views

    def get_batch(self, batch_id: str) -> ReplayBatchView:
        with self._repository.read_transaction() as session:
            batch = self._records.replay_batch(session, batch_id)
            return self._views.replay_batch(
                batch,
                retest_artifact=self._retest_artifact(session, batch),
            )

    def get_item(self, item_id: str) -> ReplayItemView:
        with self._repository.read_transaction() as session:
            return self._views.replay_item(
                self._records.replay_item(session, item_id),
                claim_authority=self._records.replay_claim_binding(session, item_id),
            )

    def get_ticket(self, ticket_id: str) -> ReplayTicketView:
        with self._repository.read_transaction() as session:
            return self._views.replay_ticket(self._records.replay_ticket(session, ticket_id))

    def get_finalization(self, ticket_id: str) -> ReplayFinalizationView | None:
        """Return one server-derived finalization without exposing Worker secrets."""

        with self._repository.read_transaction() as session:
            ticket = self._records.replay_ticket(session, ticket_id)
            finalization = self._records.replay_finalization_for_ticket(session, ticket_id)
            if finalization is None:
                return None
            job = self._records.job(session, ticket.job_id)
            item = self._records.replay_item(session, ticket.item_id)
            batch = self._records.replay_batch(session, ticket.batch_id)
            artifact = self._records.artifact(
                session,
                ArtifactLocator(
                    artifact_id=finalization.artifact_id,
                    repository_version=finalization.repository_version,
                ),
            )
            return self._views.replay_finalization(
                finalization,
                job=job,
                batch=batch,
                item=item,
                ticket=ticket,
                artifact=artifact,
                claim_authority=self._records.replay_claim_binding(session, item.item_id),
                retest_artifact=self._retest_artifact(session, batch),
            )

    def get_projection(self, batch_id: str) -> ReplayProjectionView | None:
        """Return the immutable aggregate projection published for one batch."""

        with self._repository.read_transaction() as session:
            batch = self._records.replay_batch(session, batch_id)
            projection = self._records.replay_projection_for_batch(session, batch_id)
            if projection is None:
                return None
            artifact = self._records.artifact(
                session,
                ArtifactLocator(
                    artifact_id=projection.artifact_id,
                    repository_version=projection.repository_version,
                ),
            )
            return self._views.replay_projection(
                projection,
                batch=batch,
                artifact=artifact,
                retest_artifact=self._retest_artifact(session, batch),
            )

    def _retest_artifact(
        self,
        session: Session,
        batch: ReplayBatchRecord,
    ) -> ArtifactRecord | None:
        authority = self._records.replay_retest_source(session, batch.batch_id)
        if authority is None:
            return None
        return self._records.artifact(
            session,
            ArtifactLocator(
                artifact_id=authority.artifact_id,
                repository_version=authority.repository_version,
            ),
        )
