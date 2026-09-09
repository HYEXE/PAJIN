"""Atomic urgent cancellation and human acknowledgments in the existing CP journal."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Literal, Self

from pydantic import Field, model_validator
from sqlalchemy import case, func, select, text
from sqlalchemy.orm import Session

from pajin.collaboration.urgent_observation import UrgentObservationFastGateDecision
from pajin.control_plane.abac import ControlPlaneRunCancellationAuthorizer
from pajin.control_plane.collaborator_hooks import ControlPlaneTransactionHooks
from pajin.control_plane.database import ControlPlaneRepository, EventRecord
from pajin.control_plane.errors import AuthorizationDenied, ResourceNotFound, StateConflict
from pajin.control_plane.lifecycle_service import ControlPlaneLifecycleService
from pajin.control_plane.models import CancelRunRequest
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.stop_observations import (
    STOP_FENCE_EVENT,
    STOP_OBSERVATION_EVENT,
    _aware,
    _Digest,
    _digest,
    _EventId,
    _Identifier,
    _StopModel,
)
from pajin.domain.models import CampaignManifest, campaign_manifest_digest

URGENT_STOP_EVENT = "urgent-stop.applied"
URGENT_STOP_ACK_EVENT = "urgent-stop.acknowledged"


class UrgentStopBinding(_StopModel):
    """Trusted host configuration; this model is never accepted from an HTTP caller."""

    api_version: Literal["pajin.dev/urgent-stop-binding/v1"] = Field(
        default="pajin.dev/urgent-stop-binding/v1", alias="apiVersion"
    )
    run_id: _Identifier = Field(alias="runId")
    submission_digest: _Digest = Field(alias="submissionDigest")
    campaign_digest: _Digest = Field(alias="campaignDigest")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Digest = Field(alias="sourceRootDigest")
    result_artifact_id: _Identifier = Field(alias="resultArtifactId")
    result_artifact_digest: _Digest = Field(alias="resultArtifactDigest")
    terminal_handoff_id: _Identifier = Field(alias="terminalHandoffId")
    terminal_handoff_digest: _Digest = Field(alias="terminalHandoffDigest")
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Digest = Field(alias="authorityDigest")
    actor: _Identifier


class UrgentStopApplication(_StopModel):
    api_version: Literal["pajin.dev/urgent-stop-application/v1"] = Field(
        default="pajin.dev/urgent-stop-application/v1", alias="apiVersion"
    )
    binding: UrgentStopBinding
    decision: UrgentObservationFastGateDecision
    applied_at: datetime = Field(alias="appliedAt")
    state: Literal["control-plane-cancelled"] = "control-plane-cancelled"
    application_digest: str = Field(default="", alias="applicationDigest")

    @model_validator(mode="after")
    def bind_application(self) -> Self:
        if (
            self.decision.terminal_result_handoff_id != self.binding.terminal_handoff_id
            or self.decision.terminal_result_handoff_digest != self.binding.terminal_handoff_digest
            or self.decision.result_artifact_id != self.binding.result_artifact_id
            or self.decision.result_artifact_digest != self.binding.result_artifact_digest
            or self.decision.authority_id != self.binding.authority_id
            or self.decision.authority_digest != self.binding.authority_digest
        ):
            raise ValueError("Urgent stop decision differs from deployment binding")
        digest = _digest(
            "pajin.urgent-stop-application/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"application_digest"}),
        )
        if self.application_digest and self.application_digest != digest:
            raise ValueError("Urgent stop application digest differs")
        object.__setattr__(self, "application_digest", digest)
        return self


class UrgentStopAcknowledgment(_StopModel):
    alert_id: _EventId = Field(alias="alertId")
    application_digest: _Digest = Field(alias="applicationDigest")
    actor: _Identifier
    acknowledged_at: datetime = Field(alias="acknowledgedAt")


class UrgentStopAcknowledgeRequest(_StopModel):
    application_digest: _Digest = Field(alias="applicationDigest")


class UrgentStopAlert(_StopModel):
    alert_id: _EventId = Field(alias="alertId")
    application: UrgentStopApplication
    acknowledgment: UrgentStopAcknowledgment | None
    fenced_workers: int = Field(alias="fencedWorkers", ge=0)
    observed_workers: int = Field(alias="observedWorkers", ge=0)
    quiesced_workers: int = Field(alias="quiescedWorkers", ge=0)
    drained_workers: int = Field(alias="drainedWorkers", ge=0)
    incomplete_workers: int = Field(alias="incompleteWorkers", ge=0)


class UrgentStopAlertPage(_StopModel):
    items: list[UrgentStopAlert]
    next_cursor: _EventId | None = Field(alias="nextCursor")


def _application(row: EventRecord) -> UrgentStopApplication:
    try:
        value = UrgentStopApplication.model_validate(row.payload)
        if (
            value.model_dump(mode="json", by_alias=True) != row.payload
            or row.event_type != URGENT_STOP_EVENT
            or row.run_id != value.binding.run_id
            or row.actor != value.binding.actor
        ):
            raise ValueError("Urgent stop event binding differs")
        return value
    except (ValueError, TypeError) as exc:
        raise StateConflict("Stored urgent stop application is not integrity-valid") from exc


class UrgentStopService:
    def __init__(
        self,
        repository: ControlPlaneRepository,
        lifecycle: ControlPlaneLifecycleService,
        hooks: ControlPlaneTransactionHooks,
        authorizer: ControlPlaneRunCancellationAuthorizer | None,
    ) -> None:
        self._repository = repository
        self._lifecycle = lifecycle
        self._hooks = hooks
        self._authorizer = authorizer

    def _authorize(self, binding: UrgentStopBinding) -> None:
        if self._authorizer is None:
            raise AuthorizationDenied(
                "Urgent stop requires deployment-pinned Run cancellation ABAC"
            )
        self._authorizer.authorize_run_cancellation(
            principal_subject=binding.actor,
            submission_authority_digest=binding.submission_digest,
        )

    @staticmethod
    def _existing(session: Session, binding: UrgentStopBinding) -> UrgentStopApplication | None:
        rows = list(
            session.scalars(
                select(EventRecord)
                .where(
                    EventRecord.event_type == URGENT_STOP_EVENT,
                    EventRecord.payload["binding"]["terminalHandoffId"].as_string()
                    == binding.terminal_handoff_id,
                )
                .limit(2)
            )
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise StateConflict("Urgent stop handoff has multiple applications")
        value = _application(rows[0])
        if value.binding != binding:
            raise StateConflict("Urgent stop handoff is bound to another deployment target")
        return value

    def previous(self, binding: UrgentStopBinding) -> UrgentStopApplication | None:
        self._authorize(binding)
        with self._repository.read_transaction() as session:
            return self._existing(session, binding)

    def _apply_verified(
        self,
        binding: UrgentStopBinding,
        decision: UrgentObservationFastGateDecision,
    ) -> UrgentStopApplication:
        """Called only by the trusted runtime after complete source reconstruction."""

        from pajin.runtime.recovery_bindings import require_registered_control_plane

        require_registered_control_plane(str(self._repository.engine.url))
        self._authorize(binding)
        with self._repository.transaction() as session:
            if session.bind is not None and session.bind.dialect.name == "postgresql":
                lock_key = int.from_bytes(
                    sha256(("urgent-stop:" + binding.terminal_handoff_id).encode()).digest()[:8],
                    "big",
                    signed=True,
                )
                session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
            # Keep the existing Job -> Approval -> Run lock order and cancellation ABAC.
            self._lifecycle.cancel_run_in_transaction(
                session,
                binding.run_id,
                CancelRunRequest(
                    reason=f"Trusted urgent observation: {decision.observation_type.value}"
                ),
                actor=binding.actor,
            )
            run = ControlPlaneRecords.run(session, binding.run_id, lock=True)
            try:
                manifest = CampaignManifest.model_validate(run.input["manifest"])
                if (
                    run.submission_authority_digest != binding.submission_digest
                    or campaign_manifest_digest(manifest) != binding.campaign_digest
                    or manifest.metadata.name != decision.campaign_id
                ):
                    raise ValueError("Urgent stop target differs from its pinned submission")
            except (ValueError, KeyError, TypeError) as exc:
                # Any cancellation above rolls back together with this failed binding check.
                raise StateConflict(
                    "Urgent stop target is not the deployment-pinned Campaign"
                ) from exc
            previous = self._existing(session, binding)
            if previous is not None:
                if previous.decision != decision:
                    raise StateConflict("Urgent stop decision contradicts its recorded application")
                return previous
            value = UrgentStopApplication(
                binding=binding,
                decision=decision,
                appliedAt=self._hooks.clock(),
            )
            self._hooks.event_writer(
                session,
                run,
                URGENT_STOP_EVENT,
                binding.actor,
                value.model_dump(mode="json", by_alias=True),
            )
            return value

    def list_alerts(self, *, cursor: str | None = None, limit: int = 20) -> UrgentStopAlertPage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Urgent stop page limit must be between 1 and 100")
        with self._repository.read_transaction() as session:
            query = select(EventRecord).where(EventRecord.event_type == URGENT_STOP_EVENT)
            if cursor is not None:
                anchor = session.get(EventRecord, cursor)
                if anchor is None or anchor.event_type != URGENT_STOP_EVENT:
                    raise ResourceNotFound("Urgent stop cursor was not found")
                query = query.where(
                    (EventRecord.occurred_at < anchor.occurred_at)
                    | (
                        (EventRecord.occurred_at == anchor.occurred_at)
                        & (EventRecord.event_id < cursor)
                    )
                )
            rows = list(
                session.scalars(
                    query.order_by(
                        EventRecord.occurred_at.desc(), EventRecord.event_id.desc()
                    ).limit(limit + 1)
                )
            )
            items = []
            for row in rows[:limit]:
                value = _application(row)
                counts = {
                    event_type: count
                    for event_type, count in session.execute(
                        select(
                            EventRecord.event_type,
                            func.count(),
                        )
                        .where(
                            EventRecord.run_id == row.run_id,
                            EventRecord.event_type.in_((STOP_FENCE_EVENT, STOP_OBSERVATION_EVENT)),
                        )
                        .group_by(EventRecord.event_type)
                    ).all()
                }
                outcomes = session.execute(
                    select(
                        func.sum(
                            case(
                                (
                                    EventRecord.payload["report"]["cleanupStatus"]
                                    .as_string()
                                    .in_(("executor-drained", "quiesced")),
                                    1,
                                ),
                                else_=0,
                            )
                        ),
                        func.sum(
                            case(
                                (
                                    EventRecord.payload["report"]["cleanupStatus"].as_string()
                                    == "quiesced",
                                    1,
                                ),
                                else_=0,
                            )
                        ),
                        func.sum(
                            case(
                                (
                                    EventRecord.payload["report"]["cleanupStatus"].as_string()
                                    == "incomplete",
                                    1,
                                ),
                                else_=0,
                            )
                        ),
                    ).where(
                        EventRecord.run_id == row.run_id,
                        EventRecord.event_type == STOP_OBSERVATION_EVENT,
                    )
                ).one()
                acknowledgment = self._acknowledgment(session, row, value)
                items.append(
                    UrgentStopAlert(
                        alertId=row.event_id,
                        application=value,
                        acknowledgment=acknowledgment,
                        fencedWorkers=counts.get(STOP_FENCE_EVENT, 0),
                        observedWorkers=counts.get(STOP_OBSERVATION_EVENT, 0),
                        drainedWorkers=outcomes[0] or 0,
                        quiescedWorkers=outcomes[1] or 0,
                        incompleteWorkers=outcomes[2] or 0,
                    )
                )
            return UrgentStopAlertPage(
                items=items,
                nextCursor=rows[limit - 1].event_id if len(rows) > limit else None,
            )

    @staticmethod
    def _acknowledgment(
        session: Session,
        row: EventRecord,
        value: UrgentStopApplication,
    ) -> UrgentStopAcknowledgment | None:
        rows = list(
            session.scalars(
                select(EventRecord)
                .where(
                    EventRecord.run_id == row.run_id,
                    EventRecord.event_type == URGENT_STOP_ACK_EVENT,
                    EventRecord.payload["alertId"].as_string() == row.event_id,
                )
                .limit(2)
            )
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise StateConflict("Urgent stop acknowledgment is not unique")
        try:
            ack = UrgentStopAcknowledgment.model_validate(rows[0].payload)
            if (
                ack.model_dump(mode="json", by_alias=True) != rows[0].payload
                or ack.actor != rows[0].actor
                or ack.application_digest != value.application_digest
            ):
                raise ValueError("Urgent stop acknowledgment binding differs")
            return ack
        except (ValueError, TypeError) as exc:
            raise StateConflict("Stored urgent stop acknowledgment is not integrity-valid") from exc

    def acknowledge(
        self,
        alert_id: str,
        request: UrgentStopAcknowledgeRequest,
        *,
        actor: str,
    ) -> UrgentStopAcknowledgment:
        with self._repository.transaction() as session:
            row = session.get(EventRecord, alert_id)
            if row is None or row.event_type != URGENT_STOP_EVENT:
                raise ResourceNotFound("Urgent stop alert was not found")
            value = _application(row)
            run = ControlPlaneRecords.run(session, row.run_id, lock=True)
            if value.application_digest != request.application_digest:
                raise StateConflict("Urgent stop acknowledgment refers to another application")
            previous = self._acknowledgment(session, row, value)
            if previous is not None:
                return previous
            ack = UrgentStopAcknowledgment(
                alertId=alert_id,
                applicationDigest=value.application_digest,
                actor=actor,
                acknowledgedAt=_aware(self._hooks.clock()),
            )
            self._hooks.event_writer(
                session,
                run,
                URGENT_STOP_ACK_EVENT,
                actor,
                ack.model_dump(mode="json", by_alias=True),
            )
            return ack
