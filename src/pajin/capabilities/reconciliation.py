"""Sealed reconciliation for non-atomic Capability dispatch crash windows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
)
from pajin.capabilities.models import capability_definition_digest
from pajin.domain.models import StrictModel
from pajin.graph.authority import ActionPermit
from pajin.runtime.store import AuditEvent, VerifiedRunSnapshot

CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_API_VERSION: Literal[
    "pajin.dev/capability-graph-run-audit-anchor/v1alpha1"
] = "pajin.dev/capability-graph-run-audit-anchor/v1alpha1"
CAPABILITY_DISPATCH_RECONCILIATION_API_VERSION: Literal[
    "pajin.dev/capability-dispatch-reconciliation/v1alpha1"
] = "pajin.dev/capability-dispatch-reconciliation/v1alpha1"
CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE = "capability.graph.run.opened"
CAPABILITY_DISPATCH_RECONCILIATION_EVENT_TYPE = (
    "capability.dispatch-reconciliation.recorded"
)


class CapabilityDispatchReconciliationError(ValueError):
    """Raised when sealed dispatch evidence cannot be classified exactly."""


class CapabilityGraphRunAuditAnchor(StrictModel):
    """Content-addressed deployment identity sealed before a Permit claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/capability-graph-run-audit-anchor/v1alpha1"
    ] = Field(
        default=CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityGraphRunAuditAnchor"] = "CapabilityGraphRunAuditAnchor"
    anchor_id: str = Field(default="", alias="anchorId", max_length=110)
    anchor_digest: str = Field(
        default="",
        alias="anchorDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    deployment_id: str = Field(
        alias="deploymentId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    campaign_digest: str = Field(alias="campaignDigest", pattern=r"^[a-f0-9]{64}$")
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    envelope_id: str = Field(alias="envelopeId", min_length=1, max_length=81)
    envelope_digest: str = Field(alias="envelopeDigest", pattern=r"^[a-f0-9]{64}$")
    release_set_digest: str = Field(
        alias="releaseSetDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    activation_set_digest: str = Field(
        alias="activationSetDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    compiler_id: str = Field(
        alias="compilerId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    compiler_version: str = Field(
        alias="compilerVersion",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    compiler_digest: str = Field(alias="compilerDigest", pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"anchor_id", "anchor_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.graph-run-audit-anchor/v1",
            material,
        )
        anchor_id = f"capability-graph-run-anchor_{digest}"
        if self.anchor_digest and self.anchor_digest != digest:
            raise ValueError("Capability Graph Run anchor digest differs")
        if self.anchor_id and self.anchor_id != anchor_id:
            raise ValueError("Capability Graph Run anchor ID differs")
        object.__setattr__(self, "anchor_digest", digest)
        object.__setattr__(self, "anchor_id", anchor_id)
        return self


class CapabilityDispatchReconciliationStatus(StrEnum):
    """Closed classification of one consumed Permit and its sealed audit."""

    CONSUMED_WITHOUT_CLAIM = "consumed-without-claim"
    CLAIMED_OUTCOME_UNKNOWN = "claimed-outcome-unknown"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


_TERMINAL_STATUS_STAGE = {
    CapabilityDispatchReconciliationStatus.COMPLETED: CapabilityDispatchStage.COMPLETED,
    CapabilityDispatchReconciliationStatus.FAILED: CapabilityDispatchStage.FAILED,
    CapabilityDispatchReconciliationStatus.CANCELLED: CapabilityDispatchStage.CANCELLED,
    CapabilityDispatchReconciliationStatus.EXPIRED: CapabilityDispatchStage.EXPIRED,
}


class CapabilityDispatchReconciliation(StrictModel):
    """Content-addressed classification bound to the seal covering audit evidence."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/capability-dispatch-reconciliation/v1alpha1"
    ] = Field(
        default=CAPABILITY_DISPATCH_RECONCILIATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityDispatchReconciliation"] = (
        "CapabilityDispatchReconciliation"
    )
    reconciliation_id: str = Field(
        default="",
        alias="reconciliationId",
        max_length=110,
    )
    reconciliation_digest: str = Field(
        default="",
        alias="reconciliationDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    status: CapabilityDispatchReconciliationStatus
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    permit_id: str = Field(alias="permitId", min_length=1, max_length=78)
    permit_digest: str = Field(alias="permitDigest", pattern=r"^[a-f0-9]{64}$")
    dispatch_id: str = Field(alias="dispatchId", min_length=1, max_length=80)
    observed_audit_sequence: int = Field(alias="observedAuditSequence", ge=1)
    observed_audit_event_hash: str = Field(
        alias="observedAuditEventHash",
        pattern=r"^[a-f0-9]{64}$",
    )
    evidence_seal_root_digest: str = Field(
        alias="evidenceSealRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    dispatch_event_digests: tuple[str, ...] = Field(
        alias="dispatchEventDigests",
        max_length=2,
    )
    terminal_stage: CapabilityDispatchStage | None = Field(
        default=None,
        alias="terminalStage",
    )
    terminal_event_digest: str | None = Field(
        default=None,
        alias="terminalEventDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    redispatch_allowed: Literal[False] = Field(
        default=False,
        alias="redispatchAllowed",
    )
    manual_review_required: bool = Field(alias="manualReviewRequired")

    @model_validator(mode="after")
    def bind_classification_and_identity(self) -> Self:
        if len(set(self.dispatch_event_digests)) != len(self.dispatch_event_digests):
            raise ValueError("Capability reconciliation event digests must be unique")
        expected_terminal = _TERMINAL_STATUS_STAGE.get(self.status)
        incomplete = self.status in {
            CapabilityDispatchReconciliationStatus.CONSUMED_WITHOUT_CLAIM,
            CapabilityDispatchReconciliationStatus.CLAIMED_OUTCOME_UNKNOWN,
        }
        expected_event_count = (
            0
            if self.status
            is CapabilityDispatchReconciliationStatus.CONSUMED_WITHOUT_CLAIM
            else 1
            if self.status
            is CapabilityDispatchReconciliationStatus.CLAIMED_OUTCOME_UNKNOWN
            else 2
        )
        if len(self.dispatch_event_digests) != expected_event_count:
            raise ValueError(
                "Capability reconciliation event count differs from its status"
            )
        if (
            self.terminal_stage != expected_terminal
            or (self.terminal_event_digest is None) != (expected_terminal is None)
        ):
            raise ValueError(
                "Capability reconciliation terminal evidence differs from its status"
            )
        if self.manual_review_required is not incomplete:
            raise ValueError(
                "Capability reconciliation manual-review flag differs from its status"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reconciliation_id", "reconciliation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.dispatch-reconciliation/v1",
            material,
        )
        reconciliation_id = f"capability-dispatch-reconciliation_{digest}"
        if self.reconciliation_digest and self.reconciliation_digest != digest:
            raise ValueError("Capability dispatch reconciliation digest differs")
        if self.reconciliation_id and self.reconciliation_id != reconciliation_id:
            raise ValueError("Capability dispatch reconciliation ID differs")
        object.__setattr__(self, "reconciliation_digest", digest)
        object.__setattr__(self, "reconciliation_id", reconciliation_id)
        return self


@dataclass(frozen=True, slots=True)
class CapabilityDispatchReconciliationObservation:
    """Verified record plus the optional terminal event needed by the Worker."""

    record: CapabilityDispatchReconciliation
    terminal_event: CapabilityDispatchAuditEvent | None
    already_recorded: bool


def reconcile_capability_dispatch(
    snapshot: VerifiedRunSnapshot,
    permit: ActionPermit,
) -> CapabilityDispatchReconciliationObservation:
    """Classify one consumed Permit without granting redispatch authority."""

    if not isinstance(snapshot, VerifiedRunSnapshot):
        raise TypeError("Capability dispatch reconciliation requires a verified Run snapshot")
    if not isinstance(permit, ActionPermit):
        raise TypeError("Capability dispatch reconciliation requires an ActionPermit")
    if (
        snapshot.verification.run_id != permit.run_id
        or any(event.run_id != permit.run_id for event in snapshot.events)
    ):
        raise CapabilityDispatchReconciliationError(
            "Capability reconciliation Run differs from the consumed ActionPermit"
        )

    anchors, dispatch_events, existing_records = _scan_snapshot(snapshot, permit)
    lifecycle = tuple(event for _, event in dispatch_events)
    _validate_lifecycle(permit, lifecycle)
    observed_event, status, terminal_event = _classify_lifecycle(
        anchors,
        dispatch_events,
    )
    evidence_seal_root_digest = _evidence_seal_root_digest(
        snapshot,
        observed_event,
    )
    record = CapabilityDispatchReconciliation(
        status=status,
        campaignId=permit.campaign_id,
        runId=permit.run_id,
        permitId=permit.permit_id,
        permitDigest=permit.permit_digest,
        dispatchId=permit.dispatch_id,
        observedAuditSequence=observed_event.sequence,
        observedAuditEventHash=observed_event.event_hash,
        evidenceSealRootDigest=evidence_seal_root_digest,
        dispatchEventDigests=tuple(event.event_digest for event in lifecycle),
        terminalStage=terminal_event.stage if terminal_event is not None else None,
        terminalEventDigest=(
            terminal_event.event_digest if terminal_event is not None else None
        ),
        manualReviewRequired=terminal_event is None,
    )
    if len(existing_records) > 1 or any(
        existing != record for existing in existing_records
    ):
        raise CapabilityDispatchReconciliationError(
            "sealed Capability reconciliation record differs or is duplicated"
        )
    return CapabilityDispatchReconciliationObservation(
        record=record,
        terminal_event=terminal_event,
        already_recorded=bool(existing_records),
    )


def _scan_snapshot(
    snapshot: VerifiedRunSnapshot,
    permit: ActionPermit,
) -> tuple[
    list[tuple[AuditEvent, CapabilityGraphRunAuditAnchor]],
    list[tuple[AuditEvent, CapabilityDispatchAuditEvent]],
    list[CapabilityDispatchReconciliation],
]:
    anchors: list[tuple[AuditEvent, CapabilityGraphRunAuditAnchor]] = []
    dispatch_events: list[tuple[AuditEvent, CapabilityDispatchAuditEvent]] = []
    existing_records: list[CapabilityDispatchReconciliation] = []
    for audit_event in snapshot.events:
        if audit_event.event_type == CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE:
            anchor = _parse_run_anchor(audit_event)
            if (
                anchor.run_id == permit.run_id
                and anchor.campaign_id == permit.campaign_id
            ):
                anchors.append((audit_event, anchor))
        elif audit_event.event_type.startswith("capability.dispatch."):
            event = _parse_dispatch_event(audit_event)
            if event.permit_id == permit.permit_id:
                dispatch_events.append((audit_event, event))
        elif audit_event.event_type == CAPABILITY_DISPATCH_RECONCILIATION_EVENT_TYPE:
            record = _parse_reconciliation_record(audit_event)
            if record.permit_id == permit.permit_id:
                existing_records.append(record)
    return anchors, dispatch_events, existing_records


def _parse_run_anchor(audit_event: AuditEvent) -> CapabilityGraphRunAuditAnchor:
    try:
        return CapabilityGraphRunAuditAnchor.model_validate(audit_event.payload)
    except ValidationError as exc:
        raise CapabilityDispatchReconciliationError(
            "Capability Graph Run anchor is invalid"
        ) from exc


def _parse_dispatch_event(audit_event: AuditEvent) -> CapabilityDispatchAuditEvent:
    try:
        event = CapabilityDispatchAuditEvent.model_validate(audit_event.payload)
    except ValidationError as exc:
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch audit event is invalid"
        ) from exc
    if audit_event.event_type != f"capability.dispatch.{event.stage.value}":
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch outer event type differs from its stage"
        )
    return event


def _parse_reconciliation_record(
    audit_event: AuditEvent,
) -> CapabilityDispatchReconciliation:
    try:
        return CapabilityDispatchReconciliation.model_validate(audit_event.payload)
    except ValidationError as exc:
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch reconciliation record is invalid"
        ) from exc


def _classify_lifecycle(
    anchors: list[tuple[AuditEvent, CapabilityGraphRunAuditAnchor]],
    dispatch_events: list[tuple[AuditEvent, CapabilityDispatchAuditEvent]],
) -> tuple[
    AuditEvent,
    CapabilityDispatchReconciliationStatus,
    CapabilityDispatchAuditEvent | None,
]:
    lifecycle = tuple(event for _, event in dispatch_events)
    if not lifecycle:
        if len(anchors) != 1:
            raise CapabilityDispatchReconciliationError(
                "consumed Permit without dispatch audit requires one sealed Run anchor"
            )
        return (
            anchors[0][0],
            CapabilityDispatchReconciliationStatus.CONSUMED_WITHOUT_CLAIM,
            None,
        )
    if len(lifecycle) == 1:
        return (
            dispatch_events[0][0],
            CapabilityDispatchReconciliationStatus.CLAIMED_OUTCOME_UNKNOWN,
            None,
        )
    terminal_event = lifecycle[-1]
    return (
        dispatch_events[-1][0],
        CapabilityDispatchReconciliationStatus(terminal_event.stage.value),
        terminal_event,
    )


def _evidence_seal_root_digest(
    snapshot: VerifiedRunSnapshot,
    observed_event: AuditEvent,
) -> str:
    evidence_seal = next(
        (
            seal
            for seal in snapshot.seals
            if seal.event_count >= observed_event.sequence
        ),
        None,
    )
    if evidence_seal is None:
        raise CapabilityDispatchReconciliationError(
            "Capability reconciliation evidence is not covered by a Run seal"
        )
    return evidence_seal.root_digest


def _validate_lifecycle(
    permit: ActionPermit,
    lifecycle: tuple[CapabilityDispatchAuditEvent, ...],
) -> None:
    if len(lifecycle) > 2:
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch audit lifecycle is duplicated"
        )
    if lifecycle and lifecycle[0].stage is not CapabilityDispatchStage.CLAIMED:
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch terminal audit is missing its claimed event"
        )
    if len(lifecycle) == 2 and lifecycle[1].stage not in {
        CapabilityDispatchStage.COMPLETED,
        CapabilityDispatchStage.FAILED,
        CapabilityDispatchStage.CANCELLED,
        CapabilityDispatchStage.EXPIRED,
    }:
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch audit lifecycle has no valid terminal stage"
        )
    if len(lifecycle) == 2 and lifecycle[1].occurred_at < lifecycle[0].occurred_at:
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch terminal audit predates its claimed event"
        )
    for event in lifecycle:
        if (
            event.permit_digest != permit.permit_digest
            or event.dispatch_id != permit.dispatch_id
            or event.campaign_id != permit.campaign_id
            or event.run_id != permit.run_id
            or event.proposal_id != permit.proposal_id
            or event.proposal_digest != permit.proposal_digest
            or event.request_id != permit.request_id
            or event.request_digest != permit.request_digest
            or event.normalized_parameters_digest
            != permit.normalized_parameters_digest
        ):
            raise CapabilityDispatchReconciliationError(
                "Capability dispatch audit differs from the consumed ActionPermit"
            )
    if len(lifecycle) == 2 and (
        lifecycle[0].activation_set_digest != lifecycle[1].activation_set_digest
        or lifecycle[0].release != lifecycle[1].release
    ):
        raise CapabilityDispatchReconciliationError(
            "Capability dispatch terminal authority differs from its claimed event"
        )
