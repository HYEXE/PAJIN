"""Verified, redacted Graph Decision audit views for Control Plane operators."""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path
from re import fullmatch
from typing import Literal

from pydantic import Field

from pajin.domain.models import StrictModel
from pajin.graph import (
    GraphDecisionAuditError,
    GraphDecisionAuditRecord,
    GraphDecisionKind,
    GraphEventLogError,
    GraphProjectionError,
    GraphSnapshotError,
    SQLiteGraphStoreError,
    load_verified_graph_decision_audit,
    require_distinct_graph_decision_audit_paths,
)

_CAMPAIGN_PATTERN = r"^[a-z0-9][a-z0-9-]{2,79}$"
_SNAPSHOT_ID_PATTERN = r"^graph-snapshot_[a-f0-9]{64}$"
_PROJECTION_ID_PATTERN = r"^graph-projection_[a-f0-9]{64}$"
_DECISION_ID_PATTERN = r"^graph-decision_[a-f0-9]{64}$"
_RECORD_ID_PATTERN = r"^graph-decision-audit-record_[a-f0-9]{64}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_MAX_CURRENT_SNAPSHOT_DECISIONS = 500


class GraphDecisionAuditViewUnavailable(RuntimeError):
    """Raised when one of the two server-owned databases is not configured."""


class GraphDecisionAuditViewNotFound(RuntimeError):
    """Raised when the exact requested current Graph Snapshot is absent."""


class GraphDecisionAuditViewIntegrityError(RuntimeError):
    """Raised when either durable authority or a cross-store binding differs."""


class GraphDecisionAuditViewTooLarge(RuntimeError):
    """Raised when the current Snapshot Decision set exceeds the view bound."""


class GraphDecisionAuditItemView(StrictModel):
    sequence: int = Field(ge=1)
    record_id: str = Field(alias="recordId", pattern=_RECORD_ID_PATTERN)
    record_digest: str = Field(alias="recordDigest", pattern=_SHA256_PATTERN)
    previous_record_digest: str | None = Field(
        alias="previousRecordDigest",
        pattern=_SHA256_PATTERN,
    )
    decision_id: str = Field(alias="decisionId", pattern=_DECISION_ID_PATTERN)
    decision_digest: str = Field(alias="decisionDigest", pattern=_SHA256_PATTERN)
    decision_kind: GraphDecisionKind = Field(alias="decisionKind")
    decision_payload_digest: str = Field(
        alias="decisionPayloadDigest",
        pattern=_SHA256_PATTERN,
    )
    actor_digest: str = Field(alias="actorDigest", pattern=_SHA256_PATTERN)
    recorder_digest: str = Field(alias="recorderDigest", pattern=_SHA256_PATTERN)
    decision_created_at: datetime = Field(alias="decisionCreatedAt")
    recorded_at: datetime = Field(alias="recordedAt")


class GraphDecisionAuditViewAuthorityBoundary(StrictModel):
    canonical_graph_snapshot_verified: Literal[True] = Field(
        default=True,
        alias="canonicalGraphSnapshotVerified",
    )
    current_snapshot_verified: Literal[True] = Field(
        default=True,
        alias="currentSnapshotVerified",
    )
    complete_audit_chain_verified: Literal[True] = Field(
        default=True,
        alias="completeAuditChainVerified",
    )
    historical_snapshot_bindings_verified: Literal[True] = Field(
        default=True,
        alias="historicalSnapshotBindingsVerified",
    )
    append_only_historical_retention: Literal[True] = Field(
        default=True,
        alias="appendOnlyHistoricalRetention",
    )
    identifiers_redacted: Literal[True] = Field(
        default=True,
        alias="identifiersRedacted",
    )
    view_selects_hypothesis: Literal[False] = Field(
        default=False,
        alias="viewSelectsHypothesis",
    )
    view_records_decision: Literal[False] = Field(
        default=False,
        alias="viewRecordsDecision",
    )
    view_schedules_work: Literal[False] = Field(
        default=False,
        alias="viewSchedulesWork",
    )
    view_approves_action: Literal[False] = Field(
        default=False,
        alias="viewApprovesAction",
    )
    view_grants_capability: Literal[False] = Field(
        default=False,
        alias="viewGrantsCapability",
    )
    view_grants_permit: Literal[False] = Field(
        default=False,
        alias="viewGrantsPermit",
    )
    view_authorizes_execution: Literal[False] = Field(
        default=False,
        alias="viewAuthorizesExecution",
    )


class VerifiedGraphDecisionAuditView(StrictModel):
    api_version: Literal["pajin.control-plane/verified-graph-decision-audit-view/v1alpha1"] = Field(
        default="pajin.control-plane/verified-graph-decision-audit-view/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["VerifiedGraphDecisionAuditView"] = "VerifiedGraphDecisionAuditView"
    campaign_id: str = Field(alias="campaignId", pattern=_CAMPAIGN_PATTERN)
    snapshot_id: str = Field(alias="snapshotId", pattern=_SNAPSHOT_ID_PATTERN)
    snapshot_digest: str = Field(alias="snapshotDigest", pattern=_SHA256_PATTERN)
    projection_id: str = Field(alias="projectionId", pattern=_PROJECTION_ID_PATTERN)
    projection_digest: str = Field(alias="projectionDigest", pattern=_SHA256_PATTERN)
    audit_schema_version: Literal[1] = Field(default=1, alias="auditSchemaVersion")
    audit_schema_digest: str = Field(alias="auditSchemaDigest", pattern=_SHA256_PATTERN)
    recorder_digest: str = Field(alias="recorderDigest", pattern=_SHA256_PATTERN)
    total_record_count: int = Field(alias="totalRecordCount", ge=0)
    current_snapshot_decision_count: int = Field(
        alias="currentSnapshotDecisionCount",
        ge=0,
        le=_MAX_CURRENT_SNAPSHOT_DECISIONS,
    )
    audit_head_digest: str | None = Field(
        alias="auditHeadDigest",
        pattern=_SHA256_PATTERN,
    )
    decisions: list[GraphDecisionAuditItemView] = Field(max_length=_MAX_CURRENT_SNAPSHOT_DECISIONS)
    authority_boundary: GraphDecisionAuditViewAuthorityBoundary = Field(alias="authorityBoundary")


class VerifiedGraphDecisionAuditViewReader:
    """Join two query-only authorities without manufacturing Decision authority."""

    def __init__(
        self,
        *,
        graph_database: Path | None,
        audit_database: Path | None,
    ) -> None:
        self._graph_database = _absolute_path(graph_database)
        self._audit_database = _absolute_path(audit_database)

    def read(
        self,
        *,
        campaign: str,
        snapshot_id: str,
    ) -> VerifiedGraphDecisionAuditView:
        if self._graph_database is None or self._audit_database is None:
            raise GraphDecisionAuditViewUnavailable("Graph Decision audit views are not configured")
        _require_identifier(campaign, _CAMPAIGN_PATTERN, label="Campaign")
        _require_identifier(snapshot_id, _SNAPSHOT_ID_PATTERN, label="Graph Snapshot")
        try:
            graph_database = _validated_regular_database(
                self._graph_database,
                label="Canonical Graph database",
            )
            audit_database = _validated_regular_database(
                self._audit_database,
                label="Graph Decision audit database",
            )
            require_distinct_graph_decision_audit_paths(
                audit_database,
                graph_database,
            )
            verified = load_verified_graph_decision_audit(
                audit_database,
                graph_database=graph_database,
                campaign_id=campaign,
                snapshot_id=snapshot_id,
            )
        except (
            GraphDecisionAuditError,
            GraphEventLogError,
            GraphProjectionError,
            GraphSnapshotError,
            SQLiteGraphStoreError,
            OSError,
            ValueError,
        ) as exc:
            raise GraphDecisionAuditViewIntegrityError(
                "Graph Decision audit authority is not integrity-valid"
            ) from exc
        if verified is None:
            raise GraphDecisionAuditViewNotFound("Canonical Graph Snapshot was not found")
        current_records = [
            record
            for record in verified.records
            if record.decision.snapshot.snapshot_id == snapshot_id
        ]
        if len(current_records) > _MAX_CURRENT_SNAPSHOT_DECISIONS:
            raise GraphDecisionAuditViewTooLarge(
                "Current Graph Snapshot Decision audit exceeds view limits"
            )
        snapshot = verified.current_snapshot
        return VerifiedGraphDecisionAuditView(
            campaignId=campaign,
            snapshotId=snapshot.snapshot_id,
            snapshotDigest=snapshot.snapshot_digest,
            projectionId=snapshot.projection_id,
            projectionDigest=snapshot.projection_digest,
            auditSchemaVersion=verified.schema_version,
            auditSchemaDigest=verified.schema_digest,
            recorderDigest=verified.recorder_digest,
            totalRecordCount=len(verified.records),
            currentSnapshotDecisionCount=len(current_records),
            auditHeadDigest=verified.head_digest,
            decisions=[_decision_view(record) for record in current_records],
            authorityBoundary=GraphDecisionAuditViewAuthorityBoundary(),
        )


def _decision_view(record: GraphDecisionAuditRecord) -> GraphDecisionAuditItemView:
    decision = record.decision
    return GraphDecisionAuditItemView(
        sequence=record.sequence,
        recordId=record.record_id,
        recordDigest=record.record_digest,
        previousRecordDigest=record.previous_record_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        decisionKind=decision.decision_kind,
        decisionPayloadDigest=decision.decision_payload_digest,
        actorDigest=decision.actor_digest,
        recorderDigest=record.recorder_digest,
        decisionCreatedAt=decision.created_at,
        recordedAt=record.recorded_at,
    )


def _absolute_path(path: Path | None) -> Path | None:
    if path is None:
        return None
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _validated_regular_database(path: Path, *, label: str) -> Path:
    try:
        parent_stat = path.parent.lstat()
        file_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        path.parent.is_symlink()
        or path.parent.is_junction()
        or path.is_symlink()
        or path.is_junction()
        or not stat.S_ISDIR(parent_stat.st_mode)
        or not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_nlink != 1
    ):
        raise ValueError(f"{label} path identity is invalid")
    return path


def _require_identifier(value: str, pattern: str, *, label: str) -> None:
    if not isinstance(value, str) or fullmatch(pattern, value) is None:
        raise ValueError(f"{label} identifier is invalid")
