"""Verified, bounded Canonical Graph projections for Control Plane operators."""

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
    GraphAction,
    GraphCampaignFact,
    GraphContentOrigin,
    GraphEdge,
    GraphEventLogError,
    GraphEvidence,
    GraphHypothesis,
    GraphNode,
    GraphNodeKind,
    GraphObservation,
    GraphProjectionError,
    GraphSnapshot,
    GraphSnapshotError,
    GraphSnapshotReason,
    GraphSurface,
    SQLiteGraphStoreError,
    load_verified_current_graph_snapshot,
)

_CAMPAIGN_PATTERN = r"^[a-z0-9][a-z0-9-]{2,79}$"
_SNAPSHOT_ID_PATTERN = r"^graph-snapshot_[a-f0-9]{64}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_PROJECTION_ID_PATTERN = r"^graph-projection_[a-f0-9]{64}$"
_NODE_ID_PATTERN = r"^graph-node_[a-f0-9]{64}$"
_EDGE_ID_PATTERN = r"^graph-edge_[a-f0-9]{64}$"
_MAX_VIEW_NODES = 500
_MAX_VIEW_EDGES = 1_000


class CanonicalGraphViewUnavailable(RuntimeError):
    """Raised when no server-owned Graph database is configured."""


class CanonicalGraphViewNotFound(RuntimeError):
    """Raised when the exact current Graph Snapshot does not exist."""


class CanonicalGraphViewIntegrityError(RuntimeError):
    """Raised when the durable Graph authorities do not agree."""


class CanonicalGraphViewTooLarge(RuntimeError):
    """Raised when the exact Snapshot cannot fit the bounded operator view."""


class CanonicalGraphSnapshotView(StrictModel):
    snapshot_id: str = Field(alias="snapshotId", pattern=_SNAPSHOT_ID_PATTERN)
    snapshot_digest: str = Field(alias="snapshotDigest", pattern=_SHA256_PATTERN)
    previous_snapshot_digest: str | None = Field(
        alias="previousSnapshotDigest",
        pattern=_SHA256_PATTERN,
    )
    reason: GraphSnapshotReason
    created_at: datetime = Field(alias="createdAt")
    creator_id: str = Field(alias="creatorId", min_length=1, max_length=200)
    creator_digest: str = Field(alias="creatorDigest", pattern=_SHA256_PATTERN)


class CanonicalGraphProjectionView(StrictModel):
    graph_schema_version: Literal["pajin.dev/canonical-graph/v1alpha1"] = Field(
        alias="graphSchemaVersion"
    )
    revision: int = Field(ge=0)
    event_log_head_digest: str | None = Field(
        alias="eventLogHeadDigest",
        pattern=_SHA256_PATTERN,
    )
    projection_id: str = Field(alias="projectionId", pattern=_PROJECTION_ID_PATTERN)
    projection_digest: str = Field(alias="projectionDigest", pattern=_SHA256_PATTERN)
    node_projection_digest: str = Field(
        alias="nodeProjectionDigest",
        pattern=_SHA256_PATTERN,
    )
    edge_projection_digest: str = Field(
        alias="edgeProjectionDigest",
        pattern=_SHA256_PATTERN,
    )


class CanonicalGraphNodeView(StrictModel):
    node_id: str = Field(alias="nodeId", pattern=_NODE_ID_PATTERN)
    kind: GraphNodeKind
    display_key: str = Field(alias="displayKey", min_length=1, max_length=200)
    display_value: str | None = Field(
        default=None,
        alias="displayValue",
        min_length=1,
        max_length=200,
    )
    origin: GraphContentOrigin | None = None
    state: str | None = Field(default=None, min_length=1, max_length=100)
    confidence: float | None = Field(default=None, ge=0, le=1)
    occurred_at: datetime | None = Field(default=None, alias="occurredAt")


class CanonicalGraphEndpointView(StrictModel):
    node_id: str = Field(alias="nodeId", pattern=_NODE_ID_PATTERN)
    kind: GraphNodeKind


class CanonicalGraphEdgeView(StrictModel):
    edge_id: str = Field(alias="edgeId", pattern=_EDGE_ID_PATTERN)
    relation: str = Field(min_length=1, max_length=100)
    source: CanonicalGraphEndpointView
    target: CanonicalGraphEndpointView
    authority_id: str = Field(alias="authorityId", min_length=1, max_length=200)
    authority_digest: str = Field(alias="authorityDigest", pattern=_SHA256_PATTERN)


class CanonicalGraphViewAuthorityBoundary(StrictModel):
    canonical_graph_snapshot_verified: Literal[True] = Field(
        default=True,
        alias="canonicalGraphSnapshotVerified",
    )
    current_snapshot_verified: Literal[True] = Field(
        default=True,
        alias="currentSnapshotVerified",
    )
    content_redacted: Literal[True] = Field(default=True, alias="contentRedacted")
    view_authorizes_admission: Literal[False] = Field(
        default=False,
        alias="viewAuthorizesAdmission",
    )
    view_grants_capability: Literal[False] = Field(
        default=False,
        alias="viewGrantsCapability",
    )
    view_grants_permit: Literal[False] = Field(default=False, alias="viewGrantsPermit")
    view_authorizes_execution: Literal[False] = Field(
        default=False,
        alias="viewAuthorizesExecution",
    )


class VerifiedCanonicalGraphView(StrictModel):
    api_version: Literal["pajin.control-plane/verified-canonical-graph-view/v1alpha1"] = Field(
        default="pajin.control-plane/verified-canonical-graph-view/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["VerifiedCanonicalGraphView"] = "VerifiedCanonicalGraphView"
    campaign_id: str = Field(alias="campaignId", pattern=_CAMPAIGN_PATTERN)
    snapshot: CanonicalGraphSnapshotView
    projection: CanonicalGraphProjectionView
    node_count: int = Field(alias="nodeCount", ge=0, le=_MAX_VIEW_NODES)
    edge_count: int = Field(alias="edgeCount", ge=0, le=_MAX_VIEW_EDGES)
    nodes: list[CanonicalGraphNodeView] = Field(max_length=_MAX_VIEW_NODES)
    edges: list[CanonicalGraphEdgeView] = Field(max_length=_MAX_VIEW_EDGES)
    authority_boundary: CanonicalGraphViewAuthorityBoundary = Field(alias="authorityBoundary")


class VerifiedCanonicalGraphViewReader:
    """Project one current durable Graph Snapshot without Graph write authority."""

    def __init__(self, database: Path | None) -> None:
        self._database = self._validated_database(database) if database is not None else None

    def read(self, *, campaign: str, snapshot_id: str) -> VerifiedCanonicalGraphView:
        if self._database is None:
            raise CanonicalGraphViewUnavailable("Canonical Graph views are not configured")
        _require_identifier(campaign, _CAMPAIGN_PATTERN, label="Campaign")
        _require_identifier(snapshot_id, _SNAPSHOT_ID_PATTERN, label="Graph Snapshot")
        try:
            snapshot = load_verified_current_graph_snapshot(
                self._database,
                campaign_id=campaign,
                snapshot_id=snapshot_id,
            )
        except (
            GraphEventLogError,
            GraphProjectionError,
            GraphSnapshotError,
            SQLiteGraphStoreError,
            OSError,
            ValueError,
        ) as exc:
            raise CanonicalGraphViewIntegrityError(
                "Canonical Graph authority is not integrity-valid"
            ) from exc
        if snapshot is None:
            raise CanonicalGraphViewNotFound("Canonical Graph Snapshot was not found")
        if (
            len(snapshot.projection.nodes) > _MAX_VIEW_NODES
            or len(snapshot.projection.edges) > _MAX_VIEW_EDGES
        ):
            raise CanonicalGraphViewTooLarge("Canonical Graph Snapshot exceeds view limits")
        return _build_view(snapshot)

    @staticmethod
    def _validated_database(database: Path) -> Path:
        path = Path(os.path.abspath(os.fspath(database.expanduser())))
        try:
            parent_stat = path.parent.lstat()
            file_stat = path.lstat()
        except OSError as exc:
            raise ValueError("Canonical Graph database is unavailable") from exc
        if (
            path.parent.is_symlink()
            or path.parent.is_junction()
            or path.is_symlink()
            or path.is_junction()
            or not stat.S_ISDIR(parent_stat.st_mode)
            or not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
        ):
            raise ValueError("Canonical Graph database path identity is invalid")
        return path


def _build_view(snapshot: GraphSnapshot) -> VerifiedCanonicalGraphView:
    projection = snapshot.projection
    return VerifiedCanonicalGraphView(
        campaignId=snapshot.campaign_id,
        snapshot=CanonicalGraphSnapshotView(
            snapshotId=snapshot.snapshot_id,
            snapshotDigest=snapshot.snapshot_digest,
            previousSnapshotDigest=snapshot.previous_snapshot_digest,
            reason=snapshot.reason,
            createdAt=snapshot.created_at,
            creatorId=snapshot.creator_id,
            creatorDigest=snapshot.creator_digest,
        ),
        projection=CanonicalGraphProjectionView(
            graphSchemaVersion=snapshot.graph_schema_version,
            revision=snapshot.revision,
            eventLogHeadDigest=snapshot.event_log_head_digest,
            projectionId=snapshot.projection_id,
            projectionDigest=snapshot.projection_digest,
            nodeProjectionDigest=snapshot.node_projection_digest,
            edgeProjectionDigest=snapshot.edge_projection_digest,
        ),
        nodeCount=len(projection.nodes),
        edgeCount=len(projection.edges),
        nodes=[_node_view(node) for node in projection.nodes],
        edges=[_edge_view(edge) for edge in projection.edges],
        authorityBoundary=CanonicalGraphViewAuthorityBoundary(),
    )


def _node_view(node: GraphNode) -> CanonicalGraphNodeView:
    if isinstance(node, GraphSurface):
        return _display_node(
            node,
            display_key=node.surface_type,
            display_value=node.target_id,
            origin=node.origin,
        )
    if isinstance(node, GraphHypothesis):
        return _display_node(
            node,
            display_key=node.hypothesis_type,
            display_value=node.producer_id,
            origin=node.origin,
            confidence=node.confidence,
        )
    if isinstance(node, GraphAction):
        return _display_node(
            node,
            display_key=node.tool_id,
            display_value=node.capability_id,
            state=node.status.value,
            occurred_at=node.executed_at,
        )
    if isinstance(node, GraphObservation):
        return _display_node(
            node,
            display_key=node.observation_type,
            display_value=node.producer_id,
            origin=node.origin,
            confidence=node.confidence,
            occurred_at=node.observed_at,
        )
    if isinstance(node, GraphEvidence):
        return _display_node(
            node,
            display_key=node.media_type,
            display_value=node.data_classification,
        )
    if isinstance(node, GraphCampaignFact):
        return _display_node(
            node,
            display_key=node.fact_key,
            display_value=node.validation_state.value,
            origin=node.origin,
            state=node.validation_state.value,
            occurred_at=node.recorded_at,
        )
    raise CanonicalGraphViewIntegrityError("Canonical Graph node kind is unsupported")


def _display_node(
    node: GraphNode,
    *,
    display_key: str,
    display_value: str | None = None,
    origin: GraphContentOrigin | None = None,
    state: str | None = None,
    confidence: float | None = None,
    occurred_at: datetime | None = None,
) -> CanonicalGraphNodeView:
    return CanonicalGraphNodeView(
        nodeId=node.node_id,
        kind=GraphNodeKind(node.kind),
        displayKey=display_key,
        displayValue=display_value,
        origin=origin,
        state=state,
        confidence=confidence,
        occurredAt=occurred_at,
    )


def _edge_view(edge: GraphEdge) -> CanonicalGraphEdgeView:
    return CanonicalGraphEdgeView(
        edgeId=edge.edge_id,
        relation=edge.relation.value,
        source=CanonicalGraphEndpointView(
            nodeId=edge.source.node_id,
            kind=edge.source.kind,
        ),
        target=CanonicalGraphEndpointView(
            nodeId=edge.target.node_id,
            kind=edge.target.kind,
        ),
        authorityId=edge.authority_id,
        authorityDigest=edge.authority_digest,
    )


def _require_identifier(value: str, pattern: str, *, label: str) -> None:
    if not isinstance(value, str) or fullmatch(pattern, value) is None:
        raise ValueError(f"{label} identifier is invalid")
