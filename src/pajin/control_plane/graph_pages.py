"""Bounded redacted pages over one fully verified current Graph Snapshot."""

from __future__ import annotations

import base64
import binascii
from typing import Literal, Self

from pydantic import Field, model_validator

from pajin.control_plane.graph_views import (
    CanonicalGraphEdgeView,
    CanonicalGraphNodeView,
    CanonicalGraphProjectionView,
    CanonicalGraphSnapshotView,
    CanonicalGraphViewAuthorityBoundary,
    _edge_view,
    _node_view,
    _projection_view,
    _snapshot_view,
)
from pajin.domain.models import StrictModel
from pajin.graph import GraphSnapshot
from pajin.runtime.safe_files import parse_strict_json_bytes


class GraphPageCursorError(ValueError):
    """The position does not belong to this exact Snapshot and page size."""


class _Cursor(StrictModel):
    api_version: Literal["pajin.control-plane/graph-page-cursor/v1"] = (
        "pajin.control-plane/graph-page-cursor/v1"
    )
    campaign: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    snapshot_id: str = Field(pattern=r"^graph-snapshot_[a-f0-9]{64}$")
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    projection_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    limit: int = Field(strict=True, ge=1, le=500)
    offset: int = Field(strict=True, ge=1, lt=200_000)

    def encode(self) -> str:
        return base64.urlsafe_b64encode(self.model_dump_json().encode()).decode().rstrip("=")


class VerifiedCanonicalGraphPage(StrictModel):
    api_version: Literal["pajin.control-plane/verified-canonical-graph-page/v1"] = Field(
        default="pajin.control-plane/verified-canonical-graph-page/v1",
        alias="apiVersion",
    )
    kind: Literal["VerifiedCanonicalGraphPage"] = "VerifiedCanonicalGraphPage"
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    snapshot: CanonicalGraphSnapshotView
    projection: CanonicalGraphProjectionView
    node_count: int = Field(alias="nodeCount", strict=True, ge=0, le=100_000)
    edge_count: int = Field(alias="edgeCount", strict=True, ge=0, le=200_000)
    page_offset: int = Field(alias="pageOffset", strict=True, ge=0, lt=200_000)
    page_size: int = Field(alias="pageSize", strict=True, ge=1, le=500)
    nodes: list[CanonicalGraphNodeView] = Field(max_length=500)
    edges: list[CanonicalGraphEdgeView] = Field(max_length=500)
    next_cursor: str | None = Field(alias="nextCursor", max_length=2048)
    authority_boundary: CanonicalGraphViewAuthorityBoundary = Field(alias="authorityBoundary")

    @model_validator(mode="after")
    def require_complete_page(self) -> Self:
        total = max(self.node_count, self.edge_count)
        if (
            self.page_offset % self.page_size
            or self.page_offset >= max(1, total)
            or len(self.nodes) != min(self.page_size, max(0, self.node_count - self.page_offset))
            or len(self.edges) != min(self.page_size, max(0, self.edge_count - self.page_offset))
            or (self.next_cursor is not None) != (self.page_offset + self.page_size < total)
        ):
            raise ValueError("Graph page bounds or completeness differ")
        return self


def _decode_cursor(value: str) -> _Cursor:
    try:
        if not value or len(value) > 2048:
            raise ValueError("cursor size")
        content = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        cursor = _Cursor.model_validate(
            parse_strict_json_bytes(
                content,
                label="Graph page cursor",
                max_bytes=2048,
            )
        )
        if cursor.encode() != value:
            raise ValueError("noncanonical cursor")
        return cursor
    except (ValueError, TypeError, binascii.Error) as exc:
        raise GraphPageCursorError("Graph page cursor is invalid") from exc


def build_graph_page(
    snapshot: GraphSnapshot,
    *,
    limit: int = 100,
    cursor: str | None = None,
) -> VerifiedCanonicalGraphPage:
    if type(limit) is not int or not 1 <= limit <= 500:
        raise GraphPageCursorError("Graph page size must be an integer from 1 to 500")
    identity = dict(
        campaign=snapshot.campaign_id,
        snapshot_id=snapshot.snapshot_id,
        snapshot_digest=snapshot.snapshot_digest,
        projection_digest=snapshot.projection_digest,
        limit=limit,
    )
    offset = 0
    if cursor is not None:
        position = _decode_cursor(cursor)
        if position != _Cursor.model_validate({**identity, "offset": position.offset}):
            raise GraphPageCursorError("Graph page cursor belongs to another Snapshot or page size")
        offset = position.offset
    projection = snapshot.projection
    total = max(len(projection.nodes), len(projection.edges))
    if offset % limit or offset >= max(1, total):
        raise GraphPageCursorError("Graph page cursor is outside this Snapshot")
    next_cursor = (
        _Cursor.model_validate({**identity, "offset": offset + limit}).encode()
        if offset + limit < total
        else None
    )
    return VerifiedCanonicalGraphPage(
        campaignId=snapshot.campaign_id,
        snapshot=_snapshot_view(snapshot),
        projection=_projection_view(snapshot),
        nodeCount=len(projection.nodes),
        edgeCount=len(projection.edges),
        pageOffset=offset,
        pageSize=limit,
        nodes=[_node_view(node) for node in projection.nodes[offset : offset + limit]],
        edges=[_edge_view(edge) for edge in projection.edges[offset : offset + limit]],
        nextCursor=next_cursor,
        authorityBoundary=CanonicalGraphViewAuthorityBoundary(),
    )
