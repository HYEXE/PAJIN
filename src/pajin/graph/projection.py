"""Deterministic Canonical Graph projection, revision, and immutable snapshots."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from enum import StrEnum
from re import fullmatch
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.admission import (
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphEventLog,
)
from pajin.graph.models import (
    GraphEdge,
    GraphNode,
    GraphNodeKind,
    canonical_graph_json,
    graph_digest,
)

GRAPH_SCHEMA_VERSION: Literal["pajin.dev/canonical-graph/v1alpha1"] = (
    "pajin.dev/canonical-graph/v1alpha1"
)
GRAPH_PROJECTION_API_VERSION: Literal[
    "pajin.dev/canonical-graph-projection/v1alpha1"
] = "pajin.dev/canonical-graph-projection/v1alpha1"
GRAPH_SNAPSHOT_API_VERSION: Literal[
    "pajin.dev/canonical-graph-snapshot/v1alpha1"
] = "pajin.dev/canonical-graph-snapshot/v1alpha1"

_MAX_PROJECTION_BYTES = 64 * 1024 * 1024
_MAX_PROJECTION_NODES = 100_000
_MAX_PROJECTION_EDGES = 200_000
_PROJECTION_ID_PATTERN = r"^graph-projection_[a-f0-9]{64}$"
_SNAPSHOT_ID_PATTERN = r"^graph-snapshot_[a-f0-9]{64}$"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_CampaignIdentifier = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class GraphProjectionError(ValueError):
    """Base error for invalid Canonical Graph projection operations."""


class GraphProjectionConflict(GraphProjectionError):
    """Raised when a projection revision compare-and-set fails."""


class GraphSnapshotError(GraphProjectionError):
    """Raised when immutable Snapshot storage or resolution fails."""


class GraphSnapshotReason(StrEnum):
    CHECKPOINT = "checkpoint"
    HANDOFF = "handoff"
    REPLAN = "replan"
    RECOVERY = "recovery"


class GraphProjection(StrictModel):
    """One deterministic read model for an exact Event Log prefix."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/canonical-graph-projection/v1alpha1"] = Field(
        default=GRAPH_PROJECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GraphProjection"] = "GraphProjection"
    projection_id: str = Field(default="", alias="projectionId", max_length=100)
    projection_digest: str = Field(default="", alias="projectionDigest", max_length=64)
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    graph_schema_version: Literal["pajin.dev/canonical-graph/v1alpha1"] = Field(
        default=GRAPH_SCHEMA_VERSION,
        alias="graphSchemaVersion",
    )
    revision: int = Field(ge=0)
    event_log_head_digest: _Sha256 | None = Field(
        default=None,
        alias="eventLogHeadDigest",
    )
    node_projection_digest: str = Field(
        default="",
        alias="nodeProjectionDigest",
        max_length=64,
    )
    edge_projection_digest: str = Field(
        default="",
        alias="edgeProjectionDigest",
        max_length=64,
    )
    nodes: tuple[GraphNode, ...] = Field(max_length=_MAX_PROJECTION_NODES)
    edges: tuple[GraphEdge, ...] = Field(max_length=_MAX_PROJECTION_EDGES)

    @model_validator(mode="after")
    def bind_projection_identity(self) -> Self:
        if (self.revision == 0) is not (self.event_log_head_digest is None):
            raise ValueError("Graph projection revision and Event Log head are inconsistent")
        node_ids = [node.node_id for node in self.nodes]
        edge_ids = [edge.edge_id for edge in self.edges]
        if node_ids != sorted(set(node_ids)) or edge_ids != sorted(set(edge_ids)):
            raise ValueError("Graph projection material must be unique and sorted")
        if any(node.campaign_id != self.campaign_id for node in self.nodes) or any(
            edge.campaign_id != self.campaign_id for edge in self.edges
        ):
            raise ValueError("Graph projection material belongs to another Campaign")
        self._require_resolved_edges()

        node_digest = graph_digest(
            "pajin.graph.projection.nodes/v1",
            [node.model_dump(mode="json", by_alias=True) for node in self.nodes],
            max_bytes=_MAX_PROJECTION_BYTES,
        )
        edge_digest = graph_digest(
            "pajin.graph.projection.edges/v1",
            [edge.model_dump(mode="json", by_alias=True) for edge in self.edges],
            max_bytes=_MAX_PROJECTION_BYTES,
        )
        if self.node_projection_digest and self.node_projection_digest != node_digest:
            raise ValueError("Graph node projection digest differs from canonical material")
        if self.edge_projection_digest and self.edge_projection_digest != edge_digest:
            raise ValueError("Graph edge projection digest differs from canonical material")
        object.__setattr__(self, "node_projection_digest", node_digest)
        object.__setattr__(self, "edge_projection_digest", edge_digest)

        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"projection_id", "projection_digest"},
        )
        projection_digest = graph_digest(
            "pajin.graph.projection/v1",
            material,
            max_bytes=_MAX_PROJECTION_BYTES,
        )
        projection_id = f"graph-projection_{projection_digest}"
        if self.projection_digest and self.projection_digest != projection_digest:
            raise ValueError("Graph projection digest differs from canonical identity")
        if self.projection_id and self.projection_id != projection_id:
            raise ValueError("Graph projection ID differs from canonical identity")
        object.__setattr__(self, "projection_digest", projection_digest)
        object.__setattr__(self, "projection_id", projection_id)
        if fullmatch(_PROJECTION_ID_PATTERN, self.projection_id) is None:
            raise ValueError("Graph projection ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="GraphProjection",
            max_bytes=_MAX_PROJECTION_BYTES,
        )
        return self

    def _require_resolved_edges(self) -> None:
        nodes = {
            node.node_id: (node.campaign_id, GraphNodeKind(node.kind)) for node in self.nodes
        }
        for edge in self.edges:
            for reference in (edge.source, edge.target):
                identity = nodes.get(reference.node_id)
                if identity is None:
                    raise ValueError("Graph projection contains a dangling edge")
                if identity != (reference.campaign_id, reference.kind):
                    raise ValueError("Graph projection edge identity is inconsistent")


class GraphProjectionAdvanceResult(StrictModel):
    projection: GraphProjection
    previous_revision: int = Field(alias="previousRevision", ge=0)
    applied_event_count: int = Field(alias="appliedEventCount", ge=0)
    idempotent: bool

    @model_validator(mode="after")
    def require_consistent_advance(self) -> Self:
        if self.projection.revision != self.previous_revision + self.applied_event_count:
            raise ValueError("Graph projection advance result is inconsistent")
        if self.idempotent != (self.applied_event_count == 0):
            raise ValueError("Graph projection idempotency result is inconsistent")
        return self


class GraphProjector:
    """Pure replay of an ordered Canonical Event Log prefix."""

    @staticmethod
    def project(
        *,
        campaign_id: str,
        events: Iterable[GraphAdmissionEvent],
    ) -> GraphProjection:
        canonical_events = tuple(_canonical_event(event) for event in events)
        GraphProjector._require_event_chain(campaign_id, canonical_events)
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}
        for event in canonical_events:
            if event.decision is not GraphAdmissionDecision.ADMITTED:
                continue
            for node in event.admitted_nodes:
                existing = nodes.get(node.node_id)
                if existing is not None and existing != node:
                    raise GraphProjectionError("canonical Graph node identity has equivocated")
                nodes.setdefault(node.node_id, node.model_copy(deep=True))
            for edge in event.admitted_edges:
                existing_edge = edges.get(edge.edge_id)
                if existing_edge is not None and existing_edge != edge:
                    raise GraphProjectionError("canonical Graph edge identity has equivocated")
                edges.setdefault(edge.edge_id, edge.model_copy(deep=True))
        head = canonical_events[-1].event_digest if canonical_events else None
        return GraphProjection(
            campaignId=campaign_id,
            revision=len(canonical_events),
            eventLogHeadDigest=head,
            nodes=tuple(sorted(nodes.values(), key=lambda item: item.node_id)),
            edges=tuple(sorted(edges.values(), key=lambda item: item.edge_id)),
        )

    @staticmethod
    def _require_event_chain(
        campaign_id: str,
        events: tuple[GraphAdmissionEvent, ...],
    ) -> None:
        previous: str | None = None
        for sequence, event in enumerate(events, start=1):
            if event.campaign_id != campaign_id:
                raise GraphProjectionError("Graph Event Log contains another Campaign")
            if event.sequence != sequence or event.previous_event_digest != previous:
                raise GraphProjectionError("Graph Event Log chain is not contiguous")
            previous = event.event_digest


class GraphProjectionStore(Protocol):
    """Atomic compare-and-set publication of one Graph projection revision."""

    def current(self) -> GraphProjection:
        """Return a defensive copy of the current projection."""

    def compare_and_advance(
        self,
        events: Iterable[GraphAdmissionEvent],
        *,
        expected_revision: int,
        expected_head_digest: str | None,
    ) -> GraphProjectionAdvanceResult:
        """Publish an exact Event Log prefix or fail without changing state."""


class InMemoryGraphProjectionStore:
    """Reference atomic revision store rebuilt entirely from Canonical Events."""

    def __init__(self, *, campaign_id: str) -> None:
        self._campaign_id = campaign_id
        self._current = GraphProjector.project(campaign_id=campaign_id, events=())
        self._lock = threading.RLock()

    def current(self) -> GraphProjection:
        with self._lock:
            return _canonical_projection(self._current)

    def compare_and_advance(
        self,
        events: Iterable[GraphAdmissionEvent],
        *,
        expected_revision: int,
        expected_head_digest: str | None,
    ) -> GraphProjectionAdvanceResult:
        canonical_events = tuple(_canonical_event(event) for event in events)
        candidate = GraphProjector.project(
            campaign_id=self._campaign_id,
            events=canonical_events,
        )
        with self._lock:
            current = _canonical_projection(self._current)
            if (
                expected_revision != current.revision
                or expected_head_digest != current.event_log_head_digest
            ):
                raise GraphProjectionConflict("Graph projection revision compare-and-set failed")
            if candidate.revision < current.revision:
                raise GraphProjectionConflict("Graph projection rollback was rejected")
            prefix = GraphProjector.project(
                campaign_id=self._campaign_id,
                events=canonical_events[: current.revision],
            )
            if prefix.projection_digest != current.projection_digest:
                raise GraphProjectionConflict(
                    "Graph Event Log prefix differs from current projection"
                )
            applied = candidate.revision - current.revision
            if applied:
                self._current = candidate
            return GraphProjectionAdvanceResult(
                projection=_canonical_projection(self._current),
                previousRevision=current.revision,
                appliedEventCount=applied,
                idempotent=not applied,
            )


class GraphProjectionCoordinator:
    """Capture the Event Log and atomically advance its deterministic read model."""

    def __init__(
        self,
        *,
        event_log: GraphEventLog,
        projection_store: GraphProjectionStore,
    ) -> None:
        self._event_log = event_log
        self._projection_store = projection_store

    def refresh(self) -> GraphProjectionAdvanceResult:
        current = self._projection_store.current()
        events = self._event_log.events()
        return self._projection_store.compare_and_advance(
            events,
            expected_revision=current.revision,
            expected_head_digest=current.event_log_head_digest,
        )


class GraphSnapshot(StrictModel):
    """Content-addressed immutable checkpoint over one exact Graph projection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/canonical-graph-snapshot/v1alpha1"] = Field(
        default=GRAPH_SNAPSHOT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GraphSnapshot"] = "GraphSnapshot"
    snapshot_id: str = Field(default="", alias="snapshotId", max_length=100)
    snapshot_digest: str = Field(default="", alias="snapshotDigest", max_length=64)
    previous_snapshot_digest: _Sha256 | None = Field(
        default=None,
        alias="previousSnapshotDigest",
    )
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    graph_schema_version: Literal["pajin.dev/canonical-graph/v1alpha1"] = Field(
        default=GRAPH_SCHEMA_VERSION,
        alias="graphSchemaVersion",
    )
    revision: int = Field(ge=0)
    event_log_head_digest: _Sha256 | None = Field(
        default=None,
        alias="eventLogHeadDigest",
    )
    projection_id: str = Field(alias="projectionId", pattern=_PROJECTION_ID_PATTERN)
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    node_projection_digest: _Sha256 = Field(alias="nodeProjectionDigest")
    edge_projection_digest: _Sha256 = Field(alias="edgeProjectionDigest")
    reason: GraphSnapshotReason
    created_at: datetime = Field(alias="createdAt")
    creator_id: _Identifier = Field(alias="creatorId")
    creator_digest: _Sha256 = Field(alias="creatorDigest")
    projection: GraphProjection

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Graph Snapshot created_at must include an explicit UTC offset or Z")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_snapshot_identity(self) -> Self:
        expected = (
            self.projection.campaign_id,
            self.projection.graph_schema_version,
            self.projection.revision,
            self.projection.event_log_head_digest,
            self.projection.projection_id,
            self.projection.projection_digest,
            self.projection.node_projection_digest,
            self.projection.edge_projection_digest,
        )
        observed = (
            self.campaign_id,
            self.graph_schema_version,
            self.revision,
            self.event_log_head_digest,
            self.projection_id,
            self.projection_digest,
            self.node_projection_digest,
            self.edge_projection_digest,
        )
        if observed != expected:
            raise ValueError("Graph Snapshot differs from its bound projection")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"snapshot_id", "snapshot_digest"},
        )
        snapshot_digest = graph_digest(
            "pajin.graph.snapshot/v1",
            material,
            max_bytes=_MAX_PROJECTION_BYTES,
        )
        snapshot_id = f"graph-snapshot_{snapshot_digest}"
        if self.snapshot_digest and self.snapshot_digest != snapshot_digest:
            raise ValueError("Graph Snapshot digest differs from canonical identity")
        if self.snapshot_id and self.snapshot_id != snapshot_id:
            raise ValueError("Graph Snapshot ID differs from canonical identity")
        object.__setattr__(self, "snapshot_digest", snapshot_digest)
        object.__setattr__(self, "snapshot_id", snapshot_id)
        if fullmatch(_SNAPSHOT_ID_PATTERN, self.snapshot_id) is None:
            raise ValueError("Graph Snapshot ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="GraphSnapshot",
            max_bytes=_MAX_PROJECTION_BYTES,
        )
        return self


class GraphSnapshotRef(StrictModel):
    snapshot_id: str = Field(alias="snapshotId", pattern=_SNAPSHOT_ID_PATTERN)
    snapshot_digest: _Sha256 = Field(alias="snapshotDigest")
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    graph_schema_version: Literal["pajin.dev/canonical-graph/v1alpha1"] = Field(
        default=GRAPH_SCHEMA_VERSION,
        alias="graphSchemaVersion",
    )
    revision: int = Field(ge=0)
    event_log_head_digest: _Sha256 | None = Field(
        default=None,
        alias="eventLogHeadDigest",
    )
    projection_digest: _Sha256 = Field(alias="projectionDigest")

    @model_validator(mode="after")
    def require_consistent_revision(self) -> Self:
        if (self.revision == 0) is not (self.event_log_head_digest is None):
            raise ValueError("Graph Snapshot reference revision and Event Log head differ")
        return self


def graph_snapshot_ref(snapshot: GraphSnapshot) -> GraphSnapshotRef:
    """Return an exact decision-safe reference to one immutable Snapshot."""

    snapshot = _canonical_snapshot(snapshot)
    return GraphSnapshotRef(
        snapshotId=snapshot.snapshot_id,
        snapshotDigest=snapshot.snapshot_digest,
        campaignId=snapshot.campaign_id,
        graphSchemaVersion=snapshot.graph_schema_version,
        revision=snapshot.revision,
        eventLogHeadDigest=snapshot.event_log_head_digest,
        projectionDigest=snapshot.projection_digest,
    )


class GraphSnapshotStore(Protocol):
    """Append-only immutable Snapshot repository."""

    def claim_writer(self, creator_id: str, creator_digest: str) -> object:
        """Issue the only process-local Snapshot writer capability."""

    def head_digest(self) -> str | None:
        """Return the current Snapshot chain head."""

    def append(self, snapshot: GraphSnapshot, *, writer: object) -> GraphSnapshot:
        """Append one immutable Snapshot or fail without changing the repository."""

    def resolve(self, reference: GraphSnapshotRef) -> GraphSnapshot:
        """Resolve and exact-match one immutable Snapshot reference."""

    def snapshots(self) -> tuple[GraphSnapshot, ...]:
        """Return defensive copies of the Snapshot chain."""


class InMemoryGraphSnapshotStore:
    """Reference append-only Snapshot chain with one opaque writer capability."""

    def __init__(self) -> None:
        self._snapshots: list[GraphSnapshot] = []
        self._by_id: dict[str, GraphSnapshot] = {}
        self._writer: object | None = None
        self._writer_identity: tuple[str, str] | None = None
        self._lock = threading.RLock()

    def claim_writer(self, creator_id: str, creator_digest: str) -> object:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", creator_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", creator_digest) is None
        ):
            raise GraphSnapshotError("Graph Snapshot writer identity is invalid")
        with self._lock:
            if self._writer is not None:
                raise GraphSnapshotError("Graph Snapshot writer is already claimed")
            writer = object()
            self._writer = writer
            self._writer_identity = (creator_id, creator_digest)
            return writer

    def head_digest(self) -> str | None:
        with self._lock:
            return self._snapshots[-1].snapshot_digest if self._snapshots else None

    def append(self, snapshot: GraphSnapshot, *, writer: object) -> GraphSnapshot:
        with self._lock:
            if writer is not self._writer:
                raise GraphSnapshotError("Graph Snapshot write authority is invalid")
            stored = _canonical_snapshot(snapshot)
            if self._writer_identity != (stored.creator_id, stored.creator_digest):
                raise GraphSnapshotError("Graph Snapshot creator differs from claimed writer")
            existing = self._by_id.get(stored.snapshot_id)
            if existing is not None:
                return _canonical_snapshot(existing)
            if stored.previous_snapshot_digest != self.head_digest():
                raise GraphSnapshotError("Graph Snapshot predecessor is stale")
            self._snapshots.append(stored)
            self._by_id[stored.snapshot_id] = stored
            return _canonical_snapshot(stored)

    def resolve(self, reference: GraphSnapshotRef) -> GraphSnapshot:
        try:
            reference = GraphSnapshotRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except ValidationError as exc:
            raise GraphSnapshotError("Graph Snapshot reference is invalid") from exc
        with self._lock:
            snapshot = self._by_id.get(reference.snapshot_id)
            if snapshot is None:
                raise GraphSnapshotError("Graph Snapshot was not found")
            resolved = _canonical_snapshot(snapshot)
        if (
            resolved.snapshot_digest,
            resolved.campaign_id,
            resolved.graph_schema_version,
            resolved.revision,
            resolved.event_log_head_digest,
            resolved.projection_digest,
        ) != (
            reference.snapshot_digest,
            reference.campaign_id,
            reference.graph_schema_version,
            reference.revision,
            reference.event_log_head_digest,
            reference.projection_digest,
        ):
            raise GraphSnapshotError("Graph Snapshot reference differs from stored authority")
        return resolved

    def snapshots(self) -> tuple[GraphSnapshot, ...]:
        with self._lock:
            return tuple(_canonical_snapshot(snapshot) for snapshot in self._snapshots)


class GraphSnapshotAuthority:
    """Capture immutable Snapshots only from the current canonical projection."""

    def __init__(
        self,
        *,
        creator_id: str,
        creator_digest: str,
        projection_store: GraphProjectionStore,
        snapshot_store: GraphSnapshotStore,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._creator_id = creator_id
        self._creator_digest = creator_digest
        self._projection_store = projection_store
        self._snapshot_store = snapshot_store
        self._writer = snapshot_store.claim_writer(creator_id, creator_digest)
        self._clock = clock or _utc_now
        self._lock = threading.RLock()

    def capture(self, reason: GraphSnapshotReason) -> GraphSnapshot:
        with self._lock:
            projection = self._projection_store.current()
            snapshot = GraphSnapshot(
                previousSnapshotDigest=self._snapshot_store.head_digest(),
                campaignId=projection.campaign_id,
                graphSchemaVersion=projection.graph_schema_version,
                revision=projection.revision,
                eventLogHeadDigest=projection.event_log_head_digest,
                projectionId=projection.projection_id,
                projectionDigest=projection.projection_digest,
                nodeProjectionDigest=projection.node_projection_digest,
                edgeProjectionDigest=projection.edge_projection_digest,
                reason=reason,
                createdAt=self._clock(),
                creatorId=self._creator_id,
                creatorDigest=self._creator_digest,
                projection=projection,
            )
            return self._snapshot_store.append(snapshot, writer=self._writer)


def _canonical_event(event: GraphAdmissionEvent) -> GraphAdmissionEvent:
    try:
        return GraphAdmissionEvent.model_validate(
            event.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise GraphProjectionError("Graph admission event is not canonical") from exc


def _canonical_projection(projection: GraphProjection) -> GraphProjection:
    try:
        return GraphProjection.model_validate(
            projection.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise GraphProjectionError("Graph projection is not canonical") from exc


def _canonical_snapshot(snapshot: GraphSnapshot) -> GraphSnapshot:
    try:
        return GraphSnapshot.model_validate(
            snapshot.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise GraphSnapshotError("Graph Snapshot is not canonical") from exc


def _utc_now() -> datetime:
    return datetime.now(UTC)
