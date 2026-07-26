"""GRAPH-004 consistency, recovery, contradiction, and stale-decision contracts."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from enum import StrEnum
from re import fullmatch
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.admission import (
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphEventLog,
)
from pajin.graph.models import (
    GraphHypothesis,
    GraphNodeKind,
    GraphNodeRef,
    GraphRelation,
    canonical_graph_json,
    graph_digest,
    graph_node_ref,
)
from pajin.graph.projection import (
    GraphProjection,
    GraphProjectionConflict,
    GraphProjectionError,
    GraphProjectionStore,
    GraphProjector,
    GraphSnapshotError,
    GraphSnapshotRef,
    GraphSnapshotStore,
)

GRAPH_CONSISTENCY_VIEW_API_VERSION: Literal[
    "pajin.dev/canonical-graph-consistency-view/v1alpha1"
] = "pajin.dev/canonical-graph-consistency-view/v1alpha1"
GRAPH_DECISION_API_VERSION: Literal["pajin.dev/graph-decision/v1alpha1"] = (
    "pajin.dev/graph-decision/v1alpha1"
)
GRAPH_DECISION_PREFLIGHT_API_VERSION: Literal[
    "pajin.dev/graph-decision-preflight/v1alpha1"
] = "pajin.dev/graph-decision-preflight/v1alpha1"

_MAX_CONSISTENCY_BYTES = 64 * 1024 * 1024
_MAX_DECISION_BYTES = 1024 * 1024
_CONSISTENCY_VIEW_ID_PATTERN = r"^graph-consistency-view_[a-f0-9]{64}$"
_DECISION_ID_PATTERN = r"^graph-decision_[a-f0-9]{64}$"
_GRAPH_NODE_ID_PATTERN = r"^graph-node_[a-f0-9]{64}$"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_CampaignIdentifier = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_GraphNodeId = Annotated[str, Field(pattern=_GRAPH_NODE_ID_PATTERN)]


class GraphConsistencyError(GraphProjectionError):
    """Raised when Event Log, projection, or decision consistency fails."""


class GraphStaleDecisionError(GraphConsistencyError):
    """Raised when a Snapshot-bound decision is no longer current."""


class GraphHypothesisState(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    CONTESTED = "contested"


class GraphHypothesisAssessment(StrictModel):
    """Deterministic non-destructive support/contradiction state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    hypothesis: GraphNodeRef
    supporting_observation_ids: tuple[_GraphNodeId, ...] = Field(
        alias="supportingObservationIds",
    )
    contradicting_observation_ids: tuple[_GraphNodeId, ...] = Field(
        alias="contradictingObservationIds",
    )
    state: GraphHypothesisState

    @model_validator(mode="after")
    def derive_state(self) -> Self:
        if self.hypothesis.kind is not GraphNodeKind.HYPOTHESIS:
            raise ValueError("Graph Hypothesis assessment references another node kind")
        supporting = self.supporting_observation_ids
        contradicting = self.contradicting_observation_ids
        if supporting != tuple(sorted(set(supporting))) or contradicting != tuple(
            sorted(set(contradicting))
        ):
            raise ValueError("Graph Hypothesis observations must be unique and sorted")
        if set(supporting) & set(contradicting):
            raise ValueError(
                "one Graph Observation cannot support and contradict one Hypothesis"
            )
        expected = (
            GraphHypothesisState.CONTESTED
            if supporting and contradicting
            else GraphHypothesisState.SUPPORTED
            if supporting
            else GraphHypothesisState.CONTRADICTED
            if contradicting
            else GraphHypothesisState.OPEN
        )
        if self.state is not expected:
            raise ValueError("Graph Hypothesis state differs from canonical relations")
        return self


class GraphConsistencyView(StrictModel):
    """Content-addressed analysis over one exact Event Log projection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/canonical-graph-consistency-view/v1alpha1"
    ] = Field(default=GRAPH_CONSISTENCY_VIEW_API_VERSION, alias="apiVersion")
    kind: Literal["GraphConsistencyView"] = "GraphConsistencyView"
    view_id: str = Field(default="", alias="viewId", max_length=100)
    view_digest: str = Field(default="", alias="viewDigest", max_length=64)
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    revision: int = Field(ge=0)
    event_log_head_digest: _Sha256 | None = Field(
        default=None,
        alias="eventLogHeadDigest",
    )
    projection_id: str = Field(alias="projectionId")
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    duplicate_node_occurrence_count: int = Field(
        alias="duplicateNodeOccurrenceCount",
        ge=0,
    )
    duplicate_edge_occurrence_count: int = Field(
        alias="duplicateEdgeOccurrenceCount",
        ge=0,
    )
    hypotheses: tuple[GraphHypothesisAssessment, ...]

    @model_validator(mode="after")
    def bind_view_identity(self) -> Self:
        if (self.revision == 0) is not (self.event_log_head_digest is None):
            raise ValueError("Graph consistency revision and Event Log head differ")
        hypothesis_ids = [item.hypothesis.node_id for item in self.hypotheses]
        if hypothesis_ids != sorted(set(hypothesis_ids)):
            raise ValueError("Graph Hypothesis assessments must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"view_id", "view_digest"},
        )
        digest = graph_digest(
            "pajin.graph.consistency-view/v1",
            material,
            max_bytes=_MAX_CONSISTENCY_BYTES,
        )
        view_id = f"graph-consistency-view_{digest}"
        if self.view_digest and self.view_digest != digest:
            raise ValueError("Graph consistency view digest differs from canonical identity")
        if self.view_id and self.view_id != view_id:
            raise ValueError("Graph consistency view ID differs from canonical identity")
        object.__setattr__(self, "view_digest", digest)
        object.__setattr__(self, "view_id", view_id)
        if fullmatch(_CONSISTENCY_VIEW_ID_PATTERN, self.view_id) is None:
            raise ValueError("Graph consistency view ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="GraphConsistencyView",
            max_bytes=_MAX_CONSISTENCY_BYTES,
        )
        return self


class GraphConsistencyAnalyzer:
    """Analyze duplicates and contradictions without mutating canonical material."""

    @staticmethod
    def analyze(
        *,
        projection: GraphProjection,
        events: Iterable[GraphAdmissionEvent],
    ) -> GraphConsistencyView:
        projection = _canonical_projection(projection)
        canonical_events = tuple(_canonical_event(event) for event in events)
        replayed = GraphProjector.project(
            campaign_id=projection.campaign_id,
            events=canonical_events,
        )
        if replayed.projection_digest != projection.projection_digest:
            raise GraphConsistencyError(
                "Graph consistency analysis projection differs from Event Log"
            )

        node_occurrences: list[str] = []
        edge_occurrences: list[str] = []
        for event in canonical_events:
            if event.decision is GraphAdmissionDecision.ADMITTED:
                node_occurrences.extend(node.node_id for node in event.admitted_nodes)
                edge_occurrences.extend(edge.edge_id for edge in event.admitted_edges)

        supporting: dict[str, set[str]] = {}
        contradicting: dict[str, set[str]] = {}
        for edge in projection.edges:
            if edge.relation is GraphRelation.SUPPORTS:
                supporting.setdefault(edge.target.node_id, set()).add(edge.source.node_id)
            elif edge.relation is GraphRelation.CONTRADICTS:
                contradicting.setdefault(edge.target.node_id, set()).add(
                    edge.source.node_id
                )

        assessments: list[GraphHypothesisAssessment] = []
        for node in projection.nodes:
            if not isinstance(node, GraphHypothesis):
                continue
            supports = tuple(sorted(supporting.get(node.node_id, set())))
            contradictions = tuple(sorted(contradicting.get(node.node_id, set())))
            if set(supports) & set(contradictions):
                raise GraphConsistencyError(
                    "one Graph Observation both supports and contradicts a Hypothesis"
                )
            state = (
                GraphHypothesisState.CONTESTED
                if supports and contradictions
                else GraphHypothesisState.SUPPORTED
                if supports
                else GraphHypothesisState.CONTRADICTED
                if contradictions
                else GraphHypothesisState.OPEN
            )
            assessments.append(
                GraphHypothesisAssessment(
                    hypothesis=graph_node_ref(node),
                    supportingObservationIds=supports,
                    contradictingObservationIds=contradictions,
                    state=state,
                )
            )

        return GraphConsistencyView(
            campaignId=projection.campaign_id,
            revision=projection.revision,
            eventLogHeadDigest=projection.event_log_head_digest,
            projectionId=projection.projection_id,
            projectionDigest=projection.projection_digest,
            duplicateNodeOccurrenceCount=len(node_occurrences)
            - len(set(node_occurrences)),
            duplicateEdgeOccurrenceCount=len(edge_occurrences)
            - len(set(edge_occurrences)),
            hypotheses=tuple(
                sorted(assessments, key=lambda item: item.hypothesis.node_id)
            ),
        )


class GraphProjectionReconciliationStatus(StrEnum):
    IN_SYNC = "in-sync"
    RECOVERED = "recovered"


class GraphProjectionReconciliationResult(StrictModel):
    status: GraphProjectionReconciliationStatus
    previous_revision: int = Field(alias="previousRevision", ge=0)
    recovered_event_count: int = Field(alias="recoveredEventCount", ge=0)
    projection: GraphProjection

    @model_validator(mode="after")
    def require_consistent_result(self) -> Self:
        if self.projection.revision != (
            self.previous_revision + self.recovered_event_count
        ):
            raise ValueError("Graph projection reconciliation result is inconsistent")
        expected = (
            GraphProjectionReconciliationStatus.RECOVERED
            if self.recovered_event_count
            else GraphProjectionReconciliationStatus.IN_SYNC
        )
        if self.status is not expected:
            raise ValueError("Graph projection reconciliation status is inconsistent")
        return self


class GraphProjectionReconciler:
    """Repair a lagging projection from the Event Log with bounded CAS retries."""

    def __init__(
        self,
        *,
        event_log: GraphEventLog,
        projection_store: GraphProjectionStore,
        max_attempts: int = 3,
    ) -> None:
        if not 1 <= max_attempts <= 16:
            raise ValueError("Graph projection recovery attempts must be between 1 and 16")
        self._event_log = event_log
        self._projection_store = projection_store
        self._max_attempts = max_attempts

    def reconcile(self) -> GraphProjectionReconciliationResult:
        last_conflict: GraphProjectionConflict | None = None
        for _ in range(self._max_attempts):
            current = self._projection_store.current()
            events = self._event_log.events()
            if len(events) < current.revision:
                raise GraphConsistencyError(
                    "Graph projection is ahead of its authoritative Event Log"
                )
            prefix = GraphProjector.project(
                campaign_id=current.campaign_id,
                events=events[: current.revision],
            )
            if prefix.projection_digest != current.projection_digest:
                raise GraphConsistencyError(
                    "Graph projection diverges from its authoritative Event Log"
                )
            if len(events) == current.revision:
                return GraphProjectionReconciliationResult(
                    status=GraphProjectionReconciliationStatus.IN_SYNC,
                    previousRevision=current.revision,
                    recoveredEventCount=0,
                    projection=current,
                )
            try:
                advanced = self._projection_store.compare_and_advance(
                    events,
                    expected_revision=current.revision,
                    expected_head_digest=current.event_log_head_digest,
                )
            except GraphProjectionConflict as exc:
                last_conflict = exc
                continue
            return GraphProjectionReconciliationResult(
                status=GraphProjectionReconciliationStatus.RECOVERED,
                previousRevision=current.revision,
                recoveredEventCount=advanced.applied_event_count,
                projection=advanced.projection,
            )
        raise GraphProjectionConflict(
            "Graph projection reconciliation exhausted compare-and-set retries"
        ) from last_conflict


class GraphDecisionKind(StrEnum):
    PLAN = "plan"
    TASK_ASSIGNMENT = "task-assignment"
    REPLAN = "replan"
    ACTION_PROPOSAL = "action-proposal"
    STOP = "stop"


class GraphDecision(StrictModel):
    """One non-executable decision bound to an exact immutable Graph Snapshot."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/graph-decision/v1alpha1"] = Field(
        default=GRAPH_DECISION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GraphDecision"] = "GraphDecision"
    decision_id: str = Field(default="", alias="decisionId", max_length=100)
    decision_digest: str = Field(default="", alias="decisionDigest", max_length=64)
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    decision_kind: GraphDecisionKind = Field(alias="decisionKind")
    decision_payload_digest: _Sha256 = Field(alias="decisionPayloadDigest")
    snapshot: GraphSnapshotRef
    actor_id: _Identifier = Field(alias="actorId")
    actor_digest: _Sha256 = Field(alias="actorDigest")
    created_at: datetime = Field(alias="createdAt")

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Graph Decision created_at requires an explicit UTC offset or Z")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_decision_identity(self) -> Self:
        if self.snapshot.campaign_id != self.campaign_id:
            raise ValueError("Graph Decision Snapshot belongs to another Campaign")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"decision_id", "decision_digest"},
        )
        digest = graph_digest(
            "pajin.graph.decision/v1",
            material,
            max_bytes=_MAX_DECISION_BYTES,
        )
        decision_id = f"graph-decision_{digest}"
        if self.decision_digest and self.decision_digest != digest:
            raise ValueError("Graph Decision digest differs from canonical identity")
        if self.decision_id and self.decision_id != decision_id:
            raise ValueError("Graph Decision ID differs from canonical identity")
        object.__setattr__(self, "decision_digest", digest)
        object.__setattr__(self, "decision_id", decision_id)
        if fullmatch(_DECISION_ID_PATTERN, self.decision_id) is None:
            raise ValueError("Graph Decision ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="GraphDecision",
            max_bytes=_MAX_DECISION_BYTES,
        )
        return self


class GraphDecisionPreflight(StrictModel):
    """Audit-only stale check; this value is not an execution Permit."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/graph-decision-preflight/v1alpha1"] = Field(
        default=GRAPH_DECISION_PREFLIGHT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GraphDecisionPreflight"] = "GraphDecisionPreflight"
    decision_id: str = Field(alias="decisionId", pattern=_DECISION_ID_PATTERN)
    decision_digest: _Sha256 = Field(alias="decisionDigest")
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    snapshot_id: str = Field(alias="snapshotId")
    snapshot_digest: _Sha256 = Field(alias="snapshotDigest")
    revision: int = Field(ge=0)
    event_log_head_digest: _Sha256 | None = Field(
        default=None,
        alias="eventLogHeadDigest",
    )
    projection_id: str = Field(alias="projectionId")
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    checked_at: datetime = Field(alias="checkedAt")

    @field_validator("checked_at")
    @classmethod
    def normalize_checked_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "Graph Decision preflight time requires an explicit UTC offset or Z"
            )
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_revision_head(self) -> Self:
        if (self.revision == 0) is not (self.event_log_head_digest is None):
            raise ValueError("Graph Decision preflight revision and Event Log head differ")
        return self


class GraphDecisionGuard:
    """Fail closed when a Snapshot-bound decision is stale before dispatch."""

    def __init__(
        self,
        *,
        event_log: GraphEventLog,
        projection_store: GraphProjectionStore,
        snapshot_store: GraphSnapshotStore,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._event_log = event_log
        self._projection_store = projection_store
        self._snapshot_store = snapshot_store
        self._clock = clock or _utc_now

    def validate_for_dispatch(self, decision: GraphDecision) -> GraphDecisionPreflight:
        decision = _canonical_decision(decision)
        try:
            snapshot = self._snapshot_store.resolve(decision.snapshot)
        except GraphSnapshotError as exc:
            raise GraphConsistencyError(
                "Graph Decision Snapshot cannot be resolved"
            ) from exc
        if decision.created_at < snapshot.created_at:
            raise GraphConsistencyError("Graph Decision predates its bound Snapshot")

        current = self._projection_store.current()
        latest = GraphProjector.project(
            campaign_id=decision.campaign_id,
            events=self._event_log.events(),
        )
        if current.projection_digest != latest.projection_digest:
            raise GraphStaleDecisionError(
                "Graph projection recovery is required before dispatch"
            )
        observed = (
            snapshot.campaign_id,
            snapshot.revision,
            snapshot.event_log_head_digest,
            snapshot.projection_id,
            snapshot.projection_digest,
        )
        expected = (
            latest.campaign_id,
            latest.revision,
            latest.event_log_head_digest,
            latest.projection_id,
            latest.projection_digest,
        )
        if observed != expected:
            raise GraphStaleDecisionError(
                "Graph changed after the decision Snapshot was captured"
            )
        return GraphDecisionPreflight(
            decisionId=decision.decision_id,
            decisionDigest=decision.decision_digest,
            campaignId=decision.campaign_id,
            snapshotId=snapshot.snapshot_id,
            snapshotDigest=snapshot.snapshot_digest,
            revision=snapshot.revision,
            eventLogHeadDigest=snapshot.event_log_head_digest,
            projectionId=snapshot.projection_id,
            projectionDigest=snapshot.projection_digest,
            checkedAt=self._clock(),
        )


def _canonical_projection(projection: GraphProjection) -> GraphProjection:
    try:
        return GraphProjection.model_validate(
            projection.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise GraphConsistencyError("Graph projection is not canonical") from exc


def _canonical_event(event: GraphAdmissionEvent) -> GraphAdmissionEvent:
    try:
        return GraphAdmissionEvent.model_validate(
            event.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise GraphConsistencyError("Graph admission event is not canonical") from exc


def _canonical_decision(decision: GraphDecision) -> GraphDecision:
    try:
        return GraphDecision.model_validate(
            decision.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise GraphConsistencyError("Graph Decision is not canonical") from exc


def _utc_now() -> datetime:
    return datetime.now(UTC)
