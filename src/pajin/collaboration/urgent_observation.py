"""Bounded urgent-observation decisions over existing collaboration authorities."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from re import fullmatch
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.snapshots import (
    CollaborationSnapshot,
    CollaborationSnapshotError,
    SharedArtifactSource,
    verify_collaboration_snapshot,
)
from pajin.collaboration.terminal_result import (
    TerminalResultHandoff,
    TerminalResultHandoffAuthority,
    TerminalResultHandoffError,
)
from pajin.domain.models import StrictModel
from pajin.graph.models import (
    GraphContentOrigin,
    GraphEdge,
    GraphNodeKind,
    GraphNodeRef,
    GraphObservation,
    GraphRelation,
    canonical_graph_json,
    graph_digest,
)
from pajin.graph.projection import GraphSnapshotError, GraphSnapshotStore

URGENT_OBSERVATION_FAST_GATE_API_VERSION = (
    "pajin.dev/urgent-observation-fast-gate/v1alpha1"
)
_MAX_POLICY_BYTES = 16 * 1024
_MAX_DECISION_BYTES = 128 * 1024
_DECISION_ID_PATTERN = r"^urgent-observation-decision_[a-f0-9]{64}$"


class UrgentObservationFastGateError(ValueError):
    """Raised when an urgent Observation decision cannot be reconstructed exactly."""


class UrgentObservationType(StrEnum):
    CREDENTIAL_MATERIAL_EXPOSURE = "credential-material-exposure"
    SCOPE_BOUNDARY_VIOLATION = "scope-boundary-violation"
    UNSAFE_SIDE_EFFECT = "unsafe-side-effect"


class UrgentObservationDisposition(StrEnum):
    STOP_AND_ESCALATE = "stop-and-escalate"


class UrgentObservationFastGatePolicy(StrictModel):
    """Code-owned policy for one non-executing urgent Observation decision."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    policy_id: Literal["pajin.collaboration.urgent-observation-fast-gate.v1"] = Field(
        default="pajin.collaboration.urgent-observation-fast-gate.v1",
        alias="policyId",
    )
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    allowed_observation_types: tuple[UrgentObservationType, ...] = Field(
        default=(
            UrgentObservationType.CREDENTIAL_MATERIAL_EXPOSURE,
            UrgentObservationType.SCOPE_BOUNDARY_VIOLATION,
            UrgentObservationType.UNSAFE_SIDE_EFFECT,
        ),
        alias="allowedObservationTypes",
        min_length=3,
        max_length=3,
    )
    allowed_origins: tuple[GraphContentOrigin, ...] = Field(
        default=(GraphContentOrigin.OPERATOR, GraphContentOrigin.TRUSTED_CORE),
        alias="allowedOrigins",
        min_length=2,
        max_length=2,
    )
    minimum_confidence: float = Field(
        default=1.0,
        alias="minimumConfidence",
        strict=True,
        ge=1.0,
        le=1.0,
    )
    max_urgent_observations_per_handoff: Literal[1] = Field(
        default=1,
        alias="maxUrgentObservationsPerHandoff",
    )
    max_decisions_per_handoff: Literal[1] = Field(
        default=1,
        alias="maxDecisionsPerHandoff",
    )
    max_budget_units_per_handoff: Literal[1] = Field(
        default=1,
        alias="maxBudgetUnitsPerHandoff",
    )

    @field_validator(
        "max_urgent_observations_per_handoff",
        "max_decisions_per_handoff",
        "max_budget_units_per_handoff",
        mode="before",
    )
    @classmethod
    def require_one(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("urgent Observation policy bounds must be integer one")
        return value

    @model_validator(mode="after")
    def bind_policy(self) -> Self:
        if (
            self.allowed_observation_types != tuple(UrgentObservationType)
            or self.allowed_origins
            != (GraphContentOrigin.OPERATOR, GraphContentOrigin.TRUSTED_CORE)
        ):
            raise ValueError("urgent Observation policy allowlists differ from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"policy_digest"})
        digest = graph_digest(
            "pajin.collaboration.urgent-observation-fast-gate-policy/v1",
            material,
            max_bytes=_MAX_POLICY_BYTES,
        )
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("urgent Observation policy digest differs")
        object.__setattr__(self, "policy_digest", digest)
        return self


class UrgentObservationFastGateDecision(StrictModel):
    """Metadata-only stop-and-escalate decision for one admitted Observation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/urgent-observation-fast-gate/v1alpha1"] = Field(
        default="pajin.dev/urgent-observation-fast-gate/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["UrgentObservationFastGateDecision"] = (
        "UrgentObservationFastGateDecision"
    )
    decision_id: str = Field(default="", alias="decisionId", max_length=92)
    decision_digest: str = Field(default="", alias="decisionDigest", max_length=64)
    authority_id: str = Field(
        alias="authorityId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    authority_digest: str = Field(alias="authorityDigest", pattern=r"^[a-f0-9]{64}$")
    policy: UrgentObservationFastGatePolicy
    terminal_result_handoff_id: str = Field(
        alias="terminalResultHandoffId",
        pattern=r"^terminal-result-handoff_[a-f0-9]{64}$",
    )
    terminal_result_handoff_digest: str = Field(
        alias="terminalResultHandoffDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    handoff_id: str = Field(alias="handoffId", pattern=r"^agent-handoff_[a-f0-9]{64}$")
    handoff_digest: str = Field(alias="handoffDigest", pattern=r"^[a-f0-9]{64}$")
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    collaboration_snapshot_id: str = Field(
        alias="collaborationSnapshotId",
        pattern=r"^collaboration-snapshot_[a-f0-9]{64}$",
    )
    collaboration_snapshot_digest: str = Field(
        alias="collaborationSnapshotDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    observation: GraphNodeRef
    observation_type: UrgentObservationType = Field(alias="observationType")
    observation_origin: GraphContentOrigin = Field(alias="observationOrigin")
    observation_value_digest: str = Field(
        alias="observationValueDigest", pattern=r"^[a-f0-9]{64}$"
    )
    result_artifact_id: str = Field(
        alias="resultArtifactId", pattern=r"^shared-artifact_[a-f0-9]{64}$"
    )
    result_artifact_digest: str = Field(
        alias="resultArtifactDigest", pattern=r"^[a-f0-9]{64}$"
    )
    disposition: Literal[UrgentObservationDisposition.STOP_AND_ESCALATE] = (
        UrgentObservationDisposition.STOP_AND_ESCALATE
    )
    decision_state: Literal["admitted-not-applied"] = Field(
        default="admitted-not-applied",
        alias="decisionState",
    )
    decision_index: Literal[1] = Field(default=1, alias="decisionIndex")
    observation_count: Literal[1] = Field(default=1, alias="observationCount")
    consumed_budget_units: Literal[1] = Field(default=1, alias="consumedBudgetUnits")
    previous_decision_id: Literal[None] = Field(default=None, alias="previousDecisionId")
    decided_at: datetime = Field(alias="decidedAt")
    escalation_required: Literal[True] = Field(default=True, alias="escalationRequired")
    autonomous_execution_allowed: Literal[False] = Field(
        default=False, alias="autonomousExecutionAllowed"
    )
    content_embedded: Literal[False] = Field(default=False, alias="contentEmbedded")
    prompt_interpreted: Literal[False] = Field(default=False, alias="promptInterpreted")
    replan_selected: Literal[False] = Field(default=False, alias="replanSelected")
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("decided_at")
    @classmethod
    def normalize_decided_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("urgent Observation decision time requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "decision_index",
        "observation_count",
        "consumed_budget_units",
        mode="before",
    )
    @classmethod
    def require_one(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("urgent Observation decision bounds must be integer one")
        return value

    @field_validator("escalation_required", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("urgent Observation escalation marker must be boolean true")
        return value

    @field_validator(
        "autonomous_execution_allowed",
        "content_embedded",
        "prompt_interpreted",
        "replan_selected",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("urgent Observation authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if (
            self.observation.kind is not GraphNodeKind.OBSERVATION
            or self.observation.campaign_id != self.campaign_id
        ):
            raise ValueError("urgent Observation reference belongs to another Campaign or kind")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"decision_id", "decision_digest"}
        )
        digest = graph_digest(
            "pajin.collaboration.urgent-observation-fast-gate-decision/v1",
            material,
            max_bytes=_MAX_DECISION_BYTES,
        )
        decision_id = f"urgent-observation-decision_{digest}"
        if self.decision_digest and self.decision_digest != digest:
            raise ValueError("urgent Observation decision digest differs")
        if self.decision_id and self.decision_id != decision_id:
            raise ValueError("urgent Observation decision ID differs")
        object.__setattr__(self, "decision_digest", digest)
        object.__setattr__(self, "decision_id", decision_id)
        if fullmatch(_DECISION_ID_PATTERN, self.decision_id) is None:
            raise ValueError("urgent Observation decision ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="UrgentObservationFastGateDecision",
            max_bytes=_MAX_DECISION_BYTES,
        )
        return self


class UrgentObservationFastGateAuthority:
    """Process-local single writer for one bounded urgent decision per handoff."""

    def __init__(self, *, authority_id: str, authority_digest: str) -> None:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", authority_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", authority_digest) is None
        ):
            raise ValueError("urgent Observation authority identity is invalid")
        self._authority_id = authority_id
        self._authority_digest = authority_digest
        self._policy = UrgentObservationFastGatePolicy()
        self._by_handoff: dict[str, UrgentObservationFastGateDecision] = {}

    def admit(
        self,
        *,
        terminal_result_authority: TerminalResultHandoffAuthority,
        terminal_result: TerminalResultHandoff,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource],
        observation: GraphNodeRef,
        decided_at: datetime,
    ) -> UrgentObservationFastGateDecision:
        try:
            result = terminal_result_authority.resolve(terminal_result)
            snapshot = verify_collaboration_snapshot(
                collaboration_snapshot,
                graph_snapshot_store=graph_snapshot_store,
                shared_artifact_sources=shared_artifact_sources,
            )
            if (
                snapshot.collaboration_snapshot_id != result.collaboration_snapshot_id
                or snapshot.collaboration_snapshot_digest
                != result.collaboration_snapshot_digest
                or snapshot.campaign_id != result.campaign_id
                or result.result_artifact not in snapshot.shared_artifacts
            ):
                raise ValueError("urgent Observation differs from terminal result Snapshot")
            canonical_ref = GraphNodeRef.model_validate(
                observation.model_dump(mode="json", by_alias=True)
            )
            graph = graph_snapshot_store.resolve(snapshot.graph_snapshot)
            if graph_snapshot_store.head_digest() != snapshot.graph_snapshot.snapshot_digest:
                raise ValueError("urgent Observation Graph authority became stale")
            node = next(
                (item for item in graph.projection.nodes if item.node_id == canonical_ref.node_id),
                None,
            )
            if not isinstance(node, GraphObservation) or canonical_ref != GraphNodeRef(
                campaignId=node.campaign_id,
                nodeId=node.node_id,
                kind=GraphNodeKind.OBSERVATION,
            ):
                raise ValueError("urgent Observation is not an exact current Graph member")
            _require_urgent_observation(
                node,
                result=result,
                graph_edges=graph.projection.edges,
                policy=self._policy,
                decided_at=decided_at,
            )
            decision = UrgentObservationFastGateDecision(
                authorityId=self._authority_id,
                authorityDigest=self._authority_digest,
                policy=self._policy,
                terminalResultHandoffId=result.result_handoff_id,
                terminalResultHandoffDigest=result.result_handoff_digest,
                handoffId=result.handoff_id,
                handoffDigest=result.handoff_digest,
                campaignId=result.campaign_id,
                collaborationSnapshotId=snapshot.collaboration_snapshot_id,
                collaborationSnapshotDigest=snapshot.collaboration_snapshot_digest,
                observation=canonical_ref,
                observationType=UrgentObservationType(node.observation_type),
                observationOrigin=node.origin,
                observationValueDigest=node.value_digest,
                resultArtifactId=result.result_artifact.shared_artifact_id,
                resultArtifactDigest=result.result_artifact.shared_artifact_digest,
                decidedAt=decided_at,
            )
            existing = self._by_handoff.get(result.handoff_id)
            if existing is not None:
                if _decision_semantics(existing) != _decision_semantics(decision):
                    raise ValueError("urgent Observation decision has equivocated")
                return existing
            self._by_handoff[result.handoff_id] = decision
            return decision
        except (
            AttributeError,
            CollaborationSnapshotError,
            GraphSnapshotError,
            TerminalResultHandoffError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise UrgentObservationFastGateError(
                "urgent Observation decision could not be admitted"
            ) from exc

    def verify(
        self,
        decision: UrgentObservationFastGateDecision,
        *,
        terminal_result_authority: TerminalResultHandoffAuthority,
        terminal_result: TerminalResultHandoff,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource],
        observation: GraphNodeRef,
    ) -> UrgentObservationFastGateDecision:
        """Reconstruct one stored decision from its complete admission inputs."""

        try:
            canonical = UrgentObservationFastGateDecision.model_validate(
                decision.model_dump(mode="json", by_alias=True)
            )
            stored = self._by_handoff.get(canonical.handoff_id)
            if (
                canonical.authority_id != self._authority_id
                or canonical.authority_digest != self._authority_digest
                or stored != canonical
            ):
                raise ValueError("urgent Observation decision was not admitted here")
            rebuilt = self.admit(
                terminal_result_authority=terminal_result_authority,
                terminal_result=terminal_result,
                collaboration_snapshot=collaboration_snapshot,
                graph_snapshot_store=graph_snapshot_store,
                shared_artifact_sources=shared_artifact_sources,
                observation=observation,
                decided_at=canonical.decided_at,
            )
            if rebuilt != canonical:
                raise ValueError("urgent Observation decision differs from current authority")
            return canonical
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise UrgentObservationFastGateError(
                "urgent Observation decision could not be verified"
            ) from exc


def _require_urgent_observation(
    observation: GraphObservation,
    *,
    result: TerminalResultHandoff,
    graph_edges: Iterable[GraphEdge],
    policy: UrgentObservationFastGatePolicy,
    decided_at: datetime,
) -> None:
    try:
        observation_type = UrgentObservationType(observation.observation_type)
    except ValueError as exc:
        raise ValueError("Graph Observation type is not urgent") from exc
    if (
        observation_type not in policy.allowed_observation_types
        or observation.origin not in policy.allowed_origins
        or observation.confidence < policy.minimum_confidence
        or observation.value_digest != result.result_artifact.sha256
        or observation.observed_at > result.completed_at
        or decided_at < result.completed_at
    ):
        raise ValueError("Graph Observation differs from urgent policy or terminal result")
    edges = tuple(graph_edges)
    supported = [
        edge
        for edge in edges
        if edge.relation is GraphRelation.SUPPORTED_BY
        and edge.source.node_id == observation.node_id
        and edge.target == result.result_artifact.evidence
    ]
    produced = [
        edge
        for edge in edges
        if edge.relation is GraphRelation.PRODUCES
        and edge.target.node_id == observation.node_id
    ]
    if len(supported) != 1 or len(produced) != 1:
        raise ValueError("urgent Observation lacks exact Action and result Evidence lineage")


def _decision_semantics(decision: UrgentObservationFastGateDecision) -> object:
    return decision.model_dump(
        mode="json",
        exclude={"decision_id", "decision_digest", "decided_at"},
    )
