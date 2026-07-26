"""Minimum Canonical Graph node, edge, and unprivileged proposal contracts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import PurePosixPath
from re import fullmatch
from typing import Annotated, Literal, Self

from pydantic import Field, TypeAdapter, field_validator, model_validator

from pajin.domain.models import StrictModel

GRAPH_NODE_API_VERSION: Literal["pajin.dev/canonical-graph-node/v1alpha1"] = (
    "pajin.dev/canonical-graph-node/v1alpha1"
)
GRAPH_EDGE_API_VERSION: Literal["pajin.dev/canonical-graph-edge/v1alpha1"] = (
    "pajin.dev/canonical-graph-edge/v1alpha1"
)
GRAPH_PROPOSAL_API_VERSION: Literal["pajin.dev/canonical-graph-proposal/v1alpha1"] = (
    "pajin.dev/canonical-graph-proposal/v1alpha1"
)

_MAX_NODE_BYTES = 64 * 1024
_MAX_EDGE_BYTES = 16 * 1024
_MAX_PROPOSAL_BYTES = 2 * 1024 * 1024
_MAX_PROPOSAL_EDGES = 1_000
_MAX_PROPOSAL_EVIDENCE = 1_000
_NODE_ID_PATTERN = r"^graph-node_[a-f0-9]{64}$"
_EDGE_ID_PATTERN = r"^graph-edge_[a-f0-9]{64}$"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_PortableIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
]
_CampaignIdentifier = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Confidence = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class GraphNodeKind(StrEnum):
    SURFACE = "Surface"
    HYPOTHESIS = "Hypothesis"
    ACTION = "Action"
    OBSERVATION = "Observation"
    EVIDENCE = "Evidence"
    CAMPAIGN_FACT = "CampaignFact"


class GraphRelation(StrEnum):
    MOTIVATES = "motivates"
    TESTED_BY = "tested-by"
    PRODUCES = "produces"
    SUPPORTED_BY = "supported-by"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    DISCOVERS = "discovers"
    ENABLES = "enables"


_RELATION_ENDPOINTS: dict[GraphRelation, tuple[GraphNodeKind, GraphNodeKind]] = {
    GraphRelation.MOTIVATES: (GraphNodeKind.SURFACE, GraphNodeKind.HYPOTHESIS),
    GraphRelation.TESTED_BY: (GraphNodeKind.HYPOTHESIS, GraphNodeKind.ACTION),
    GraphRelation.PRODUCES: (GraphNodeKind.ACTION, GraphNodeKind.OBSERVATION),
    GraphRelation.SUPPORTED_BY: (GraphNodeKind.OBSERVATION, GraphNodeKind.EVIDENCE),
    GraphRelation.SUPPORTS: (GraphNodeKind.OBSERVATION, GraphNodeKind.HYPOTHESIS),
    GraphRelation.CONTRADICTS: (GraphNodeKind.OBSERVATION, GraphNodeKind.HYPOTHESIS),
    GraphRelation.DISCOVERS: (GraphNodeKind.OBSERVATION, GraphNodeKind.SURFACE),
    GraphRelation.ENABLES: (GraphNodeKind.OBSERVATION, GraphNodeKind.HYPOTHESIS),
}


class GraphContentOrigin(StrEnum):
    TRUSTED_CORE = "trusted-core"
    OPERATOR = "operator"
    AGENT_DERIVED = "agent-derived"
    TARGET_DERIVED = "target-derived"


class GraphActionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GraphAuthorityKind(StrEnum):
    CAPABILITY_GRANT = "capability-grant"
    ACTION_PERMIT = "action-permit"
    REPLAY_CAPABILITY_GRANT = "replay-capability-grant"


class CampaignFactValidationState(StrEnum):
    ADMITTED = "admitted"
    CORROBORATED = "corroborated"
    CONTESTED = "contested"
    INVALIDATED = "invalidated"


class GraphProposalKind(StrEnum):
    SURFACE = "SurfaceProposal"
    OBSERVATION = "ObservationProposal"
    CAMPAIGN_FACT = "CampaignFactProposal"


def canonical_graph_json(value: object, *, label: str, max_bytes: int) -> bytes:
    """Encode bounded canonical UTF-8 JSON or fail closed."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the canonical byte limit")
    return encoded


def graph_digest(domain: str, value: object, *, max_bytes: int) -> str:
    """Return one domain-separated digest for canonical graph material."""

    domain_bytes = domain.encode("ascii", errors="strict")
    encoded = canonical_graph_json(value, label=domain, max_bytes=max_bytes)
    return sha256(domain_bytes + b"\x00" + encoded).hexdigest()


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _require_safe_text(value: str, *, label: str) -> str:
    if value != value.strip():
        raise ValueError(f"{label} cannot contain surrounding whitespace")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} cannot contain control characters")
    return value


def _require_safe_reference(value: str) -> str:
    value = _require_safe_text(value, label="Graph evidence reference")
    if "\\" in value:
        raise ValueError("Graph evidence reference must use forward slashes")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Graph evidence reference must be a normalized relative path")
    if path.as_posix() != value:
        raise ValueError("Graph evidence reference must be a normalized relative path")
    return value


class _GraphNodeBase(StrictModel):
    api_version: Literal["pajin.dev/canonical-graph-node/v1alpha1"] = Field(
        default=GRAPH_NODE_API_VERSION,
        alias="apiVersion",
    )
    node_id: str = Field(default="", alias="nodeId", max_length=75)
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")

    @model_validator(mode="after")
    def bind_canonical_node_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"node_id"},
        )
        expected = "graph-node_" + graph_digest(
            "pajin.graph.node/v1",
            material,
            max_bytes=_MAX_NODE_BYTES,
        )
        if not self.node_id:
            self.node_id = expected
        elif self.node_id != expected:
            raise ValueError("Graph node ID differs from canonical identity")
        if fullmatch(_NODE_ID_PATTERN, self.node_id) is None:
            raise ValueError("Graph node ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label=self.__class__.__name__,
            max_bytes=_MAX_NODE_BYTES,
        )
        return self


class GraphSurface(_GraphNodeBase):
    kind: Literal["Surface"] = "Surface"
    target_id: _Identifier = Field(alias="targetId")
    surface_type: _Identifier = Field(alias="surfaceType")
    locator_schema: _Identifier = Field(alias="locatorSchema")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    origin: GraphContentOrigin


class GraphHypothesis(_GraphNodeBase):
    kind: Literal["Hypothesis"] = "Hypothesis"
    hypothesis_type: _Identifier = Field(alias="hypothesisType")
    statement: str = Field(min_length=1, max_length=4_000)
    expected_observable: str = Field(alias="expectedObservable", min_length=1, max_length=4_000)
    producer_id: _Identifier = Field(alias="producerId")
    producer_version: _Identifier = Field(alias="producerVersion")
    producer_digest: _Sha256 = Field(alias="producerDigest")
    origin: GraphContentOrigin
    confidence: _Confidence

    @field_validator("statement", "expected_observable")
    @classmethod
    def require_safe_hypothesis_text(cls, value: str) -> str:
        return _require_safe_text(value, label="Graph Hypothesis text")


class GraphAction(_GraphNodeBase):
    kind: Literal["Action"] = "Action"
    request_id: _PortableIdentifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    authority_kind: GraphAuthorityKind = Field(alias="authorityKind")
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")
    capability_id: _Identifier = Field(alias="capabilityId")
    capability_version: _Identifier = Field(alias="capabilityVersion")
    capability_digest: _Sha256 = Field(alias="capabilityDigest")
    tool_id: _Identifier = Field(alias="toolId")
    target_digest: _Sha256 = Field(alias="targetDigest")
    status: GraphActionStatus
    executed_at: datetime = Field(alias="executedAt")

    @field_validator("executed_at")
    @classmethod
    def normalize_executed_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Graph Action executed_at")


class GraphObservation(_GraphNodeBase):
    kind: Literal["Observation"] = "Observation"
    observation_type: _Identifier = Field(alias="observationType")
    summary: str = Field(min_length=1, max_length=4_000)
    value_digest: _Sha256 = Field(alias="valueDigest")
    producer_id: _Identifier = Field(alias="producerId")
    producer_version: _Identifier = Field(alias="producerVersion")
    producer_digest: _Sha256 = Field(alias="producerDigest")
    origin: GraphContentOrigin
    confidence: _Confidence
    observed_at: datetime = Field(alias="observedAt")

    @field_validator("summary")
    @classmethod
    def require_safe_observation_summary(cls, value: str) -> str:
        return _require_safe_text(value, label="Graph Observation summary")

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Graph Observation observed_at")


class GraphEvidence(_GraphNodeBase):
    kind: Literal["Evidence"] = "Evidence"
    reference: str = Field(min_length=1, max_length=2_000)
    sha256: _Sha256
    media_type: str = Field(
        default="application/json",
        alias="mediaType",
        min_length=1,
        max_length=100,
    )
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    data_classification: _Identifier = Field(
        default="internal",
        alias="dataClassification",
    )

    @field_validator("reference")
    @classmethod
    def require_safe_evidence_reference(cls, value: str) -> str:
        return _require_safe_reference(value)

    @field_validator("media_type")
    @classmethod
    def require_safe_media_type(cls, value: str) -> str:
        return _require_safe_text(value, label="Graph Evidence media type")


class GraphCampaignFact(_GraphNodeBase):
    kind: Literal["CampaignFact"] = "CampaignFact"
    fact_key: _Identifier = Field(alias="factKey")
    statement: str = Field(min_length=1, max_length=4_000)
    value_digest: _Sha256 = Field(alias="valueDigest")
    validation_state: CampaignFactValidationState = Field(alias="validationState")
    producer_id: _Identifier = Field(alias="producerId")
    producer_version: _Identifier = Field(alias="producerVersion")
    producer_digest: _Sha256 = Field(alias="producerDigest")
    origin: GraphContentOrigin
    recorded_at: datetime = Field(alias="recordedAt")

    @field_validator("statement")
    @classmethod
    def require_safe_fact_statement(cls, value: str) -> str:
        return _require_safe_text(value, label="Campaign Fact statement")

    @field_validator("recorded_at")
    @classmethod
    def normalize_recorded_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Campaign Fact recorded_at")


class CampaignFactPayload(StrictModel):
    """Unprivileged fact material without canonical validation-state authority."""

    fact_key: _Identifier = Field(alias="factKey")
    statement: str = Field(min_length=1, max_length=4_000)
    value_digest: _Sha256 = Field(alias="valueDigest")
    producer_id: _Identifier = Field(alias="producerId")
    producer_version: _Identifier = Field(alias="producerVersion")
    producer_digest: _Sha256 = Field(alias="producerDigest")
    origin: GraphContentOrigin
    recorded_at: datetime = Field(alias="recordedAt")

    @field_validator("statement")
    @classmethod
    def require_safe_fact_statement(cls, value: str) -> str:
        return _require_safe_text(value, label="Campaign Fact Proposal statement")

    @field_validator("recorded_at")
    @classmethod
    def normalize_recorded_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Campaign Fact Proposal recorded_at")


GraphNode = Annotated[
    GraphSurface
    | GraphHypothesis
    | GraphAction
    | GraphObservation
    | GraphEvidence
    | GraphCampaignFact,
    Field(discriminator="kind"),
]
_GRAPH_NODE_ADAPTER: TypeAdapter[GraphNode] = TypeAdapter(GraphNode)


class GraphNodeRef(StrictModel):
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    node_id: str = Field(alias="nodeId", pattern=_NODE_ID_PATTERN)
    kind: GraphNodeKind


def graph_node_ref(node: GraphNode) -> GraphNodeRef:
    """Return an exact typed reference to one immutable graph node."""

    return GraphNodeRef(
        campaignId=node.campaign_id,
        nodeId=node.node_id,
        kind=GraphNodeKind(node.kind),
    )


class GraphEdge(StrictModel):
    api_version: Literal["pajin.dev/canonical-graph-edge/v1alpha1"] = Field(
        default=GRAPH_EDGE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GraphEdge"] = "GraphEdge"
    edge_id: str = Field(default="", alias="edgeId", max_length=75)
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    relation: GraphRelation
    source: GraphNodeRef
    target: GraphNodeRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_typed_endpoints_and_identity(self) -> Self:
        if (
            self.source.campaign_id != self.campaign_id
            or self.target.campaign_id != self.campaign_id
        ):
            raise ValueError("Graph edge endpoints belong to another Campaign")
        if self.source.node_id == self.target.node_id:
            raise ValueError("Graph edge cannot be a self-edge")
        expected_endpoints = _RELATION_ENDPOINTS[self.relation]
        observed_endpoints = (self.source.kind, self.target.kind)
        if observed_endpoints != expected_endpoints:
            raise ValueError("Graph edge relation uses invalid endpoint kinds")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"edge_id"},
        )
        expected_id = "graph-edge_" + graph_digest(
            "pajin.graph.edge/v1",
            material,
            max_bytes=_MAX_EDGE_BYTES,
        )
        if not self.edge_id:
            self.edge_id = expected_id
        elif self.edge_id != expected_id:
            raise ValueError("Graph edge ID differs from canonical identity")
        if fullmatch(_EDGE_ID_PATTERN, self.edge_id) is None:
            raise ValueError("Graph edge ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="GraphEdge",
            max_bytes=_MAX_EDGE_BYTES,
        )
        return self


class GraphEvidenceBinding(StrictModel):
    reference: str = Field(min_length=1, max_length=2_000)
    sha256: _Sha256

    @field_validator("reference")
    @classmethod
    def require_safe_binding_reference(cls, value: str) -> str:
        return _require_safe_reference(value)


class GraphProposalLineage(StrictModel):
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    agent_id: _Identifier = Field(alias="agentId")
    task_id: _Identifier = Field(alias="taskId")
    request_id: _PortableIdentifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    capability_grant_id: _Identifier = Field(alias="capabilityGrantId")
    capability_grant_digest: _Sha256 = Field(alias="capabilityGrantDigest")
    capability_id: _Identifier = Field(alias="capabilityId")
    capability_version: _Identifier = Field(alias="capabilityVersion")
    capability_digest: _Sha256 = Field(alias="capabilityDigest")
    action_permit_id: _Identifier | None = Field(default=None, alias="actionPermitId")
    action_permit_digest: _Sha256 | None = Field(
        default=None,
        alias="actionPermitDigest",
    )
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    evidence: list[GraphEvidenceBinding] = Field(
        min_length=1,
        max_length=_MAX_PROPOSAL_EVIDENCE,
    )
    produced_at: datetime = Field(alias="producedAt")

    @field_validator("produced_at")
    @classmethod
    def normalize_produced_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Graph Proposal produced_at")

    @model_validator(mode="after")
    def require_complete_canonical_lineage(self) -> Self:
        if (self.action_permit_id is None) is not (self.action_permit_digest is None):
            raise ValueError("Action Permit ID and digest must be provided together")
        keys = [(item.reference, item.sha256) for item in self.evidence]
        if keys != sorted(set(keys)):
            raise ValueError("Graph Proposal evidence must be unique and sorted")
        return self


class _GraphProposalBase(StrictModel):
    api_version: Literal["pajin.dev/canonical-graph-proposal/v1alpha1"] = Field(
        default=GRAPH_PROPOSAL_API_VERSION,
        alias="apiVersion",
    )
    proposal_id: _Identifier = Field(alias="proposalId")
    producer_id: _Identifier = Field(alias="producerId")
    producer_version: _Identifier = Field(alias="producerVersion")
    producer_digest: _Sha256 = Field(alias="producerDigest")
    lineage: GraphProposalLineage

    @model_validator(mode="after")
    def require_bounded_proposal(self) -> Self:
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label=self.__class__.__name__,
            max_bytes=_MAX_PROPOSAL_BYTES,
        )
        return self

    def digest(self) -> str:
        return graph_digest(
            "pajin.graph.proposal/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_PROPOSAL_BYTES,
        )


class SurfaceProposal(_GraphProposalBase):
    kind: Literal["SurfaceProposal"] = "SurfaceProposal"
    surface: GraphSurface
    edges: list[GraphEdge] = Field(
        default_factory=list,
        max_length=_MAX_PROPOSAL_EDGES,
    )

    @model_validator(mode="after")
    def bind_surface_to_lineage_and_edges(self) -> Self:
        if self.surface.campaign_id != self.lineage.campaign_id:
            raise ValueError("Surface Proposal node belongs to another Campaign")
        for edge in self.edges:
            if (
                edge.campaign_id != self.lineage.campaign_id
                or edge.relation is not GraphRelation.DISCOVERS
                or edge.target.node_id != self.surface.node_id
                or edge.target.kind is not GraphNodeKind.SURFACE
            ):
                raise ValueError("Surface Proposal contains an unrelated edge")
        edge_ids = [edge.edge_id for edge in self.edges]
        if edge_ids != sorted(set(edge_ids)):
            raise ValueError("Surface Proposal edges must be unique and sorted")
        return self


class ObservationProposal(_GraphProposalBase):
    kind: Literal["ObservationProposal"] = "ObservationProposal"
    action: GraphAction
    observation: GraphObservation
    evidence_nodes: list[GraphEvidence] = Field(
        alias="evidenceNodes",
        min_length=1,
        max_length=_MAX_PROPOSAL_EVIDENCE,
    )
    edges: list[GraphEdge] = Field(
        min_length=2,
        max_length=_MAX_PROPOSAL_EDGES,
    )

    @model_validator(mode="after")
    def bind_observation_evidence_and_edges(self) -> Self:
        campaign_id = self.lineage.campaign_id
        if (
            self.action.campaign_id != campaign_id
            or self.observation.campaign_id != campaign_id
            or any(
            evidence.campaign_id != campaign_id for evidence in self.evidence_nodes
            )
        ):
            raise ValueError("Observation Proposal node belongs to another Campaign")
        if (
            self.action.request_id != self.lineage.request_id
            or self.action.request_digest != self.lineage.request_digest
            or self.action.capability_id != self.lineage.capability_id
            or self.action.capability_version != self.lineage.capability_version
            or self.action.capability_digest != self.lineage.capability_digest
        ):
            raise ValueError("Observation Proposal Action differs from its request lineage")
        expected_authority = (
            (
                GraphAuthorityKind.ACTION_PERMIT,
                self.lineage.action_permit_id,
                self.lineage.action_permit_digest,
            )
            if self.lineage.action_permit_id is not None
            else (
                GraphAuthorityKind.CAPABILITY_GRANT,
                self.lineage.capability_grant_id,
                self.lineage.capability_grant_digest,
            )
        )
        if (
            self.action.authority_kind,
            self.action.authority_id,
            self.action.authority_digest,
        ) != expected_authority:
            raise ValueError("Observation Proposal Action differs from its execution authority")
        if (
            self.observation.observed_at < self.action.executed_at
            or self.lineage.produced_at < self.observation.observed_at
        ):
            raise ValueError("Observation Proposal timestamps are causally inconsistent")

        evidence_ids = [evidence.node_id for evidence in self.evidence_nodes]
        if evidence_ids != sorted(set(evidence_ids)):
            raise ValueError("Observation Proposal evidence nodes must be unique and sorted")
        lineage_evidence = {
            (item.reference, item.sha256) for item in self.lineage.evidence
        }
        proposed_evidence = {
            (item.reference, item.sha256) for item in self.evidence_nodes
        }
        if proposed_evidence != lineage_evidence:
            raise ValueError("Observation Proposal evidence differs from its lineage")
        if any(
            item.source_root_digest != self.lineage.source_root_digest
            for item in self.evidence_nodes
        ):
            raise ValueError("Observation Proposal Evidence belongs to another source root")

        edge_ids = [edge.edge_id for edge in self.edges]
        if edge_ids != sorted(set(edge_ids)):
            raise ValueError("Observation Proposal edges must be unique and sorted")
        if any(
            edge.campaign_id != campaign_id
            or self.observation.node_id
            not in {edge.source.node_id, edge.target.node_id}
            for edge in self.edges
        ):
            raise ValueError("Observation Proposal contains an unrelated edge")

        production_edges = [
            edge
            for edge in self.edges
            if edge.relation is GraphRelation.PRODUCES
            and edge.source.node_id == self.action.node_id
            and edge.target.node_id == self.observation.node_id
        ]
        if len(production_edges) != 1:
            raise ValueError("Observation Proposal requires one Action produces edge")
        supported_evidence_ids = {
            edge.target.node_id
            for edge in self.edges
            if edge.relation is GraphRelation.SUPPORTED_BY
            and edge.source.node_id == self.observation.node_id
        }
        if supported_evidence_ids != set(evidence_ids):
            raise ValueError(
                "Observation Proposal must bind every Evidence node with supported-by"
            )
        return self


class CampaignFactProposal(_GraphProposalBase):
    kind: Literal["CampaignFactProposal"] = "CampaignFactProposal"
    fact: CampaignFactPayload

    @model_validator(mode="after")
    def require_causal_fact_time(self) -> Self:
        if self.fact.recorded_at > self.lineage.produced_at:
            raise ValueError("Campaign Fact Proposal predates its Fact")
        return self


GraphProposal = Annotated[
    SurfaceProposal | ObservationProposal | CampaignFactProposal,
    Field(discriminator="kind"),
]
_GRAPH_PROPOSAL_ADAPTER: TypeAdapter[GraphProposal] = TypeAdapter(GraphProposal)


def parse_graph_node(value: object) -> GraphNode:
    """Parse one strictly discriminated Minimum Graph node."""

    return _GRAPH_NODE_ADAPTER.validate_python(value)


def parse_graph_proposal(value: object) -> GraphProposal:
    """Parse one strictly discriminated unprivileged graph proposal."""

    return _GRAPH_PROPOSAL_ADAPTER.validate_python(value)
