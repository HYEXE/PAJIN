"""Single-writer Canonical Graph proposal admission and append-only event contracts."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from enum import StrEnum
from re import fullmatch
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.models import (
    CampaignFactProposal,
    CampaignFactValidationState,
    GraphAction,
    GraphAuthorityKind,
    GraphCampaignFact,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphNode,
    GraphNodeKind,
    GraphObservation,
    GraphProposal,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSurface,
    ObservationProposal,
    SurfaceProposal,
    canonical_graph_json,
    graph_digest,
    parse_graph_proposal,
)

GRAPH_ADMISSION_EVENT_API_VERSION: Literal[
    "pajin.dev/graph-admission-event/v1alpha1"
] = "pajin.dev/graph-admission-event/v1alpha1"

_MAX_EVENT_BYTES = 4 * 1024 * 1024
_MAX_LINEAGE_BYTES = 512 * 1024
_MAX_EVENT_NODES = 2_000
_MAX_EVENT_EDGES = 2_000
_EVENT_ID_PATTERN = r"^graph-admission-event_[a-f0-9]{64}$"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class GraphAdmissionError(ValueError):
    """Base error for invalid Graph admission authority operations."""


class GraphLineageVerificationError(GraphAdmissionError):
    """Raised when a proposal is not bound to a registered trusted source."""


class GraphEventLogError(GraphAdmissionError):
    """Raised when an append would violate the Canonical Event Log contract."""


class GraphAdmissionDecision(StrEnum):
    ADMITTED = "admitted"
    REJECTED = "rejected"


class GraphAdmissionReason(StrEnum):
    ADMITTED = "admitted"
    FOREIGN_CAMPAIGN = "foreign-campaign"
    PRODUCER_NOT_REGISTERED = "producer-not-registered"
    PRODUCER_CONTRACT_MISMATCH = "producer-contract-mismatch"
    PROPOSAL_KIND_NOT_ALLOWED = "proposal-kind-not-allowed"
    PRODUCER_PAYLOAD_MISMATCH = "producer-payload-mismatch"
    LINEAGE_VERIFICATION_FAILED = "lineage-verification-failed"
    DANGLING_EDGE = "dangling-edge"
    PROPOSAL_EQUIVOCATION = "proposal-equivocation"


class GraphProducerRegistration(StrictModel):
    """Code-owned producer identity and the proposal kinds it may submit."""

    producer_id: _Identifier = Field(
        alias="producerId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    producer_version: _Identifier = Field(
        alias="producerVersion",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    producer_digest: _Sha256 = Field(
        alias="producerDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    allowed_proposal_kinds: tuple[GraphProposalKind, ...] = Field(
        alias="allowedProposalKinds",
        min_length=1,
    )

    @model_validator(mode="after")
    def require_sorted_unique_kinds(self) -> Self:
        values = [item.value for item in self.allowed_proposal_kinds]
        if values != sorted(set(values)):
            raise ValueError("allowed Graph Proposal kinds must be unique and sorted")
        return self


class GraphProducerRegistry:
    """Immutable-at-runtime registry of trusted Graph proposal producers."""

    def __init__(self, registrations: Iterable[GraphProducerRegistration]) -> None:
        self._registrations: dict[str, GraphProducerRegistration] = {}
        for registration in registrations:
            if registration.producer_id in self._registrations:
                raise ValueError("Graph producer is registered more than once")
            self._registrations[registration.producer_id] = registration.model_copy(deep=True)
        if not self._registrations:
            raise ValueError("Graph producer registry requires at least one registration")

    def registration(self, producer_id: str) -> GraphProducerRegistration | None:
        registration = self._registrations.get(producer_id)
        return registration.model_copy(deep=True) if registration is not None else None


class GraphLineageVerifier(Protocol):
    """Trusted adapter boundary for Run/request/Capability/evidence lineage."""

    def verify(self, lineage: GraphProposalLineage) -> None:
        """Fail unless all proposal lineage fields match a registered trusted source."""


class TrustedGraphLineageRegistry:
    """Reference verifier for exact, pre-registered trusted lineage records.

    Runtime adapters can populate this registry only after verifying a sealed Run,
    request authority, Capability/Permit, source root, and evidence digests.
    """

    def __init__(self, lineages: Iterable[GraphProposalLineage] = ()) -> None:
        self._digests: dict[tuple[str, str, str, str, str], str] = {}
        for lineage in lineages:
            self.register(lineage)

    def register(self, lineage: GraphProposalLineage) -> None:
        key = _lineage_key(lineage)
        digest = _lineage_digest(lineage)
        existing = self._digests.get(key)
        if existing is not None and existing != digest:
            raise ValueError("trusted Graph lineage identity has equivocated")
        self._digests[key] = digest

    def verify(self, lineage: GraphProposalLineage) -> None:
        expected = self._digests.get(_lineage_key(lineage))
        if expected is None or expected != _lineage_digest(lineage):
            raise GraphLineageVerificationError(
                "Graph proposal lineage does not match a registered trusted source"
            )


class GraphAdmissionEvent(StrictModel):
    """One immutable semantic attempt in the append-only Canonical Event Log."""

    api_version: Literal["pajin.dev/graph-admission-event/v1alpha1"] = Field(
        default=GRAPH_ADMISSION_EVENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GraphAdmissionEvent"] = "GraphAdmissionEvent"
    event_id: str = Field(default="", alias="eventId", max_length=100)
    event_digest: str = Field(default="", alias="eventDigest", max_length=64)
    sequence: int = Field(ge=1)
    previous_event_digest: _Sha256 | None = Field(
        default=None,
        alias="previousEventDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    occurred_at: datetime = Field(alias="occurredAt")
    produced_at: datetime = Field(alias="producedAt")
    authority_id: _Identifier = Field(
        alias="authorityId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    authority_digest: _Sha256 = Field(
        alias="authorityDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    decision: GraphAdmissionDecision
    reason: GraphAdmissionReason
    proposal_id: _Identifier = Field(
        alias="proposalId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    proposal_digest: _Sha256 = Field(
        alias="proposalDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    proposal_kind: GraphProposalKind = Field(alias="proposalKind")
    producer_id: _Identifier = Field(
        alias="producerId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    producer_version: _Identifier = Field(
        alias="producerVersion",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    producer_digest: _Sha256 = Field(
        alias="producerDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    campaign_id: _Identifier = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    proposal_campaign_id: _Identifier = Field(
        alias="proposalCampaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    run_id: _Identifier = Field(alias="runId", min_length=1, max_length=200)
    agent_id: _Identifier = Field(alias="agentId", min_length=1, max_length=200)
    task_id: _Identifier = Field(alias="taskId", min_length=1, max_length=200)
    request_id: _Identifier = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: _Sha256 = Field(
        alias="requestDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    lineage_digest: _Sha256 = Field(
        alias="lineageDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    capability_grant_id: _Identifier = Field(
        alias="capabilityGrantId",
        min_length=1,
        max_length=200,
    )
    capability_grant_digest: _Sha256 = Field(
        alias="capabilityGrantDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    capability_id: _Identifier = Field(alias="capabilityId", min_length=1, max_length=200)
    capability_version: _Identifier = Field(
        alias="capabilityVersion",
        min_length=1,
        max_length=200,
    )
    capability_digest: _Sha256 = Field(
        alias="capabilityDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    action_permit_id: _Identifier | None = Field(default=None, alias="actionPermitId")
    action_permit_digest: _Sha256 | None = Field(
        default=None,
        alias="actionPermitDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    source_root_digest: _Sha256 = Field(
        alias="sourceRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    evidence: list[GraphEvidenceBinding] = Field(max_length=1_000)
    admitted_nodes: list[GraphNode] = Field(
        default_factory=list,
        alias="admittedNodes",
        max_length=_MAX_EVENT_NODES,
    )
    admitted_edges: list[GraphEdge] = Field(
        default_factory=list,
        alias="admittedEdges",
        max_length=_MAX_EVENT_EDGES,
    )

    @field_validator("occurred_at", "produced_at")
    @classmethod
    def normalize_event_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Graph admission time must include an explicit UTC offset or Z")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_decision_material_and_identity(self) -> Self:
        admitted = self.decision is GraphAdmissionDecision.ADMITTED
        if admitted != (self.reason is GraphAdmissionReason.ADMITTED):
            raise ValueError("Graph admission decision and reason are inconsistent")
        if not admitted and (self.admitted_nodes or self.admitted_edges):
            raise ValueError("rejected Graph event cannot contain admitted material")
        if admitted and not self.admitted_nodes:
            raise ValueError("admitted Graph event requires canonical node material")
        if admitted and self.proposal_campaign_id != self.campaign_id:
            raise ValueError("admitted Graph event contains a foreign Proposal Campaign")
        if self.occurred_at < self.produced_at:
            raise ValueError("Graph admission event predates its Proposal")
        if (self.action_permit_id is None) is not (self.action_permit_digest is None):
            raise ValueError("Graph admission Action Permit binding is incomplete")
        evidence_keys = [(item.reference, item.sha256) for item in self.evidence]
        if evidence_keys != sorted(set(evidence_keys)):
            raise ValueError("Graph admission Evidence bindings must be unique and sorted")
        node_ids = [node.node_id for node in self.admitted_nodes]
        edge_ids = [edge.edge_id for edge in self.admitted_edges]
        if node_ids != sorted(set(node_ids)) or edge_ids != sorted(set(edge_ids)):
            raise ValueError("admitted Graph material must be unique and sorted")
        if any(node.campaign_id != self.campaign_id for node in self.admitted_nodes) or any(
            edge.campaign_id != self.campaign_id for edge in self.admitted_edges
        ):
            raise ValueError("admitted Graph material belongs to another Campaign")
        if admitted:
            self._require_proposal_material()
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"event_id", "event_digest"},
        )
        expected_digest = graph_digest(
            "pajin.graph.admission-event/v1",
            material,
            max_bytes=_MAX_EVENT_BYTES,
        )
        expected_id = f"graph-admission-event_{expected_digest}"
        if self.event_digest and self.event_digest != expected_digest:
            raise ValueError("Graph admission event digest differs from canonical identity")
        if self.event_id and self.event_id != expected_id:
            raise ValueError("Graph admission event ID differs from canonical identity")
        self.event_digest = expected_digest
        self.event_id = expected_id
        if fullmatch(_EVENT_ID_PATTERN, self.event_id) is None:
            raise ValueError("Graph admission event ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="GraphAdmissionEvent",
            max_bytes=_MAX_EVENT_BYTES,
        )
        return self

    def _require_proposal_material(self) -> None:
        if self.proposal_kind is GraphProposalKind.SURFACE:
            self._require_surface_material()
        elif self.proposal_kind is GraphProposalKind.OBSERVATION:
            self._require_observation_material()
        else:
            self._require_campaign_fact_material()

    def _require_surface_material(self) -> None:
        if len(self.admitted_nodes) != 1 or not isinstance(
            self.admitted_nodes[0],
            GraphSurface,
        ):
            raise ValueError("Surface admission event contains invalid node material")
        surface = self.admitted_nodes[0]
        if any(
            edge.relation is not GraphRelation.DISCOVERS
            or edge.target.node_id != surface.node_id
            for edge in self.admitted_edges
        ):
            raise ValueError("Surface admission event contains invalid edge material")

    def _require_observation_material(self) -> None:
        actions = [node for node in self.admitted_nodes if isinstance(node, GraphAction)]
        observations = [
            node for node in self.admitted_nodes if isinstance(node, GraphObservation)
        ]
        evidence = [node for node in self.admitted_nodes if isinstance(node, GraphEvidence)]
        if len(actions) != 1 or len(observations) != 1 or not evidence:
            raise ValueError("Observation admission event contains incomplete node material")
        if len(self.admitted_nodes) != len(actions) + len(observations) + len(evidence):
            raise ValueError("Observation admission event contains unrelated node material")
        action = actions[0]
        observation = observations[0]
        if not self._action_matches_event(action):
            raise ValueError("admitted Graph Action differs from event lineage")
        if (
            observation.producer_id,
            observation.producer_version,
            observation.producer_digest,
        ) != (self.producer_id, self.producer_version, self.producer_digest):
            raise ValueError("admitted Graph Observation differs from event producer")
        expected_evidence = {(item.reference, item.sha256) for item in self.evidence}
        observed_evidence = {(item.reference, item.sha256) for item in evidence}
        if expected_evidence != observed_evidence or any(
            item.source_root_digest != self.source_root_digest for item in evidence
        ):
            raise ValueError("admitted Graph Evidence differs from event lineage")
        if any(
            observation.node_id not in {edge.source.node_id, edge.target.node_id}
            for edge in self.admitted_edges
        ):
            raise ValueError("Observation admission event contains an unrelated edge")
        production_edges = [
            edge
            for edge in self.admitted_edges
            if edge.relation is GraphRelation.PRODUCES
            and edge.source.node_id == action.node_id
            and edge.target.node_id == observation.node_id
        ]
        supported_ids = {
            edge.target.node_id
            for edge in self.admitted_edges
            if edge.relation is GraphRelation.SUPPORTED_BY
            and edge.source.node_id == observation.node_id
        }
        if len(production_edges) != 1 or supported_ids != {
            item.node_id for item in evidence
        }:
            raise ValueError("Observation admission event contains incomplete edge material")

    def _action_matches_event(self, action: GraphAction) -> bool:
        expected_authority = (
            (
                GraphAuthorityKind.ACTION_PERMIT,
                self.action_permit_id,
                self.action_permit_digest,
            )
            if self.action_permit_id is not None
            else (
                GraphAuthorityKind.CAPABILITY_GRANT,
                self.capability_grant_id,
                self.capability_grant_digest,
            )
        )
        return (
            action.request_id == self.request_id
            and action.request_digest == self.request_digest
            and action.capability_id == self.capability_id
            and action.capability_version == self.capability_version
            and action.capability_digest == self.capability_digest
            and (
                action.authority_kind,
                action.authority_id,
                action.authority_digest,
            )
            == expected_authority
        )

    def _require_campaign_fact_material(self) -> None:
        if (
            len(self.admitted_nodes) != 1
            or not isinstance(self.admitted_nodes[0], GraphCampaignFact)
            or self.admitted_edges
        ):
            raise ValueError("Campaign Fact admission event contains invalid material")
        fact = self.admitted_nodes[0]
        if fact.validation_state is not CampaignFactValidationState.ADMITTED or (
            fact.producer_id,
            fact.producer_version,
            fact.producer_digest,
        ) != (self.producer_id, self.producer_version, self.producer_digest):
            raise ValueError("Campaign Fact admission event contains unauthorized state")


class GraphAdmissionResult(StrictModel):
    event: GraphAdmissionEvent
    idempotent: bool


class GraphEventLog(Protocol):
    """Storage-neutral append-only event contract owned by one admission authority."""

    def claim_writer(self, authority_id: str, authority_digest: str) -> object:
        """Issue the only process-local writer capability for this log."""

    def event_for_attempt(
        self,
        proposal_id: str,
        proposal_digest: str,
    ) -> GraphAdmissionEvent | None:
        """Return the prior event for one exact semantic attempt."""

    def first_proposal_digest(self, proposal_id: str) -> str | None:
        """Return the first digest that reserved a proposal ID."""

    def next_position(self) -> tuple[int, str | None]:
        """Return the next sequence and current head digest."""

    def admitted_node(self, node_id: str) -> GraphNode | None:
        """Return canonical node material already admitted by this log."""

    def append(
        self,
        event: GraphAdmissionEvent,
        *,
        writer: object,
    ) -> GraphAdmissionEvent:
        """Append exactly one event or fail without changing the log."""

    def events(self) -> tuple[GraphAdmissionEvent, ...]:
        """Return an immutable copy of the ordered event sequence."""


class InMemoryGraphEventLog:
    """Reference event-log spike with hash-chain and append-only invariants."""

    def __init__(self) -> None:
        self._events: list[GraphAdmissionEvent] = []
        self._attempts: dict[tuple[str, str], GraphAdmissionEvent] = {}
        self._first_digests: dict[str, str] = {}
        self._nodes: dict[str, GraphNode] = {}
        self._writer: object | None = None
        self._writer_identity: tuple[str, str] | None = None
        self._lock = threading.RLock()

    def claim_writer(self, authority_id: str, authority_digest: str) -> object:
        with self._lock:
            if (
                fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", authority_id) is None
                or fullmatch(r"^[a-f0-9]{64}$", authority_digest) is None
            ):
                raise GraphEventLogError("Canonical Event Log writer identity is invalid")
            if self._writer is not None:
                raise GraphEventLogError("Canonical Event Log writer is already claimed")
            writer = object()
            self._writer = writer
            self._writer_identity = (authority_id, authority_digest)
            return writer

    def event_for_attempt(
        self,
        proposal_id: str,
        proposal_digest: str,
    ) -> GraphAdmissionEvent | None:
        with self._lock:
            event = self._attempts.get((proposal_id, proposal_digest))
            return event.model_copy(deep=True) if event is not None else None

    def first_proposal_digest(self, proposal_id: str) -> str | None:
        with self._lock:
            return self._first_digests.get(proposal_id)

    def next_position(self) -> tuple[int, str | None]:
        with self._lock:
            head = self._events[-1].event_digest if self._events else None
            return len(self._events) + 1, head

    def admitted_node(self, node_id: str) -> GraphNode | None:
        with self._lock:
            node = self._nodes.get(node_id)
            return node.model_copy(deep=True) if node is not None else None

    def append(
        self,
        event: GraphAdmissionEvent,
        *,
        writer: object,
    ) -> GraphAdmissionEvent:
        with self._lock:
            if writer is not self._writer:
                raise GraphEventLogError("Canonical Event Log write authority is invalid")
            stored = GraphAdmissionEvent.model_validate(
                event.model_dump(mode="json", by_alias=True)
            )
            if self._writer_identity != (stored.authority_id, stored.authority_digest):
                raise GraphEventLogError("Graph event authority differs from the claimed writer")
            self._require_next_event(stored)
            self._events.append(stored)
            key = (stored.proposal_id, stored.proposal_digest)
            self._attempts[key] = stored
            self._first_digests.setdefault(stored.proposal_id, stored.proposal_digest)
            if stored.decision is GraphAdmissionDecision.ADMITTED:
                for node in stored.admitted_nodes:
                    self._nodes.setdefault(node.node_id, node.model_copy(deep=True))
            return stored.model_copy(deep=True)

    def events(self) -> tuple[GraphAdmissionEvent, ...]:
        with self._lock:
            return tuple(event.model_copy(deep=True) for event in self._events)

    def _require_next_event(self, event: GraphAdmissionEvent) -> None:
        expected_sequence = len(self._events) + 1
        expected_previous = self._events[-1].event_digest if self._events else None
        if event.sequence != expected_sequence or event.previous_event_digest != expected_previous:
            raise GraphEventLogError("Graph event sequence or predecessor is stale")
        key = (event.proposal_id, event.proposal_digest)
        if key in self._attempts:
            raise GraphEventLogError("Graph semantic attempt is already recorded")
        if any(item.event_id == event.event_id for item in self._events):
            raise GraphEventLogError("Graph event identity is already recorded")
        proposed = {
            node.node_id: (node.campaign_id, GraphNodeKind(node.kind))
            for node in event.admitted_nodes
        }
        for edge in event.admitted_edges:
            for reference in (edge.source, edge.target):
                identity = proposed.get(reference.node_id)
                if identity is None:
                    existing = self._nodes.get(reference.node_id)
                    if existing is None:
                        raise GraphEventLogError("Graph event contains a dangling edge")
                    identity = (existing.campaign_id, GraphNodeKind(existing.kind))
                if identity != (reference.campaign_id, reference.kind):
                    raise GraphEventLogError("Graph event edge identity is inconsistent")


class GraphAdmissionAuthority:
    """The only component permitted to turn proposals into canonical Graph events."""

    def __init__(
        self,
        *,
        campaign_id: str,
        authority_id: str,
        authority_digest: str,
        producers: GraphProducerRegistry,
        lineage_verifier: GraphLineageVerifier,
        event_log: GraphEventLog,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("Graph Admission Authority campaign ID is invalid")
        if fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", authority_id) is None:
            raise ValueError("Graph Admission Authority ID is invalid")
        if fullmatch(r"^[a-f0-9]{64}$", authority_digest) is None:
            raise ValueError("Graph Admission Authority digest is invalid")
        self._campaign_id = campaign_id
        self._authority_id = authority_id
        self._authority_digest = authority_digest
        self._producers = producers
        self._lineage_verifier = lineage_verifier
        self._event_log = event_log
        self._event_writer = event_log.claim_writer(authority_id, authority_digest)
        self._clock = clock or _utc_now
        self._lock = threading.RLock()

    def submit(self, proposal: GraphProposal) -> GraphAdmissionResult:
        """Validate and append one proposal attempt under the single-writer lock."""

        proposal = parse_graph_proposal(proposal.model_dump(mode="json", by_alias=True))
        proposal_digest = proposal.digest()
        with self._lock:
            prior = self._event_log.event_for_attempt(proposal.proposal_id, proposal_digest)
            if prior is not None:
                return GraphAdmissionResult(event=prior, idempotent=True)

            first_digest = self._event_log.first_proposal_digest(proposal.proposal_id)
            if first_digest is not None and first_digest != proposal_digest:
                return self._reject(
                    proposal,
                    proposal_digest,
                    GraphAdmissionReason.PROPOSAL_EQUIVOCATION,
                )

            reason = self._rejection_reason(proposal)
            if reason is not None:
                return self._reject(proposal, proposal_digest, reason)

            nodes, edges = self._materialize(proposal)
            if not self._edges_resolve(nodes, edges):
                return self._reject(
                    proposal,
                    proposal_digest,
                    GraphAdmissionReason.DANGLING_EDGE,
                )
            event = self._new_event(
                proposal,
                proposal_digest,
                decision=GraphAdmissionDecision.ADMITTED,
                reason=GraphAdmissionReason.ADMITTED,
                nodes=nodes,
                edges=edges,
            )
            return GraphAdmissionResult(
                event=self._event_log.append(event, writer=self._event_writer),
                idempotent=False,
            )

    def _rejection_reason(self, proposal: GraphProposal) -> GraphAdmissionReason | None:
        if proposal.lineage.campaign_id != self._campaign_id:
            return GraphAdmissionReason.FOREIGN_CAMPAIGN
        registration = self._producers.registration(proposal.producer_id)
        if registration is None:
            return GraphAdmissionReason.PRODUCER_NOT_REGISTERED
        if (
            registration.producer_version != proposal.producer_version
            or registration.producer_digest != proposal.producer_digest
        ):
            return GraphAdmissionReason.PRODUCER_CONTRACT_MISMATCH
        if GraphProposalKind(proposal.kind) not in registration.allowed_proposal_kinds:
            return GraphAdmissionReason.PROPOSAL_KIND_NOT_ALLOWED
        if not _payload_producer_matches(proposal):
            return GraphAdmissionReason.PRODUCER_PAYLOAD_MISMATCH
        try:
            self._lineage_verifier.verify(proposal.lineage)
        except GraphLineageVerificationError:
            return GraphAdmissionReason.LINEAGE_VERIFICATION_FAILED
        return None

    def _reject(
        self,
        proposal: GraphProposal,
        proposal_digest: str,
        reason: GraphAdmissionReason,
    ) -> GraphAdmissionResult:
        event = self._new_event(
            proposal,
            proposal_digest,
            decision=GraphAdmissionDecision.REJECTED,
            reason=reason,
            nodes=[],
            edges=[],
        )
        return GraphAdmissionResult(
            event=self._event_log.append(event, writer=self._event_writer),
            idempotent=False,
        )

    def _new_event(
        self,
        proposal: GraphProposal,
        proposal_digest: str,
        *,
        decision: GraphAdmissionDecision,
        reason: GraphAdmissionReason,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> GraphAdmissionEvent:
        sequence, previous = self._event_log.next_position()
        lineage = proposal.lineage
        return GraphAdmissionEvent(
            sequence=sequence,
            previousEventDigest=previous,
            occurredAt=self._clock(),
            producedAt=lineage.produced_at,
            authorityId=self._authority_id,
            authorityDigest=self._authority_digest,
            decision=decision,
            reason=reason,
            proposalId=proposal.proposal_id,
            proposalDigest=proposal_digest,
            proposalKind=GraphProposalKind(proposal.kind),
            producerId=proposal.producer_id,
            producerVersion=proposal.producer_version,
            producerDigest=proposal.producer_digest,
            campaignId=self._campaign_id,
            proposalCampaignId=lineage.campaign_id,
            runId=lineage.run_id,
            agentId=lineage.agent_id,
            taskId=lineage.task_id,
            requestId=lineage.request_id,
            requestDigest=lineage.request_digest,
            lineageDigest=_lineage_digest(lineage),
            capabilityGrantId=lineage.capability_grant_id,
            capabilityGrantDigest=lineage.capability_grant_digest,
            capabilityId=lineage.capability_id,
            capabilityVersion=lineage.capability_version,
            capabilityDigest=lineage.capability_digest,
            actionPermitId=lineage.action_permit_id,
            actionPermitDigest=lineage.action_permit_digest,
            sourceRootDigest=lineage.source_root_digest,
            evidence=[item.model_copy(deep=True) for item in lineage.evidence],
            admittedNodes=sorted(nodes, key=lambda item: item.node_id),
            admittedEdges=sorted(edges, key=lambda item: item.edge_id),
        )

    @staticmethod
    def _materialize(proposal: GraphProposal) -> tuple[list[GraphNode], list[GraphEdge]]:
        if isinstance(proposal, SurfaceProposal):
            return [proposal.surface.model_copy(deep=True)], [
                edge.model_copy(deep=True) for edge in proposal.edges
            ]
        if isinstance(proposal, ObservationProposal):
            nodes: list[GraphNode] = [
                proposal.action.model_copy(deep=True),
                proposal.observation.model_copy(deep=True),
                *(item.model_copy(deep=True) for item in proposal.evidence_nodes),
            ]
            return nodes, [edge.model_copy(deep=True) for edge in proposal.edges]
        if isinstance(proposal, CampaignFactProposal):
            payload = proposal.fact.model_dump(mode="python", by_alias=True)
            fact = GraphCampaignFact(
                campaignId=proposal.lineage.campaign_id,
                validationState=CampaignFactValidationState.ADMITTED,
                **payload,
            )
            return [fact], []
        raise TypeError("unsupported Graph Proposal kind")

    def _edges_resolve(self, nodes: list[GraphNode], edges: list[GraphEdge]) -> bool:
        proposed = {
            node.node_id: (node.campaign_id, GraphNodeKind(node.kind)) for node in nodes
        }
        for edge in edges:
            for reference in (edge.source, edge.target):
                identity = proposed.get(reference.node_id)
                if identity is None:
                    existing = self._event_log.admitted_node(reference.node_id)
                    if existing is None:
                        return False
                    identity = (existing.campaign_id, GraphNodeKind(existing.kind))
                if identity != (reference.campaign_id, reference.kind):
                    return False
        return True


def _payload_producer_matches(proposal: GraphProposal) -> bool:
    payload: GraphObservation | object
    if isinstance(proposal, ObservationProposal):
        payload = proposal.observation
    elif isinstance(proposal, CampaignFactProposal):
        payload = proposal.fact
    else:
        return True
    return (
        getattr(payload, "producer_id", None) == proposal.producer_id
        and getattr(payload, "producer_version", None) == proposal.producer_version
        and getattr(payload, "producer_digest", None) == proposal.producer_digest
    )


def _lineage_key(lineage: GraphProposalLineage) -> tuple[str, str, str, str, str]:
    return (
        lineage.campaign_id,
        lineage.run_id,
        lineage.agent_id,
        lineage.task_id,
        lineage.request_id,
    )


def _lineage_digest(lineage: GraphProposalLineage) -> str:
    return graph_digest(
        "pajin.graph.proposal-lineage/v1",
        lineage.model_dump(mode="json", by_alias=True),
        max_bytes=_MAX_LINEAGE_BYTES,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)
