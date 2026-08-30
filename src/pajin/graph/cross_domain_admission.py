"""DOMAIN-005 exact cross-domain knowledge admission without authority transfer."""

from __future__ import annotations

from hashlib import sha256
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphAdmissionReason,
    GraphEventLog,
    GraphProducerRegistration,
    TrustedGraphLineageRegistry,
)
from pajin.graph.domain_semantics import (
    SecurityDomainGraphTypeSetRef,
    registered_multi_domain_graph_semantics,
    resolve_registered_security_domain_graph_type_set,
)
from pajin.graph.models import (
    GraphContentOrigin,
    GraphEdge,
    GraphHypothesis,
    GraphNodeKind,
    GraphObservation,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    GraphSurface,
    HypothesisProposal,
    SurfaceProposal,
    graph_digest,
    graph_node_ref,
)
from pajin.graph.projection import (
    GraphProjector,
    GraphSnapshot,
    GraphSnapshotRef,
    graph_snapshot_ref,
)

CROSS_DOMAIN_GRAPH_PRODUCER_CONTRACT_API_VERSION: Literal[
    "pajin.dev/cross-domain-graph-producer-contract/v1alpha1"
] = "pajin.dev/cross-domain-graph-producer-contract/v1alpha1"
CROSS_DOMAIN_GRAPH_ADMISSION_CANDIDATE_API_VERSION: Literal[
    "pajin.dev/cross-domain-graph-admission-candidate/v1alpha1"
] = "pajin.dev/cross-domain-graph-admission-candidate/v1alpha1"
CROSS_DOMAIN_GRAPH_ADMISSION_API_VERSION: Literal[
    "pajin.dev/cross-domain-graph-admission/v1alpha1"
] = "pajin.dev/cross-domain-graph-admission/v1alpha1"

CROSS_DOMAIN_GRAPH_PRODUCER_ID = "pajin.graph.cross-domain.ai-to-web-knowledge"
CROSS_DOMAIN_GRAPH_PRODUCER_VERSION = "1.0.0"
CROSS_DOMAIN_GRAPH_PRODUCER_DIGEST = sha256(
    b"pajin.graph.cross-domain.ai-to-web-knowledge/v1"
).hexdigest()

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_FALSE_AUTHORITY_FIELDS = (
    "campaign_mutation_authorized",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "budget_change_authorized",
    "egress_change_authorized",
    "credential_use_authorized",
    "worker_selection_authorized",
    "approval_satisfied",
    "permit_issuance_authorized",
    "source_authority_transfer_authorized",
    "execution_authorized",
)


class CrossDomainGraphAdmissionError(ValueError):
    """Raised when cross-domain knowledge cannot be admitted exactly."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class CrossDomainGraphProducerContract(_FrozenStrictModel):
    """One code-owned semantic transition, never a runtime authority root."""

    api_version: Literal["pajin.dev/cross-domain-graph-producer-contract/v1alpha1"] = Field(
        default=CROSS_DOMAIN_GRAPH_PRODUCER_CONTRACT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CrossDomainGraphProducerContract"] = "CrossDomainGraphProducerContract"
    contract_id: str = Field(default="", alias="contractId", max_length=100)
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    producer_id: Literal["pajin.graph.cross-domain.ai-to-web-knowledge"] = Field(
        default="pajin.graph.cross-domain.ai-to-web-knowledge",
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="producerVersion",
    )
    producer_digest: _Sha256 = Field(
        default=CROSS_DOMAIN_GRAPH_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    source_type_set: SecurityDomainGraphTypeSetRef = Field(alias="sourceTypeSet")
    target_type_set: SecurityDomainGraphTypeSetRef = Field(alias="targetTypeSet")
    allowed_proposal_kinds: tuple[GraphProposalKind, ...] = Field(
        alias="allowedProposalKinds",
        min_length=2,
        max_length=2,
    )
    knowledge_only: Literal[True] = Field(default=True, alias="knowledgeOnly")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("knowledge_only", "execution_authorized", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cross-domain producer markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_code_owned_transition(self) -> Self:
        source = resolve_registered_security_domain_graph_type_set(self.source_type_set)
        target = resolve_registered_security_domain_graph_type_set(self.target_type_set)
        if (
            self.producer_digest != CROSS_DOMAIN_GRAPH_PRODUCER_DIGEST
            or source.domain_classification.domain is not SecurityDomain.AI
            or target.domain_classification.domain is not SecurityDomain.WEB
            or self.allowed_proposal_kinds
            != (GraphProposalKind.HYPOTHESIS, GraphProposalKind.SURFACE)
        ):
            raise ValueError("Cross-domain producer contract differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_id", "contract_digest"},
        )
        digest = graph_digest(
            "pajin.graph.cross-domain-producer-contract/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        contract_id = f"cross-domain-producer_{digest}"
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Cross-domain producer contract Digest differs")
        if self.contract_id and self.contract_id != contract_id:
            raise ValueError("Cross-domain producer contract ID differs")
        object.__setattr__(self, "contract_digest", digest)
        object.__setattr__(self, "contract_id", contract_id)
        return self


CrossDomainKnowledgeProposal = Annotated[
    SurfaceProposal | HypothesisProposal,
    Field(discriminator="kind"),
]


class CrossDomainGraphAdmissionCandidate(_FrozenStrictModel):
    """Snapshot-bound knowledge proposal derived from one admitted Observation."""

    api_version: Literal["pajin.dev/cross-domain-graph-admission-candidate/v1alpha1"] = Field(
        default=CROSS_DOMAIN_GRAPH_ADMISSION_CANDIDATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CrossDomainGraphAdmissionCandidate"] = "CrossDomainGraphAdmissionCandidate"
    candidate_id: str = Field(default="", alias="candidateId", max_length=110)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    contract: CrossDomainGraphProducerContract
    snapshot: GraphSnapshotRef
    source_graph_event: GraphAdmissionEvent = Field(alias="sourceGraphEvent")
    source_observation: GraphObservation = Field(alias="sourceObservation")
    proposal: CrossDomainKnowledgeProposal
    target_knowledge_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="targetKnowledgeState",
    )
    source_authority_provenance_bound: Literal[True] = Field(
        default=True,
        alias="sourceAuthorityProvenanceBound",
    )
    campaign_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="campaignMutationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    budget_change_authorized: Literal[False] = Field(
        default=False,
        alias="budgetChangeAuthorized",
    )
    egress_change_authorized: Literal[False] = Field(
        default=False,
        alias="egressChangeAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    source_authority_transfer_authorized: Literal[False] = Field(
        default=False,
        alias="sourceAuthorityTransferAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("source_authority_provenance_bound", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cross-domain source provenance marker must be true")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cross-domain knowledge cannot carry execution authority")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        source_type_set = resolve_registered_security_domain_graph_type_set(
            self.contract.source_type_set
        )
        target_type_set = resolve_registered_security_domain_graph_type_set(
            self.contract.target_type_set
        )
        proposal = self.proposal
        expected_relation = (
            GraphRelation.DISCOVERS
            if isinstance(proposal, SurfaceProposal)
            else GraphRelation.ENABLES
        )
        target = proposal.surface if isinstance(proposal, SurfaceProposal) else proposal.hypothesis
        if (
            self.snapshot.campaign_id != self.source_observation.campaign_id
            or self.snapshot.revision < self.source_graph_event.sequence
            or self.source_graph_event.decision is not GraphAdmissionDecision.ADMITTED
            or self.source_graph_event.reason is not GraphAdmissionReason.ADMITTED
            or self.source_graph_event.proposal_kind is not GraphProposalKind.OBSERVATION
            or self.source_observation not in self.source_graph_event.admitted_nodes
            or self.source_observation.observation_type != source_type_set.observation_type
            or proposal.lineage != _lineage_from_event(self.source_graph_event)
            or (
                proposal.producer_id,
                proposal.producer_version,
                proposal.producer_digest,
            )
            != (
                self.contract.producer_id,
                self.contract.producer_version,
                self.contract.producer_digest,
            )
            or GraphProposalKind(proposal.kind) not in self.contract.allowed_proposal_kinds
            or target.campaign_id != self.snapshot.campaign_id
            or len(proposal.edges) != 1
            or proposal.edges[0].relation is not expected_relation
            or proposal.edges[0].source != graph_node_ref(self.source_observation)
            or proposal.edges[0].target != graph_node_ref(target)
        ):
            raise ValueError("Cross-domain admission candidate lineage or relation differs")
        if isinstance(target, GraphSurface):
            if (
                target.surface_type != target_type_set.surface_type
                or target.locator_schema != target_type_set.locator_schema
                or target.origin is not GraphContentOrigin.TARGET_DERIVED
            ):
                raise ValueError("Cross-domain Surface semantics differ from target Domain")
        elif (
            target.hypothesis_type != target_type_set.hypothesis_type
            or target.origin is not GraphContentOrigin.AGENT_DERIVED
        ):
            raise ValueError("Cross-domain Hypothesis semantics differ from target Domain")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.graph.cross-domain-admission-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"cross-domain-candidate_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Cross-domain admission candidate Digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Cross-domain admission candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class CrossDomainGraphAdmission(_FrozenStrictModel):
    """Content-addressed proof of knowledge-only Canonical Graph admission."""

    api_version: Literal["pajin.dev/cross-domain-graph-admission/v1alpha1"] = Field(
        default=CROSS_DOMAIN_GRAPH_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CrossDomainGraphAdmission"] = "CrossDomainGraphAdmission"
    admission_id: str = Field(default="", alias="admissionId", max_length=110)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: CrossDomainGraphAdmissionCandidate
    graph_event: GraphAdmissionEvent = Field(alias="graphEvent")
    graph_admitted: Literal[True] = Field(default=True, alias="graphAdmitted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("graph_admitted", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Cross-domain Graph admitted marker must be true")
        return value

    @field_validator("execution_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Cross-domain Graph admission cannot authorize execution")
        return value

    @model_validator(mode="after")
    def bind_admission_identity(self) -> Self:
        proposal = self.candidate.proposal
        target_kind = (
            GraphNodeKind.SURFACE
            if isinstance(proposal, SurfaceProposal)
            else GraphNodeKind.HYPOTHESIS
        )
        if (
            self.graph_event.decision is not GraphAdmissionDecision.ADMITTED
            or self.graph_event.reason is not GraphAdmissionReason.ADMITTED
            or self.graph_event.proposal_id != proposal.proposal_id
            or self.graph_event.proposal_digest != proposal.digest()
            or len(self.graph_event.admitted_nodes) != 1
            or self.graph_event.admitted_nodes[0].kind != target_kind
            or self.graph_event.admitted_edges != proposal.edges
            or self.graph_event.capability_grant_id
            != self.candidate.source_graph_event.capability_grant_id
            or self.graph_event.capability_grant_digest
            != self.candidate.source_graph_event.capability_grant_digest
            or self.graph_event.action_permit_id
            != self.candidate.source_graph_event.action_permit_id
            or self.graph_event.action_permit_digest
            != self.candidate.source_graph_event.action_permit_digest
        ):
            raise ValueError("Cross-domain Graph event differs from candidate provenance")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.graph.cross-domain-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"cross-domain-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Cross-domain Graph admission Digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Cross-domain Graph admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def registered_cross_domain_graph_producer_contract() -> CrossDomainGraphProducerContract:
    """Return the first exact DOMAIN-005 AI Observation to Web knowledge producer."""

    type_sets = registered_multi_domain_graph_semantics().domain_type_sets
    source = next(
        item for item in type_sets if item.domain_classification.domain is SecurityDomain.AI
    )
    target = next(
        item for item in type_sets if item.domain_classification.domain is SecurityDomain.WEB
    )
    return CrossDomainGraphProducerContract(
        sourceTypeSet=source.reference(),
        targetTypeSet=target.reference(),
        allowedProposalKinds=(GraphProposalKind.HYPOTHESIS, GraphProposalKind.SURFACE),
    )


def cross_domain_graph_producer_registration() -> GraphProducerRegistration:
    """Return the existing Graph writer registration for the DOMAIN-005 producer."""

    contract = registered_cross_domain_graph_producer_contract()
    return GraphProducerRegistration(
        producerId=contract.producer_id,
        producerVersion=contract.producer_version,
        producerDigest=contract.producer_digest,
        allowedProposalKinds=contract.allowed_proposal_kinds,
    )


class CrossDomainGraphAdmissionGate:
    """Compile exact knowledge proposals and re-enter the existing Graph writer."""

    def __init__(
        self,
        *,
        event_log: GraphEventLog,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
    ) -> None:
        if not isinstance(graph_admission, GraphAdmissionAuthority):
            raise TypeError("Cross-domain admission requires GraphAdmissionAuthority")
        if not isinstance(trusted_lineages, TrustedGraphLineageRegistry):
            raise TypeError("Cross-domain admission requires TrustedGraphLineageRegistry")
        if (
            getattr(graph_admission, "_event_log", None) is not event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
        ):
            raise ValueError("Cross-domain Graph authority wiring differs")
        contract = registered_cross_domain_graph_producer_contract()
        producers = getattr(graph_admission, "_producers", None)
        if producers is None or producers.registration(contract.producer_id) != (
            cross_domain_graph_producer_registration()
        ):
            raise ValueError("Cross-domain Graph producer is not registered exactly")
        campaign_id = getattr(graph_admission, "_campaign_id", None)
        authority_id = getattr(graph_admission, "_authority_id", None)
        authority_digest = getattr(graph_admission, "_authority_digest", None)
        if not all(
            isinstance(value, str) for value in (campaign_id, authority_id, authority_digest)
        ):
            raise ValueError("Cross-domain Graph authority identity is incomplete")
        self._event_log = event_log
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages
        self._contract = contract
        self._campaign_id = cast(str, campaign_id)
        self._authority_id = cast(str, authority_id)
        self._authority_digest = cast(str, authority_digest)

    def prepare_surface(
        self,
        *,
        source_event: GraphAdmissionEvent,
        snapshot: GraphSnapshot,
        target_id: str,
        locator_digest: str,
    ) -> CrossDomainGraphAdmissionCandidate:
        """Prepare a Web Surface that remains registered-not-authorized."""

        try:
            return self._build_surface(
                source_event=source_event,
                snapshot=snapshot,
                target_id=target_id,
                locator_digest=locator_digest,
                require_current=True,
            )
        except CrossDomainGraphAdmissionError:
            raise
        except Exception as exc:
            raise CrossDomainGraphAdmissionError(
                "Cross-domain Surface candidate preparation failed closed"
            ) from exc

    def prepare_hypothesis(
        self,
        *,
        source_event: GraphAdmissionEvent,
        snapshot: GraphSnapshot,
        statement: str,
        expected_observable: str,
        confidence: float,
    ) -> CrossDomainGraphAdmissionCandidate:
        """Prepare a bounded Web Hypothesis without action or Finding authority."""

        try:
            return self._build_hypothesis(
                source_event=source_event,
                snapshot=snapshot,
                statement=statement,
                expected_observable=expected_observable,
                confidence=confidence,
                require_current=True,
            )
        except CrossDomainGraphAdmissionError:
            raise
        except Exception as exc:
            raise CrossDomainGraphAdmissionError(
                "Cross-domain Hypothesis candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        candidate: CrossDomainGraphAdmissionCandidate,
        *,
        snapshot: GraphSnapshot,
    ) -> CrossDomainGraphAdmission:
        """Admit one exact candidate or return its prior admitted semantic attempt."""

        try:
            canonical = CrossDomainGraphAdmissionCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            proposal = canonical.proposal
            if isinstance(proposal, SurfaceProposal):
                rebuilt = self._build_surface(
                    source_event=canonical.source_graph_event,
                    snapshot=snapshot,
                    target_id=proposal.surface.target_id,
                    locator_digest=proposal.surface.locator_digest,
                    require_current=False,
                )
            else:
                rebuilt = self._build_hypothesis(
                    source_event=canonical.source_graph_event,
                    snapshot=snapshot,
                    statement=proposal.hypothesis.statement,
                    expected_observable=proposal.hypothesis.expected_observable,
                    confidence=proposal.hypothesis.confidence,
                    require_current=False,
                )
            if rebuilt != canonical:
                raise CrossDomainGraphAdmissionError(
                    "Cross-domain candidate differs from its registered producer"
                )
            proposal_digest = proposal.digest()
            prior = self._event_log.event_for_attempt(proposal.proposal_id, proposal_digest)
            if prior is None:
                expected_head = canonical.snapshot.event_log_head_digest
                if expected_head is None:
                    raise CrossDomainGraphAdmissionError(
                        "Cross-domain admission requires a non-empty Graph Snapshot"
                    )
                self._trusted_lineages.register(proposal.lineage)
                result = self._graph_admission.submit_if_current(
                    proposal,
                    expected_event_log_head_digest=expected_head,
                )
                event = result.event
            else:
                event = prior
            if event.decision is not GraphAdmissionDecision.ADMITTED:
                raise CrossDomainGraphAdmissionError(
                    f"Cross-domain Graph admission was rejected: {event.reason.value}"
                )
            return CrossDomainGraphAdmission(candidate=canonical, graphEvent=event)
        except CrossDomainGraphAdmissionError:
            raise
        except Exception as exc:
            raise CrossDomainGraphAdmissionError(
                "Cross-domain Graph admission failed closed"
            ) from exc

    def _build_surface(
        self,
        *,
        source_event: GraphAdmissionEvent,
        snapshot: GraphSnapshot,
        target_id: str,
        locator_digest: str,
        require_current: bool,
    ) -> CrossDomainGraphAdmissionCandidate:
        snapshot, source_event, observation = self._verified_source(
            source_event,
            snapshot,
            require_current=require_current,
        )
        target = resolve_registered_security_domain_graph_type_set(self._contract.target_type_set)
        surface = GraphSurface(
            campaignId=snapshot.campaign_id,
            targetId=target_id,
            surfaceType=target.surface_type,
            locatorSchema=target.locator_schema,
            locatorDigest=locator_digest,
            origin=GraphContentOrigin.TARGET_DERIVED,
        )
        edge = self._edge(
            relation=GraphRelation.DISCOVERS,
            source=observation,
            target=surface,
        )
        key = graph_digest(
            "pajin.graph.cross-domain-surface-proposal-id/v1",
            {
                "contractDigest": self._contract.contract_digest,
                "snapshotDigest": snapshot.snapshot_digest,
                "sourceEventDigest": source_event.event_digest,
                "surfaceNodeId": surface.node_id,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        proposal = SurfaceProposal(
            proposalId=f"proposal:cross-domain-surface:{key}",
            producerId=self._contract.producer_id,
            producerVersion=self._contract.producer_version,
            producerDigest=self._contract.producer_digest,
            lineage=_lineage_from_event(source_event),
            surface=surface,
            edges=[edge],
        )
        return CrossDomainGraphAdmissionCandidate(
            contract=self._contract,
            snapshot=graph_snapshot_ref(snapshot),
            sourceGraphEvent=source_event,
            sourceObservation=observation,
            proposal=proposal,
        )

    def _build_hypothesis(
        self,
        *,
        source_event: GraphAdmissionEvent,
        snapshot: GraphSnapshot,
        statement: str,
        expected_observable: str,
        confidence: float,
        require_current: bool,
    ) -> CrossDomainGraphAdmissionCandidate:
        snapshot, source_event, observation = self._verified_source(
            source_event,
            snapshot,
            require_current=require_current,
        )
        target = resolve_registered_security_domain_graph_type_set(self._contract.target_type_set)
        hypothesis = GraphHypothesis(
            campaignId=snapshot.campaign_id,
            hypothesisType=target.hypothesis_type,
            statement=statement,
            expectedObservable=expected_observable,
            producerId=self._contract.producer_id,
            producerVersion=self._contract.producer_version,
            producerDigest=self._contract.producer_digest,
            origin=GraphContentOrigin.AGENT_DERIVED,
            confidence=confidence,
        )
        edge = self._edge(
            relation=GraphRelation.ENABLES,
            source=observation,
            target=hypothesis,
        )
        key = graph_digest(
            "pajin.graph.cross-domain-hypothesis-proposal-id/v1",
            {
                "contractDigest": self._contract.contract_digest,
                "snapshotDigest": snapshot.snapshot_digest,
                "sourceEventDigest": source_event.event_digest,
                "hypothesisNodeId": hypothesis.node_id,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        proposal = HypothesisProposal(
            proposalId=f"proposal:cross-domain-hypothesis:{key}",
            producerId=self._contract.producer_id,
            producerVersion=self._contract.producer_version,
            producerDigest=self._contract.producer_digest,
            lineage=_lineage_from_event(source_event),
            hypothesis=hypothesis,
            edges=[edge],
        )
        return CrossDomainGraphAdmissionCandidate(
            contract=self._contract,
            snapshot=graph_snapshot_ref(snapshot),
            sourceGraphEvent=source_event,
            sourceObservation=observation,
            proposal=proposal,
        )

    def _verified_source(
        self,
        source_event: GraphAdmissionEvent,
        snapshot: GraphSnapshot,
        *,
        require_current: bool,
    ) -> tuple[GraphSnapshot, GraphAdmissionEvent, GraphObservation]:
        canonical_snapshot = GraphSnapshot.model_validate(
            snapshot.model_dump(mode="json", by_alias=True)
        )
        canonical_event = GraphAdmissionEvent.model_validate(
            source_event.model_dump(mode="json", by_alias=True)
        )
        events = self._event_log.events()
        if canonical_snapshot.campaign_id != self._campaign_id or canonical_snapshot.revision > len(
            events
        ):
            raise CrossDomainGraphAdmissionError(
                "Cross-domain Graph Snapshot belongs to another or future Campaign head"
            )
        prefix = events[: canonical_snapshot.revision]
        projected = GraphProjector.project(campaign_id=self._campaign_id, events=prefix)
        if projected != canonical_snapshot.projection or (
            require_current and canonical_snapshot.revision != len(events)
        ):
            raise CrossDomainGraphAdmissionError(
                "Cross-domain Graph Snapshot is not the required canonical head"
            )
        matching = tuple(
            event
            for event in prefix
            if event.event_id == canonical_event.event_id
            and event.event_digest == canonical_event.event_digest
        )
        observations = tuple(
            node for node in canonical_event.admitted_nodes if isinstance(node, GraphObservation)
        )
        source_type_set = resolve_registered_security_domain_graph_type_set(
            self._contract.source_type_set
        )
        if (
            len(matching) != 1
            or matching[0] != canonical_event
            or canonical_event.decision is not GraphAdmissionDecision.ADMITTED
            or canonical_event.proposal_kind is not GraphProposalKind.OBSERVATION
            or canonical_event.source_authority_id is not None
            or canonical_event.source_authority_digest is not None
            or len(observations) != 1
            or observations[0].observation_type != source_type_set.observation_type
        ):
            raise CrossDomainGraphAdmissionError(
                "Cross-domain source is not one exact admitted Domain Observation"
            )
        return canonical_snapshot, canonical_event, observations[0]

    def _edge(
        self,
        *,
        relation: GraphRelation,
        source: GraphObservation,
        target: GraphSurface | GraphHypothesis,
    ) -> GraphEdge:
        return GraphEdge(
            campaignId=source.campaign_id,
            relation=relation,
            source=graph_node_ref(source),
            target=graph_node_ref(target),
            authorityId=self._authority_id,
            authorityDigest=self._authority_digest,
        )


def _lineage_from_event(event: GraphAdmissionEvent) -> GraphProposalLineage:
    return GraphProposalLineage(
        campaignId=event.proposal_campaign_id,
        runId=event.run_id,
        agentId=event.agent_id,
        taskId=event.task_id,
        requestId=event.request_id,
        requestDigest=event.request_digest,
        capabilityGrantId=event.capability_grant_id,
        capabilityGrantDigest=event.capability_grant_digest,
        capabilityId=event.capability_id,
        capabilityVersion=event.capability_version,
        capabilityDigest=event.capability_digest,
        actionPermitId=event.action_permit_id,
        actionPermitDigest=event.action_permit_digest,
        sourceRootDigest=event.source_root_digest,
        evidence=event.evidence,
        producedAt=event.produced_at,
    )
