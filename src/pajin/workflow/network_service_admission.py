"""NET-001C sealed Network Observation and bounded Hypothesis admission."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    capability_gateway_outcome_digest,
    capability_grant_digest,
)
from pajin.capabilities.network_service import (
    NetworkServiceCapabilityActivation,
    NetworkServiceIdentificationPreparation,
    prepare_network_service_identification,
)
from pajin.capabilities.reconciliation import (
    CapabilityDispatchReconciliation,
    CapabilityDispatchReconciliationStatus,
    reconcile_capability_dispatch,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery.network_surfaces import (
    NetworkHostServiceSurfaceRef,
    NetworkSurfaceClass,
)
from pajin.domain.models import CampaignManifest, StrictModel, ToolRequest, ToolResult
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphProducerRegistration,
    TrustedGraphLineageRegistry,
)
from pajin.graph.approval import (
    ActionApprovalConsumptionReceipt,
    build_action_approval_consumption_receipt,
)
from pajin.graph.authority import ActionPermit
from pajin.graph.domain_semantics import (
    MultiDomainGraphSemanticsError,
    SecurityDomainGraphTypeSetRef,
    resolve_registered_security_domain_graph_type_set,
)
from pajin.graph.models import (
    GraphAction,
    GraphActionStatus,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphNodeKind,
    GraphObservation,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    HypothesisProposal,
    ObservationProposal,
    graph_digest,
    graph_node_ref,
)
from pajin.graph.projection import GraphSnapshotRef, graph_snapshot_ref
from pajin.graph.sqlite_store import SQLiteGraphStore, load_verified_current_graph_snapshot
from pajin.policy.engine import PolicyDecision
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import VerifiedRunSnapshot, load_verified_run_artifacts
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerResult, WorkerStatus
from pajin.tools.execution_receipts import safe_job_metadata
from pajin.tools.gateway import GatewayOutcome
from pajin.tools.network import (
    MAX_NETWORK_SERVICE_BANNER_BYTES,
    NetworkServiceIdentificationTool,
)

NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_ID: Literal[
    "pajin.workflow.network-protocol-knowledge-admission"
] = "pajin.workflow.network-protocol-knowledge-admission"
NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_VERSION: Literal["1.0.0"] = "1.0.0"
NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.network-protocol-knowledge-admission/v1"
).hexdigest()
NETWORK_PROTOCOL_KNOWLEDGE_ADMISSION_API_VERSION: Literal[
    "pajin.dev/network-protocol-knowledge-admission/v1alpha1"
] = "pajin.dev/network-protocol-knowledge-admission/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_ArtifactPath = Annotated[
    str,
    Field(pattern=r"^(?:evidence|requests)/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$"),
]
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_ServiceName = Literal["ftp", "imap", "pop3", "smtp", "ssh"]
_SERVICE_NAMES: tuple[_ServiceName, ...] = ("ftp", "imap", "pop3", "smtp", "ssh")
_FALSE_AUTHORITY_FIELDS = (
    "service_label_authority",
    "surface_mutation_authorized",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "tool_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
    "execution_authorized",
)


class NetworkProtocolKnowledgeAdmissionError(ValueError):
    """Raised when sealed Network execution cannot become bounded Graph knowledge."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class NetworkProtocolKnowledgeAdmissionPolicy(_FrozenStrictModel):
    """Code-owned neutral Observation and bounded open-Hypothesis policy."""

    api_version: Literal["pajin.dev/network-protocol-knowledge-admission-policy/v1alpha1"] = Field(
        default="pajin.dev/network-protocol-knowledge-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["NetworkProtocolKnowledgeAdmissionPolicy"] = (
        "NetworkProtocolKnowledgeAdmissionPolicy"
    )
    policy_id: str = Field(default="", alias="policyId", max_length=110)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.network-protocol-knowledge-admission"] = Field(
        default=NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_ID,
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(
        default=NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_VERSION,
        alias="producerVersion",
    )
    producer_digest: _Sha256 = Field(
        default=NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["network.protocol-observation"] = Field(
        default="network.protocol-observation",
        alias="observationType",
    )
    hypothesis_type: Literal["network.exposure"] = Field(
        default="network.exposure",
        alias="hypothesisType",
    )
    service_names: tuple[_ServiceName, ...] = Field(
        default=_SERVICE_NAMES,
        alias="serviceNames",
        min_length=5,
        max_length=5,
    )
    knowledge_only: Literal[True] = Field(default=True, alias="knowledgeOnly")
    bounded_hypothesis_enabled: Literal[True] = Field(
        default=True,
        alias="boundedHypothesisEnabled",
    )
    service_label_authority: Literal[False] = Field(
        default=False,
        alias="serviceLabelAuthority",
    )
    surface_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="surfaceMutationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("knowledge_only", "bounded_hypothesis_enabled", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Network knowledge policy markers must be true")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Network knowledge cannot carry execution authority")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        if (
            self.producer_digest != NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_DIGEST
            or self.service_names != _SERVICE_NAMES
        ):
            raise ValueError("Network knowledge policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.network-protocol-knowledge-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"network-protocol-knowledge-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Network knowledge policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Network knowledge policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class NetworkGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph Snapshot and its already-existing single writer."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError("Network knowledge admission requires a non-empty Graph Snapshot")
        return self


@dataclass(frozen=True, slots=True)
class NetworkServiceObservationSourceInputs:
    """Current NET-001B preparation and one sealed approved execution source."""

    run_path: Path
    expected_run_id: str
    activation: NetworkServiceCapabilityActivation
    campaign: CampaignManifest
    preparation: NetworkServiceIdentificationPreparation
    job: CapabilityGraphCampaignJobInput


class _NetworkServiceToolEvidence(_FrozenStrictModel):
    request: ToolRequest
    policy_decision: PolicyDecision = Field(alias="policyDecision")
    result: ToolResult
    worker_job: dict[str, object] = Field(alias="workerJob")
    worker_result: WorkerResult = Field(alias="workerResult")
    network_log_trusted: bool = Field(alias="networkLogTrusted")

    @field_validator("network_log_trusted", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Network Tool evidence trust marker must be boolean")
        return value


class NetworkProtocolKnowledgeCandidate(_FrozenStrictModel):
    """Content-addressed neutral Observation and optional bounded Hypothesis."""

    api_version: Literal["pajin.dev/network-protocol-knowledge-candidate/v1alpha1"] = Field(
        default="pajin.dev/network-protocol-knowledge-candidate/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["NetworkProtocolKnowledgeCandidate"] = "NetworkProtocolKnowledgeCandidate"
    candidate_id: str = Field(default="", alias="candidateId", max_length=110)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: NetworkProtocolKnowledgeAdmissionPolicy
    graph: NetworkGraphAdmissionBinding
    preparation: NetworkServiceIdentificationPreparation
    surface: NetworkHostServiceSurfaceRef
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    source_execution_snapshot: GraphSnapshotRef = Field(alias="sourceExecutionSnapshot")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    request_reservation_path: _ArtifactPath = Field(alias="requestReservationPath")
    request_reservation_sha256: _Sha256 = Field(alias="requestReservationSha256")
    execution_evidence_path: _ArtifactPath = Field(alias="executionEvidencePath")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    terminal_event_digest: _Sha256 = Field(alias="terminalEventDigest")
    reconciliation_digest: _Sha256 = Field(alias="reconciliationDigest")
    banner_sha256: _Sha256 = Field(alias="bannerSha256")
    service_name: _ServiceName | None = Field(
        default=None,
        alias="serviceName",
    )
    observation_proposal: ObservationProposal = Field(alias="observationProposal")
    hypothesis_proposal: HypothesisProposal | None = Field(
        default=None,
        alias="hypothesisProposal",
    )
    state: Literal["sealed-knowledge-not-admitted"] = "sealed-knowledge-not-admitted"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    protocol_observation_produced: Literal[True] = Field(
        default=True,
        alias="protocolObservationProduced",
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    service_label_authority: Literal[False] = Field(
        default=False,
        alias="serviceLabelAuthority",
    )
    surface_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="surfaceMutationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "sealed_source_verified",
        "protocol_observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Network sealed knowledge markers must be true")
        return value

    @field_validator("graph_admitted", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Network knowledge candidate authority flags must be false")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError("Network Domain Graph semantics are not registered exactly") from exc
        observation = self.observation_proposal
        evidence = {(item.reference, item.sha256) for item in observation.evidence_nodes}
        expected_evidence = {
            (self.request_reservation_path, self.request_reservation_sha256),
            (self.execution_evidence_path, self.execution_evidence_sha256),
        }
        hypothesis = self.hypothesis_proposal
        expected_hypothesis = self.service_name is not None
        if (
            self.surface != self.preparation.surface.reference()
            or self.preparation.surface.surface_class is not NetworkSurfaceClass.PORT
            or self.preparation.surface.domain_graph_type_set != self.domain_graph_type_set
            or semantics.domain_classification.domain is not SecurityDomain.NETWORK
            or semantics.surface_type != "network.host-service"
            or semantics.locator_schema != "pajin.locator.network.host-service.v1"
            or semantics.observation_type != self.policy.observation_type
            or semantics.hypothesis_type != self.policy.hypothesis_type
            or observation.observation.observation_type != self.policy.observation_type
            or observation.observation.summary
            != (
                "A permitted passive TCP connection produced sealed protocol evidence "
                "for the exact bound Network Surface."
            )
            or observation.observation.origin is not GraphContentOrigin.TARGET_DERIVED
            or observation.observation.confidence != 1.0
            or observation.producer_id != self.policy.producer_id
            or observation.producer_version != self.policy.producer_version
            or observation.producer_digest != self.policy.producer_digest
            or observation.lineage.campaign_id != self.graph.snapshot.campaign_id
            or observation.lineage.run_id != self.source_run_id
            or observation.lineage.source_root_digest != self.source_root_digest
            or evidence != expected_evidence
            or len(observation.evidence_nodes) != 2
            or {edge.relation for edge in observation.edges}
            != {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
            or expected_hypothesis != (hypothesis is not None)
        ):
            raise ValueError("Network knowledge candidate differs from sealed semantics")
        if hypothesis is not None and (
            hypothesis.producer_id != self.policy.producer_id
            or hypothesis.producer_version != self.policy.producer_version
            or hypothesis.producer_digest != self.policy.producer_digest
            or hypothesis.lineage.campaign_id != observation.lineage.campaign_id
            or hypothesis.lineage.run_id != observation.lineage.run_id
            or hypothesis.lineage.source_root_digest != observation.lineage.source_root_digest
            or hypothesis.lineage.evidence != observation.lineage.evidence
            or hypothesis.hypothesis.hypothesis_type != self.policy.hypothesis_type
            or hypothesis.hypothesis.statement
            != (f"The exact TCP endpoint may expose the observed {self.service_name} protocol.")
            or hypothesis.hypothesis.expected_observable
            != (
                "A separately authorized fresh passive TCP handshake yields a banner "
                "compatible with the same protocol label."
            )
            or hypothesis.hypothesis.origin is not GraphContentOrigin.AGENT_DERIVED
            or hypothesis.hypothesis.confidence != 0.5
            or len(hypothesis.edges) != 1
            or hypothesis.edges[0].relation is not GraphRelation.ENABLES
            or hypothesis.edges[0].source != graph_node_ref(observation.observation)
            or hypothesis.edges[0].target != graph_node_ref(hypothesis.hypothesis)
        ):
            raise ValueError("Network bounded Hypothesis differs from the neutral Observation")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.network-protocol-knowledge-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"network-protocol-knowledge_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Network knowledge candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Network knowledge candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class NetworkProtocolKnowledgeAdmission(_FrozenStrictModel):
    """Proof that sealed Network output entered only the existing Graph writer."""

    api_version: Literal["pajin.dev/network-protocol-knowledge-admission/v1alpha1"] = Field(
        default=NETWORK_PROTOCOL_KNOWLEDGE_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkProtocolKnowledgeAdmission"] = "NetworkProtocolKnowledgeAdmission"
    admission_id: str = Field(default="", alias="admissionId", max_length=110)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: NetworkProtocolKnowledgeCandidate
    observation_graph_event: GraphAdmissionEvent = Field(alias="observationGraphEvent")
    hypothesis_graph_event: GraphAdmissionEvent | None = Field(
        default=None,
        alias="hypothesisGraphEvent",
    )
    state: Literal["registered-not-authorized"] = "registered-not-authorized"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    protocol_observation_produced: Literal[True] = Field(
        default=True,
        alias="protocolObservationProduced",
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[True] = Field(default=True, alias="graphAdmitted")
    graph_single_writer_reused: Literal[True] = Field(
        default=True,
        alias="graphSingleWriterReused",
    )
    bounded_hypothesis_admitted: bool = Field(alias="boundedHypothesisAdmitted")
    service_label_authority: Literal[False] = Field(
        default=False,
        alias="serviceLabelAuthority",
    )
    surface_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="surfaceMutationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "sealed_source_verified",
        "protocol_observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "graph_single_writer_reused",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Network knowledge admission markers must be true")
        return value

    @field_validator("bounded_hypothesis_admitted", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Network bounded Hypothesis marker must be boolean")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Network knowledge admission cannot carry execution authority")
        return value

    @model_validator(mode="after")
    def bind_admission_identity(self) -> Self:
        observation = self.candidate.observation_proposal
        _require_admitted_event(
            event=self.observation_graph_event,
            proposal=observation,
            graph=self.candidate.graph,
            expected_kind=GraphProposalKind.OBSERVATION,
        )
        kinds = [node.kind for node in self.observation_graph_event.admitted_nodes]
        if (
            kinds.count(GraphNodeKind.ACTION.value) != 1
            or kinds.count(GraphNodeKind.OBSERVATION.value) != 1
            or kinds.count(GraphNodeKind.EVIDENCE.value) != 2
            or len(kinds) != 4
            or any(
                edge.relation not in {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
                for edge in self.observation_graph_event.admitted_edges
            )
        ):
            raise ValueError("Network Observation admission exceeds neutral knowledge authority")
        hypothesis = self.candidate.hypothesis_proposal
        expected_hypothesis = hypothesis is not None
        if (
            self.bounded_hypothesis_admitted is not expected_hypothesis
            or (self.hypothesis_graph_event is not None) is not expected_hypothesis
        ):
            raise ValueError("Network bounded Hypothesis admission marker differs")
        if hypothesis is not None and self.hypothesis_graph_event is not None:
            _require_admitted_event(
                event=self.hypothesis_graph_event,
                proposal=hypothesis,
                graph=self.candidate.graph,
                expected_kind=GraphProposalKind.HYPOTHESIS,
            )
            event = self.hypothesis_graph_event
            if (
                event.sequence != self.observation_graph_event.sequence + 1
                or event.previous_event_digest != self.observation_graph_event.event_digest
                or event.admitted_nodes != [hypothesis.hypothesis]
                or event.admitted_edges != hypothesis.edges
                or len(event.admitted_edges) != 1
                or event.admitted_edges[0].relation is not GraphRelation.ENABLES
            ):
                raise ValueError("Network bounded Hypothesis exceeds open knowledge authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.network-protocol-knowledge-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"network-protocol-knowledge-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Network knowledge admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Network knowledge admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


@dataclass(frozen=True, slots=True)
class VerifiedNetworkServiceObservationSource:
    """One sealed successful approved passive TCP dispatch, independently verified."""

    snapshot: VerifiedRunSnapshot
    preparation: NetworkServiceIdentificationPreparation
    job: CapabilityGraphCampaignJobInput
    permit: ActionPermit
    approval_receipt: ActionApprovalConsumptionReceipt
    terminal: CapabilityDispatchAuditEvent
    reconciliation: CapabilityDispatchReconciliation
    evidence: _NetworkServiceToolEvidence
    reservation_path: str
    evidence_path: str
    reservation_sha256: str
    evidence_sha256: str


def network_protocol_knowledge_producer_registration() -> GraphProducerRegistration:
    """Return the exact code-owned Observation/Hypothesis producer registration."""

    return GraphProducerRegistration(
        producerId=NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_ID,
        producerVersion=NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_VERSION,
        producerDigest=NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_DIGEST,
        allowedProposalKinds=(
            GraphProposalKind.HYPOTHESIS,
            GraphProposalKind.OBSERVATION,
        ),
    )


class NetworkProtocolKnowledgeAdmissionGate:
    """Reverify sealed Network output and reuse the existing Graph single writer."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
    ) -> None:
        if not isinstance(graph_store, SQLiteGraphStore):
            raise TypeError("Network knowledge admission requires an exact SQLite Graph Store")
        if not isinstance(graph_admission, GraphAdmissionAuthority):
            raise TypeError("Network knowledge admission requires the Graph Admission authority")
        if not isinstance(trusted_lineages, TrustedGraphLineageRegistry):
            raise TypeError("Network knowledge admission requires the trusted lineage registry")
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("Network knowledge Graph authority wiring differs")
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages

    def prepare_candidate(
        self,
        inputs: NetworkServiceObservationSourceInputs,
        graph: NetworkGraphAdmissionBinding,
    ) -> NetworkProtocolKnowledgeCandidate:
        try:
            canonical_graph = NetworkGraphAdmissionBinding.model_validate(
                graph.model_dump(mode="json", by_alias=True)
            )
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except NetworkProtocolKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network knowledge candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: NetworkServiceObservationSourceInputs,
        candidate: NetworkProtocolKnowledgeCandidate,
    ) -> NetworkProtocolKnowledgeAdmission:
        try:
            canonical = NetworkProtocolKnowledgeCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise NetworkProtocolKnowledgeAdmissionError(
                    "Network knowledge candidate differs from sealed source authority"
                )
            observation = canonical.observation_proposal
            observation_prior = self._graph_store.event_log.event_for_attempt(
                observation.proposal_id,
                observation.digest(),
            )
            if observation_prior is None:
                self._require_current_graph(canonical.graph)
                expected_head = canonical.graph.snapshot.event_log_head_digest
                if expected_head is None:
                    raise NetworkProtocolKnowledgeAdmissionError(
                        "Network knowledge admission requires a non-empty Graph head"
                    )
                self._trusted_lineages.register(observation.lineage)
                observation_result = self._graph_admission.submit_if_current(
                    observation,
                    expected_event_log_head_digest=expected_head,
                )
            else:
                observation_result = self._graph_admission.submit(observation)
            self._require_admitted_result(observation_result.event, canonical.graph)

            hypothesis_event: GraphAdmissionEvent | None = None
            hypothesis = canonical.hypothesis_proposal
            if hypothesis is not None:
                hypothesis_prior = self._graph_store.event_log.event_for_attempt(
                    hypothesis.proposal_id,
                    hypothesis.digest(),
                )
                if hypothesis_prior is None:
                    if self._graph_store.event_log.next_position()[1] != (
                        observation_result.event.event_digest
                    ):
                        raise NetworkProtocolKnowledgeAdmissionError(
                            "Network bounded Hypothesis source is no longer the current Graph head"
                        )
                    self._trusted_lineages.register(hypothesis.lineage)
                    hypothesis_result = self._graph_admission.submit_if_current(
                        hypothesis,
                        expected_event_log_head_digest=observation_result.event.event_digest,
                    )
                else:
                    hypothesis_result = self._graph_admission.submit(hypothesis)
                self._require_admitted_result(hypothesis_result.event, canonical.graph)
                hypothesis_event = hypothesis_result.event
            return NetworkProtocolKnowledgeAdmission(
                candidate=canonical,
                observationGraphEvent=observation_result.event,
                hypothesisGraphEvent=hypothesis_event,
                boundedHypothesisAdmitted=hypothesis is not None,
            )
        except NetworkProtocolKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network knowledge admission failed closed"
            ) from exc

    def _require_admitted_result(
        self,
        event: GraphAdmissionEvent,
        graph: NetworkGraphAdmissionBinding,
    ) -> None:
        if (
            event.decision is not GraphAdmissionDecision.ADMITTED
            or event.authority_id != graph.authority_id
            or event.authority_digest != graph.authority_digest
        ):
            raise NetworkProtocolKnowledgeAdmissionError(
                "Graph Admission authority rejected Network knowledge"
            )

    def _build_candidate(
        self,
        inputs: NetworkServiceObservationSourceInputs,
        graph: NetworkGraphAdmissionBinding,
    ) -> NetworkProtocolKnowledgeCandidate:
        source = load_verified_network_service_observation_source(
            inputs,
            graph_store=self._graph_store,
        )
        permit = source.permit
        if graph.snapshot.campaign_id != permit.campaign_id:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network execution source and Graph admission Campaigns differ"
            )
        policy = NetworkProtocolKnowledgeAdmissionPolicy()
        surface = source.preparation.surface.reference()
        type_set = source.preparation.surface.domain_graph_type_set
        data = source.evidence.result.data
        banner_sha256 = data.get("bannerSha256")
        service_name = data.get("serviceName")
        banner_bytes = data.get("bannerBytes")
        if (
            not isinstance(banner_sha256, str)
            or len(banner_sha256) != 64
            or isinstance(banner_bytes, bool)
            or not isinstance(banner_bytes, int)
            or (service_name is not None and service_name not in policy.service_names)
        ):
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network service output lacks bounded protocol identity"
            )
        value_digest = graph_digest(
            "pajin.workflow.network-protocol-observation-value/v1",
            {
                "preparationDigest": source.preparation.preparation_digest,
                "surfaceReference": surface.model_dump(mode="json", by_alias=True),
                "requestDigest": permit.request_digest,
                "approvalReceiptDigest": source.approval_receipt.receipt_digest,
                "gatewayOutcomeDigest": source.terminal.gateway_outcome_digest,
                "terminalEventDigest": source.terminal.event_digest,
                "reconciliationDigest": source.reconciliation.reconciliation_digest,
                "sourceRootDigest": source.snapshot.verification.root_digest,
                "requestReservationSha256": source.reservation_sha256,
                "executionEvidenceSha256": source.evidence_sha256,
                "bannerSha256": banner_sha256,
                "bannerBytes": banner_bytes,
                "serviceName": service_name,
                "connected": True,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        action = GraphAction(
            campaignId=permit.campaign_id,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            authorityKind=GraphAuthorityKind.ACTION_PERMIT,
            authorityId=permit.permit_id,
            authorityDigest=permit.permit_digest,
            capabilityId=permit.capability.capability_id,
            capabilityVersion=permit.capability.capability_version,
            capabilityDigest=permit.capability.definition_digest,
            toolId=source.job.request.tool_id,
            targetDigest=permit.target_digest,
            status=GraphActionStatus.SUCCEEDED,
            executedAt=source.evidence.worker_result.started_at,
        )
        observation = GraphObservation(
            campaignId=permit.campaign_id,
            observationType=policy.observation_type,
            summary=(
                "A permitted passive TCP connection produced sealed protocol evidence "
                "for the exact bound Network Surface."
            ),
            valueDigest=value_digest,
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            origin=GraphContentOrigin.TARGET_DERIVED,
            confidence=1.0,
            observedAt=source.evidence.worker_result.finished_at,
        )
        bindings = sorted(
            (
                GraphEvidenceBinding(
                    reference=source.reservation_path,
                    sha256=source.reservation_sha256,
                ),
                GraphEvidenceBinding(
                    reference=source.evidence_path,
                    sha256=source.evidence_sha256,
                ),
            ),
            key=lambda item: (item.reference, item.sha256),
        )
        evidence_nodes = sorted(
            (
                GraphEvidence(
                    campaignId=permit.campaign_id,
                    reference=item.reference,
                    sha256=item.sha256,
                    sourceRootDigest=source.snapshot.verification.root_digest,
                    dataClassification="internal",
                )
                for item in bindings
            ),
            key=lambda item: item.node_id,
        )
        edges = [
            GraphEdge(
                campaignId=permit.campaign_id,
                relation=GraphRelation.PRODUCES,
                source=graph_node_ref(action),
                target=graph_node_ref(observation),
                authorityId=graph.authority_id,
                authorityDigest=graph.authority_digest,
            ),
            *(
                GraphEdge(
                    campaignId=permit.campaign_id,
                    relation=GraphRelation.SUPPORTED_BY,
                    source=graph_node_ref(observation),
                    target=graph_node_ref(item),
                    authorityId=graph.authority_id,
                    authorityDigest=graph.authority_digest,
                )
                for item in evidence_nodes
            ),
        ]
        produced_at = max(
            source.terminal.occurred_at,
            source.evidence.worker_result.finished_at,
        )
        observation_lineage = _source_lineage(
            source=source,
            bindings=bindings,
            agent_id="agent:network-protocol-observation-admission",
            task_id=f"task:network-protocol-observation:{source.terminal.event_digest[:32]}",
            produced_at=produced_at,
        )
        proposal_key = graph_digest(
            "pajin.workflow.network-protocol-observation-proposal-id/v1",
            {
                "sourceRootDigest": source.snapshot.verification.root_digest,
                "terminalEventDigest": source.terminal.event_digest,
                "reconciliationDigest": source.reconciliation.reconciliation_digest,
                "snapshotDigest": graph.snapshot.snapshot_digest,
                "observationNodeId": observation.node_id,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        observation_proposal = ObservationProposal(
            proposalId=f"proposal:network-observation:{proposal_key}",
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            lineage=observation_lineage,
            action=action,
            observation=observation,
            evidenceNodes=evidence_nodes,
            edges=sorted(edges, key=lambda item: item.edge_id),
        )
        hypothesis_proposal: HypothesisProposal | None = None
        if isinstance(service_name, str):
            hypothesis = GraphHypothesis(
                campaignId=permit.campaign_id,
                hypothesisType=policy.hypothesis_type,
                statement=(
                    f"The exact TCP endpoint may expose the observed {service_name} protocol."
                ),
                expectedObservable=(
                    "A separately authorized fresh passive TCP handshake yields a banner "
                    "compatible with the same protocol label."
                ),
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                origin=GraphContentOrigin.AGENT_DERIVED,
                confidence=0.5,
            )
            hypothesis_edge = GraphEdge(
                campaignId=permit.campaign_id,
                relation=GraphRelation.ENABLES,
                source=graph_node_ref(observation),
                target=graph_node_ref(hypothesis),
                authorityId=graph.authority_id,
                authorityDigest=graph.authority_digest,
            )
            hypothesis_lineage = _source_lineage(
                source=source,
                bindings=bindings,
                agent_id="agent:network-exposure-hypothesis-admission",
                task_id=f"task:network-exposure-hypothesis:{source.terminal.event_digest[:32]}",
                produced_at=produced_at,
            )
            hypothesis_key = graph_digest(
                "pajin.workflow.network-exposure-hypothesis-proposal-id/v1",
                {
                    "observationProposalDigest": observation_proposal.digest(),
                    "hypothesisNodeId": hypothesis.node_id,
                    "serviceName": service_name,
                },
                max_bytes=_MAX_CANONICAL_BYTES,
            )
            hypothesis_proposal = HypothesisProposal(
                proposalId=f"proposal:network-hypothesis:{hypothesis_key}",
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                lineage=hypothesis_lineage,
                hypothesis=hypothesis,
                edges=[hypothesis_edge],
            )
        return NetworkProtocolKnowledgeCandidate(
            policy=policy,
            graph=graph,
            preparation=source.preparation,
            surface=surface,
            domainGraphTypeSet=type_set,
            sourceExecutionSnapshot=permit.snapshot,
            sourceRunId=permit.run_id,
            sourceRootDigest=source.snapshot.verification.root_digest,
            approvalReceiptId=source.approval_receipt.receipt_id,
            approvalReceiptDigest=source.approval_receipt.receipt_digest,
            requestReservationPath=source.reservation_path,
            requestReservationSha256=source.reservation_sha256,
            executionEvidencePath=source.evidence_path,
            executionEvidenceSha256=source.evidence_sha256,
            terminalEventDigest=source.terminal.event_digest,
            reconciliationDigest=source.reconciliation.reconciliation_digest,
            bannerSha256=banner_sha256,
            serviceName=service_name,
            observationProposal=observation_proposal,
            hypothesisProposal=hypothesis_proposal,
        )

    def _require_current_graph(self, graph: NetworkGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest != getattr(self._graph_admission, "_authority_digest", None)
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network knowledge Graph Admission authority differs"
            )
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network knowledge Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network knowledge Graph Snapshot is not the current canonical head"
            )


def _source_lineage(
    *,
    source: VerifiedNetworkServiceObservationSource,
    bindings: list[GraphEvidenceBinding],
    agent_id: str,
    task_id: str,
    produced_at: datetime,
) -> GraphProposalLineage:
    permit = source.permit
    return GraphProposalLineage(
        campaignId=permit.campaign_id,
        runId=permit.run_id,
        agentId=agent_id,
        taskId=task_id,
        requestId=permit.request_id,
        requestDigest=permit.request_digest,
        capabilityGrantId=source.job.grant.grant_id,
        capabilityGrantDigest=capability_grant_digest(source.job.grant),
        capabilityId=permit.capability.capability_id,
        capabilityVersion=permit.capability.capability_version,
        capabilityDigest=permit.capability.definition_digest,
        actionPermitId=permit.permit_id,
        actionPermitDigest=permit.permit_digest,
        sourceRootDigest=source.snapshot.verification.root_digest,
        evidence=bindings,
        producedAt=produced_at,
    )


def load_verified_network_service_observation_source(
    inputs: NetworkServiceObservationSourceInputs,
    *,
    graph_store: SQLiteGraphStore,
) -> VerifiedNetworkServiceObservationSource:
    """Open one sealed Network Run and recheck approval-to-CONNECT bindings."""

    if not isinstance(inputs, NetworkServiceObservationSourceInputs):
        raise TypeError("Network knowledge admission requires exact source inputs")
    if not isinstance(graph_store, SQLiteGraphStore):
        raise TypeError("Network source verification requires the exact SQLite Graph Store")
    if not isinstance(inputs.activation, NetworkServiceCapabilityActivation):
        raise TypeError("Network source verification requires current Network activation")
    try:
        campaign = CampaignManifest.model_validate(
            inputs.campaign.model_dump(mode="json", by_alias=True)
        )
        preparation = NetworkServiceIdentificationPreparation.model_validate(
            inputs.preparation.model_dump(mode="json", by_alias=True)
        )
        job = CapabilityGraphCampaignJobInput.model_validate(
            inputs.job.model_dump(mode="json", by_alias=True)
        )
        prepared = preparation.prepared_action
        rebuilt = prepare_network_service_identification(
            activation=inputs.activation,
            release=preparation.release,
            campaign=campaign,
            surface=preparation.surface,
            request_id=prepared.request.request_id,
            agent_id=prepared.request.agent_id,
        )
        if rebuilt != preparation:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network preparation differs from current signed and scoped authority"
            )
        if (
            job.profile != "capability-graph-v1"
            or job.approval is None
            or job.release != preparation.release
            or job.request != prepared.request
            or job.proposal.capability != prepared.capability
            or job.proposal.request_id != prepared.request.request_id
            or job.proposal.request_digest != prepared.request_digest
            or job.proposal.normalized_parameters_digest != prepared.normalized_parameters_digest
            or job.proposal.snapshot != job.decision.snapshot
            or job.proposal.decision_id != job.decision.decision_id
            or job.proposal.decision_digest != job.decision.decision_digest
            or job.proposal.campaign_id != campaign.metadata.name
            or job.proposal.campaign_id != job.grant.campaign
            or job.request.agent_id != job.grant.subject
            or job.request.tool_id not in job.grant.tools
            or job.request.target not in job.grant.targets
        ):
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network preparation and approved execution inputs differ"
            )
        permits = tuple(
            permit
            for permit in graph_store.permit_store.permits()
            if permit.run_id == inputs.expected_run_id
            and permit.request_id == prepared.request.request_id
        )
        if len(permits) != 1:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network execution source lacks one exact consumed ActionPermit"
            )
        permit = permits[0]
        if (
            permit.campaign_id != job.proposal.campaign_id
            or permit.run_id != job.proposal.run_id
            or permit.proposal_id != job.proposal.proposal_id
            or permit.proposal_digest != job.proposal.proposal_digest
            or permit.envelope_id != job.proposal.envelope_id
            or permit.envelope_digest != job.proposal.envelope_digest
            or permit.decision_id != job.decision.decision_id
            or permit.decision_digest != job.decision.decision_digest
            or permit.snapshot != job.decision.snapshot
            or permit.capability != prepared.capability
            or permit.target_digest != job.proposal.target_digest
            or permit.target_digest != sha256(prepared.request.target.encode("utf-8")).hexdigest()
            or permit.request_id != prepared.request.request_id
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
            or permit.reservation != job.proposal.reservation
        ):
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network consumed ActionPermit differs from the prepared action"
            )
        receipts = tuple(
            receipt
            for receipt in graph_store.permit_store.approval_consumptions()
            if receipt.action_permit.permit_id == permit.permit_id
        )
        if len(receipts) != 1:
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network execution source lacks one exact approval consumption receipt"
            )
        receipt = receipts[0]
        if (
            receipt.action_permit != permit
            or receipt.approval != job.approval
            or receipt != build_action_approval_consumption_receipt(job.approval, permit)
        ):
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network approval receipt differs from the consumed action"
            )
        reservation_path = f"requests/{permit.request_id}.json"
        evidence_path = f"evidence/{permit.request_id}.json"
        snapshot = load_verified_run_artifacts(
            inputs.run_path,
            requests={
                reservation_path: _MAX_ARTIFACT_BYTES,
                evidence_path: _MAX_ARTIFACT_BYTES,
            },
            expected_run_id=inputs.expected_run_id,
        )
        reconciliation = reconcile_capability_dispatch(snapshot, permit)
        terminal = reconciliation.terminal_event
        if (
            reconciliation.record.status is not CapabilityDispatchReconciliationStatus.COMPLETED
            or terminal is None
            or terminal.stage is not CapabilityDispatchStage.COMPLETED
        ):
            raise NetworkProtocolKnowledgeAdmissionError(
                "Network dispatch is not one sealed successful terminal lifecycle"
            )
        reservation_bytes = snapshot.artifact_bytes(reservation_path)
        evidence_bytes = snapshot.artifact_bytes(evidence_path)
        reservation = parse_strict_json_bytes(
            reservation_bytes,
            label="sealed Network Tool request reservation",
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        evidence = _NetworkServiceToolEvidence.model_validate(
            parse_strict_json_bytes(
                evidence_bytes,
                label="sealed Network Tool execution evidence",
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
        )
        expected_reservation: dict[str, object] = {
            "apiVersion": "pajin.dev/tool-request-reservation/v1",
            "kind": "ToolRequestReservation",
            "requestId": permit.request_id,
            "requestSha256": permit.request_digest,
        }
        _validate_network_execution_authority(
            campaign=campaign,
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=receipt,
            terminal=terminal,
            evidence=evidence,
            evidence_path=evidence_path,
            reservation=reservation,
            expected_reservation=expected_reservation,
        )
        return VerifiedNetworkServiceObservationSource(
            snapshot=snapshot,
            preparation=preparation,
            job=job,
            permit=permit,
            approval_receipt=receipt,
            terminal=terminal,
            reconciliation=reconciliation.record,
            evidence=evidence,
            reservation_path=reservation_path,
            evidence_path=evidence_path,
            reservation_sha256=sha256(reservation_bytes).hexdigest(),
            evidence_sha256=sha256(evidence_bytes).hexdigest(),
        )
    except NetworkProtocolKnowledgeAdmissionError:
        raise
    except Exception as exc:
        raise NetworkProtocolKnowledgeAdmissionError(
            "sealed Network execution source authority is invalid"
        ) from exc


def _validate_network_execution_authority(
    *,
    campaign: CampaignManifest,
    preparation: NetworkServiceIdentificationPreparation,
    job: CapabilityGraphCampaignJobInput,
    permit: ActionPermit,
    approval_receipt: ActionApprovalConsumptionReceipt,
    terminal: CapabilityDispatchAuditEvent,
    evidence: _NetworkServiceToolEvidence,
    evidence_path: str,
    reservation: object,
    expected_reservation: dict[str, object],
) -> None:
    prepared = preparation.prepared_action
    if (
        reservation != expected_reservation
        or approval_receipt.action_permit != permit
        or evidence.request != job.request
        or terminal.activation_set_digest != prepared.activation_set_digest
        or terminal.release != preparation.release
        or terminal.permit_id != permit.permit_id
        or terminal.permit_digest != permit.permit_digest
        or terminal.dispatch_id != permit.dispatch_id
        or terminal.campaign_id != permit.campaign_id
        or terminal.run_id != permit.run_id
        or terminal.proposal_id != permit.proposal_id
        or terminal.proposal_digest != permit.proposal_digest
        or terminal.request_id != permit.request_id
        or terminal.request_digest != permit.request_digest
        or terminal.normalized_parameters_digest != permit.normalized_parameters_digest
        or terminal.capability_grant_digest != capability_grant_digest(job.grant)
        or terminal.executed is not True
        or terminal.policy_allowed is not True
        or terminal.tool_success is not True
        or terminal.gateway_execution_id != evidence.worker_result.execution_id
        or terminal.evidence != (evidence_path,)
        or terminal.occurred_at < evidence.worker_result.finished_at
        or not (permit.consumed_at <= evidence.worker_result.started_at < permit.expires_at)
        or evidence.policy_decision.allowed is not True
        or evidence.result.request_id != job.request.request_id
        or evidence.result.tool_id != job.request.tool_id
        or evidence.result.success is not True
        or evidence.result.error is not None
        or evidence.result.evidence
        or evidence.result.data.get("connected") is not True
        or evidence.worker_result.status is not WorkerStatus.SUCCEEDED
        or evidence.worker_result.backend != "docker"
        or evidence.network_log_trusted is not True
    ):
        raise NetworkProtocolKnowledgeAdmissionError(
            "sealed Network Tool evidence differs or is unsuccessful"
        )
    tool = NetworkServiceIdentificationTool()
    expected_result = tool.interpret(job.request, evidence.worker_result)
    if expected_result != evidence.result:
        raise NetworkProtocolKnowledgeAdmissionError(
            "sealed Network Tool result differs from the code-owned adapter"
        )
    try:
        tool.validate_trusted_execution(
            job.request,
            evidence.result,
            evidence.worker_result,
            network_log_trusted=evidence.network_log_trusted,
        )
    except ValueError as exc:
        raise NetworkProtocolKnowledgeAdmissionError(
            "sealed Network Tool evidence lacks the exact trusted CONNECT receipt"
        ) from exc
    _validate_network_worker_job_metadata(
        campaign=campaign,
        preparation=preparation,
        job=job,
        evidence=evidence,
        tool=tool,
    )
    outcome = GatewayOutcome(
        decision=evidence.policy_decision,
        result=evidence.result.model_copy(update={"evidence": [evidence_path]}, deep=True),
        worker_result=evidence.worker_result,
        network_log_trusted=True,
        result_identity_valid=True,
        executed=True,
    )
    if terminal.gateway_outcome_digest != capability_gateway_outcome_digest(outcome):
        raise NetworkProtocolKnowledgeAdmissionError(
            "sealed Network Gateway outcome digest differs from Tool evidence"
        )


def _validate_network_worker_job_metadata(
    *,
    campaign: CampaignManifest,
    preparation: NetworkServiceIdentificationPreparation,
    job: CapabilityGraphCampaignJobInput,
    evidence: _NetworkServiceToolEvidence,
    tool: NetworkServiceIdentificationTool,
) -> None:
    metadata = evidence.worker_job
    expected_keys = {
        "requestId",
        "executionId",
        "image",
        "command",
        "network",
        "egressPolicy",
        "limits",
        "stdinBytes",
        "stdinSha256",
        "secretRequests",
        "secretLeaseIds",
    }
    prepared = tool.prepare(job.request)
    prepared_metadata = safe_job_metadata(job.request, prepared)
    stable_keys = {
        "requestId",
        "image",
        "command",
        "limits",
        "stdinBytes",
        "stdinSha256",
        "secretRequests",
        "secretLeaseIds",
    }
    if (
        set(metadata) != expected_keys
        or any(metadata.get(key) != prepared_metadata[key] for key in stable_keys)
        or metadata.get("executionId") != evidence.worker_result.execution_id
        or metadata.get("network") != NetworkMode.EGRESS_PROXY.value
        or metadata.get("secretRequests") != []
        or metadata.get("secretLeaseIds") != []
    ):
        raise NetworkProtocolKnowledgeAdmissionError(
            "sealed Network Worker metadata differs from the code-owned adapter"
        )
    egress = EgressPolicy.model_validate(metadata.get("egressPolicy"))
    if (
        egress.allow != [preparation.matched_allow_rule]
        or egress.deny
        or egress.allowed_methods != set(campaign.spec.rules_of_engagement.allowed_methods)
        or egress.allow_private_networks
        is not campaign.spec.rules_of_engagement.allow_private_networks
        or egress.max_requests != 1
        or egress.max_response_bytes != MAX_NETWORK_SERVICE_BANNER_BYTES
    ):
        raise NetworkProtocolKnowledgeAdmissionError(
            "sealed Network Worker egress differs from exact CONNECT authority"
        )


def _require_admitted_event(
    *,
    event: GraphAdmissionEvent,
    proposal: ObservationProposal | HypothesisProposal,
    graph: NetworkGraphAdmissionBinding,
    expected_kind: GraphProposalKind,
) -> None:
    lineage = proposal.lineage
    expected_nodes = (
        sorted(
            [proposal.action, proposal.observation, *proposal.evidence_nodes],
            key=lambda item: item.node_id,
        )
        if isinstance(proposal, ObservationProposal)
        else [proposal.hypothesis]
    )
    expected_edges = sorted(proposal.edges, key=lambda item: item.edge_id)
    expected_lineage_digest = graph_digest(
        "pajin.graph.proposal-lineage/v1",
        lineage.model_dump(mode="json", by_alias=True),
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    if (
        event.decision is not GraphAdmissionDecision.ADMITTED
        or event.proposal_id != proposal.proposal_id
        or event.proposal_digest != proposal.digest()
        or event.proposal_kind is not expected_kind
        or event.producer_id != proposal.producer_id
        or event.producer_version != proposal.producer_version
        or event.producer_digest != proposal.producer_digest
        or event.authority_id != graph.authority_id
        or event.authority_digest != graph.authority_digest
        or event.campaign_id != lineage.campaign_id
        or event.proposal_campaign_id != lineage.campaign_id
        or event.run_id != lineage.run_id
        or event.agent_id != lineage.agent_id
        or event.task_id != lineage.task_id
        or event.request_id != lineage.request_id
        or event.request_digest != lineage.request_digest
        or event.lineage_digest != expected_lineage_digest
        or event.capability_grant_id != lineage.capability_grant_id
        or event.capability_grant_digest != lineage.capability_grant_digest
        or event.capability_id != lineage.capability_id
        or event.capability_version != lineage.capability_version
        or event.capability_digest != lineage.capability_digest
        or event.action_permit_id != lineage.action_permit_id
        or event.action_permit_digest != lineage.action_permit_digest
        or event.source_root_digest != lineage.source_root_digest
        or event.evidence != lineage.evidence
        or event.produced_at != lineage.produced_at
        or event.admitted_nodes != expected_nodes
        or event.admitted_edges != expected_edges
    ):
        raise ValueError("Network Graph admission differs from its bounded Proposal")


__all__ = [
    "NETWORK_PROTOCOL_KNOWLEDGE_ADMISSION_API_VERSION",
    "NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_DIGEST",
    "NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_ID",
    "NETWORK_PROTOCOL_KNOWLEDGE_PRODUCER_VERSION",
    "NetworkGraphAdmissionBinding",
    "NetworkProtocolKnowledgeAdmission",
    "NetworkProtocolKnowledgeAdmissionError",
    "NetworkProtocolKnowledgeAdmissionGate",
    "NetworkProtocolKnowledgeAdmissionPolicy",
    "NetworkProtocolKnowledgeCandidate",
    "NetworkServiceObservationSourceInputs",
    "VerifiedNetworkServiceObservationSource",
    "load_verified_network_service_observation_source",
    "network_protocol_knowledge_producer_registration",
]
