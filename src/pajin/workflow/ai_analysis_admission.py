"""AI-001C sealed cross-Surface AI Observation admission through the Graph writer."""

from __future__ import annotations

from dataclasses import dataclass
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
from pajin.capabilities.ai_analysis import (
    AIMeasurementOperationPreparation,
    AIReadOnlyAnalysisPreparation,
)
from pajin.capabilities.reconciliation import (
    CapabilityDispatchReconciliation,
    CapabilityDispatchReconciliationStatus,
    reconcile_capability_dispatch,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery.ai_surfaces import AISecuritySurfaceRef
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphProducerRegistration,
    TrustedGraphLineageRegistry,
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
    GraphNodeKind,
    GraphObservation,
    GraphProposalKind,
    GraphProposalLineage,
    GraphRelation,
    ObservationProposal,
    graph_digest,
    graph_node_ref,
)
from pajin.graph.projection import GraphSnapshotRef, graph_snapshot_ref
from pajin.graph.sqlite_store import SQLiteGraphStore, load_verified_current_graph_snapshot
from pajin.policy.engine import PolicyDecision
from pajin.policy.scope import scope_matches
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import VerifiedRunSnapshot, load_verified_run_artifacts
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerResult, WorkerStatus
from pajin.tools.ai import (
    AIChatProbeTool,
    AIM03MeasurementChatProbeTool,
    AIM03SourceChatProbeTool,
)
from pajin.tools.base import Tool
from pajin.tools.execution_receipts import safe_job_metadata
from pajin.tools.gateway import GatewayOutcome
from pajin.tools.mcp import demo_mcp_tool

AI_ANALYSIS_OBSERVATION_PRODUCER_ID = "pajin.workflow.ai-analysis-observation-admission"
AI_ANALYSIS_OBSERVATION_PRODUCER_VERSION = "1.0.0"
AI_ANALYSIS_OBSERVATION_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.ai-analysis-observation-admission/v1"
).hexdigest()
AI_ANALYSIS_OBSERVATION_ADMISSION_API_VERSION: Literal[
    "pajin.dev/ai-analysis-observation-admission/v1alpha1"
] = "pajin.dev/ai-analysis-observation-admission/v1alpha1"

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
_FALSE_AUTHORITY_FIELDS = (
    "surface_authority",
    "hypothesis_authority",
    "finding_authority",
    "profile_metadata_authority",
    "domain_metadata_authority",
    "tool_metadata_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "tool_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "execution_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
)


class AIAnalysisObservationAdmissionError(ValueError):
    """Raised when sealed AI execution material cannot become neutral Graph knowledge."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class AIAnalysisObservationAdmissionPolicy(_FrozenStrictModel):
    """Code-owned Observation-only authority; AI metadata remains inert input."""

    api_version: Literal["pajin.dev/ai-analysis-observation-admission-policy/v1alpha1"] = Field(
        default="pajin.dev/ai-analysis-observation-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AIAnalysisObservationAdmissionPolicy"] = "AIAnalysisObservationAdmissionPolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=100)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.ai-analysis-observation-admission"] = Field(
        default="pajin.workflow.ai-analysis-observation-admission",
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="producerVersion",
    )
    producer_digest: _Sha256 = Field(
        default=AI_ANALYSIS_OBSERVATION_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["ai.behavior-observation"] = Field(
        default="ai.behavior-observation",
        alias="observationType",
    )
    surface_authority: Literal[False] = Field(default=False, alias="surfaceAuthority")
    hypothesis_authority: Literal[False] = Field(
        default=False,
        alias="hypothesisAuthority",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    profile_metadata_authority: Literal[False] = Field(
        default=False,
        alias="profileMetadataAuthority",
    )
    domain_metadata_authority: Literal[False] = Field(
        default=False,
        alias="domainMetadataAuthority",
    )
    tool_metadata_authority: Literal[False] = Field(
        default=False,
        alias="toolMetadataAuthority",
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
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI Observation admission authority flags must be false")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        if self.producer_digest != AI_ANALYSIS_OBSERVATION_PRODUCER_DIGEST:
            raise ValueError("AI Observation producer digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.ai-analysis-observation-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"ai-analysis-observation-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("AI Observation admission policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("AI Observation admission policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class AIAnalysisGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph Snapshot and the already-existing single writer."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError("AI Observation admission requires a non-empty Graph Snapshot")
        return self


@dataclass(frozen=True, slots=True)
class AIAnalysisObservationSourceInputs:
    """Exact AI-001B preparation and its already sealed REDTEAM execution source."""

    run_path: Path
    expected_run_id: str
    preparation: AIReadOnlyAnalysisPreparation | AIMeasurementOperationPreparation
    job: CapabilityGraphCampaignJobInput


class _AIAnalysisToolEvidence(_FrozenStrictModel):
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
            raise ValueError("AI Tool evidence trust marker must be boolean")
        return value


class AIAnalysisObservationCandidate(_FrozenStrictModel):
    """Content-addressed cross-Surface candidate with no execution authority."""

    api_version: Literal["pajin.dev/ai-analysis-observation-candidate/v1alpha1"] = Field(
        default="pajin.dev/ai-analysis-observation-candidate/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AIAnalysisObservationCandidate"] = "AIAnalysisObservationCandidate"
    candidate_id: str = Field(default="", alias="candidateId", max_length=110)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: AIAnalysisObservationAdmissionPolicy
    graph: AIAnalysisGraphAdmissionBinding
    preparation: AIReadOnlyAnalysisPreparation
    surfaces: tuple[AISecuritySurfaceRef, ...] = Field(min_length=2, max_length=3)
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    domain_observation_type: Literal["ai.behavior-observation"] = Field(
        default="ai.behavior-observation",
        alias="domainObservationType",
    )
    source_execution_snapshot: GraphSnapshotRef = Field(alias="sourceExecutionSnapshot")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    request_reservation_path: _ArtifactPath = Field(alias="requestReservationPath")
    request_reservation_sha256: _Sha256 = Field(alias="requestReservationSha256")
    execution_evidence_path: _ArtifactPath = Field(alias="executionEvidencePath")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    terminal_event_digest: _Sha256 = Field(alias="terminalEventDigest")
    reconciliation_digest: _Sha256 = Field(alias="reconciliationDigest")
    proposal: ObservationProposal
    state: Literal["sealed-observation-evidence-not-admitted"] = (
        "sealed-observation-evidence-not-admitted"
    )
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    cross_surface_observation_produced: Literal[True] = Field(
        default=True,
        alias="crossSurfaceObservationProduced",
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    surface_authority: Literal[False] = Field(default=False, alias="surfaceAuthority")
    hypothesis_authority: Literal[False] = Field(
        default=False,
        alias="hypothesisAuthority",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    profile_metadata_authority: Literal[False] = Field(
        default=False,
        alias="profileMetadataAuthority",
    )
    domain_metadata_authority: Literal[False] = Field(
        default=False,
        alias="domainMetadataAuthority",
    )
    tool_metadata_authority: Literal[False] = Field(
        default=False,
        alias="toolMetadataAuthority",
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
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )

    @field_validator(
        "sealed_source_verified",
        "cross_surface_observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI Observation sealed knowledge markers must be true")
        return value

    @field_validator("graph_admitted", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI Observation candidate authority flags must be false")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError("AI Domain Graph semantics are not registered exactly") from exc
        expected_surfaces = tuple(
            surface.reference() for surface in self.preparation.binding.surfaces
        )
        proposal = self.proposal
        evidence = {(item.reference, item.sha256) for item in proposal.evidence_nodes}
        expected_evidence = {
            (self.request_reservation_path, self.request_reservation_sha256),
            (self.execution_evidence_path, self.execution_evidence_sha256),
        }
        if (
            self.surfaces != expected_surfaces
            or any(
                surface.domain_graph_type_set != self.domain_graph_type_set
                for surface in self.preparation.binding.surfaces
            )
            or semantics.domain_classification.domain is not SecurityDomain.AI
            or semantics.surface_type != "ai.model-rag-agent-tool"
            or semantics.locator_schema != "pajin.locator.ai.model-rag-agent-tool.v1"
            or semantics.observation_type != self.domain_observation_type
            or proposal.observation.observation_type != self.domain_observation_type
            or proposal.producer_id != self.policy.producer_id
            or proposal.producer_version != self.policy.producer_version
            or proposal.producer_digest != self.policy.producer_digest
            or proposal.lineage.campaign_id != self.graph.snapshot.campaign_id
            or proposal.lineage.run_id != self.source_run_id
            or proposal.lineage.source_root_digest != self.source_root_digest
            or evidence != expected_evidence
            or len(proposal.evidence_nodes) != 2
            or {edge.relation for edge in proposal.edges}
            != {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
        ):
            raise ValueError("AI Observation candidate differs from sealed cross-Surface semantics")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.ai-analysis-observation-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"ai-analysis-observation_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("AI Observation candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("AI Observation candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class AIAnalysisObservationAdmission(_FrozenStrictModel):
    """Proof that sealed AI evidence entered only the existing Graph writer."""

    api_version: Literal["pajin.dev/ai-analysis-observation-admission/v1alpha1"] = Field(
        default=AI_ANALYSIS_OBSERVATION_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIAnalysisObservationAdmission"] = "AIAnalysisObservationAdmission"
    admission_id: str = Field(default="", alias="admissionId", max_length=110)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: AIAnalysisObservationCandidate
    graph_event: GraphAdmissionEvent = Field(alias="graphEvent")
    state: Literal["registered-not-authorized"] = "registered-not-authorized"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    cross_surface_observation_produced: Literal[True] = Field(
        default=True,
        alias="crossSurfaceObservationProduced",
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[True] = Field(default=True, alias="graphAdmitted")
    graph_single_writer_reused: Literal[True] = Field(
        default=True,
        alias="graphSingleWriterReused",
    )
    surface_authority: Literal[False] = Field(default=False, alias="surfaceAuthority")
    hypothesis_authority: Literal[False] = Field(
        default=False,
        alias="hypothesisAuthority",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    profile_metadata_authority: Literal[False] = Field(
        default=False,
        alias="profileMetadataAuthority",
    )
    domain_metadata_authority: Literal[False] = Field(
        default=False,
        alias="domainMetadataAuthority",
    )
    tool_metadata_authority: Literal[False] = Field(
        default=False,
        alias="toolMetadataAuthority",
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
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )

    @field_validator(
        "sealed_source_verified",
        "cross_surface_observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "graph_single_writer_reused",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI Observation admission markers must be true")
        return value

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI Observation admission authority flags must be false")
        return value

    @model_validator(mode="after")
    def bind_admission_identity(self) -> Self:
        proposal = self.candidate.proposal
        lineage = proposal.lineage
        expected_nodes = sorted(
            [proposal.action, proposal.observation, *proposal.evidence_nodes],
            key=lambda item: item.node_id,
        )
        expected_edges = sorted(proposal.edges, key=lambda item: item.edge_id)
        expected_lineage_digest = graph_digest(
            "pajin.graph.proposal-lineage/v1",
            lineage.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        kinds = [node.kind for node in self.graph_event.admitted_nodes]
        if (
            self.graph_event.decision is not GraphAdmissionDecision.ADMITTED
            or self.graph_event.proposal_id != proposal.proposal_id
            or self.graph_event.proposal_digest != proposal.digest()
            or self.graph_event.proposal_kind is not GraphProposalKind.OBSERVATION
            or self.graph_event.producer_id != proposal.producer_id
            or self.graph_event.producer_version != proposal.producer_version
            or self.graph_event.producer_digest != proposal.producer_digest
            or self.graph_event.authority_id != self.candidate.graph.authority_id
            or self.graph_event.authority_digest != self.candidate.graph.authority_digest
            or self.graph_event.campaign_id != lineage.campaign_id
            or self.graph_event.proposal_campaign_id != lineage.campaign_id
            or self.graph_event.run_id != lineage.run_id
            or self.graph_event.agent_id != lineage.agent_id
            or self.graph_event.task_id != lineage.task_id
            or self.graph_event.request_id != lineage.request_id
            or self.graph_event.request_digest != lineage.request_digest
            or self.graph_event.lineage_digest != expected_lineage_digest
            or self.graph_event.capability_grant_id != lineage.capability_grant_id
            or self.graph_event.capability_grant_digest != lineage.capability_grant_digest
            or self.graph_event.capability_id != lineage.capability_id
            or self.graph_event.capability_version != lineage.capability_version
            or self.graph_event.capability_digest != lineage.capability_digest
            or self.graph_event.action_permit_id != lineage.action_permit_id
            or self.graph_event.action_permit_digest != lineage.action_permit_digest
            or self.graph_event.source_root_digest != lineage.source_root_digest
            or self.graph_event.evidence != lineage.evidence
            or self.graph_event.produced_at != lineage.produced_at
            or self.graph_event.admitted_nodes != expected_nodes
            or self.graph_event.admitted_edges != expected_edges
            or kinds.count(GraphNodeKind.ACTION.value) != 1
            or kinds.count(GraphNodeKind.OBSERVATION.value) != 1
            or kinds.count(GraphNodeKind.EVIDENCE.value) != 2
            or len(kinds) != 4
            or any(
                edge.relation not in {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
                for edge in self.graph_event.admitted_edges
            )
        ):
            raise ValueError("AI Observation admission exceeds Observation/Evidence authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.ai-analysis-observation-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"ai-analysis-observation-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("AI Observation admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("AI Observation admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


@dataclass(frozen=True, slots=True)
class VerifiedAIAnalysisObservationSource:
    """One sealed, successful REDTEAM AI dispatch independently reverified."""

    snapshot: VerifiedRunSnapshot
    preparation: AIReadOnlyAnalysisPreparation | AIMeasurementOperationPreparation
    job: CapabilityGraphCampaignJobInput
    terminal: CapabilityDispatchAuditEvent
    reconciliation: CapabilityDispatchReconciliation
    evidence: _AIAnalysisToolEvidence
    reservation_path: str
    evidence_path: str
    reservation_sha256: str
    evidence_sha256: str


def ai_analysis_observation_producer_registration() -> GraphProducerRegistration:
    """Return the exact code-owned Observation-only producer registration."""

    return GraphProducerRegistration(
        producerId=AI_ANALYSIS_OBSERVATION_PRODUCER_ID,
        producerVersion=AI_ANALYSIS_OBSERVATION_PRODUCER_VERSION,
        producerDigest=AI_ANALYSIS_OBSERVATION_PRODUCER_DIGEST,
        allowedProposalKinds=(GraphProposalKind.OBSERVATION,),
    )


class AIAnalysisObservationAdmissionGate:
    """Reverify a sealed REDTEAM outcome and reuse the existing Graph single writer."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
    ) -> None:
        if not isinstance(graph_store, SQLiteGraphStore):
            raise TypeError("AI Observation admission requires an exact SQLite Graph Store")
        if not isinstance(graph_admission, GraphAdmissionAuthority):
            raise TypeError("AI Observation admission requires the Graph Admission authority")
        if not isinstance(trusted_lineages, TrustedGraphLineageRegistry):
            raise TypeError("AI Observation admission requires the trusted lineage registry")
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("AI Observation Graph authority wiring differs")
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages

    def prepare_candidate(
        self,
        inputs: AIAnalysisObservationSourceInputs,
        graph: AIAnalysisGraphAdmissionBinding,
    ) -> AIAnalysisObservationCandidate:
        try:
            canonical_graph = AIAnalysisGraphAdmissionBinding.model_validate(
                graph.model_dump(mode="json", by_alias=True)
            )
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except AIAnalysisObservationAdmissionError:
            raise
        except Exception as exc:
            raise AIAnalysisObservationAdmissionError(
                "AI Observation candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: AIAnalysisObservationSourceInputs,
        candidate: AIAnalysisObservationCandidate,
    ) -> AIAnalysisObservationAdmission:
        try:
            canonical = AIAnalysisObservationCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise AIAnalysisObservationAdmissionError(
                    "AI Observation candidate differs from sealed source authority"
                )
            proposal = canonical.proposal
            proposal_digest = proposal.digest()
            prior = self._graph_store.event_log.event_for_attempt(
                proposal.proposal_id,
                proposal_digest,
            )
            if prior is None:
                self._require_current_graph(canonical.graph)
                expected_head = canonical.graph.snapshot.event_log_head_digest
                if expected_head is None:
                    raise AIAnalysisObservationAdmissionError(
                        "AI Observation admission requires a non-empty Graph head"
                    )
                self._trusted_lineages.register(proposal.lineage)
                result = self._graph_admission.submit_if_current(
                    proposal,
                    expected_event_log_head_digest=expected_head,
                )
            else:
                result = self._graph_admission.submit(proposal)
            if (
                result.event.decision is not GraphAdmissionDecision.ADMITTED
                or result.event.authority_id != canonical.graph.authority_id
                or result.event.authority_digest != canonical.graph.authority_digest
            ):
                raise AIAnalysisObservationAdmissionError(
                    "Graph Admission authority rejected the AI Observation"
                )
            return AIAnalysisObservationAdmission(candidate=canonical, graphEvent=result.event)
        except AIAnalysisObservationAdmissionError:
            raise
        except Exception as exc:
            raise AIAnalysisObservationAdmissionError(
                "AI Observation admission failed closed"
            ) from exc

    def _build_candidate(
        self,
        inputs: AIAnalysisObservationSourceInputs,
        graph: AIAnalysisGraphAdmissionBinding,
    ) -> AIAnalysisObservationCandidate:
        source = load_verified_ai_analysis_observation_source(
            inputs,
            graph_store=self._graph_store,
        )
        if not isinstance(source.preparation, AIReadOnlyAnalysisPreparation):
            raise AIAnalysisObservationAdmissionError(
                "AI measurement execution cannot become a Graph candidate"
            )
        permit = next(
            item
            for item in self._graph_store.permit_store.permits()
            if item.permit_id == source.terminal.permit_id
        )
        if graph.snapshot.campaign_id != permit.campaign_id:
            raise AIAnalysisObservationAdmissionError(
                "AI execution source and Graph admission Campaigns differ"
            )
        policy = AIAnalysisObservationAdmissionPolicy()
        surfaces = tuple(item.reference() for item in source.preparation.binding.surfaces)
        type_set = source.preparation.binding.surfaces[0].domain_graph_type_set
        value_digest = graph_digest(
            "pajin.workflow.ai-analysis-observation-value/v1",
            {
                "preparationDigest": source.preparation.preparation_digest,
                "surfaceReferences": [
                    item.model_dump(mode="json", by_alias=True) for item in surfaces
                ],
                "requestDigest": permit.request_digest,
                "gatewayOutcomeDigest": source.terminal.gateway_outcome_digest,
                "terminalEventDigest": source.terminal.event_digest,
                "reconciliationDigest": source.reconciliation.reconciliation_digest,
                "sourceRootDigest": source.snapshot.verification.root_digest,
                "requestReservationSha256": source.reservation_sha256,
                "executionEvidenceSha256": source.evidence_sha256,
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
                "A permitted read-only AI analysis produced sealed behavior evidence "
                "across the exact bound AI Surfaces."
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
        proposal_key = graph_digest(
            "pajin.workflow.ai-analysis-observation-proposal-id/v1",
            {
                "sourceRootDigest": source.snapshot.verification.root_digest,
                "terminalEventDigest": source.terminal.event_digest,
                "reconciliationDigest": source.reconciliation.reconciliation_digest,
                "snapshotDigest": graph.snapshot.snapshot_digest,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        proposal = ObservationProposal(
            proposalId=f"proposal:ai-observation:{proposal_key}",
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            lineage=GraphProposalLineage(
                campaignId=permit.campaign_id,
                runId=permit.run_id,
                agentId="agent:ai-analysis-observation-admission",
                taskId=f"task:ai-analysis-observation:{source.terminal.event_digest[:32]}",
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
                producedAt=max(
                    source.terminal.occurred_at,
                    source.evidence.worker_result.finished_at,
                ),
            ),
            action=action,
            observation=observation,
            evidenceNodes=evidence_nodes,
            edges=sorted(edges, key=lambda item: item.edge_id),
        )
        return AIAnalysisObservationCandidate(
            policy=policy,
            graph=graph,
            preparation=source.preparation,
            surfaces=surfaces,
            domainGraphTypeSet=type_set,
            sourceExecutionSnapshot=permit.snapshot,
            sourceRunId=permit.run_id,
            sourceRootDigest=source.snapshot.verification.root_digest,
            requestReservationPath=source.reservation_path,
            requestReservationSha256=source.reservation_sha256,
            executionEvidencePath=source.evidence_path,
            executionEvidenceSha256=source.evidence_sha256,
            terminalEventDigest=source.terminal.event_digest,
            reconciliationDigest=source.reconciliation.reconciliation_digest,
            proposal=proposal,
        )

    def _require_current_graph(self, graph: AIAnalysisGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest
            != getattr(
                self._graph_admission,
                "_authority_digest",
                None,
            )
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise AIAnalysisObservationAdmissionError(
                "AI Observation Graph Admission authority differs"
            )
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise AIAnalysisObservationAdmissionError(
                "AI Observation Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise AIAnalysisObservationAdmissionError(
                "AI Observation Graph Snapshot is not the current canonical head"
            )


def load_verified_ai_analysis_observation_source(
    inputs: AIAnalysisObservationSourceInputs,
    *,
    graph_store: SQLiteGraphStore,
    source_tool: AIM03SourceChatProbeTool | None = None,
    measurement_tool: AIM03MeasurementChatProbeTool | None = None,
) -> VerifiedAIAnalysisObservationSource:
    """Open one sealed REDTEAM Run and recheck its Permit-to-Tool bindings."""

    if not isinstance(inputs, AIAnalysisObservationSourceInputs):
        raise TypeError("AI Observation admission requires exact source inputs")
    if not isinstance(graph_store, SQLiteGraphStore):
        raise TypeError("AI source verification requires the exact SQLite Graph Store")
    try:
        preparation_payload = inputs.preparation.model_dump(
            mode="json",
            by_alias=True,
        )
        preparation: AIReadOnlyAnalysisPreparation | AIMeasurementOperationPreparation
        if type(inputs.preparation) is AIReadOnlyAnalysisPreparation:
            preparation = AIReadOnlyAnalysisPreparation.model_validate(preparation_payload)
        elif type(inputs.preparation) is AIMeasurementOperationPreparation:
            preparation = AIMeasurementOperationPreparation.model_validate(preparation_payload)
        else:
            raise TypeError("AI execution source preparation type is not registered")
        job = CapabilityGraphCampaignJobInput.model_validate(
            inputs.job.model_dump(mode="json", by_alias=True)
        )
        prepared = preparation.prepared_action
        static = preparation.binding.capability_binding
        if (
            job.profile != static.profile.profile_id
            or job.release != preparation.release
            or job.request != prepared.request
            or job.proposal.capability != prepared.capability
            or job.proposal.request_id != prepared.request.request_id
            or job.proposal.request_digest != prepared.request_digest
            or job.proposal.normalized_parameters_digest != prepared.normalized_parameters_digest
            or job.proposal.snapshot != job.decision.snapshot
            or job.proposal.decision_id != job.decision.decision_id
            or job.proposal.decision_digest != job.decision.decision_digest
            or job.proposal.campaign_id != job.grant.campaign
            or job.request.agent_id != job.grant.subject
        ):
            raise AIAnalysisObservationAdmissionError(
                "AI preparation and REDTEAM execution inputs differ"
            )
        permits = tuple(
            permit
            for permit in graph_store.permit_store.permits()
            if permit.run_id == inputs.expected_run_id
            and permit.request_id == prepared.request.request_id
        )
        if len(permits) != 1:
            raise AIAnalysisObservationAdmissionError(
                "AI execution source lacks one exact consumed ActionPermit"
            )
        permit = permits[0]
        if (
            permit.campaign_id != job.proposal.campaign_id
            or permit.run_id != job.proposal.run_id
            or permit.proposal_id != job.proposal.proposal_id
            or permit.proposal_digest != job.proposal.proposal_digest
            or permit.decision_id != job.decision.decision_id
            or permit.decision_digest != job.decision.decision_digest
            or permit.snapshot != job.decision.snapshot
            or permit.capability != prepared.capability
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
        ):
            raise AIAnalysisObservationAdmissionError(
                "AI consumed ActionPermit differs from the prepared action"
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
            raise AIAnalysisObservationAdmissionError(
                "AI dispatch is not one sealed successful terminal lifecycle"
            )
        reservation_bytes = snapshot.artifact_bytes(reservation_path)
        evidence_bytes = snapshot.artifact_bytes(evidence_path)
        reservation = parse_strict_json_bytes(
            reservation_bytes,
            label="sealed AI Tool request reservation",
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        evidence = _AIAnalysisToolEvidence.model_validate(
            parse_strict_json_bytes(
                evidence_bytes,
                label="sealed AI Tool execution evidence",
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
        )
        expected_reservation: dict[str, object] = {
            "apiVersion": "pajin.dev/tool-request-reservation/v1",
            "kind": "ToolRequestReservation",
            "requestId": permit.request_id,
            "requestSha256": permit.request_digest,
        }
        _validate_ai_execution_authority(
            preparation=preparation,
            job=job,
            permit=permit,
            terminal=terminal,
            evidence=evidence,
            evidence_path=evidence_path,
            reservation=reservation,
            expected_reservation=expected_reservation,
            source_tool=source_tool,
            measurement_tool=measurement_tool,
        )
        return VerifiedAIAnalysisObservationSource(
            snapshot=snapshot,
            preparation=preparation,
            job=job,
            terminal=terminal,
            reconciliation=reconciliation.record,
            evidence=evidence,
            reservation_path=reservation_path,
            evidence_path=evidence_path,
            reservation_sha256=sha256(reservation_bytes).hexdigest(),
            evidence_sha256=sha256(evidence_bytes).hexdigest(),
        )
    except AIAnalysisObservationAdmissionError:
        raise
    except Exception as exc:
        raise AIAnalysisObservationAdmissionError(
            "sealed AI execution source authority is invalid"
        ) from exc


def _validate_ai_execution_authority(
    *,
    preparation: AIReadOnlyAnalysisPreparation | AIMeasurementOperationPreparation,
    job: CapabilityGraphCampaignJobInput,
    permit: ActionPermit,
    terminal: CapabilityDispatchAuditEvent,
    evidence: _AIAnalysisToolEvidence,
    evidence_path: str,
    reservation: object,
    expected_reservation: dict[str, object],
    source_tool: AIM03SourceChatProbeTool | None,
    measurement_tool: AIM03MeasurementChatProbeTool | None,
) -> None:
    if not isinstance(permit, ActionPermit):
        raise TypeError("AI execution verification requires an ActionPermit")
    prepared = preparation.prepared_action
    if (
        reservation != expected_reservation
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
        or evidence.policy_decision.allowed is not True
        or evidence.result.request_id != job.request.request_id
        or evidence.result.tool_id != job.request.tool_id
        or evidence.result.success is not True
        or evidence.result.error is not None
        or evidence.result.evidence
        or evidence.worker_result.status is not WorkerStatus.SUCCEEDED
    ):
        raise AIAnalysisObservationAdmissionError(
            "sealed AI Tool evidence differs or is unsuccessful"
        )
    tool = _ai_observation_tool(
        job,
        source_tool=source_tool,
        measurement_tool=measurement_tool,
    )
    expected_result = tool.interpret(job.request, evidence.worker_result)
    if expected_result != evidence.result:
        raise AIAnalysisObservationAdmissionError(
            "sealed AI Tool result differs from the code-owned adapter"
        )
    tool.validate_trusted_execution(
        job.request,
        evidence.result,
        evidence.worker_result,
        network_log_trusted=evidence.network_log_trusted,
    )
    _validate_worker_job_metadata(job, tool, evidence)
    outcome = GatewayOutcome(
        decision=evidence.policy_decision,
        result=evidence.result.model_copy(update={"evidence": [evidence_path]}, deep=True),
        worker_result=evidence.worker_result,
        network_log_trusted=evidence.network_log_trusted,
        result_identity_valid=True,
        executed=True,
    )
    if terminal.gateway_outcome_digest != capability_gateway_outcome_digest(outcome):
        raise AIAnalysisObservationAdmissionError(
            "sealed AI Gateway outcome digest differs from Tool evidence"
        )


def _ai_observation_tool(
    job: CapabilityGraphCampaignJobInput,
    *,
    source_tool: AIM03SourceChatProbeTool | None = None,
    measurement_tool: AIM03MeasurementChatProbeTool | None = None,
) -> Tool:
    if source_tool is not None and measurement_tool is not None:
        raise AIAnalysisObservationAdmissionError(
            "AI source and measurement Tool overrides are mutually exclusive"
        )
    if source_tool is not None:
        if (
            type(source_tool) is not AIM03SourceChatProbeTool
            or job.profile != "redteam-llm-v1"
            or job.request.tool_id != AIChatProbeTool.spec.tool_id
        ):
            raise AIAnalysisObservationAdmissionError(
                "AI source Tool override is outside the exact M03 admission"
            )
        return source_tool
    if measurement_tool is not None:
        if (
            type(measurement_tool) is not AIM03MeasurementChatProbeTool
            or job.profile != "redteam-llm-v1"
            or job.request.tool_id != AIChatProbeTool.spec.tool_id
        ):
            raise AIAnalysisObservationAdmissionError(
                "AI measurement Tool override is outside the exact M03 admission"
            )
        return measurement_tool
    if job.profile in {"redteam-llm-v1", "redteam-llm-rag-v1"}:
        return AIChatProbeTool()
    if job.profile == "redteam-mcp-v1":
        return demo_mcp_tool()
    raise AIAnalysisObservationAdmissionError(
        "AI Observation admission rejects non-AI REDTEAM profiles"
    )


def _validate_worker_job_metadata(
    job: CapabilityGraphCampaignJobInput,
    tool: Tool,
    evidence: _AIAnalysisToolEvidence,
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
        or metadata.get("secretRequests") != []
        or metadata.get("secretLeaseIds") != []
    ):
        raise AIAnalysisObservationAdmissionError(
            "sealed AI Worker metadata differs from the code-owned adapter"
        )
    expected_network = (
        NetworkMode.EGRESS_PROXY.value
        if job.profile in {"redteam-llm-v1", "redteam-llm-rag-v1"}
        else NetworkMode.NONE.value
    )
    if metadata.get("network") != expected_network:
        raise AIAnalysisObservationAdmissionError("sealed AI Worker network boundary differs")
    egress = metadata.get("egressPolicy")
    if expected_network == NetworkMode.NONE.value:
        if egress is not None or evidence.network_log_trusted is not False:
            raise AIAnalysisObservationAdmissionError(
                "sealed MCP analysis imported network authority"
            )
        return
    policy = EgressPolicy.model_validate(egress)
    if (
        job.request.method not in policy.allowed_methods
        or policy.max_requests != tool.network_request_cost(job.request)
        or not any(scope_matches(rule, job.request.target) for rule in policy.allow)
        or any(scope_matches(rule, job.request.target) for rule in policy.deny)
        or evidence.network_log_trusted is not True
    ):
        raise AIAnalysisObservationAdmissionError(
            "sealed AI Worker egress evidence differs from the bounded request"
        )


__all__ = [
    "AI_ANALYSIS_OBSERVATION_ADMISSION_API_VERSION",
    "AI_ANALYSIS_OBSERVATION_PRODUCER_DIGEST",
    "AI_ANALYSIS_OBSERVATION_PRODUCER_ID",
    "AI_ANALYSIS_OBSERVATION_PRODUCER_VERSION",
    "AIAnalysisGraphAdmissionBinding",
    "AIAnalysisObservationAdmission",
    "AIAnalysisObservationAdmissionError",
    "AIAnalysisObservationAdmissionGate",
    "AIAnalysisObservationAdmissionPolicy",
    "AIAnalysisObservationCandidate",
    "AIAnalysisObservationSourceInputs",
    "VerifiedAIAnalysisObservationSource",
    "ai_analysis_observation_producer_registration",
    "load_verified_ai_analysis_observation_source",
]
