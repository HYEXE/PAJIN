"""WEB-002C sealed ZAP source knowledge admission without authority transfer."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.measurement_registry_distribution import (
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionBundle,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
)
from pajin.benchmark.scanner_baseline import ScannerBaselineMeasurementPlanAuthority
from pajin.benchmark.scanner_docker_provider import (
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
)
from pajin.benchmark.scanner_measurement import load_scanner_baseline_measurement_authority
from pajin.benchmark.scanner_sarif import ZAPScannerRegistration
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementTrustAnchor,
    RegisteredBenchmarkTargetFactoryAdapter,
)
from pajin.capabilities.lifecycle import CapabilityLifecycleRegistry, CapabilityReleaseRef
from pajin.capabilities.web_measured_validation import (
    WebMeasuredValidationCapabilityBundle,
)
from pajin.discovery.web_surfaces import WebHTTPOperationSurfaceRef
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphProducerRegistration,
    TrustedGraphLineageRegistry,
)
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
    GraphSurface,
    HypothesisProposal,
    ObservationProposal,
    graph_digest,
    graph_node_ref,
)
from pajin.graph.projection import GraphSnapshotRef, graph_snapshot_ref
from pajin.graph.sqlite_store import SQLiteGraphStore, load_verified_current_graph_snapshot
from pajin.runtime.store import load_verified_run_artifacts
from pajin.workflow.web_measured_case_authority import WebMeasuredCaseAuthority
from pajin.workflow.web_replay_benchmark import WebAPIBenchmarkGroundTruthProfile
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementAuthority,
    WebZAPSourceMeasurementAuthorityRef,
    WebZAPSourceMeasurementOutcome,
    load_web_zap_source_measurement_authority,
)

WEB_ZAP_SOURCE_KNOWLEDGE_CANDIDATE_API_VERSION: Literal[
    "pajin.dev/web-zap-source-knowledge-candidate/v1alpha1"
] = "pajin.dev/web-zap-source-knowledge-candidate/v1alpha1"
WEB_ZAP_SOURCE_KNOWLEDGE_ADMISSION_API_VERSION: Literal[
    "pajin.dev/web-zap-source-knowledge-admission/v1alpha1"
] = "pajin.dev/web-zap-source-knowledge-admission/v1alpha1"
WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_ID = "pajin.workflow.web-zap-source-knowledge-admission"
WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_VERSION = "1.0.0"
WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_DIGEST = sha256(
    b"pajin.workflow.web-zap-source-knowledge-admission/v1"
).hexdigest()

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CANONICAL_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_AUTHORITY_BYTES = 16 * 1024 * 1024
_OBSERVATION_SUMMARY = (
    "A sealed registry-governed scanner completed normalized source measurement "
    "for the exact registered Web Surface."
)
_HYPOTHESIS_STATEMENT = (
    "The exact registered Web Surface may warrant separately controlled validation."
)
_HYPOTHESIS_EXPECTED_OBSERVABLE = (
    "A separately authorized fresh controlled validation produces independent "
    "evidence for the same registered Web Surface."
)
_FALSE_AUTHORITY_FIELDS = (
    "private_ground_truth_disclosed",
    "raw_sarif_embedded",
    "target_runtime_identity_embedded",
    "provider_runtime_identity_embedded",
    "controlled_validation_route_used",
    "controlled_validation_executed",
    "validation_floor_evaluated",
    "validation_floor_satisfied",
    "finding_projection_authorized",
    "finding_authorized",
    "finding_confirmation_authorized",
    "scope_expansion_authorized",
    "surface_mutation_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "worker_selection_authorized",
    "tool_selection_authorized",
    "credential_access_authorized",
    "network_access_authorized",
    "replay_authorized",
    "additional_execution_authorized",
    "product_activation_authorized",
    "report_delivery_authorized",
)


class WebZAPSourceKnowledgeAdmissionError(ValueError):
    """Raised when sealed WEB-002B knowledge cannot enter the Graph exactly."""


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    """Reject unchecked nested state introduced by model_copy(update=...)."""

    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        unknown = set(value.__dict__) - set(type(value).model_fields)
        if unknown:
            raise WebZAPSourceKnowledgeAdmissionError(f"{label} contains unmodeled instance state")
        for field_name in type(value).model_fields:
            _require_known_instance_fields(getattr(value, field_name), label=label, _seen=seen)
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if not isinstance(value, type) and is_dataclass(value):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for item in fields(value):
            _require_known_instance_fields(
                getattr(value, item.name),
                label=label,
                _seen=seen,
            )


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


@dataclass(frozen=True, slots=True)
class WebZAPSourceObservationInputs:
    """Exact WEB-002B outcome and all context required to reopen its authority."""

    outcome: WebZAPSourceMeasurementOutcome
    measured_case: WebMeasuredCaseAuthority
    capability_bundle: WebMeasuredValidationCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    release: CapabilityReleaseRef
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile
    scanner_plan: ScannerBaselineMeasurementPlanAuthority
    scanner_registration: ZAPScannerRegistration
    journal_path: Path
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor
    activation_store: BenchmarkMeasurementRegistryActivationStore
    distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor


@dataclass(frozen=True, slots=True)
class VerifiedWebZAPSourceObservation:
    """Public-safe projection inputs from one fully reopened WEB-002B source."""

    measured_surface: WebHTTPOperationSurfaceRef
    domain_graph_type_set: SecurityDomainGraphTypeSetRef
    source_authority: WebZAPSourceMeasurementAuthorityRef
    source_run_id: str
    source_root_digest: str
    authority_reference: str
    authority_sha256: str
    observed_at: datetime
    source_count: int
    registered_surface_signal: bool
    signal_digest: str


class WebZAPSourceKnowledgeAdmissionPolicy(_FrozenStrictModel):
    """Code-owned neutral Web Observation and optional open-Hypothesis policy."""

    api_version: Literal["pajin.dev/web-zap-source-knowledge-admission-policy/v1alpha1"] = Field(
        default="pajin.dev/web-zap-source-knowledge-admission-policy/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["WebZAPSourceKnowledgeAdmissionPolicy"] = "WebZAPSourceKnowledgeAdmissionPolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=112)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    producer_id: Literal["pajin.workflow.web-zap-source-knowledge-admission"] = Field(
        default="pajin.workflow.web-zap-source-knowledge-admission",
        alias="producerId",
    )
    producer_version: Literal["1.0.0"] = Field(default="1.0.0", alias="producerVersion")
    producer_digest: _Sha256 = Field(
        default=WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_DIGEST,
        alias="producerDigest",
    )
    observation_type: Literal["web.protocol-observation"] = Field(
        default="web.protocol-observation", alias="observationType"
    )
    hypothesis_type: Literal["web.security-property"] = Field(
        default="web.security-property", alias="hypothesisType"
    )
    knowledge_only: Literal[True] = Field(default=True, alias="knowledgeOnly")
    sealed_source_authority_required: Literal[True] = Field(
        default=True, alias="sealedSourceAuthorityRequired"
    )
    bounded_hypothesis_enabled: Literal[True] = Field(
        default=True, alias="boundedHypothesisEnabled"
    )
    capability_grant_substitution_authorized: Literal[False] = Field(
        default=False, alias="capabilityGrantSubstitutionAuthorized"
    )
    permit_substitution_authorized: Literal[False] = Field(
        default=False, alias="permitSubstitutionAuthorized"
    )
    finding_production_authorized: Literal[False] = Field(
        default=False, alias="findingProductionAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "knowledge_only",
        "sealed_source_authority_required",
        "bounded_hypothesis_enabled",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002C knowledge policy markers must be boolean true")
        return value

    @field_validator(
        "capability_grant_substitution_authorized",
        "permit_substitution_authorized",
        "finding_production_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002C knowledge policy cannot grant authority")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        if self.producer_digest != WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_DIGEST:
            raise ValueError("WEB-002C knowledge producer differs from code authority")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"policy_id", "policy_digest"}
        )
        digest = graph_digest(
            "pajin.workflow.web-zap-source-knowledge-admission-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"web-zap-source-knowledge-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("WEB-002C knowledge policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("WEB-002C knowledge policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class WebZAPSourceGraphAdmissionBinding(_FrozenStrictModel):
    """Exact current Graph head and pre-existing measured Web Surface."""

    snapshot: GraphSnapshotRef
    authority_id: _Identifier = Field(alias="authorityId")
    authority_digest: _Sha256 = Field(alias="authorityDigest")
    graph_surface: GraphSurface = Field(alias="graphSurface")

    @model_validator(mode="after")
    def require_nonempty_graph(self) -> Self:
        if self.snapshot.event_log_head_digest is None:
            raise ValueError("WEB-002C requires a non-empty Graph Snapshot")
        if self.graph_surface.campaign_id != self.snapshot.campaign_id:
            raise ValueError("WEB-002C Graph Surface belongs to another Campaign")
        return self


class _WebZAPSourceKnowledgeBoundary(_FrozenStrictModel):
    """Negative authority preserved through candidate and admission."""

    private_ground_truth_disclosed: Literal[False] = Field(
        default=False, alias="privateGroundTruthDisclosed"
    )
    raw_sarif_embedded: Literal[False] = Field(default=False, alias="rawSarifEmbedded")
    target_runtime_identity_embedded: Literal[False] = Field(
        default=False, alias="targetRuntimeIdentityEmbedded"
    )
    provider_runtime_identity_embedded: Literal[False] = Field(
        default=False, alias="providerRuntimeIdentityEmbedded"
    )
    controlled_validation_route_used: Literal[False] = Field(
        default=False, alias="controlledValidationRouteUsed"
    )
    controlled_validation_executed: Literal[False] = Field(
        default=False, alias="controlledValidationExecuted"
    )
    validation_floor_evaluated: Literal[False] = Field(
        default=False, alias="validationFloorEvaluated"
    )
    validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="validationFloorSatisfied"
    )
    finding_projection_authorized: Literal[False] = Field(
        default=False, alias="findingProjectionAuthorized"
    )
    finding_authorized: Literal[False] = Field(default=False, alias="findingAuthorized")
    finding_confirmation_authorized: Literal[False] = Field(
        default=False, alias="findingConfirmationAuthorized"
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    surface_mutation_authorized: Literal[False] = Field(
        default=False, alias="surfaceMutationAuthorized"
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False, alias="capabilityActivationAuthorized"
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False, alias="workerSelectionAuthorized"
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False, alias="toolSelectionAuthorized"
    )
    credential_access_authorized: Literal[False] = Field(
        default=False, alias="credentialAccessAuthorized"
    )
    network_access_authorized: Literal[False] = Field(
        default=False, alias="networkAccessAuthorized"
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    additional_execution_authorized: Literal[False] = Field(
        default=False, alias="additionalExecutionAuthorized"
    )
    product_activation_authorized: Literal[False] = Field(
        default=False, alias="productActivationAuthorized"
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False, alias="reportDeliveryAuthorized"
    )

    @field_validator(*_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002C knowledge boundary cannot grant authority")
        return value


class WebZAPSourceKnowledgeCandidate(_WebZAPSourceKnowledgeBoundary):
    """Content-addressed neutral Observation and optional bounded Hypothesis."""

    api_version: Literal["pajin.dev/web-zap-source-knowledge-candidate/v1alpha1"] = Field(
        default=WEB_ZAP_SOURCE_KNOWLEDGE_CANDIDATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebZAPSourceKnowledgeCandidate"] = "WebZAPSourceKnowledgeCandidate"
    candidate_id: str = Field(default="", alias="candidateId", max_length=112)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    policy: WebZAPSourceKnowledgeAdmissionPolicy
    graph: WebZAPSourceGraphAdmissionBinding
    measured_case: WebHTTPOperationSurfaceRef = Field(alias="measuredCaseSurface")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    source_measurement: WebZAPSourceMeasurementAuthorityRef = Field(alias="sourceMeasurement")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_authority_reference: str = Field(
        alias="sourceAuthorityReference",
        min_length=1,
        max_length=300,
    )
    source_authority_sha256: _Sha256 = Field(alias="sourceAuthoritySha256")
    source_count: int = Field(alias="sourceCount", strict=True, ge=1, le=2_000)
    registered_surface_signal: bool = Field(alias="registeredSurfaceSignal")
    signal_digest: _Sha256 = Field(alias="signalDigest")
    observation_proposal: ObservationProposal = Field(alias="observationProposal")
    hypothesis_proposal: HypothesisProposal | None = Field(
        default=None,
        alias="hypothesisProposal",
    )
    state: Literal["sealed-knowledge-not-admitted"] = "sealed-knowledge-not-admitted"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    neutral_observation_produced: Literal[True] = Field(
        default=True, alias="neutralObservationProduced"
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")

    @field_validator(
        "sealed_source_verified",
        "neutral_observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002C sealed knowledge markers must be boolean true")
        return value

    @field_validator("graph_admitted", mode="before")
    @classmethod
    def require_not_admitted(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002C candidate cannot claim prior Graph admission")
        return value

    @field_validator("registered_surface_signal", mode="before")
    @classmethod
    def require_boolean_signal(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("WEB-002C registered Surface signal must be boolean")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError("WEB-002C Domain Graph semantics are not registered exactly") from exc
        observation = self.observation_proposal
        action = observation.action
        lineage = observation.lineage
        evidence = observation.evidence_nodes
        graph_surface = self.graph.graph_surface
        expected_binding = GraphEvidenceBinding(
            reference=self.source_authority_reference,
            sha256=self.source_authority_sha256,
        )
        expected_surface = GraphSurface(
            campaignId=self.graph.snapshot.campaign_id,
            targetId=self.measured_case.surface_id,
            surfaceType=self.measured_case.surface_type,
            locatorSchema=self.measured_case.locator_schema,
            locatorDigest=self.measured_case.surface_digest,
            origin=GraphContentOrigin.TRUSTED_CORE,
        )
        source_authority = (
            self.source_measurement.authority_id,
            self.source_measurement.authority_digest,
        )
        if self.policy != WebZAPSourceKnowledgeAdmissionPolicy():
            raise ValueError("WEB-002C admission policy differs from code authority")
        if (
            semantics.domain_classification.domain is not SecurityDomain.WEB
            or semantics.surface_type != self.measured_case.surface_type
            or semantics.locator_schema != self.measured_case.locator_schema
            or semantics.observation_type != self.policy.observation_type
            or semantics.hypothesis_type != self.policy.hypothesis_type
            or graph_surface != expected_surface
            or observation.observation.observation_type != self.policy.observation_type
            or observation.observation.summary != _OBSERVATION_SUMMARY
            or observation.observation.origin is not GraphContentOrigin.TARGET_DERIVED
            or observation.observation.confidence != 1.0
            or observation.producer_id != self.policy.producer_id
            or observation.producer_version != self.policy.producer_version
            or observation.producer_digest != self.policy.producer_digest
            or lineage.campaign_id != self.graph.snapshot.campaign_id
            or lineage.run_id != self.source_run_id
            or lineage.source_root_digest != self.source_root_digest
            or (lineage.source_authority_id, lineage.source_authority_digest) != source_authority
            or lineage.capability_grant_id is not None
            or lineage.capability_grant_digest is not None
            or lineage.action_permit_id is not None
            or lineage.action_permit_digest is not None
            or lineage.capability_id is not None
            or lineage.capability_version is not None
            or lineage.capability_digest is not None
            or lineage.evidence != [expected_binding]
            or action.authority_kind is not GraphAuthorityKind.SEALED_SOURCE_AUTHORITY
            or (action.authority_id, action.authority_digest) != source_authority
            or action.capability_id is not None
            or action.capability_version is not None
            or action.capability_digest is not None
            or action.tool_id != "pajin.workflow.web-zap-source-measurement"
            or action.target_digest != self.measured_case.surface_digest
            or len(evidence) != 1
            or evidence[0].reference != self.source_authority_reference
            or evidence[0].sha256 != self.source_authority_sha256
            or evidence[0].source_root_digest != self.source_root_digest
            or evidence[0].data_classification != "internal"
            or len(observation.edges) != 2
            or {edge.relation for edge in observation.edges}
            != {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
        ):
            raise ValueError("WEB-002C candidate differs from sealed neutral semantics")
        hypothesis = self.hypothesis_proposal
        if self.registered_surface_signal is not (hypothesis is not None):
            raise ValueError("WEB-002C bounded Hypothesis marker differs from source signal")
        if hypothesis is not None:
            hypothesis_lineage = hypothesis.lineage
            if (
                hypothesis.producer_id != self.policy.producer_id
                or hypothesis.producer_version != self.policy.producer_version
                or hypothesis.producer_digest != self.policy.producer_digest
                or hypothesis_lineage.campaign_id != lineage.campaign_id
                or hypothesis_lineage.run_id != lineage.run_id
                or hypothesis_lineage.source_root_digest != lineage.source_root_digest
                or hypothesis_lineage.source_authority_id != lineage.source_authority_id
                or hypothesis_lineage.source_authority_digest != lineage.source_authority_digest
                or hypothesis_lineage.evidence != lineage.evidence
                or hypothesis.hypothesis.hypothesis_type != self.policy.hypothesis_type
                or hypothesis.hypothesis.statement != _HYPOTHESIS_STATEMENT
                or hypothesis.hypothesis.expected_observable != _HYPOTHESIS_EXPECTED_OBSERVABLE
                or hypothesis.hypothesis.origin is not GraphContentOrigin.AGENT_DERIVED
                or hypothesis.hypothesis.confidence != 0.5
                or len(hypothesis.edges) != 1
                or hypothesis.edges[0].relation is not GraphRelation.ENABLES
                or hypothesis.edges[0].source != graph_node_ref(observation.observation)
                or hypothesis.edges[0].target != graph_node_ref(hypothesis.hypothesis)
            ):
                raise ValueError("WEB-002C bounded Hypothesis differs from the neutral Observation")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.web-zap-source-knowledge-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"web-zap-source-knowledge_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("WEB-002C candidate digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("WEB-002C candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class WebZAPSourceKnowledgeAdmission(_WebZAPSourceKnowledgeBoundary):
    """Proof that sealed WEB-002B knowledge used only the existing Graph writer."""

    api_version: Literal["pajin.dev/web-zap-source-knowledge-admission/v1alpha1"] = Field(
        default=WEB_ZAP_SOURCE_KNOWLEDGE_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebZAPSourceKnowledgeAdmission"] = "WebZAPSourceKnowledgeAdmission"
    admission_id: str = Field(default="", alias="admissionId", max_length=112)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: WebZAPSourceKnowledgeCandidate
    observation_graph_event: GraphAdmissionEvent = Field(alias="observationGraphEvent")
    hypothesis_graph_event: GraphAdmissionEvent | None = Field(
        default=None,
        alias="hypothesisGraphEvent",
    )
    state: Literal["registered-not-authorized"] = "registered-not-authorized"
    sealed_source_verified: Literal[True] = Field(default=True, alias="sealedSourceVerified")
    neutral_observation_produced: Literal[True] = Field(
        default=True, alias="neutralObservationProduced"
    )
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[True] = Field(default=True, alias="graphAdmitted")
    graph_single_writer_reused: Literal[True] = Field(default=True, alias="graphSingleWriterReused")
    bounded_hypothesis_admitted: bool = Field(alias="boundedHypothesisAdmitted")

    @field_validator(
        "sealed_source_verified",
        "neutral_observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "graph_single_writer_reused",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002C admission markers must be boolean true")
        return value

    @field_validator("bounded_hypothesis_admitted", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("WEB-002C bounded Hypothesis marker must be boolean")
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
            or kinds.count(GraphNodeKind.EVIDENCE.value) != 1
            or len(kinds) != 3
            or any(
                edge.relation not in {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
                for edge in self.observation_graph_event.admitted_edges
            )
        ):
            raise ValueError("WEB-002C Observation admission exceeds neutral knowledge authority")
        hypothesis = self.candidate.hypothesis_proposal
        expected_hypothesis = hypothesis is not None
        if (
            self.bounded_hypothesis_admitted is not expected_hypothesis
            or (self.hypothesis_graph_event is not None) is not expected_hypothesis
        ):
            raise ValueError("WEB-002C bounded Hypothesis admission marker differs")
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
                raise ValueError("WEB-002C bounded Hypothesis exceeds open knowledge authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.web-zap-source-knowledge-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"web-zap-source-knowledge-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("WEB-002C admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("WEB-002C admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def web_zap_source_knowledge_producer_registration() -> GraphProducerRegistration:
    """Return the exact code-owned WEB-002C Observation/Hypothesis producer."""

    return GraphProducerRegistration(
        producerId=WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_ID,
        producerVersion=WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_VERSION,
        producerDigest=WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_DIGEST,
        allowedProposalKinds=(
            GraphProposalKind.HYPOTHESIS,
            GraphProposalKind.OBSERVATION,
        ),
    )


class WebZAPSourceKnowledgeAdmissionGate:
    """Reopen WEB-002B and reuse the existing Graph single writer only."""

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        graph_admission: GraphAdmissionAuthority,
        trusted_lineages: TrustedGraphLineageRegistry,
    ) -> None:
        if type(graph_store) is not SQLiteGraphStore:
            raise TypeError("WEB-002C requires an exact SQLite Graph Store")
        if type(graph_admission) is not GraphAdmissionAuthority:
            raise TypeError("WEB-002C requires the Graph Admission authority")
        if type(trusted_lineages) is not TrustedGraphLineageRegistry:
            raise TypeError("WEB-002C requires the trusted lineage registry")
        if (
            getattr(graph_admission, "_event_log", None) is not graph_store.event_log
            or getattr(graph_admission, "_lineage_verifier", None) is not trusted_lineages
            or getattr(graph_admission, "_campaign_id", None) != graph_store.campaign_id
        ):
            raise ValueError("WEB-002C Graph authority wiring differs")
        registration = getattr(graph_admission, "_producers", None)
        if (
            registration is None
            or registration.registration(WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_ID)
            != web_zap_source_knowledge_producer_registration()
        ):
            raise ValueError("WEB-002C Graph producer registration differs")
        self._graph_store = graph_store
        self._graph_admission = graph_admission
        self._trusted_lineages = trusted_lineages

    def prepare_candidate(
        self,
        inputs: WebZAPSourceObservationInputs,
        graph: WebZAPSourceGraphAdmissionBinding,
    ) -> WebZAPSourceKnowledgeCandidate:
        """Reverify the source and prepare knowledge without writing the Graph."""

        try:
            if type(graph) is not WebZAPSourceGraphAdmissionBinding:
                raise TypeError("WEB-002C requires an exact Graph admission binding")
            _require_known_instance_fields(graph, label="WEB-002C Graph binding")
            canonical_graph = WebZAPSourceGraphAdmissionBinding.model_validate(
                graph.model_dump(mode="json", by_alias=True)
            )
            self._require_current_graph(canonical_graph)
            return self._build_candidate(inputs, canonical_graph)
        except WebZAPSourceKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise WebZAPSourceKnowledgeAdmissionError(
                "WEB-002C candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: WebZAPSourceObservationInputs,
        candidate: WebZAPSourceKnowledgeCandidate,
    ) -> WebZAPSourceKnowledgeAdmission:
        """Rebuild from the sealed source and use CAS admission for both proposals."""

        try:
            if type(candidate) is not WebZAPSourceKnowledgeCandidate:
                raise TypeError("WEB-002C requires an exact knowledge candidate")
            _require_known_instance_fields(candidate, label="WEB-002C knowledge candidate")
            canonical = WebZAPSourceKnowledgeCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            rebuilt = self._build_candidate(inputs, canonical.graph)
            if rebuilt != canonical:
                raise WebZAPSourceKnowledgeAdmissionError(
                    "WEB-002C candidate differs from sealed source authority"
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
                    raise WebZAPSourceKnowledgeAdmissionError(
                        "WEB-002C requires a non-empty Graph head"
                    )
                self._trusted_lineages.register(
                    observation.lineage,
                    proposal_digest=observation.digest(),
                    expected_event_log_head_digest=expected_head,
                )
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
                        raise WebZAPSourceKnowledgeAdmissionError(
                            "WEB-002C Hypothesis source is no longer the current Graph head"
                        )
                    self._trusted_lineages.register(
                        hypothesis.lineage,
                        proposal_digest=hypothesis.digest(),
                        expected_event_log_head_digest=(observation_result.event.event_digest),
                    )
                    hypothesis_result = self._graph_admission.submit_if_current(
                        hypothesis,
                        expected_event_log_head_digest=observation_result.event.event_digest,
                    )
                else:
                    hypothesis_result = self._graph_admission.submit(hypothesis)
                self._require_admitted_result(hypothesis_result.event, canonical.graph)
                hypothesis_event = hypothesis_result.event
            return WebZAPSourceKnowledgeAdmission(
                candidate=canonical,
                observationGraphEvent=observation_result.event,
                hypothesisGraphEvent=hypothesis_event,
                boundedHypothesisAdmitted=hypothesis is not None,
            )
        except WebZAPSourceKnowledgeAdmissionError:
            raise
        except Exception as exc:
            raise WebZAPSourceKnowledgeAdmissionError(
                "WEB-002C Graph admission failed closed"
            ) from exc

    def _require_admitted_result(
        self,
        event: GraphAdmissionEvent,
        graph: WebZAPSourceGraphAdmissionBinding,
    ) -> None:
        if (
            event.decision is not GraphAdmissionDecision.ADMITTED
            or event.authority_id != graph.authority_id
            or event.authority_digest != graph.authority_digest
        ):
            raise WebZAPSourceKnowledgeAdmissionError(
                "Graph Admission authority rejected WEB-002C knowledge"
            )

    def _build_candidate(
        self,
        inputs: WebZAPSourceObservationInputs,
        graph: WebZAPSourceGraphAdmissionBinding,
    ) -> WebZAPSourceKnowledgeCandidate:
        source = load_verified_web_zap_source_observation(inputs)
        surface_ref = source.measured_surface
        if graph.snapshot.campaign_id != self._graph_store.campaign_id:
            raise WebZAPSourceKnowledgeAdmissionError(
                "WEB-002C source and Graph admission Campaigns differ"
            )
        expected_graph_surface = GraphSurface(
            campaignId=graph.snapshot.campaign_id,
            targetId=surface_ref.surface_id,
            surfaceType=surface_ref.surface_type,
            locatorSchema=surface_ref.locator_schema,
            locatorDigest=surface_ref.surface_digest,
            origin=GraphContentOrigin.TRUSTED_CORE,
        )
        if graph.graph_surface != expected_graph_surface:
            raise WebZAPSourceKnowledgeAdmissionError(
                "WEB-002C measured Surface differs from the current Graph Surface"
            )
        policy = WebZAPSourceKnowledgeAdmissionPolicy()
        value_digest = graph_digest(
            "pajin.workflow.web-zap-source-observation-value/v1",
            {
                "measuredCaseSurface": surface_ref.model_dump(mode="json", by_alias=True),
                "sourceAuthorityId": source.source_authority.authority_id,
                "sourceAuthorityDigest": source.source_authority.authority_digest,
                "sourceRunId": source.source_run_id,
                "sourceRootDigest": source.source_root_digest,
                "sourceAuthorityReference": source.authority_reference,
                "sourceAuthoritySha256": source.authority_sha256,
                "sourceCount": source.source_count,
                "registeredSurfaceSignal": source.registered_surface_signal,
                "signalDigest": source.signal_digest,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        request_digest = graph_digest(
            "pajin.workflow.web-zap-source-observation-request/v1",
            {
                "policyDigest": policy.policy_digest,
                "snapshotDigest": graph.snapshot.snapshot_digest,
                "surfaceDigest": surface_ref.surface_digest,
                "valueDigest": value_digest,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        request_id = f"tool_web_zap_source_{request_digest}"
        action = GraphAction(
            campaignId=graph.snapshot.campaign_id,
            requestId=request_id,
            requestDigest=request_digest,
            authorityKind=GraphAuthorityKind.SEALED_SOURCE_AUTHORITY,
            authorityId=source.source_authority.authority_id,
            authorityDigest=source.source_authority.authority_digest,
            toolId="pajin.workflow.web-zap-source-measurement",
            targetDigest=surface_ref.surface_digest,
            status=GraphActionStatus.SUCCEEDED,
            executedAt=source.observed_at,
        )
        observation = GraphObservation(
            campaignId=graph.snapshot.campaign_id,
            observationType=policy.observation_type,
            summary=_OBSERVATION_SUMMARY,
            valueDigest=value_digest,
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            origin=GraphContentOrigin.TARGET_DERIVED,
            confidence=1.0,
            observedAt=source.observed_at,
        )
        binding = GraphEvidenceBinding(
            reference=source.authority_reference,
            sha256=source.authority_sha256,
        )
        evidence = GraphEvidence(
            campaignId=graph.snapshot.campaign_id,
            reference=binding.reference,
            sha256=binding.sha256,
            sourceRootDigest=source.source_root_digest,
            dataClassification="internal",
        )
        edges = sorted(
            [
                GraphEdge(
                    campaignId=graph.snapshot.campaign_id,
                    relation=GraphRelation.PRODUCES,
                    source=graph_node_ref(action),
                    target=graph_node_ref(observation),
                    authorityId=graph.authority_id,
                    authorityDigest=graph.authority_digest,
                ),
                GraphEdge(
                    campaignId=graph.snapshot.campaign_id,
                    relation=GraphRelation.SUPPORTED_BY,
                    source=graph_node_ref(observation),
                    target=graph_node_ref(evidence),
                    authorityId=graph.authority_id,
                    authorityDigest=graph.authority_digest,
                ),
            ],
            key=lambda item: item.edge_id,
        )
        observation_lineage = _source_lineage(
            source=source,
            campaign_id=graph.snapshot.campaign_id,
            request_id=request_id,
            request_digest=request_digest,
            binding=binding,
            agent_id="agent:web-zap-source-observation-admission",
            task_id=f"task:web-zap-observation:{source.signal_digest[:32]}",
        )
        proposal_key = graph_digest(
            "pajin.workflow.web-zap-source-observation-proposal-id/v1",
            {
                "sourceAuthorityDigest": source.source_authority.authority_digest,
                "sourceRootDigest": source.source_root_digest,
                "snapshotDigest": graph.snapshot.snapshot_digest,
                "observationNodeId": observation.node_id,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        observation_proposal = ObservationProposal(
            proposalId=f"proposal:web-zap-observation:{proposal_key}",
            producerId=policy.producer_id,
            producerVersion=policy.producer_version,
            producerDigest=policy.producer_digest,
            lineage=observation_lineage,
            action=action,
            observation=observation,
            evidenceNodes=[evidence],
            edges=edges,
        )

        hypothesis_proposal: HypothesisProposal | None = None
        if source.registered_surface_signal:
            hypothesis = GraphHypothesis(
                campaignId=graph.snapshot.campaign_id,
                hypothesisType=policy.hypothesis_type,
                statement=_HYPOTHESIS_STATEMENT,
                expectedObservable=_HYPOTHESIS_EXPECTED_OBSERVABLE,
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                origin=GraphContentOrigin.AGENT_DERIVED,
                confidence=0.5,
            )
            hypothesis_edge = GraphEdge(
                campaignId=graph.snapshot.campaign_id,
                relation=GraphRelation.ENABLES,
                source=graph_node_ref(observation),
                target=graph_node_ref(hypothesis),
                authorityId=graph.authority_id,
                authorityDigest=graph.authority_digest,
            )
            hypothesis_lineage = _source_lineage(
                source=source,
                campaign_id=graph.snapshot.campaign_id,
                request_id=request_id,
                request_digest=request_digest,
                binding=binding,
                agent_id="agent:web-zap-source-hypothesis-admission",
                task_id=f"task:web-zap-hypothesis:{source.signal_digest[:32]}",
            )
            hypothesis_key = graph_digest(
                "pajin.workflow.web-zap-source-hypothesis-proposal-id/v1",
                {
                    "observationProposalDigest": observation_proposal.digest(),
                    "hypothesisNodeId": hypothesis.node_id,
                    "signalDigest": source.signal_digest,
                },
                max_bytes=_MAX_CANONICAL_BYTES,
            )
            hypothesis_proposal = HypothesisProposal(
                proposalId=f"proposal:web-zap-hypothesis:{hypothesis_key}",
                producerId=policy.producer_id,
                producerVersion=policy.producer_version,
                producerDigest=policy.producer_digest,
                lineage=hypothesis_lineage,
                hypothesis=hypothesis,
                edges=[hypothesis_edge],
            )
        return WebZAPSourceKnowledgeCandidate(
            policy=policy,
            graph=graph,
            measuredCaseSurface=surface_ref,
            domainGraphTypeSet=source.domain_graph_type_set,
            sourceMeasurement=source.source_authority,
            sourceRunId=source.source_run_id,
            sourceRootDigest=source.source_root_digest,
            sourceAuthorityReference=source.authority_reference,
            sourceAuthoritySha256=source.authority_sha256,
            sourceCount=source.source_count,
            registeredSurfaceSignal=source.registered_surface_signal,
            signalDigest=source.signal_digest,
            observationProposal=observation_proposal,
            hypothesisProposal=hypothesis_proposal,
        )

    def _require_current_graph(self, graph: WebZAPSourceGraphAdmissionBinding) -> None:
        if (
            graph.authority_id != getattr(self._graph_admission, "_authority_id", None)
            or graph.authority_digest != getattr(self._graph_admission, "_authority_digest", None)
            or graph.snapshot.campaign_id != self._graph_store.campaign_id
        ):
            raise WebZAPSourceKnowledgeAdmissionError("WEB-002C Graph Admission authority differs")
        try:
            current = load_verified_current_graph_snapshot(
                self._graph_store.path,
                campaign_id=self._graph_store.campaign_id,
                snapshot_id=graph.snapshot.snapshot_id,
            )
        except Exception as exc:
            raise WebZAPSourceKnowledgeAdmissionError(
                "WEB-002C Graph Snapshot is not the current canonical head"
            ) from exc
        if current is None or graph_snapshot_ref(current) != graph.snapshot:
            raise WebZAPSourceKnowledgeAdmissionError(
                "WEB-002C Graph Snapshot is not the current canonical head"
            )
        projected = next(
            (
                node
                for node in current.projection.nodes
                if node.node_id == graph.graph_surface.node_id
            ),
            None,
        )
        if projected != graph.graph_surface:
            raise WebZAPSourceKnowledgeAdmissionError(
                "WEB-002C measured Surface is absent from the current Graph projection"
            )


def load_verified_web_zap_source_observation(
    inputs: WebZAPSourceObservationInputs,
) -> VerifiedWebZAPSourceObservation:
    """Reopen all WEB-002B seals and derive one public-safe Surface signal."""

    if type(inputs) is not WebZAPSourceObservationInputs:
        raise TypeError("WEB-002C requires exact source observation inputs")
    _require_known_instance_fields(
        (
            inputs.outcome,
            inputs.measured_case,
            inputs.capability_bundle,
            inputs.lifecycle,
            inputs.release,
            inputs.target_adapter,
            inputs.private_ground_truth_profile,
            inputs.scanner_plan,
            inputs.scanner_registration,
            inputs.catalog_provider,
            inputs.measurement_trust_anchor,
            inputs.activation_store,
            inputs.distribution_bundle,
            inputs.distribution_trust_anchor,
        ),
        label="WEB-002C source inputs",
    )
    try:
        source_authority = load_web_zap_source_measurement_authority(
            inputs.outcome,
            measured_case=inputs.measured_case,
            capability_bundle=inputs.capability_bundle,
            lifecycle=inputs.lifecycle,
            release=inputs.release,
            target_adapter=inputs.target_adapter,
            private_ground_truth_profile=inputs.private_ground_truth_profile,
            scanner_plan=inputs.scanner_plan,
            scanner_registration=inputs.scanner_registration,
            journal_path=inputs.journal_path,
            catalog_provider=inputs.catalog_provider,
            measurement_trust_anchor=inputs.measurement_trust_anchor,
            activation_store=inputs.activation_store,
            distribution_bundle=inputs.distribution_bundle,
            distribution_trust_anchor=inputs.distribution_trust_anchor,
        )
        scanner_authority = load_scanner_baseline_measurement_authority(
            inputs.scanner_plan,
            inputs.outcome.scanner_measurement_outcome,
            catalog_provider=inputs.catalog_provider,
            source_outcomes=inputs.outcome.source_outcomes,
            activation_store=inputs.activation_store,
            distribution_trust_anchor=inputs.distribution_trust_anchor,
        )
        snapshot = load_verified_run_artifacts(
            inputs.outcome.run_path,
            requests={inputs.outcome.authority_path: _MAX_SOURCE_AUTHORITY_BYTES},
            expected_run_id=inputs.outcome.run_id,
        )
        authority_bytes = snapshot.artifact_bytes(inputs.outcome.authority_path)
        sealed_source_authority = WebZAPSourceMeasurementAuthority.model_validate_json(
            authority_bytes
        )
        measured_case = WebMeasuredCaseAuthority.model_validate(
            inputs.measured_case.model_dump(mode="json", by_alias=True)
        )
        normalizations = tuple(
            sorted(
                (item.normalization for item in scanner_authority.sources),
                key=lambda item: item.normalization_digest,
            )
        )
        registered_surface_signal = any(
            finding.known_surface
            for normalization in normalizations
            for finding in normalization.findings
        )
        signal_digest = graph_digest(
            "pajin.workflow.web-zap-source-registered-surface-signal/v1",
            {
                "sourceAuthorityDigest": source_authority.authority_digest,
                "normalizationDigests": [item.normalization_digest for item in normalizations],
                "registeredSurfaceSignal": registered_surface_signal,
            },
            max_bytes=_MAX_CANONICAL_BYTES,
        )
    except WebZAPSourceKnowledgeAdmissionError:
        raise
    except Exception as exc:
        raise WebZAPSourceKnowledgeAdmissionError(
            "WEB-002C source verification failed closed"
        ) from exc
    if (
        inputs.outcome.authority_path != "web-zap-source-measurement-authority.json"
        or sealed_source_authority != source_authority
        or authority_bytes != _strict_web_source_authority_bytes(source_authority)
        or source_authority.measured_case != measured_case.reference()
        or source_authority.measurement_run_id != inputs.outcome.scanner_measurement_outcome.run_id
        or source_authority.scanner_measurement_authority_id != scanner_authority.authority_id
        or source_authority.scanner_measurement_authority_digest
        != scanner_authority.authority_digest
        or len(source_authority.lineages) != len(scanner_authority.sources)
        or tuple(event.event_type for event in snapshot.events)
        != (
            "campaign.started",
            "benchmark.web-zap-source-measurement.sealed",
            "campaign.completed",
        )
        or tuple(event.payload for event in snapshot.events)
        != _web_source_event_payloads(source_authority)
        or not all(
            normalization.known_surface_detected
            is any(finding.known_surface for finding in normalization.findings)
            for normalization in normalizations
        )
    ):
        raise WebZAPSourceKnowledgeAdmissionError(
            "WEB-002C source differs from exact sealed WEB-002B authority"
        )
    return VerifiedWebZAPSourceObservation(
        measured_surface=measured_case.surface.reference(),
        domain_graph_type_set=measured_case.surface.domain_graph_type_set,
        source_authority=source_authority.reference(),
        source_run_id=inputs.outcome.run_id,
        source_root_digest=snapshot.verification.root_digest,
        authority_reference=inputs.outcome.authority_path,
        authority_sha256=sha256(authority_bytes).hexdigest(),
        observed_at=snapshot.events[-1].occurred_at,
        source_count=len(scanner_authority.sources),
        registered_surface_signal=registered_surface_signal,
        signal_digest=signal_digest,
    )


def load_web_zap_source_knowledge_admission(
    admission: WebZAPSourceKnowledgeAdmission,
    *,
    inputs: WebZAPSourceObservationInputs,
    graph_store: SQLiteGraphStore,
) -> WebZAPSourceKnowledgeAdmission:
    """Reopen one historical WEB-002C admission without requiring it to be the Graph head."""

    if type(admission) is not WebZAPSourceKnowledgeAdmission:
        raise TypeError("WEB-002C historical reload requires an exact admission")
    if type(graph_store) is not SQLiteGraphStore:
        raise TypeError("WEB-002C historical reload requires the SQLite Graph Store")
    try:
        _require_known_instance_fields(admission, label="WEB-002C historical admission")
        canonical = WebZAPSourceKnowledgeAdmission.model_validate(
            admission.model_dump(mode="json", by_alias=True)
        )
        source = load_verified_web_zap_source_observation(inputs)
        candidate = canonical.candidate
        if (
            graph_store.campaign_id != candidate.graph.snapshot.campaign_id
            or candidate.measured_case != source.measured_surface
            or candidate.domain_graph_type_set != source.domain_graph_type_set
            or candidate.source_measurement != source.source_authority
            or candidate.source_run_id != source.source_run_id
            or candidate.source_root_digest != source.source_root_digest
            or candidate.source_authority_reference != source.authority_reference
            or candidate.source_authority_sha256 != source.authority_sha256
            or candidate.source_count != source.source_count
            or candidate.registered_surface_signal is not source.registered_surface_signal
            or candidate.signal_digest != source.signal_digest
        ):
            raise ValueError("WEB-002C historical admission differs from its sealed source")
        stored_events = graph_store.event_log.events()
        expected_events = (canonical.observation_graph_event,) + (
            (canonical.hypothesis_graph_event,)
            if canonical.hypothesis_graph_event is not None
            else ()
        )
        for expected in expected_events:
            matches = tuple(
                event
                for event in stored_events
                if event.event_id == expected.event_id
                and event.event_digest == expected.event_digest
            )
            if len(matches) != 1 or matches[0] != expected:
                raise ValueError("WEB-002C historical Graph event is absent or differs")
        return canonical.model_copy(deep=True)
    except WebZAPSourceKnowledgeAdmissionError:
        raise
    except Exception as exc:
        raise WebZAPSourceKnowledgeAdmissionError(
            "WEB-002C historical admission failed closed"
        ) from exc


def _strict_web_source_authority_bytes(
    authority: WebZAPSourceMeasurementAuthority,
) -> bytes:
    serialized = json.dumps(
        authority.model_dump(mode="json", by_alias=True),
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return (serialized + "\n").encode("utf-8")


def _web_source_event_payloads(
    authority: WebZAPSourceMeasurementAuthority,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    return (
        {
            "purpose": "web-zap-source-measurement",
            "measuredCaseAuthorityId": authority.measured_case.authority_id,
            "measurementRunId": authority.measurement_run_id,
        },
        {
            "artifact": "web-zap-source-measurement-authority.json",
            "authorityId": authority.authority_id,
            "authorityDigest": authority.authority_digest,
            "measuredCaseAuthorityId": authority.measured_case.authority_id,
            "measuredCaseAuthorityDigest": authority.measured_case.authority_digest,
            "measurementRunId": authority.measurement_run_id,
            "measurementRootDigest": authority.measurement_root_digest,
            "scannerMeasurementAuthorityDigest": (authority.scanner_measurement_authority_digest),
            "baselineResultDigest": authority.baseline_result_digest,
            "sourceCount": len(authority.lineages),
            "measurementState": authority.measurement_state,
            "targetCleanupVerified": authority.target_cleanup_verified,
            "controlledValidationExecuted": authority.controlled_validation_executed,
            "benchmarkValidationFloorSatisfied": (authority.benchmark_validation_floor_satisfied),
            "findingAuthorized": authority.finding_authorized,
            "graphAdmissionAuthorized": authority.graph_admission_authorized,
            "additionalExecutionAuthorized": authority.additional_execution_authorized,
        },
        {
            "purpose": "web-zap-source-measurement",
            "artifact": "web-zap-source-measurement-authority.json",
        },
    )


def _source_lineage(
    *,
    source: VerifiedWebZAPSourceObservation,
    campaign_id: str,
    request_id: str,
    request_digest: str,
    binding: GraphEvidenceBinding,
    agent_id: str,
    task_id: str,
) -> GraphProposalLineage:
    return GraphProposalLineage(
        campaignId=campaign_id,
        runId=source.source_run_id,
        agentId=agent_id,
        taskId=task_id,
        requestId=request_id,
        requestDigest=request_digest,
        sourceAuthorityId=source.source_authority.authority_id,
        sourceAuthorityDigest=source.source_authority.authority_digest,
        sourceRootDigest=source.source_root_digest,
        evidence=[binding],
        producedAt=source.observed_at,
    )


def _require_admitted_event(
    *,
    event: GraphAdmissionEvent,
    proposal: ObservationProposal | HypothesisProposal,
    graph: WebZAPSourceGraphAdmissionBinding,
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
        or event.capability_grant_id is not None
        or event.capability_grant_digest is not None
        or event.capability_id is not None
        or event.capability_version is not None
        or event.capability_digest is not None
        or event.action_permit_id is not None
        or event.action_permit_digest is not None
        or event.source_authority_id != lineage.source_authority_id
        or event.source_authority_digest != lineage.source_authority_digest
        or event.source_root_digest != lineage.source_root_digest
        or event.evidence != lineage.evidence
        or event.produced_at != lineage.produced_at
        or event.admitted_nodes != expected_nodes
        or event.admitted_edges != expected_edges
    ):
        raise ValueError("WEB-002C Graph admission differs from its bounded Proposal")


__all__ = [
    "WEB_ZAP_SOURCE_KNOWLEDGE_ADMISSION_API_VERSION",
    "WEB_ZAP_SOURCE_KNOWLEDGE_CANDIDATE_API_VERSION",
    "WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_DIGEST",
    "WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_ID",
    "WEB_ZAP_SOURCE_KNOWLEDGE_PRODUCER_VERSION",
    "VerifiedWebZAPSourceObservation",
    "WebZAPSourceGraphAdmissionBinding",
    "WebZAPSourceKnowledgeAdmission",
    "WebZAPSourceKnowledgeAdmissionError",
    "WebZAPSourceKnowledgeAdmissionGate",
    "WebZAPSourceKnowledgeAdmissionPolicy",
    "WebZAPSourceKnowledgeCandidate",
    "WebZAPSourceObservationInputs",
    "load_verified_web_zap_source_observation",
    "web_zap_source_knowledge_producer_registration",
]
