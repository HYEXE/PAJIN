"""WEB-001C sealed Web discovery knowledge through the existing Graph writer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.web_discovery import WebReadOnlyDiscoveryPreparation
from pajin.discovery.models import HTTPSurfaceLocator
from pajin.discovery.web_surfaces import WebHTTPOperationSurfaceRef
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.domain_semantics import (
    MultiDomainGraphSemanticsError,
    SecurityDomainGraphTypeSetRef,
    resolve_registered_security_domain_graph_type_set,
)
from pajin.graph.models import GraphNodeKind, GraphRelation, graph_digest
from pajin.workflow.pentest_discovery_admission import (
    PentestReconDiscoveryAdmission,
    PentestReconDiscoveryAdmissionError,
    PentestReconDiscoveryAdmissionGate,
    PentestReconDiscoverySourceInputs,
    PentestReconGraphAdmissionBinding,
    PentestReconObservationCandidate,
)

WEB_DISCOVERY_ADMISSION_API_VERSION: Literal["pajin.dev/web-discovery-admission/v1alpha1"] = (
    "pajin.dev/web-discovery-admission/v1alpha1"
)
WEB_DISCOVERY_OBSERVATION_CANDIDATE_API_VERSION: Literal[
    "pajin.dev/web-discovery-observation-candidate/v1alpha1"
] = "pajin.dev/web-discovery-observation-candidate/v1alpha1"

_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_FALSE_AUTHORITY_FIELDS = (
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "execution_authorized",
    "replay_authorized",
    "finding_confirmation_authorized",
)


class WebDiscoveryAdmissionError(ValueError):
    """Raised when WEB-001C lineage or authority differs from the sealed source."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


@dataclass(frozen=True, slots=True)
class WebDiscoverySourceInputs:
    """Exact WEB-001B preparation and its PENTEST-002A sealed execution source."""

    preparation: WebReadOnlyDiscoveryPreparation
    pentest_source: PentestReconDiscoverySourceInputs


class WebDiscoveryObservationCandidate(_FrozenStrictModel):
    """Content-addressed Web classification of one sealed neutral Observation candidate."""

    api_version: Literal["pajin.dev/web-discovery-observation-candidate/v1alpha1"] = Field(
        default=WEB_DISCOVERY_OBSERVATION_CANDIDATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebDiscoveryObservationCandidate"] = "WebDiscoveryObservationCandidate"
    candidate_id: str = Field(default="", alias="candidateId", max_length=110)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    preparation: WebReadOnlyDiscoveryPreparation
    surface: WebHTTPOperationSurfaceRef
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    domain_observation_type: Literal["web.protocol-observation"] = Field(
        default="web.protocol-observation",
        alias="domainObservationType",
    )
    source_observation_type: Literal["pentest-http-response-observed"] = Field(
        default="pentest-http-response-observed",
        alias="sourceObservationType",
    )
    pentest_candidate: PentestReconObservationCandidate = Field(alias="pentestCandidate")
    state: Literal["sealed-observation-evidence-not-admitted"] = (
        "sealed-observation-evidence-not-admitted"
    )
    sealed_source_verified: Literal[True] = Field(
        default=True,
        alias="sealedSourceVerified",
    )
    observation_produced: Literal[True] = Field(default=True, alias="observationProduced")
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    target_knowledge_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="targetKnowledgeState",
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
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
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

    @field_validator(
        "sealed_source_verified",
        "observation_produced",
        "evidence_sealed",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Web discovery sealed knowledge markers must be boolean true")
        return value

    @field_validator("graph_admitted", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Web discovery candidate authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_candidate_identity(self) -> Self:
        try:
            semantics = resolve_registered_security_domain_graph_type_set(
                self.domain_graph_type_set
            )
        except MultiDomainGraphSemanticsError as exc:
            raise ValueError(
                "Web discovery Domain Graph semantics are not registered exactly"
            ) from exc
        proposal = self.pentest_candidate.proposal
        evidence = {(node.reference, node.sha256) for node in proposal.evidence_nodes}
        expected_evidence = {
            (
                self.pentest_candidate.request_reservation_path,
                self.pentest_candidate.request_reservation_sha256,
            ),
            (
                self.pentest_candidate.execution_evidence_path,
                self.pentest_candidate.execution_evidence_sha256,
            ),
            (
                self.pentest_candidate.outcome_path,
                self.pentest_candidate.outcome_sha256,
            ),
        }
        if (
            self.preparation.surface.reference() != self.surface
            or self.preparation.surface.domain_graph_type_set != self.domain_graph_type_set
            or semantics.domain_classification.domain is not SecurityDomain.WEB
            or semantics.surface_type != self.preparation.surface.surface_type
            or semantics.locator_schema != self.preparation.surface.locator_schema
            or semantics.observation_type != self.domain_observation_type
            or proposal.observation.observation_type != self.source_observation_type
            or proposal.observation.observation_type
            != self.pentest_candidate.policy.observation_type
            or evidence != expected_evidence
            or len(proposal.evidence_nodes) != 3
            or {edge.relation for edge in proposal.edges}
            != {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
        ):
            raise ValueError("Web discovery candidate differs from sealed Web semantics")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.web-discovery-observation-candidate/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        candidate_id = f"web-discovery-observation_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Web discovery candidate Digest differs")
        if self.candidate_id and self.candidate_id != candidate_id:
            raise ValueError("Web discovery candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", candidate_id)
        return self


class WebDiscoveryAdmission(_FrozenStrictModel):
    """Proof that sealed Web knowledge used the existing Graph single writer only."""

    api_version: Literal["pajin.dev/web-discovery-admission/v1alpha1"] = Field(
        default=WEB_DISCOVERY_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebDiscoveryAdmission"] = "WebDiscoveryAdmission"
    admission_id: str = Field(default="", alias="admissionId", max_length=110)
    admission_digest: str = Field(default="", alias="admissionDigest", max_length=64)
    candidate: WebDiscoveryObservationCandidate
    pentest_admission: PentestReconDiscoveryAdmission = Field(alias="pentestAdmission")
    state: Literal["registered-not-authorized"] = "registered-not-authorized"
    sealed_source_verified: Literal[True] = Field(
        default=True,
        alias="sealedSourceVerified",
    )
    observation_produced: Literal[True] = Field(default=True, alias="observationProduced")
    evidence_sealed: Literal[True] = Field(default=True, alias="evidenceSealed")
    graph_admitted: Literal[True] = Field(default=True, alias="graphAdmitted")
    graph_single_writer_reused: Literal[True] = Field(
        default=True,
        alias="graphSingleWriterReused",
    )
    finding_produced: Literal[False] = Field(default=False, alias="findingProduced")
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
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
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

    @field_validator(
        "sealed_source_verified",
        "observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "graph_single_writer_reused",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Web discovery admission markers must be boolean true")
        return value

    @field_validator("finding_produced", *_FALSE_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Web discovery admission authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_admission_identity(self) -> Self:
        event = self.pentest_admission.graph_event
        node_kinds = {node.kind for node in event.admitted_nodes}
        relations = {edge.relation for edge in event.admitted_edges}
        if (
            self.pentest_admission.candidate != self.candidate.pentest_candidate
            or event.proposal_id != self.candidate.pentest_candidate.proposal.proposal_id
            or event.proposal_digest != self.candidate.pentest_candidate.proposal.digest()
            or node_kinds
            != {GraphNodeKind.ACTION, GraphNodeKind.OBSERVATION, GraphNodeKind.EVIDENCE}
            or relations != {GraphRelation.PRODUCES, GraphRelation.SUPPORTED_BY}
            or len(event.admitted_nodes) != 5
            or len(event.admitted_edges) != 4
        ):
            raise ValueError("Web discovery admission exceeds sealed knowledge authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = graph_digest(
            "pajin.workflow.web-discovery-admission/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        admission_id = f"web-discovery-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Web discovery admission Digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Web discovery admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


class WebDiscoveryAdmissionGate:
    """Compose WEB-001B and PENTEST-002A without becoming another Graph writer."""

    def __init__(self, pentest_gate: PentestReconDiscoveryAdmissionGate) -> None:
        if not isinstance(pentest_gate, PentestReconDiscoveryAdmissionGate):
            raise TypeError("Web discovery requires the existing Pentest Graph admission gate")
        self._pentest_gate = pentest_gate

    def prepare_candidate(
        self,
        inputs: WebDiscoverySourceInputs,
        graph: PentestReconGraphAdmissionBinding,
    ) -> WebDiscoveryObservationCandidate:
        """Reverify the sealed source and classify its neutral candidate as Web knowledge."""

        try:
            preparation = _verified_preparation(inputs)
            pentest_candidate = self._pentest_gate.prepare_candidate(
                inputs.pentest_source,
                graph,
            )
            return WebDiscoveryObservationCandidate(
                preparation=preparation,
                surface=preparation.surface.reference(),
                domainGraphTypeSet=preparation.surface.domain_graph_type_set,
                pentestCandidate=pentest_candidate,
            )
        except WebDiscoveryAdmissionError:
            raise
        except Exception as exc:
            raise WebDiscoveryAdmissionError(
                "Web discovery candidate preparation failed closed"
            ) from exc

    def admit(
        self,
        inputs: WebDiscoverySourceInputs,
        candidate: WebDiscoveryObservationCandidate,
    ) -> WebDiscoveryAdmission:
        """Use PENTEST-002A admission and return the exact Web knowledge proof."""

        try:
            preparation = _verified_preparation(inputs)
            canonical = WebDiscoveryObservationCandidate.model_validate(
                candidate.model_dump(mode="json", by_alias=True)
            )
            if canonical.preparation != preparation:
                raise WebDiscoveryAdmissionError(
                    "Web discovery candidate differs from WEB-001B preparation"
                )
            pentest_admission = self._pentest_gate.admit(
                inputs.pentest_source,
                canonical.pentest_candidate,
            )
            return WebDiscoveryAdmission(
                candidate=canonical,
                pentestAdmission=pentest_admission,
            )
        except WebDiscoveryAdmissionError:
            raise
        except PentestReconDiscoveryAdmissionError as exc:
            raise WebDiscoveryAdmissionError("Web discovery Graph admission failed closed") from exc
        except Exception as exc:
            raise WebDiscoveryAdmissionError("Web discovery Graph admission failed closed") from exc


def _verified_preparation(
    inputs: WebDiscoverySourceInputs,
) -> WebReadOnlyDiscoveryPreparation:
    if not isinstance(inputs, WebDiscoverySourceInputs):
        raise TypeError("Web discovery requires exact source inputs")
    if not isinstance(inputs.pentest_source, PentestReconDiscoverySourceInputs):
        raise TypeError("Web discovery requires exact Pentest source inputs")
    try:
        preparation = WebReadOnlyDiscoveryPreparation.model_validate(
            inputs.preparation.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise WebDiscoveryAdmissionError("WEB-001B preparation is not canonical") from exc
    locator = preparation.surface.locator
    intent = inputs.pentest_source.intent
    if (
        not isinstance(locator, HTTPSurfaceLocator)
        or preparation.prepared_action != intent.prepared
        or preparation.release != intent.prepared.release
        or locator.url != intent.prepared.request.target
        or locator.method != "GET"
        or intent.prepared.request.method != "GET"
        or intent.prepared.request.arguments != {}
    ):
        raise WebDiscoveryAdmissionError(
            "WEB-001B preparation differs from sealed Pentest execution intent"
        )
    return preparation


__all__ = [
    "WEB_DISCOVERY_ADMISSION_API_VERSION",
    "WEB_DISCOVERY_OBSERVATION_CANDIDATE_API_VERSION",
    "WebDiscoveryAdmission",
    "WebDiscoveryAdmissionError",
    "WebDiscoveryAdmissionGate",
    "WebDiscoveryObservationCandidate",
    "WebDiscoverySourceInputs",
]
