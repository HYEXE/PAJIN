"""Neutral Canonical Graph proposals for one sealed WEB-003 source Run.

This module consumes only an inert local Campaign draft and caller-pinned,
source-integrity-verified WEB-003 material.  It never accepts a core Campaign,
Capability grant, ActionPermit, approval receipt, or execution receipt.  The
resulting proposals use ``sealed-source-authority`` lineage and remain
unprivileged proposal material: no Graph admission, independent execution,
Finding, SARIF, or delivery authority is asserted.
"""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.graph.models import (
    GraphAction,
    GraphActionStatus,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphEdge,
    GraphEvidence,
    GraphEvidenceBinding,
    GraphHypothesis,
    GraphObservation,
    GraphProposalLineage,
    GraphRelation,
    HypothesisProposal,
    ObservationProposal,
    graph_digest,
    graph_node_ref,
)
from pajin.runtime.store import load_verified_run_artifacts
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignDraft,
    LocalWebAssessmentRunReference,
    build_local_web_assessment_campaign_draft,
    local_web_assessment_run_reference,
)
from pajin.web_assessment.semantic import (
    ValidatedLocalWebSemanticClaims,
    ValidatedWebIssueClaim,
    validate_local_web_assessment_semantics,
)
from pajin.web_assessment.verification import (
    VerifiedLocalWebAssessmentSourceIntegrity,
    load_verified_local_web_assessment_source_integrity,
)

LOCAL_WEB_SEALED_SOURCE_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/local-web-sealed-source-authority/v1alpha1"
] = "pajin.dev/local-web-sealed-source-authority/v1alpha1"
LOCAL_WEB_NEUTRAL_GRAPH_PROJECTION_API_VERSION: Literal[
    "pajin.dev/local-web-neutral-graph-projection/v1alpha1"
] = "pajin.dev/local-web-neutral-graph-projection/v1alpha1"

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_MAX_CANONICAL_BYTES = 2 * 1024 * 1024
_CORE_EVIDENCE_LIMITS = {
    "authorization.json": 256 * 1024,
    "plan.json": 1 * 1024 * 1024,
    "provisioning-receipt.json": 1 * 1024 * 1024,
    "report.md": 16 * 1024 * 1024,
    "result.json": 16 * 1024 * 1024,
}
_SCREENSHOT_LIMIT = 10_000_000
_SOURCE_TOOL_ID: Literal["pajin.web-assessment.local-source-observation"] = (
    "pajin.web-assessment.local-source-observation"
)
_PRODUCER_ID = "pajin.web-assessment.neutral-graph-projection"
_PRODUCER_VERSION = "1.0.0"
_PRODUCER_DIGEST = graph_digest(
    "pajin.web-assessment.neutral-graph-projection-producer/v2",
    {
        "producerId": _PRODUCER_ID,
        "producerVersion": _PRODUCER_VERSION,
        "semantics": "neutral-sealed-source-observation-only",
        "authorityKind": GraphAuthorityKind.SEALED_SOURCE_AUTHORITY.value,
        "independentExecutionAttested": False,
        "findingAuthority": False,
        "sarifAuthority": False,
        "graphAdmissionPerformed": False,
    },
    max_bytes=_MAX_CANONICAL_BYTES,
)


class LocalWebNeutralGraphProjectionError(ValueError):
    """Raised when draft, source authority, source content, or pins differ."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class LocalWebSealedSourceAuthority(_FrozenStrictModel):
    """Content address for sealed source material, never execution authority."""

    api_version: Literal["pajin.dev/local-web-sealed-source-authority/v1alpha1"] = Field(
        default=LOCAL_WEB_SEALED_SOURCE_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LocalWebSealedSourceAuthority"] = "LocalWebSealedSourceAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=90)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    graph_campaign_id: str = Field(
        alias="graphCampaignId",
        pattern=r"^local-web-[a-f0-9]{64}$",
    )
    campaign_draft_id: str = Field(alias="campaignDraftId", min_length=1, max_length=100)
    campaign_draft_digest: str = Field(
        alias="campaignDraftDigest",
        pattern=_SHA256_PATTERN,
    )
    run_role: Literal["source", "validation"] = Field(alias="runRole")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    run_reference_digest: str = Field(
        alias="runReferenceDigest",
        pattern=_SHA256_PATTERN,
    )
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_SHA256_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_SHA256_PATTERN)
    source_plan_digest: str = Field(alias="sourcePlanDigest", pattern=_SHA256_PATTERN)
    authorization_id: str = Field(alias="authorizationId", min_length=1, max_length=110)
    semantic_claims_digest: str = Field(
        alias="semanticClaimsDigest",
        pattern=_SHA256_PATTERN,
    )
    request_id: str = Field(
        alias="requestId",
        pattern=r"^local-web-source-[a-f0-9]{32}$",
    )
    request_digest: str = Field(alias="requestDigest", pattern=_SHA256_PATTERN)
    target_digest: str = Field(alias="targetDigest", pattern=_SHA256_PATTERN)
    tool_id: Literal["pajin.web-assessment.local-source-observation"] = Field(
        default=_SOURCE_TOOL_ID,
        alias="toolId",
    )
    source_integrity_verified: Literal[True] = Field(
        default=True,
        alias="sourceIntegrityVerified",
    )
    source_identity_pin_independently_supplied: bool = Field(
        alias="sourceIdentityPinIndependentlySupplied",
        strict=True,
    )
    independent_execution_attested: Literal[False] = Field(
        default=False,
        alias="independentExecutionAttested",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    sarif_authority: Literal[False] = Field(default=False, alias="sarifAuthority")
    graph_admission_performed: Literal[False] = Field(
        default=False,
        alias="graphAdmissionPerformed",
    )

    @field_validator("source_integrity_verified", mode="before")
    @classmethod
    def require_source_integrity(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("sealed source authority requires verified source integrity")
        return value

    @field_validator(
        "independent_execution_attested",
        "finding_authority",
        "sarif_authority",
        "graph_admission_performed",
        mode="before",
    )
    @classmethod
    def prohibit_authority_upgrade(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("sealed source authority cannot claim downstream authority")
        return value

    @model_validator(mode="after")
    def bind_source_identity(self) -> Self:
        request_material = {
            "campaignDraftDigest": self.campaign_draft_digest,
            "runRole": self.run_role,
            "runId": self.run_id,
            "runReferenceDigest": self.run_reference_digest,
            "sourceRootDigest": self.source_root_digest,
            "resultDigest": self.result_digest,
            "sourcePlanDigest": self.source_plan_digest,
            "authorizationId": self.authorization_id,
            "semanticClaimsDigest": self.semantic_claims_digest,
            "toolId": self.tool_id,
            "targetDigest": self.target_digest,
        }
        expected_campaign_id = f"local-web-{self.campaign_draft_digest}"
        expected_request_digest = graph_digest(
            "pajin.web-assessment.sealed-source-request/v1",
            request_material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        expected_request_id = f"local-web-source-{expected_request_digest[:32]}"
        if (
            self.graph_campaign_id != expected_campaign_id
            or self.request_digest != expected_request_digest
            or self.request_id != expected_request_id
        ):
            raise ValueError("sealed source request identity differs from its content pins")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        expected_digest = graph_digest(
            "pajin.web-assessment.sealed-source-authority/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        expected_id = f"sealed-source:{expected_digest}"
        if self.authority_digest and self.authority_digest != expected_digest:
            raise ValueError("sealed source authority digest differs")
        if self.authority_id and self.authority_id != expected_id:
            raise ValueError("sealed source authority ID differs")
        object.__setattr__(self, "authority_digest", expected_digest)
        object.__setattr__(self, "authority_id", expected_id)
        return self


class LocalWebNeutralGraphProjection(_FrozenStrictModel):
    """Pure proposal material with explicit non-authority markers."""

    api_version: Literal["pajin.dev/local-web-neutral-graph-projection/v1alpha1"] = Field(
        default=LOCAL_WEB_NEUTRAL_GRAPH_PROJECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LocalWebNeutralGraphProjection"] = "LocalWebNeutralGraphProjection"
    projection_digest: str = Field(default="", alias="projectionDigest", max_length=64)
    source_authority: LocalWebSealedSourceAuthority = Field(alias="sourceAuthority")
    observation_proposal: ObservationProposal = Field(alias="observationProposal")
    hypothesis_proposals: tuple[
        HypothesisProposal,
        HypothesisProposal,
        HypothesisProposal,
    ] = Field(alias="hypothesisProposals")
    semantics: Literal["neutral-sealed-source-observation-only"] = (
        "neutral-sealed-source-observation-only"
    )
    independent_execution_attested: Literal[False] = Field(
        default=False,
        alias="independentExecutionAttested",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    sarif_authority: Literal[False] = Field(default=False, alias="sarifAuthority")
    graph_admission_performed: Literal[False] = Field(
        default=False,
        alias="graphAdmissionPerformed",
    )

    @field_validator(
        "independent_execution_attested",
        "finding_authority",
        "sarif_authority",
        "graph_admission_performed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("neutral local web Graph projection authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_projection(self) -> Self:
        authority = self.source_authority
        observation = self.observation_proposal
        lineage = observation.lineage
        action = observation.action
        if (
            lineage.campaign_id != authority.graph_campaign_id
            or lineage.run_id != authority.run_id
            or lineage.request_id != authority.request_id
            or lineage.request_digest != authority.request_digest
            or lineage.source_authority_id != authority.authority_id
            or lineage.source_authority_digest != authority.authority_digest
            or lineage.source_root_digest != authority.source_root_digest
            or lineage.capability_grant_id is not None
            or lineage.action_permit_id is not None
            or lineage.capability_id is not None
            or action.request_id != authority.request_id
            or action.request_digest != authority.request_digest
            or action.authority_kind is not GraphAuthorityKind.SEALED_SOURCE_AUTHORITY
            or action.authority_id != authority.authority_id
            or action.authority_digest != authority.authority_digest
            or action.capability_id is not None
            or action.capability_version is not None
            or action.capability_digest is not None
            or action.tool_id != authority.tool_id
            or action.target_digest != authority.target_digest
        ):
            raise ValueError("neutral observation Proposal differs from sealed source authority")
        hypothesis_ids: list[str] = []
        for proposal in self.hypothesis_proposals:
            hypothesis_ids.append(proposal.hypothesis.node_id)
            hypothesis_lineage = proposal.lineage
            if (
                hypothesis_lineage.campaign_id != authority.graph_campaign_id
                or hypothesis_lineage.run_id != authority.run_id
                or hypothesis_lineage.request_id != authority.request_id
                or hypothesis_lineage.request_digest != authority.request_digest
                or hypothesis_lineage.source_authority_id != authority.authority_id
                or hypothesis_lineage.source_authority_digest != authority.authority_digest
                or hypothesis_lineage.source_root_digest != authority.source_root_digest
                or hypothesis_lineage.capability_grant_id is not None
                or hypothesis_lineage.action_permit_id is not None
                or hypothesis_lineage.capability_id is not None
                or hypothesis_lineage.evidence != lineage.evidence
                or len(proposal.edges) != 1
                or proposal.edges[0].relation is not GraphRelation.ENABLES
                or proposal.edges[0].source.node_id != observation.observation.node_id
            ):
                raise ValueError("neutral Hypothesis Proposal differs from sealed source authority")
        if hypothesis_ids != sorted(set(hypothesis_ids)):
            raise ValueError("neutral Hypothesis Proposals must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"projection_digest"},
        )
        expected = graph_digest(
            "pajin.web-assessment.neutral-graph-projection/v2",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.projection_digest and self.projection_digest != expected:
            raise ValueError("local web neutral Graph projection digest differs")
        object.__setattr__(self, "projection_digest", expected)
        return self


def build_local_web_sealed_source_authority(
    *,
    draft: LocalWebAssessmentCampaignDraft,
    run_reference: LocalWebAssessmentRunReference,
    source: VerifiedLocalWebAssessmentSourceIntegrity,
    source_identity_pin_independently_supplied: bool,
) -> LocalWebSealedSourceAuthority:
    """Bind exact source content without interpreting it as execution authority."""

    canonical_draft, canonical_reference, verified_source = _canonical_inputs(
        draft=draft,
        run_reference=run_reference,
        source=source,
    )
    if type(source_identity_pin_independently_supplied) is not bool:
        raise LocalWebNeutralGraphProjectionError(
            "source identity pin disclosure must be an exact boolean"
        )
    target_digest = sha256(canonical_draft.origin.encode("utf-8")).hexdigest()
    request_material = {
        "campaignDraftDigest": canonical_draft.draft_digest,
        "runRole": canonical_reference.role,
        "runId": canonical_reference.run_id,
        "runReferenceDigest": canonical_reference.reference_digest,
        "sourceRootDigest": verified_source.verification.root_digest,
        "resultDigest": verified_source.result.result_digest,
        "sourcePlanDigest": verified_source.plan.plan_digest,
        "authorizationId": verified_source.authorization.authorization_id,
        "semanticClaimsDigest": canonical_reference.semantic_claims.claims_digest,
        "toolId": _SOURCE_TOOL_ID,
        "targetDigest": target_digest,
    }
    request_digest = graph_digest(
        "pajin.web-assessment.sealed-source-request/v1",
        request_material,
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    return LocalWebSealedSourceAuthority(
        graphCampaignId=f"local-web-{canonical_draft.draft_digest}",
        campaignDraftId=canonical_draft.draft_id,
        campaignDraftDigest=canonical_draft.draft_digest,
        runRole=canonical_reference.role,
        runId=canonical_reference.run_id,
        runReferenceDigest=canonical_reference.reference_digest,
        sourceRootDigest=verified_source.verification.root_digest,
        resultDigest=verified_source.result.result_digest,
        sourcePlanDigest=verified_source.plan.plan_digest,
        authorizationId=verified_source.authorization.authorization_id,
        semanticClaimsDigest=canonical_reference.semantic_claims.claims_digest,
        requestId=f"local-web-source-{request_digest[:32]}",
        requestDigest=request_digest,
        targetDigest=target_digest,
        sourceIdentityPinIndependentlySupplied=source_identity_pin_independently_supplied,
    )


def build_local_web_neutral_graph_projection(
    *,
    source_authority: LocalWebSealedSourceAuthority,
    draft: LocalWebAssessmentCampaignDraft,
    run_reference: LocalWebAssessmentRunReference,
    source: VerifiedLocalWebAssessmentSourceIntegrity,
) -> LocalWebNeutralGraphProjection:
    """Build unprivileged proposals after exact sealed-source re-verification."""

    try:
        canonical_authority = _canonical_source_authority(source_authority)
        canonical_draft, canonical_reference, verified_source = _canonical_inputs(
            draft=draft,
            run_reference=run_reference,
            source=source,
        )
        expected_authority = build_local_web_sealed_source_authority(
            draft=canonical_draft,
            run_reference=canonical_reference,
            source=verified_source,
            source_identity_pin_independently_supplied=(
                canonical_authority.source_identity_pin_independently_supplied
            ),
        )
        if canonical_authority != expected_authority:
            raise LocalWebNeutralGraphProjectionError(
                "sealed source authority differs from the exact draft or source Run"
            )
        evidence = _load_evidence_bindings(verified_source)
        return _build_projection(
            authority=canonical_authority,
            source=verified_source,
            semantics=canonical_reference.semantic_claims,
            evidence_bindings=evidence,
        )
    except LocalWebNeutralGraphProjectionError:
        raise
    except Exception as exc:
        raise LocalWebNeutralGraphProjectionError(
            "local web neutral Graph projection failed closed"
        ) from exc


def _canonical_inputs(
    *,
    draft: LocalWebAssessmentCampaignDraft,
    run_reference: LocalWebAssessmentRunReference,
    source: VerifiedLocalWebAssessmentSourceIntegrity,
) -> tuple[
    LocalWebAssessmentCampaignDraft,
    LocalWebAssessmentRunReference,
    VerifiedLocalWebAssessmentSourceIntegrity,
]:
    canonical_draft = _canonical_draft(draft)
    canonical_reference = _canonical_run_reference(run_reference)
    verified_source = _reload_exact_source(source)
    expected_draft = build_local_web_assessment_campaign_draft(
        verified_source.plan,
        verified_source.authorization,
        evaluated_at=canonical_draft.evaluated_at,
    )
    expected_reference = local_web_assessment_run_reference(
        role=canonical_reference.role,
        verified_source=verified_source,
    )
    expected_semantics = validate_local_web_assessment_semantics(verified_source.result)
    if canonical_draft != expected_draft:
        raise LocalWebNeutralGraphProjectionError(
            "local web Campaign draft differs from the sealed source plan or assertion"
        )
    if canonical_reference != expected_reference:
        raise LocalWebNeutralGraphProjectionError(
            "local web Run reference differs from the re-verified source Run"
        )
    if canonical_reference.semantic_claims != expected_semantics:
        raise LocalWebNeutralGraphProjectionError(
            "local web semantic claims differ from the re-verified source Run"
        )
    return canonical_draft, canonical_reference, verified_source


def _canonical_draft(
    draft: LocalWebAssessmentCampaignDraft,
) -> LocalWebAssessmentCampaignDraft:
    if type(draft) is not LocalWebAssessmentCampaignDraft:
        raise LocalWebNeutralGraphProjectionError(
            "local web Graph projection requires an exact inert Campaign draft"
        )
    try:
        return LocalWebAssessmentCampaignDraft.model_validate(
            draft.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise LocalWebNeutralGraphProjectionError(
            "local web Campaign draft is not canonical"
        ) from exc


def _canonical_run_reference(
    run_reference: LocalWebAssessmentRunReference,
) -> LocalWebAssessmentRunReference:
    if type(run_reference) is not LocalWebAssessmentRunReference:
        raise LocalWebNeutralGraphProjectionError(
            "local web Graph projection requires an exact Run reference"
        )
    try:
        return LocalWebAssessmentRunReference.model_validate(
            run_reference.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise LocalWebNeutralGraphProjectionError(
            "local web Run reference is not canonical"
        ) from exc


def _canonical_source_authority(
    authority: LocalWebSealedSourceAuthority,
) -> LocalWebSealedSourceAuthority:
    if type(authority) is not LocalWebSealedSourceAuthority:
        raise LocalWebNeutralGraphProjectionError(
            "local web Graph projection requires exact sealed source authority"
        )
    try:
        return LocalWebSealedSourceAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise LocalWebNeutralGraphProjectionError(
            "local web sealed source authority is not canonical"
        ) from exc


def _reload_exact_source(
    source: VerifiedLocalWebAssessmentSourceIntegrity,
) -> VerifiedLocalWebAssessmentSourceIntegrity:
    if type(source) is not VerifiedLocalWebAssessmentSourceIntegrity:
        raise LocalWebNeutralGraphProjectionError(
            "local web Graph projection requires exact source-integrity material"
        )
    if (
        source.semantics != "source-integrity-only"
        or source.independent_replay_verified is not False
        or source.finding_authority is not False
        or source.verification.valid is not True
    ):
        raise LocalWebNeutralGraphProjectionError(
            "local web source attempts to elevate integrity into validation authority"
        )
    try:
        verified = load_verified_local_web_assessment_source_integrity(
            source.run_path,
            expected_run_id=source.verification.run_id,
            expected_root_digest=source.verification.root_digest,
        )
    except Exception as exc:
        raise LocalWebNeutralGraphProjectionError(
            "local web source Run no longer passes pinned integrity verification"
        ) from exc
    if verified != source:
        raise LocalWebNeutralGraphProjectionError(
            "local web source-integrity object differs from the pinned Run"
        )
    return verified


def _load_evidence_bindings(
    source: VerifiedLocalWebAssessmentSourceIntegrity,
) -> list[GraphEvidenceBinding]:
    requests = {
        **_CORE_EVIDENCE_LIMITS,
        **{reference: _SCREENSHOT_LIMIT for reference in source.screenshot_references},
    }
    try:
        snapshot = load_verified_run_artifacts(
            source.run_path,
            requests=requests,
            expected_run_id=source.verification.run_id,
        )
    except Exception as exc:
        raise LocalWebNeutralGraphProjectionError(
            "local web Graph Evidence could not be read from the pinned Run"
        ) from exc
    if snapshot.verification != source.verification:
        raise LocalWebNeutralGraphProjectionError(
            "local web Graph Evidence belongs to another source root"
        )
    if snapshot.artifact_bytes("report.md") != source.report_markdown.encode("utf-8"):
        raise LocalWebNeutralGraphProjectionError(
            "local web Graph report Evidence differs from the verified source"
        )
    return sorted(
        (
            GraphEvidenceBinding(
                reference=reference,
                sha256=sha256(snapshot.artifact_bytes(reference)).hexdigest(),
            )
            for reference in requests
        ),
        key=lambda item: (item.reference, item.sha256),
    )


def _lineage(
    *,
    authority: LocalWebSealedSourceAuthority,
    evidence: list[GraphEvidenceBinding],
    task_id: str,
    produced_at: datetime,
) -> GraphProposalLineage:
    return GraphProposalLineage(
        campaignId=authority.graph_campaign_id,
        runId=authority.run_id,
        agentId="agent:web-neutral-graph-projection",
        taskId=task_id,
        requestId=authority.request_id,
        requestDigest=authority.request_digest,
        sourceAuthorityId=authority.authority_id,
        sourceAuthorityDigest=authority.authority_digest,
        sourceRootDigest=authority.source_root_digest,
        evidence=evidence,
        producedAt=produced_at,
    )


def _build_projection(
    *,
    authority: LocalWebSealedSourceAuthority,
    source: VerifiedLocalWebAssessmentSourceIntegrity,
    semantics: ValidatedLocalWebSemanticClaims,
    evidence_bindings: list[GraphEvidenceBinding],
) -> LocalWebNeutralGraphProjection:
    result = source.result
    observation_value_digest = graph_digest(
        "pajin.web-assessment.neutral-observation-value/v2",
        {
            "sourceAuthorityDigest": authority.authority_digest,
            "claimDigests": [claim.claim_digest for claim in semantics.claims],
            "claimStatuses": [claim.status for claim in semantics.claims],
            "sourceIntegrityOnly": True,
            "independentExecutionAttested": False,
            "findingAuthority": False,
            "sarifAuthority": False,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    action = GraphAction(
        campaignId=authority.graph_campaign_id,
        requestId=authority.request_id,
        requestDigest=authority.request_digest,
        authorityKind=GraphAuthorityKind.SEALED_SOURCE_AUTHORITY,
        authorityId=authority.authority_id,
        authorityDigest=authority.authority_digest,
        toolId=authority.tool_id,
        targetDigest=authority.target_digest,
        status=GraphActionStatus.SUCCEEDED,
        executedAt=result.started_at,
    )
    observation = GraphObservation(
        campaignId=authority.graph_campaign_id,
        observationType="local-web-sealed-source-semantic-observation",
        summary=(
            "One sealed local browser Run produced source-integrity-checked, code-owned "
            "semantic material; no independent execution or Finding authority is asserted."
        ),
        valueDigest=observation_value_digest,
        producerId=_PRODUCER_ID,
        producerVersion=_PRODUCER_VERSION,
        producerDigest=_PRODUCER_DIGEST,
        origin=GraphContentOrigin.TARGET_DERIVED,
        confidence=0.5,
        observedAt=result.finished_at,
    )
    evidence_nodes = sorted(
        (
            GraphEvidence(
                campaignId=authority.graph_campaign_id,
                reference=item.reference,
                sha256=item.sha256,
                sourceRootDigest=authority.source_root_digest,
                dataClassification="internal",
            )
            for item in evidence_bindings
        ),
        key=lambda item: item.node_id,
    )
    edges = [
        GraphEdge(
            campaignId=authority.graph_campaign_id,
            relation=GraphRelation.PRODUCES,
            source=graph_node_ref(action),
            target=graph_node_ref(observation),
            authorityId=_PRODUCER_ID,
            authorityDigest=_PRODUCER_DIGEST,
        ),
        *(
            GraphEdge(
                campaignId=authority.graph_campaign_id,
                relation=GraphRelation.SUPPORTED_BY,
                source=graph_node_ref(observation),
                target=graph_node_ref(evidence),
                authorityId=_PRODUCER_ID,
                authorityDigest=_PRODUCER_DIGEST,
            )
            for evidence in evidence_nodes
        ),
    ]
    observation_proposal = ObservationProposal(
        proposalId=(
            "proposal:web-local-neutral-observation:"
            + graph_digest(
                "pajin.web-assessment.neutral-observation-proposal-id/v2",
                {
                    "sourceAuthorityDigest": authority.authority_digest,
                    "observationNodeId": observation.node_id,
                },
                max_bytes=_MAX_CANONICAL_BYTES,
            )
        ),
        producerId=_PRODUCER_ID,
        producerVersion=_PRODUCER_VERSION,
        producerDigest=_PRODUCER_DIGEST,
        lineage=_lineage(
            authority=authority,
            evidence=evidence_bindings,
            task_id=f"task:web-neutral-observation:{semantics.claims_digest[:32]}",
            produced_at=result.finished_at,
        ),
        action=action,
        observation=observation,
        evidenceNodes=evidence_nodes,
        edges=sorted(edges, key=lambda item: item.edge_id),
    )
    hypotheses = sorted(
        (
            _hypothesis_proposal(
                authority=authority,
                observation=observation,
                observation_proposal=observation_proposal,
                evidence=evidence_bindings,
                claim=claim,
                produced_at=result.finished_at,
            )
            for claim in semantics.claims
        ),
        key=lambda item: item.hypothesis.node_id,
    )
    return LocalWebNeutralGraphProjection(
        sourceAuthority=authority,
        observationProposal=observation_proposal,
        hypothesisProposals=(hypotheses[0], hypotheses[1], hypotheses[2]),
    )


def _hypothesis_proposal(
    *,
    authority: LocalWebSealedSourceAuthority,
    observation: GraphObservation,
    observation_proposal: ObservationProposal,
    evidence: list[GraphEvidenceBinding],
    claim: ValidatedWebIssueClaim,
    produced_at: datetime,
) -> HypothesisProposal:
    hypothesis = GraphHypothesis(
        campaignId=authority.graph_campaign_id,
        hypothesisType="local-web-independent-validation-required",
        statement=(
            f"The {claim.check} local outcome requires separately authorized independent "
            "execution before any Finding decision."
        ),
        expectedObservable=(
            "A separately authorized execution and distinct sealed source root produce typed "
            "facts that can be reconciled without promoting either Run to a Finding."
        ),
        producerId=_PRODUCER_ID,
        producerVersion=_PRODUCER_VERSION,
        producerDigest=_PRODUCER_DIGEST,
        origin=GraphContentOrigin.AGENT_DERIVED,
        confidence=0.25,
    )
    edge = GraphEdge(
        campaignId=authority.graph_campaign_id,
        relation=GraphRelation.ENABLES,
        source=graph_node_ref(observation),
        target=graph_node_ref(hypothesis),
        authorityId=_PRODUCER_ID,
        authorityDigest=_PRODUCER_DIGEST,
    )
    proposal_key = graph_digest(
        "pajin.web-assessment.neutral-hypothesis-proposal-id/v2",
        {
            "sourceAuthorityDigest": authority.authority_digest,
            "observationProposalDigest": observation_proposal.digest(),
            "claimDigest": claim.claim_digest,
            "hypothesisNodeId": hypothesis.node_id,
        },
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    return HypothesisProposal(
        proposalId=f"proposal:web-local-neutral-hypothesis:{proposal_key}",
        producerId=_PRODUCER_ID,
        producerVersion=_PRODUCER_VERSION,
        producerDigest=_PRODUCER_DIGEST,
        lineage=_lineage(
            authority=authority,
            evidence=evidence,
            task_id=f"task:web-neutral-hypothesis:{claim.claim_digest[:32]}",
            produced_at=produced_at,
        ),
        hypothesis=hypothesis,
        edges=[edge],
    )


__all__ = [
    "LOCAL_WEB_NEUTRAL_GRAPH_PROJECTION_API_VERSION",
    "LOCAL_WEB_SEALED_SOURCE_AUTHORITY_API_VERSION",
    "LocalWebNeutralGraphProjection",
    "LocalWebNeutralGraphProjectionError",
    "LocalWebSealedSourceAuthority",
    "build_local_web_neutral_graph_projection",
    "build_local_web_sealed_source_authority",
]
