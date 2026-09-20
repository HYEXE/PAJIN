"""Content-addressed receipts for the Skill-bound WEB-007 successor."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.providers.receipts import ProviderBoundChatOutcome
from pajin.runtime.store import RunIntegrityVerification
from pajin.web_assessment.analysis_runtime import WebAnalysisProviderExecutionContext
from pajin.web_assessment.analysis_skill_invocation import (
    CompiledSkillBoundWebAnalysisProposal,
    SkillBoundWebAnalysisProposalDraft,
    SkillBoundWebAnalysisProviderExecutionContext,
    SkillBoundWebAnalysisRequestEnvelope,
)
from pajin.web_assessment.analysis_skill_projection import (
    SkillBoundWebAnalysisSnapshot,
    SkillRegistryRef,
    canonical_skill_contract,
)
from pajin.web_assessment.analysis_transport import WebAnalysisTransportRuntimePin

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_MAX_RAW_DRAFT_BYTES = 256 * 1024
_MAX_RECEIPT_BYTES = 16 * 1024 * 1024


class _AliasWireModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
        validate_default=True,
    )


class SkillBoundWebAnalysisInvocationReceipt(_AliasWireModel):
    """Successful one-shot Provider response bound to non-authoritative Skill output."""

    api_version: Literal["pajin.dev/skill-bound-web-analysis-invocation-receipt/v1alpha1"] = Field(
        default="pajin.dev/skill-bound-web-analysis-invocation-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["SkillBoundWebAnalysisInvocationReceipt"] = (
        "SkillBoundWebAnalysisInvocationReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    analysis_run_id: str = Field(alias="analysisRunId", pattern=_RUN_ID_PATTERN)
    request_envelope: SkillBoundWebAnalysisRequestEnvelope = Field(alias="requestEnvelope")
    skill_projection_run_id: str = Field(
        alias="skillProjectionRunId",
        pattern=_RUN_ID_PATTERN,
    )
    skill_projection_root_digest: _Sha256 = Field(alias="skillProjectionRootDigest")
    skill_bound_snapshot_digest: _Sha256 = Field(alias="skillBoundSnapshotDigest")
    projection_bundle_digest: _Sha256 = Field(alias="projectionBundleDigest")
    instruction_projection_digest: _Sha256 = Field(alias="instructionProjectionDigest")
    evidence_projection_digest: _Sha256 = Field(alias="evidenceProjectionDigest")
    registry: SkillRegistryRef
    selection_policy_digest: _Sha256 = Field(alias="selectionPolicyDigest")
    transport_pin: WebAnalysisTransportRuntimePin = Field(alias="transportPin")
    provider_outcome: ProviderBoundChatOutcome = Field(alias="providerOutcome")
    base_provider_execution_context: WebAnalysisProviderExecutionContext = Field(
        alias="baseProviderExecutionContext"
    )
    successor_provider_execution_context: SkillBoundWebAnalysisProviderExecutionContext = Field(
        alias="successorProviderExecutionContext"
    )
    provider_run_id: str = Field(alias="providerRunId", pattern=_RUN_ID_PATTERN)
    provider_root_digest: _Sha256 = Field(alias="providerRootDigest")
    provider_run_seal_count: Literal[1] = Field(default=1, alias="providerRunSealCount")
    raw_draft_sha256: _Sha256 = Field(alias="rawDraftSha256")
    raw_draft_bytes: int = Field(
        alias="rawDraftBytes",
        strict=True,
        ge=1,
        le=_MAX_RAW_DRAFT_BYTES,
    )
    draft_digest: _Sha256 = Field(alias="draftDigest")
    compiled_proposal: CompiledSkillBoundWebAnalysisProposal = Field(alias="compiledProposal")
    dispatch_count: Literal[1] = Field(default=1, alias="dispatchCount")
    target_request_count: Literal[0] = Field(default=0, alias="targetRequestCount")
    response_state: Literal["skill-bound-draft-compiled-not-admitted"] = Field(
        default="skill-bound-draft-compiled-not-admitted",
        alias="responseState",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    task_creation_authorized: Literal[False] = Field(
        default=False,
        alias="taskCreationAuthorized",
    )
    plan_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="planMutationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    tool_request_authorized: Literal[False] = Field(
        default=False,
        alias="toolRequestAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_authorized: Literal[False] = Field(default=False, alias="findingAuthorized")
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    activation_authorized: Literal[False] = Field(
        default=False,
        alias="activationAuthorized",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )

    @field_validator(
        "provider_run_seal_count",
        "raw_draft_bytes",
        "dispatch_count",
        "target_request_count",
        mode="before",
    )
    @classmethod
    def require_literal_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Skill-bound Web analysis receipt counts must be JSON integers")
        return value

    @field_validator(
        "automatic_redispatch_authorized",
        "task_creation_authorized",
        "plan_mutation_authorized",
        "scope_expansion_authorized",
        "tool_request_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "graph_admission_authorized",
        "finding_authorized",
        "report_delivery_authorized",
        "activation_authorized",
        "external_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_false_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        request = canonical_skill_contract(
            self.request_envelope,
            SkillBoundWebAnalysisRequestEnvelope,
        )
        registry = canonical_skill_contract(self.registry, SkillRegistryRef)
        transport = canonical_skill_contract(
            self.transport_pin,
            WebAnalysisTransportRuntimePin,
        )
        outcome = canonical_skill_contract(self.provider_outcome, ProviderBoundChatOutcome)
        base_context = canonical_skill_contract(
            self.base_provider_execution_context,
            WebAnalysisProviderExecutionContext,
        )
        successor_context = canonical_skill_contract(
            self.successor_provider_execution_context,
            SkillBoundWebAnalysisProviderExecutionContext,
        )
        proposal = canonical_skill_contract(
            self.compiled_proposal,
            CompiledSkillBoundWebAnalysisProposal,
        )
        _require_common_lineage(
            request=request,
            skill_projection_run_id=self.skill_projection_run_id,
            skill_projection_root_digest=self.skill_projection_root_digest,
            skill_bound_snapshot_digest=self.skill_bound_snapshot_digest,
            projection_bundle_digest=self.projection_bundle_digest,
            instruction_projection_digest=self.instruction_projection_digest,
            evidence_projection_digest=self.evidence_projection_digest,
            transport=transport,
            outcome=outcome,
            base_context=base_context,
            successor_context=successor_context,
        )
        if (
            proposal.skill_projection_run_id != self.skill_projection_run_id
            or proposal.skill_projection_root_digest != self.skill_projection_root_digest
            or proposal.skill_bound_snapshot_digest != self.skill_bound_snapshot_digest
            or proposal.projection_bundle_digest != self.projection_bundle_digest
            or proposal.instruction_projection_digest != self.instruction_projection_digest
            or proposal.evidence_projection_digest != self.evidence_projection_digest
            or proposal.registry != registry
            or proposal.selection_policy_digest != self.selection_policy_digest
            or proposal.transport_pin_digest != transport.pin_digest
            or outcome.content_digest is None
            or outcome.content_bytes != self.raw_draft_bytes
            or outcome.refusal_digest is not None
            or outcome.tool_call_count != 0
            or outcome.streamed is not False
            or outcome.chunks != 1
        ):
            raise ValueError("Skill-bound Web analysis success receipt lineage differs")
        self._bind_content_address()
        return self

    def _bind_content_address(self) -> None:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = _receipt_digest(
            "pajin.web-analysis.skill-bound-invocation-receipt/v1",
            material,
        )
        receipt_id = f"skill-bound-web-analysis-invocation:{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Skill-bound Web analysis receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Skill-bound Web analysis receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)


class SkillBoundWebAnalysisInvocationFailureReceipt(_AliasWireModel):
    """Terminal single-dispatch failure with no redispatch or downstream authority."""

    api_version: Literal["pajin.dev/skill-bound-web-analysis-invocation-failure/v1alpha1"] = Field(
        default="pajin.dev/skill-bound-web-analysis-invocation-failure/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["SkillBoundWebAnalysisInvocationFailureReceipt"] = (
        "SkillBoundWebAnalysisInvocationFailureReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    analysis_run_id: str = Field(alias="analysisRunId", pattern=_RUN_ID_PATTERN)
    request_envelope: SkillBoundWebAnalysisRequestEnvelope = Field(alias="requestEnvelope")
    skill_projection_run_id: str = Field(
        alias="skillProjectionRunId",
        pattern=_RUN_ID_PATTERN,
    )
    skill_projection_root_digest: _Sha256 = Field(alias="skillProjectionRootDigest")
    skill_bound_snapshot_digest: _Sha256 = Field(alias="skillBoundSnapshotDigest")
    projection_bundle_digest: _Sha256 = Field(alias="projectionBundleDigest")
    instruction_projection_digest: _Sha256 = Field(alias="instructionProjectionDigest")
    evidence_projection_digest: _Sha256 = Field(alias="evidenceProjectionDigest")
    registry: SkillRegistryRef
    selection_policy_digest: _Sha256 = Field(alias="selectionPolicyDigest")
    transport_pin: WebAnalysisTransportRuntimePin = Field(alias="transportPin")
    provider_outcome: ProviderBoundChatOutcome | None = Field(
        default=None,
        alias="providerOutcome",
    )
    base_provider_execution_context: WebAnalysisProviderExecutionContext = Field(
        alias="baseProviderExecutionContext"
    )
    successor_provider_execution_context: SkillBoundWebAnalysisProviderExecutionContext = Field(
        alias="successorProviderExecutionContext"
    )
    provider_run_id: str = Field(alias="providerRunId", pattern=_RUN_ID_PATTERN)
    provider_root_digest: _Sha256 = Field(alias="providerRootDigest")
    provider_run_seal_count: Literal[1] = Field(default=1, alias="providerRunSealCount")
    terminal_state: Literal[
        "provider-invocation-failed-uncertain",
        "provider-response-rejected",
    ] = Field(alias="terminalState")
    raw_draft_sha256: _Sha256 | None = Field(default=None, alias="rawDraftSha256")
    raw_draft_bytes: int = Field(
        default=0,
        alias="rawDraftBytes",
        strict=True,
        ge=0,
        le=_MAX_RAW_DRAFT_BYTES,
    )
    draft_digest: _Sha256 | None = Field(default=None, alias="draftDigest")
    dispatch_count: Literal[0, 1] = Field(alias="dispatchCount")
    target_request_count: Literal[0] = Field(default=0, alias="targetRequestCount")
    response_accepted: Literal[False] = Field(default=False, alias="responseAccepted")
    proposal_compiled: Literal[False] = Field(default=False, alias="proposalCompiled")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    task_creation_authorized: Literal[False] = Field(
        default=False,
        alias="taskCreationAuthorized",
    )
    plan_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="planMutationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    tool_request_authorized: Literal[False] = Field(
        default=False,
        alias="toolRequestAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_authorized: Literal[False] = Field(default=False, alias="findingAuthorized")
    report_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthorized",
    )
    activation_authorized: Literal[False] = Field(
        default=False,
        alias="activationAuthorized",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )

    @field_validator(
        "provider_run_seal_count",
        "raw_draft_bytes",
        "dispatch_count",
        "target_request_count",
        mode="before",
    )
    @classmethod
    def require_literal_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Skill-bound Web analysis failure counts must be JSON integers")
        return value

    @field_validator(
        "response_accepted",
        "proposal_compiled",
        "automatic_redispatch_authorized",
        "task_creation_authorized",
        "plan_mutation_authorized",
        "scope_expansion_authorized",
        "tool_request_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "graph_admission_authorized",
        "finding_authorized",
        "report_delivery_authorized",
        "activation_authorized",
        "external_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_false_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        request = canonical_skill_contract(
            self.request_envelope,
            SkillBoundWebAnalysisRequestEnvelope,
        )
        canonical_skill_contract(self.registry, SkillRegistryRef)
        transport = canonical_skill_contract(
            self.transport_pin,
            WebAnalysisTransportRuntimePin,
        )
        base_context = canonical_skill_contract(
            self.base_provider_execution_context,
            WebAnalysisProviderExecutionContext,
        )
        successor_context = canonical_skill_contract(
            self.successor_provider_execution_context,
            SkillBoundWebAnalysisProviderExecutionContext,
        )
        outcome = self.provider_outcome
        if outcome is not None:
            outcome = canonical_skill_contract(outcome, ProviderBoundChatOutcome)
        _require_common_lineage(
            request=request,
            skill_projection_run_id=self.skill_projection_run_id,
            skill_projection_root_digest=self.skill_projection_root_digest,
            skill_bound_snapshot_digest=self.skill_bound_snapshot_digest,
            projection_bundle_digest=self.projection_bundle_digest,
            instruction_projection_digest=self.instruction_projection_digest,
            evidence_projection_digest=self.evidence_projection_digest,
            transport=transport,
            outcome=outcome,
            base_context=base_context,
            successor_context=successor_context,
        )
        has_raw_draft = self.raw_draft_sha256 is not None
        if has_raw_draft != (self.raw_draft_bytes > 0):
            raise ValueError("Skill-bound Web analysis failure raw draft binding differs")
        if self.draft_digest is not None and not has_raw_draft:
            raise ValueError("Skill-bound Web analysis failure draft digest lacks raw content")
        invocation_uncertain = self.terminal_state == "provider-invocation-failed-uncertain"
        if invocation_uncertain:
            if outcome is not None or has_raw_draft or self.draft_digest is not None:
                raise ValueError("Uncertain Skill-bound invocation cannot claim a response")
        else:
            if outcome is None or self.dispatch_count != 1:
                raise ValueError("Rejected Skill-bound response requires a Provider outcome")
            if has_raw_draft and (
                outcome.content_digest is None or outcome.content_bytes != self.raw_draft_bytes
            ):
                raise ValueError("Rejected Skill-bound response content binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = _receipt_digest(
            "pajin.web-analysis.skill-bound-invocation-failure/v1",
            material,
        )
        receipt_id = f"skill-bound-web-analysis-failure:{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Skill-bound Web analysis failure receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Skill-bound Web analysis failure receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


@dataclass(frozen=True, slots=True)
class SkillBoundWebAnalysisInvocationPublication:
    """One sealed successor analysis Run under independent Run/root anchors."""

    run_path: Path
    run_id: str
    root_digest: str


@dataclass(frozen=True, slots=True)
class SkillBoundWebAnalysisProviderRunPublication:
    """One terminal Provider Run and its active successor execution context."""

    run_path: Path
    run_id: str
    root_digest: str
    execution_context: SkillBoundWebAnalysisProviderExecutionContext


@dataclass(frozen=True, slots=True)
class VerifiedSkillBoundWebAnalysisInvocationRun:
    """Strictly reloaded successful successor artifacts with no downstream authority."""

    run_path: Path
    verification: RunIntegrityVerification
    snapshot: SkillBoundWebAnalysisSnapshot
    request: SkillBoundWebAnalysisRequestEnvelope
    provider_execution_context: SkillBoundWebAnalysisProviderExecutionContext
    provider_publication: SkillBoundWebAnalysisProviderRunPublication
    provider_outcome: ProviderBoundChatOutcome
    raw_draft: bytes
    draft: SkillBoundWebAnalysisProposalDraft
    proposal: CompiledSkillBoundWebAnalysisProposal
    receipt: SkillBoundWebAnalysisInvocationReceipt
    semantics: Literal["skill-bound-compiled-proposal-not-authority"] = (
        "skill-bound-compiled-proposal-not-authority"
    )
    dispatch_count: Literal[1] = 1
    target_request_count: Literal[0] = 0
    execution_authority: Literal[False] = False
    graph_admission_authority: Literal[False] = False
    finding_authority: Literal[False] = False
    report_delivery_authority: Literal[False] = False


@dataclass(frozen=True, slots=True)
class VerifiedSkillBoundWebAnalysisFailureRun:
    """Strictly reloaded terminal successor failure proving no same-Run redispatch."""

    run_path: Path
    verification: RunIntegrityVerification
    snapshot: SkillBoundWebAnalysisSnapshot
    request: SkillBoundWebAnalysisRequestEnvelope
    provider_execution_context: SkillBoundWebAnalysisProviderExecutionContext
    provider_publication: SkillBoundWebAnalysisProviderRunPublication
    provider_outcome: ProviderBoundChatOutcome | None
    raw_draft: bytes | None
    receipt: SkillBoundWebAnalysisInvocationFailureReceipt
    dispatch_count: Literal[0, 1]
    semantics: Literal["terminal-skill-bound-failure-no-redispatch"] = (
        "terminal-skill-bound-failure-no-redispatch"
    )
    target_request_count: Literal[0] = 0
    automatic_redispatch_authority: Literal[False] = False
    execution_authority: Literal[False] = False


@dataclass(frozen=True, slots=True)
class SkillBoundWebAnalysisInvocationCompletion:
    """One accepted draft, compiled proposal, receipt, and both sealed publications."""

    draft: SkillBoundWebAnalysisProposalDraft
    proposal: CompiledSkillBoundWebAnalysisProposal
    receipt: SkillBoundWebAnalysisInvocationReceipt
    publication: SkillBoundWebAnalysisInvocationPublication
    provider_publication: SkillBoundWebAnalysisProviderRunPublication


def _require_common_lineage(
    *,
    request: SkillBoundWebAnalysisRequestEnvelope,
    skill_projection_run_id: str,
    skill_projection_root_digest: str,
    skill_bound_snapshot_digest: str,
    projection_bundle_digest: str,
    instruction_projection_digest: str,
    evidence_projection_digest: str,
    transport: WebAnalysisTransportRuntimePin,
    outcome: ProviderBoundChatOutcome | None,
    base_context: WebAnalysisProviderExecutionContext,
    successor_context: SkillBoundWebAnalysisProviderExecutionContext,
) -> None:
    if (
        request.skill_projection_run_id != skill_projection_run_id
        or request.skill_projection_root_digest != skill_projection_root_digest
        or request.skill_bound_snapshot_digest != skill_bound_snapshot_digest
        or request.projection_bundle_digest != projection_bundle_digest
        or request.instruction_projection_digest != instruction_projection_digest
        or request.evidence_projection_digest != evidence_projection_digest
        or request.transport_pin_digest != transport.pin_digest
        or successor_context.base_provider_execution_context != base_context
        or successor_context.transport_pin != transport
        or request.automatic_redispatch_authorized is not False
        or request.target_request_authorized is not False
        or request.execution_authorized is not False
    ):
        raise ValueError("Skill-bound Web analysis receipt request lineage differs")
    if outcome is not None and (
        outcome.request_id != request.request_id
        or outcome.chat_request_digest != request.provider_chat_request_digest
        or outcome.provider_runtime_digest != request.provider_runtime_digest
        or outcome.provider_id != base_context.provider_id
        or outcome.model != base_context.model
        or outcome.tool_id != base_context.tool_id
        or outcome.automatic_redispatch_authorized is not False
        or outcome.execution_authorized is not False
    ):
        raise ValueError("Skill-bound Web analysis receipt Provider lineage differs")


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Skill-bound Web analysis authority marker must be literal false")
    return False


def _receipt_digest(domain: str, value: object) -> str:
    return sha256(
        domain.encode("ascii", errors="strict")
        + b"\x00"
        + canonical_json_bytes(
            value,
            label="Skill-bound Web analysis receipt identity",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
    ).hexdigest()


__all__ = [
    "SkillBoundWebAnalysisInvocationCompletion",
    "SkillBoundWebAnalysisInvocationFailureReceipt",
    "SkillBoundWebAnalysisInvocationPublication",
    "SkillBoundWebAnalysisInvocationReceipt",
    "SkillBoundWebAnalysisProviderRunPublication",
    "VerifiedSkillBoundWebAnalysisFailureRun",
    "VerifiedSkillBoundWebAnalysisInvocationRun",
]
