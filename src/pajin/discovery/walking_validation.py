"""Approved, permitted, and sealed Candidate admission for WALK-005A."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.agents.base import CandidateAuthority, CandidateProduction
from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    capability_gateway_outcome_digest,
    capability_grant_digest,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.reconciliation import (
    CapabilityDispatchReconciliation,
    CapabilityDispatchReconciliationError,
    CapabilityDispatchReconciliationStatus,
    reconcile_capability_dispatch,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.walking import _campaign_digest
from pajin.discovery.walking_replanning import (
    WalkingObservationReplanAuthority,
    WalkingObservationReplanError,
    WalkingObservationReplanOutcome,
    load_walking_observation_replan_authority,
)
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    Finding,
    FindingSeverity,
    StrictModel,
    ToolRequest,
    ToolResult,
)
from pajin.domain.validation import AtomicClaim, CandidateFinding, candidate_atomic_claims
from pajin.graph.authority import ActionPermit
from pajin.policy.engine import PolicyDecision
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.gateway import GatewayOutcome
from pajin.workflow.tool_loop import PendingToolIntent, ToolLoopApproval

WALKING_CANDIDATE_ADMISSION_API_VERSION: Literal[
    "pajin.dev/walking-candidate-admission/v1alpha1"
] = "pajin.dev/walking-candidate-admission/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_MAX_AUTHORITY_BYTES = 4 * 1024 * 1024
_EVIDENCE_ROOT = "evidence"


class WalkingCandidateAdmissionError(RuntimeError):
    """Raised when WALK-005A cannot prove exact execution and Candidate authority."""


class _WalkingMCPProbeInput(StrictModel):
    text: str = Field(min_length=1, max_length=100_000)


class _WalkingMCPTextContent(StrictModel):
    type: Literal["text"]
    text: Literal["inspection complete"]


class _WalkingMCPProbeOutput(StrictModel):
    vulnerable: Literal[True]
    authorization_enforced: Literal[False] = Field(alias="authorizationEnforced")
    internal_data_accessed: Literal[True] = Field(alias="internalDataAccessed")
    observation: Literal["untrusted text contains an instruction-hijacking pattern"]
    target: str = Field(min_length=1, max_length=2_000)
    mcp_server_id: _Identifier = Field(alias="mcpServerId")
    mcp_tool_name: _Identifier = Field(alias="mcpToolName")
    mcp_content: tuple[_WalkingMCPTextContent, ...] = Field(
        alias="mcpContent",
        min_length=1,
        max_length=1,
    )


class WalkingIndependentApprovalReceipt(StrictModel):
    """Content-addressed projection of one explicit approval for an exact Tool intent."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt_id: str = Field(default="", alias="receiptId", max_length=100)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    replan_authority_id: str = Field(alias="replanAuthorityId", min_length=1, max_length=100)
    replan_authority_digest: _Sha256 = Field(alias="replanAuthorityDigest")
    plan_id: str = Field(alias="planId", min_length=1, max_length=100)
    plan_digest: _Sha256 = Field(alias="planDigest")
    approval: ToolLoopApproval
    intent: PendingToolIntent
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: _Sha256 = Field(alias="requestDigest")
    approved_request_digest: _Sha256 = Field(alias="approvedRequestDigest")
    capability_grant_digest: _Sha256 = Field(alias="capabilityGrantDigest")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        approved_at = _utc(self.approval.approved_at, label="approval time")
        expires_at = _utc(self.approval.expires_at, label="approval expiry")
        requested_at = _utc(self.intent.requested_at, label="approval request time")
        if not requested_at <= approved_at < expires_at:
            raise ValueError("Walking approval request, decision, or expiry window is invalid")
        expected = _approved_request_digest(self.intent)
        if self.approved_request_digest != expected:
            raise ValueError("Walking approval receipt differs from its exact intent")
        if (
            self.approval.call_fingerprint != self.intent.fingerprint
            or self.approval.tool_id != self.intent.tool_id
            or self.approval.target != self.intent.target
        ):
            raise ValueError("Walking approval does not authorize its bound Tool intent")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = discovery_digest("pajin.walking.independent-approval-receipt/v1", material)
        receipt_id = f"walking-approval_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Walking approval receipt Digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Walking approval receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


def walking_independent_approval_receipt(
    replan: WalkingObservationReplanAuthority,
    request: ToolRequest,
    intent: PendingToolIntent,
    approval: ToolLoopApproval,
    grant: CapabilityGrant,
) -> WalkingIndependentApprovalReceipt:
    """Bind an existing explicit approval to WALK-004 before Permit dispatch."""

    canonical_request = ToolRequest.model_validate(request.model_dump(mode="json"))
    canonical_intent = PendingToolIntent.model_validate(intent.model_dump(mode="json"))
    canonical_approval = ToolLoopApproval.model_validate(approval.model_dump(mode="json"))
    canonical_grant = CapabilityGrant.model_validate(grant.model_dump(mode="json"))
    if not _intent_matches_request(canonical_intent, canonical_request):
        raise WalkingCandidateAdmissionError(
            "Walking approval intent differs from its exact Tool request"
        )
    return WalkingIndependentApprovalReceipt(
        replanAuthorityId=replan.authority_id,
        replanAuthorityDigest=replan.authority_digest,
        planId=replan.plan.plan_id,
        planDigest=replan.plan.plan_digest,
        approval=canonical_approval,
        intent=canonical_intent,
        requestId=canonical_request.request_id,
        requestDigest=capability_tool_request_digest(canonical_request),
        approvedRequestDigest=_approved_request_digest(canonical_intent),
        capabilityGrantDigest=capability_grant_digest(canonical_grant),
    )


class SealedWalkingCapabilityExecution(StrictModel):
    """Verified Permit-to-Gateway evidence used by Candidate admission."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    root_digest: _Sha256 = Field(alias="rootDigest")
    evidence_path: str = Field(alias="evidencePath", min_length=1, max_length=2_000)
    evidence_sha256: _Sha256 = Field(alias="evidenceSha256")
    approval: WalkingIndependentApprovalReceipt
    grant: CapabilityGrant
    permit: ActionPermit
    reconciliation: CapabilityDispatchReconciliation
    terminal_event: CapabilityDispatchAuditEvent = Field(alias="terminalEvent")
    request: ToolRequest
    policy_decision: PolicyDecision = Field(alias="policyDecision")
    result: ToolResult
    worker_result: WorkerResult = Field(alias="workerResult")
    execution_digest: str = Field(default="", alias="executionDigest", max_length=64)

    @model_validator(mode="after")
    def bind_execution(self) -> Self:
        terminal = self.terminal_event
        grant_digest = capability_grant_digest(self.grant)
        if (
            self.run_id != self.permit.run_id
            or self.reconciliation.status is not CapabilityDispatchReconciliationStatus.COMPLETED
            or self.reconciliation.run_id != self.run_id
            or self.reconciliation.permit_id != self.permit.permit_id
            or self.reconciliation.permit_digest != self.permit.permit_digest
            or self.reconciliation.terminal_event_digest != terminal.event_digest
            or terminal.stage is not CapabilityDispatchStage.COMPLETED
        ):
            raise ValueError("Walking execution lacks one exact completed Permit lifecycle")
        if (
            self.approval.capability_grant_digest != grant_digest
            or terminal.capability_grant_digest != grant_digest
            or self.grant.campaign != self.permit.campaign_id
            or self.grant.subject != self.request.agent_id
            or self.grant.tools != {self.request.tool_id}
            or self.grant.targets != {self.request.target}
            or self.grant.max_risk_tier != self.permit.capability.risk_tier
            or self.grant.max_calls != 1
            or not (
                _utc(self.grant.issued_at, label="Capability Grant issue time")
                <= self.permit.consumed_at
                < _utc(self.grant.expires_at, label="Capability Grant expiry")
            )
        ):
            raise ValueError("Walking execution did not use its exact authorized Capability Grant")
        if (
            self.request.request_id != self.permit.request_id
            or capability_tool_request_digest(self.request) != self.permit.request_digest
            or capability_normalized_parameters_digest(self.request.arguments)
            != self.permit.normalized_parameters_digest
            or self.result.request_id != self.request.request_id
            or self.result.tool_id != self.request.tool_id
        ):
            raise ValueError("Walking execution request or result differs from its ActionPermit")
        if (
            self.approval.request_id != self.request.request_id
            or self.approval.request_digest != self.permit.request_digest
            or not _intent_matches_request(self.approval.intent, self.request)
            or not self.approval.approval.authorizes(
                self.approval.intent,
                at=self.permit.consumed_at,
            )
            or _utc(self.approval.approval.approved_at, label="approval time")
            > self.permit.consumed_at
            or self.approval.approval.approved_by == self.request.agent_id
        ):
            raise ValueError("Walking execution was not explicitly approved before Permit use")
        if (
            not self.policy_decision.allowed
            or not self.result.success
            or self.worker_result.status is not WorkerStatus.SUCCEEDED
            or terminal.gateway_execution_id != self.worker_result.execution_id
            or terminal.executed is not True
            or terminal.policy_allowed is not True
            or terminal.tool_success is not True
            or terminal.evidence != tuple(sorted(set(self.result.evidence)))
            or self.result.started_at != self.worker_result.started_at
            or self.result.finished_at != self.worker_result.finished_at
            or terminal.occurred_at < self.worker_result.finished_at
        ):
            raise ValueError(
                "Walking execution did not complete through an allowed successful Gateway"
            )
        outcome = GatewayOutcome(
            decision=self.policy_decision,
            result=self.result,
            worker_result=self.worker_result,
            network_log_trusted=False,
            result_identity_valid=True,
            executed=True,
        )
        if terminal.gateway_outcome_digest != capability_gateway_outcome_digest(outcome):
            raise ValueError("Walking execution Gateway outcome differs from sealed dispatch audit")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"execution_digest"},
        )
        digest = discovery_digest("pajin.walking.sealed-capability-execution/v1", material)
        if self.execution_digest and self.execution_digest != digest:
            raise ValueError("Walking execution Digest differs")
        object.__setattr__(self, "execution_digest", digest)
        return self


class WalkingCandidateAdmissionAuthority(StrictModel):
    """Complete WALK-005A authority; it admits no confirmation or replay authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-candidate-admission/v1alpha1"] = Field(
        default=WALKING_CANDIDATE_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingCandidateAdmissionAuthority"] = "WalkingCandidateAdmissionAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    replan: WalkingObservationReplanAuthority
    execution: SealedWalkingCapabilityExecution
    candidate: CandidateFinding
    atomic_claims: tuple[AtomicClaim, ...] = Field(alias="atomicClaims", min_length=3, max_length=3)
    validation_state: Literal["candidate-admitted-not-confirmed"] = Field(
        default="candidate-admitted-not-confirmed",
        alias="validationState",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        hypothesis = self.replan.source.hypothesis
        capability = hypothesis.capability
        permit_capability = self.execution.permit.capability
        request = self.execution.request
        if (
            self.campaign_digest != self.replan.campaign_digest
            or self.execution.approval.replan_authority_id != self.replan.authority_id
            or self.execution.approval.replan_authority_digest != self.replan.authority_digest
            or self.execution.approval.plan_id != self.replan.plan.plan_id
            or self.execution.approval.plan_digest != self.replan.plan.plan_digest
            or self.replan.plan.execution_state != "proposed-not-authorized"
        ):
            raise ValueError("Walking Candidate execution differs from its non-executable Plan")
        if (
            permit_capability.capability_id != capability.capability_id
            or permit_capability.capability_version != capability.capability_version
            or permit_capability.definition_digest != capability.capability_digest
            or permit_capability.tool_id != capability.tool.tool_id
            or permit_capability.tool_version != capability.tool.tool_version
            or permit_capability.tool_digest != capability.tool.tool_digest
            or permit_capability.risk_tier != capability.risk_tier
            or request.tool_id != hypothesis.invocation.tool_id
            or request.target != _campaign_target(self.replan, hypothesis.mcp_target_id)
            or request.method != "POST"
        ):
            raise ValueError(
                "Walking Candidate execution expands or substitutes Capability authority"
            )
        expected_candidate = _candidate(self.replan, self.execution)
        expected_claims = tuple(candidate_atomic_claims(expected_candidate))
        if self.candidate != expected_candidate or self.atomic_claims != expected_claims:
            raise ValueError("Walking Candidate or Atomic Claims differ from verified execution")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest("pajin.walking.candidate-admission-authority/v1", material)
        authority_id = f"walking-candidate-admission_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking Candidate admission authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking Candidate admission authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Walking Candidate admission authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self

    def candidate_production(self) -> CandidateProduction:
        """Project the already-verified exact Candidate into the existing gate contract."""

        candidate = self.candidate.model_copy(deep=True)
        return CandidateProduction(
            candidates=(candidate,),
            authoritative_request_claims=frozenset(
                {
                    CandidateAuthority(
                        request_id=self.execution.request.request_id,
                        target=candidate.claim.target,
                        threat_class=candidate.claim.threat_class,
                    )
                }
            ),
        )


@dataclass(frozen=True, slots=True)
class WalkingExecutionEvidence:
    run_path: Path
    grant: CapabilityGrant
    permit: ActionPermit
    request: ToolRequest
    intent: PendingToolIntent
    approval: ToolLoopApproval


@dataclass(frozen=True, slots=True)
class WalkingCandidateAdmissionOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: WalkingCandidateAdmissionAuthority


class WalkingCandidateAdmissionRunner:
    """Verify and seal WALK-005A without dispatching a Tool or creating approval."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        replan_outcome: WalkingObservationReplanOutcome,
        execution_evidence: WalkingExecutionEvidence,
    ) -> WalkingCandidateAdmissionOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            replan = load_walking_observation_replan_authority(
                authoritative_campaign,
                replan_outcome,
            )
            execution = _load_execution(replan, execution_evidence)
            candidate = _candidate(replan, execution)
            authority = WalkingCandidateAdmissionAuthority(
                campaignDigest=_campaign_digest(authoritative_campaign),
                replan=replan,
                execution=execution,
                candidate=candidate,
                atomicClaims=tuple(candidate_atomic_claims(candidate)),
            )
            source_snapshot = load_verified_run_artifacts(
                execution_evidence.run_path,
                requests={execution.evidence_path: _MAX_AUTHORITY_BYTES},
                expected_run_id=execution.run_id,
            )
            source_evidence = source_snapshot.artifact_bytes(execution.evidence_path)
            if (
                source_snapshot.verification.root_digest != execution.root_digest
                or sha256(source_evidence).hexdigest() != execution.evidence_sha256
            ):
                raise ValueError("Walking source execution changed before Candidate publication")
            source_evidence_payload = parse_strict_json_bytes(
                source_evidence,
                label="Walking copied Gateway evidence",
                max_bytes=_MAX_AUTHORITY_BYTES,
            )
        except (
            CapabilityDispatchReconciliationError,
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            WalkingObservationReplanError,
        ) as exc:
            raise WalkingCandidateAdmissionError(
                "WALK-005A Candidate admission authority could not be verified"
            ) from exc
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-candidate-admission",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        copied_evidence_path = store.write_json(
            authority.execution.evidence_path,
            source_evidence_payload,
        )
        if copied_evidence_path != authority.execution.evidence_path:
            raise WalkingCandidateAdmissionError("WALK-005A copied Gateway evidence path changed")
        artifact_path = store.write_json(
            "walking-candidate-admission-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.candidate-admission-authority.created",
            {
                "artifact": artifact_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "candidateId": authority.candidate.candidate_id,
                "claimIds": [claim.claim_id for claim in authority.atomic_claims],
                "validationState": authority.validation_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-candidate-admission-authority-sealed",
                "purpose": "walking-candidate-admission",
                "authorityId": authority.authority_id,
                "validationState": authority.validation_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-candidate-admission", "artifact": artifact_path},
        )
        store.seal()
        return WalkingCandidateAdmissionOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_candidate_admission_authority(
    campaign: CampaignManifest,
    outcome: WalkingCandidateAdmissionOutcome,
) -> WalkingCandidateAdmissionAuthority:
    """Rebuild WALK-005A from its sealed artifact and exact publication event."""

    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_AUTHORITY_BYTES,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
                outcome.authority.execution.evidence_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = WalkingCandidateAdmissionAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
    except (OSError, RunIntegrityError, ValueError) as exc:
        raise WalkingCandidateAdmissionError(
            "WALK-005A Candidate admission authority is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or authority != outcome.authority:
        raise WalkingCandidateAdmissionError(
            "WALK-005A Candidate admission outcome differs from sealed authority"
        )
    if (
        sha256(snapshot.artifact_bytes(authority.execution.evidence_path)).hexdigest()
        != authority.execution.evidence_sha256
    ):
        raise WalkingCandidateAdmissionError(
            "WALK-005A copied Gateway evidence differs from source execution"
        )
    created = [
        event
        for event in snapshot.events
        if event.event_type == "walking.candidate-admission-authority.created"
    ]
    expected = {
        "artifact": outcome.artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "candidateId": authority.candidate.candidate_id,
        "claimIds": [claim.claim_id for claim in authority.atomic_claims],
        "validationState": authority.validation_state,
    }
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingCandidateAdmissionError(
            "WALK-005A Candidate admission publication event differs from authority"
        )
    return authority.model_copy(deep=True)


def _load_execution(
    replan: WalkingObservationReplanAuthority,
    evidence: WalkingExecutionEvidence,
) -> SealedWalkingCapabilityExecution:
    request = ToolRequest.model_validate(evidence.request.model_dump(mode="json"))
    grant = CapabilityGrant.model_validate(evidence.grant.model_dump(mode="json"))
    permit = ActionPermit.model_validate(evidence.permit.model_dump(mode="json", by_alias=True))
    intent = PendingToolIntent.model_validate(evidence.intent.model_dump(mode="json"))
    approval = ToolLoopApproval.model_validate(evidence.approval.model_dump(mode="json"))
    evidence_path = f"{_EVIDENCE_ROOT}/{request.request_id}.json"
    snapshot = load_verified_run_artifacts(
        evidence.run_path,
        requests={evidence_path: _MAX_AUTHORITY_BYTES},
        expected_run_id=permit.run_id,
    )
    reconciliation = reconcile_capability_dispatch(snapshot, permit)
    if reconciliation.terminal_event is None:
        raise ValueError("Walking execution has no completed terminal event")
    raw_bytes = snapshot.artifact_bytes(evidence_path)
    raw = parse_strict_json_bytes(
        raw_bytes,
        label="Walking Tool Gateway evidence",
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    if type(raw) is not dict:
        raise ValueError("Walking Tool Gateway evidence must be an object")
    payload = cast(dict[str, object], raw)
    recorded_request = ToolRequest.model_validate(payload.get("request"))
    policy = PolicyDecision.model_validate(payload.get("policyDecision"))
    recorded_result = ToolResult.model_validate(payload.get("result"))
    worker = WorkerResult.model_validate(payload.get("workerResult"))
    network_log_trusted = payload.get("networkLogTrusted")
    if network_log_trusted is not False:
        raise ValueError("Walking local MCP execution unexpectedly claims trusted network evidence")
    if recorded_request != request:
        raise ValueError("Walking supplied request differs from sealed Gateway evidence")
    if recorded_result.evidence:
        raise ValueError("Walking raw Gateway result unexpectedly contains external evidence")
    result = recorded_result.model_copy(update={"evidence": [evidence_path]}, deep=True)
    approval_receipt = walking_independent_approval_receipt(
        replan,
        request,
        intent,
        approval,
        grant,
    )
    approval_events = [
        event
        for event in snapshot.events
        if event.event_type == "walking.independent-approval.consumed"
        and event.payload == approval_receipt.model_dump(mode="json", by_alias=True)
    ]
    claimed_events = [
        event
        for event in snapshot.events
        if event.event_type == "capability.dispatch.claimed"
        and event.payload.get("permitId") == permit.permit_id
    ]
    if (
        len(approval_events) != 1
        or len(claimed_events) != 1
        or approval_events[0].occurred_at != approval.approved_at
        or approval_events[0].sequence >= claimed_events[0].sequence
        or not (permit.consumed_at <= claimed_events[0].occurred_at < permit.expires_at)
    ):
        raise ValueError(
            "Walking approval receipt must be sealed exactly once before Permit dispatch"
        )
    return SealedWalkingCapabilityExecution(
        runId=snapshot.verification.run_id,
        rootDigest=snapshot.verification.root_digest,
        evidencePath=evidence_path,
        evidenceSha256=sha256(raw_bytes).hexdigest(),
        approval=approval_receipt,
        grant=grant,
        permit=permit,
        reconciliation=reconciliation.record,
        terminalEvent=reconciliation.terminal_event,
        request=request,
        policyDecision=policy,
        result=result,
        workerResult=worker,
    )


def load_sealed_walking_capability_execution(
    replan: WalkingObservationReplanAuthority,
    evidence: WalkingExecutionEvidence,
) -> SealedWalkingCapabilityExecution:
    """Rebuild one approved, permitted, sealed execution without admitting a Candidate."""

    try:
        return _load_execution(replan, evidence)
    except (
        CapabilityDispatchReconciliationError,
        OSError,
        RunIntegrityError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WalkingCandidateAdmissionError(
            "Walking sealed Capability execution could not be verified"
        ) from exc


def walking_candidate_from_execution(
    replan: WalkingObservationReplanAuthority,
    execution: SealedWalkingCapabilityExecution,
) -> CandidateFinding:
    """Derive the exact unconfirmed Candidate semantics from one verified execution."""

    try:
        return _candidate(replan, execution)
    except (ValidationError, ValueError) as exc:
        raise WalkingCandidateAdmissionError(
            "Walking execution does not prove Candidate observables"
        ) from exc


def _candidate(
    replan: WalkingObservationReplanAuthority,
    execution: SealedWalkingCapabilityExecution,
) -> CandidateFinding:
    hypothesis = replan.source.hypothesis
    probe_input = _WalkingMCPProbeInput.model_validate(execution.request.arguments)
    output = _WalkingMCPProbeOutput.model_validate(execution.result.data)
    if (
        "ignore previous" not in probe_input.text.lower()
        or output.target != execution.request.target
        or output.mcp_server_id != hypothesis.invocation.server_id
        or output.mcp_tool_name != hypothesis.invocation.remote_tool_name
    ):
        raise ValueError("Walking MCP result does not prove the registered RAG authorization probe")
    identity = discovery_digest(
        "pajin.walking.candidate/v1",
        {
            "replanAuthorityId": replan.authority_id,
            "replanAuthorityDigest": replan.authority_digest,
            "executionDigest": execution.execution_digest,
            "requestId": execution.request.request_id,
            "evidence": list(execution.result.evidence),
        },
    )
    candidate = CandidateFinding(
        candidate_id=f"candidate_walk_{identity}",
        claim=Finding(
            finding_id=f"finding_walk_{identity}",
            title="RAG 유래 지시가 승인 경계 없는 MCP 내부 데이터 접근을 유발함",
            severity=FindingSeverity.HIGH,
            threat_class="A02",
            target=execution.request.target,
            summary=(
                "봉인된 승인·Permit·Gateway 실행에서 비신뢰 RAG 지시가 등록된 MCP 도구에 "
                "전달되었고, 대상의 독립 승인 제어 없이 내부 데이터 접근이 관찰되었다."
            ),
            impact=(
                "비신뢰 문서가 등록된 MCP 도구의 내부 데이터 접근을 유도하여 신뢰 경계를 "
                "넘는 정보 노출로 이어질 수 있다."
            ),
            affected_component=hypothesis.invocation.tool_id,
            root_cause="대상이 문서 유래 MCP 인자에 독립 사용자 승인 제어를 적용하지 않았다.",
            reproduction=[
                "봉인된 WALK-004 독립 승인 요청 Plan을 확인한다.",
                "별도의 명시적 승인과 단일 사용 ActionPermit으로 정확한 MCP 요청을 실행한다.",
                "봉인된 Gateway 증빙에서 문서 유래 지시, 승인 제어 부재, 내부 데이터 "
                "접근을 확인한다.",
            ],
            evidence=list(execution.result.evidence),
            remediation=[
                "문서 유래 MCP 인자를 신뢰 입력과 분리하고 독립 사용자 승인을 강제한다.",
                "승인 대상 Tool, target, 인자 digest를 단일 사용 Permit에 결박한다.",
            ],
            confidence=1.0,
            validated=False,
        ),
        source="walking-approved-permitted-execution",
        source_agent_id="pajin.walk.candidate-producer.v1",
        source_request_ids=[execution.request.request_id],
        created_at=execution.terminal_event.occurred_at,
    )
    return candidate


def _campaign_target(replan: WalkingObservationReplanAuthority, target_id: str) -> str:
    manifest = CampaignManifest.model_validate(replan.campaign_manifest)
    targets = [target.endpoint for target in manifest.spec.targets if target.id == target_id]
    if len(targets) != 1:
        raise ValueError("Walking MCP target is absent or duplicated in the Campaign")
    return targets[0]


def _approved_request_digest(intent: PendingToolIntent) -> str:
    return discovery_digest(
        "pajin.walking.approved-tool-intent/v1",
        {
            "callFingerprint": intent.fingerprint,
            "functionName": intent.function_name,
            "toolId": intent.tool_id,
            "target": intent.target,
            "method": intent.method,
            "arguments": intent.arguments,
        },
    )


def _intent_matches_request(intent: PendingToolIntent, request: ToolRequest) -> bool:
    expected_fingerprint = sha256(
        json.dumps(
            {
                "function": intent.function_name,
                "tool": request.tool_id,
                "target": request.target,
                "method": request.method,
                "arguments": request.arguments,
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return (
        intent.tool_id == request.tool_id
        and intent.target == request.target
        and intent.method == request.method
        and intent.arguments == request.arguments
        and intent.fingerprint == expected_fingerprint
    )


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)
