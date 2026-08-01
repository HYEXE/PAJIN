"""Claim-bound, non-executable MCP Replay planning for WALK-005B1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.capabilities.activation import (
    capability_grant_digest,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.walking import _campaign_digest
from pajin.discovery.walking_validation import (
    SealedWalkingCapabilityExecution,
    WalkingCandidateAdmissionAuthority,
    WalkingCandidateAdmissionError,
    WalkingCandidateAdmissionOutcome,
    WalkingExecutionEvidence,
    WalkingIndependentApprovalReceipt,
    load_sealed_walking_capability_execution,
    load_walking_candidate_admission_authority,
    walking_candidate_from_execution,
    walking_independent_approval_receipt,
)
from pajin.domain.models import CampaignManifest, CapabilityGrant, StrictModel, ToolRequest
from pajin.domain.validation import (
    AtomicClaim,
    AtomicClaimType,
    ClaimReplayStatus,
    candidate_atomic_claims,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.workflow.tool_loop import PendingToolIntent, ToolLoopApproval

WALKING_MCP_REPLAY_PLAN_API_VERSION: Literal["pajin.dev/walking-mcp-replay-plan/v1alpha1"] = (
    "pajin.dev/walking-mcp-replay-plan/v1alpha1"
)
WALKING_MCP_CLAIM_REPLAY_API_VERSION: Literal["pajin.dev/walking-mcp-claim-replay/v1alpha1"] = (
    "pajin.dev/walking-mcp-claim-replay/v1alpha1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_PLAN_BYTES = 4 * 1024 * 1024
_FreshnessRequirement = Literal[
    "approval-id",
    "capability-grant-id",
    "dispatch-id",
    "execution-run-id",
    "permit-id",
    "request-id",
    "worker-execution-id",
]
_FRESHNESS_REQUIREMENTS: tuple[_FreshnessRequirement, ...] = (
    "approval-id",
    "capability-grant-id",
    "dispatch-id",
    "execution-run-id",
    "permit-id",
    "request-id",
    "worker-execution-id",
)


class WalkingMCPReplayPlanError(RuntimeError):
    """Raised when WALK-005B1 cannot prove a Claim-bound Replay Plan."""


class WalkingMCPClaimReplayError(RuntimeError):
    """Raised when WALK-005B2 cannot prove a Plan-bound fresh Claim replay."""


class WalkingMCPReplayPlan(StrictModel):
    """Complete non-executable authority for one fresh MCP validity replay."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-mcp-replay-plan/v1alpha1"] = Field(
        default=WALKING_MCP_REPLAY_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingMCPReplayPlan"] = "WalkingMCPReplayPlan"
    plan_id: str = Field(default="", alias="planId", max_length=110)
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source: WalkingCandidateAdmissionAuthority
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: Literal["walking-candidate-admission-authority.json"] = Field(
        default="walking-candidate-admission-authority.json",
        alias="sourceArtifactPath",
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    claim: AtomicClaim
    original_execution_digest: _Sha256 = Field(alias="originalExecutionDigest")
    original_run_id: str = Field(alias="originalRunId", min_length=1, max_length=200)
    original_request_id: str = Field(alias="originalRequestId", min_length=1, max_length=200)
    original_request_digest: _Sha256 = Field(alias="originalRequestDigest")
    tool_id: str = Field(alias="toolId", min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=2_000)
    method: Literal["POST"] = "POST"
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    freshness_requirements: tuple[_FreshnessRequirement, ...] = Field(
        alias="freshnessRequirements",
        min_length=7,
        max_length=7,
    )
    execution_state: Literal["planned-not-authorized"] = Field(
        default="planned-not-authorized",
        alias="executionState",
    )

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        execution = self.source.execution
        request = execution.request
        validity_claims = tuple(
            claim
            for claim in self.source.atomic_claims
            if claim.claim_type is AtomicClaimType.VALIDITY
        )
        if (
            self.source.validation_state != "candidate-admitted-not-confirmed"
            or len(validity_claims) != 1
            or self.claim != validity_claims[0]
            or self.claim.candidate_id != self.source.candidate.candidate_id
        ):
            raise ValueError("Walking MCP Replay Plan differs from its exact validity Claim")
        if (
            self.campaign_digest != self.source.campaign_digest
            or self.source_run_id == self.original_run_id
            or self.original_execution_digest != execution.execution_digest
            or self.original_run_id != execution.run_id
            or self.original_request_id != request.request_id
            or self.original_request_digest != execution.permit.request_digest
            or self.tool_id != request.tool_id
            or self.target != request.target
            or self.method != request.method
            or self.normalized_parameters_digest
            != capability_normalized_parameters_digest(request.arguments)
        ):
            raise ValueError("Walking MCP Replay Plan changes original execution authority")
        if self.freshness_requirements != _FRESHNESS_REQUIREMENTS:
            raise ValueError("Walking MCP Replay Plan freshness requirements differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_id", "plan_digest"},
        )
        digest = discovery_digest("pajin.walking.mcp-replay-plan/v1", material)
        plan_id = f"walking-mcp-replay-plan_{digest}"
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("Walking MCP Replay Plan Digest differs")
        if self.plan_id and self.plan_id != plan_id:
            raise ValueError("Walking MCP Replay Plan ID differs")
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "plan_id", plan_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Walking MCP Replay Plan",
            max_bytes=_MAX_PLAN_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingMCPReplayPlanOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    plan: WalkingMCPReplayPlan


class WalkingMCPReplayPlanRunner:
    """Re-verify WALK-005A and seal only its deterministic validity Replay Plan."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        source_outcome: WalkingCandidateAdmissionOutcome,
    ) -> WalkingMCPReplayPlanOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            source = load_walking_candidate_admission_authority(
                authoritative_campaign,
                source_outcome,
            )
            source_snapshot = load_verified_run_artifacts(
                source_outcome.run_path,
                requests={source_outcome.artifact_path: _MAX_PLAN_BYTES},
                expected_run_id=source_outcome.run_id,
            )
            source_artifact = source_snapshot.artifact_bytes(source_outcome.artifact_path)
            if source_outcome.artifact_path != "walking-candidate-admission-authority.json":
                raise ValueError("WALK-005A authority artifact path differs")
            validity_claims = tuple(
                claim
                for claim in source.atomic_claims
                if claim.claim_type is AtomicClaimType.VALIDITY
            )
            if len(validity_claims) != 1:
                raise ValueError("WALK-005A authority has no exact validity Claim")
            request = source.execution.request
            plan = WalkingMCPReplayPlan(
                campaignDigest=_campaign_digest(authoritative_campaign),
                source=source,
                sourceRunId=source_snapshot.verification.run_id,
                sourceRootDigest=source_snapshot.verification.root_digest,
                sourceArtifactPath="walking-candidate-admission-authority.json",
                sourceArtifactSha256=sha256(source_artifact).hexdigest(),
                claim=validity_claims[0],
                originalExecutionDigest=source.execution.execution_digest,
                originalRunId=source.execution.run_id,
                originalRequestId=request.request_id,
                originalRequestDigest=source.execution.permit.request_digest,
                toolId=request.tool_id,
                target=request.target,
                method="POST",
                normalizedParametersDigest=capability_normalized_parameters_digest(
                    request.arguments
                ),
                freshnessRequirements=_FRESHNESS_REQUIREMENTS,
            )
        except (ValidationError, ValueError, WalkingCandidateAdmissionError) as exc:
            raise WalkingMCPReplayPlanError(
                "WALK-005B1 MCP Replay Plan authority could not be verified"
            ) from exc
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-mcp-replay-plan",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            "walking-mcp-replay-plan.json",
            plan.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.mcp-replay-plan.created",
            {
                "artifact": artifact_path,
                "planId": plan.plan_id,
                "planDigest": plan.plan_digest,
                "candidateId": plan.source.candidate.candidate_id,
                "claimId": plan.claim.claim_id,
                "executionState": plan.execution_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-mcp-replay-plan-sealed",
                "purpose": "walking-mcp-replay-plan",
                "planId": plan.plan_id,
                "executionState": plan.execution_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-mcp-replay-plan", "artifact": artifact_path},
        )
        store.seal()
        return WalkingMCPReplayPlanOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            plan=plan.model_copy(deep=True),
        )


def load_walking_mcp_replay_plan(
    campaign: CampaignManifest,
    outcome: WalkingMCPReplayPlanOutcome,
) -> WalkingMCPReplayPlan:
    """Rebuild WALK-005B1 from its sealed Plan and exact publication event."""

    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_PLAN_BYTES,
                outcome.artifact_path: _MAX_PLAN_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        plan = WalkingMCPReplayPlan.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise WalkingMCPReplayPlanError(
            "WALK-005B1 MCP Replay Plan is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or plan != outcome.plan:
        raise WalkingMCPReplayPlanError(
            "WALK-005B1 MCP Replay Plan outcome differs from sealed authority"
        )
    created = [
        event for event in snapshot.events if event.event_type == "walking.mcp-replay-plan.created"
    ]
    expected = {
        "artifact": outcome.artifact_path,
        "planId": plan.plan_id,
        "planDigest": plan.plan_digest,
        "candidateId": plan.source.candidate.candidate_id,
        "claimId": plan.claim.claim_id,
        "executionState": plan.execution_state,
    }
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingMCPReplayPlanError("WALK-005B1 MCP Replay Plan publication event differs")
    return plan.model_copy(deep=True)


class WalkingMCPReplayApprovalReceipt(StrictModel):
    """Pre-dispatch binding between a B1 Plan and exact approved replay authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    plan_id: str = Field(alias="planId", min_length=1, max_length=110)
    plan_digest: _Sha256 = Field(alias="planDigest")
    claim_id: str = Field(alias="claimId", min_length=1, max_length=200)
    claim_digest: _Sha256 = Field(alias="claimDigest")
    approval: WalkingIndependentApprovalReceipt

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"receipt_id", "receipt_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-replay-approval/v1", material)
        receipt_id = f"walking-mcp-replay-approval_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Walking MCP Replay approval receipt Digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Walking MCP Replay approval receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


def walking_mcp_replay_approval_receipt(
    plan: WalkingMCPReplayPlan,
    request: ToolRequest,
    intent: PendingToolIntent,
    approval: ToolLoopApproval,
    grant: CapabilityGrant,
) -> WalkingMCPReplayApprovalReceipt:
    """Bind fresh approved execution authority to B1 before replay dispatch."""

    base = walking_independent_approval_receipt(
        plan.source.replan, request, intent, approval, grant
    )
    original = plan.source.execution.request
    if (
        request.request_id == plan.original_request_id
        or request.agent_id != original.agent_id
        or request.tool_id != plan.tool_id
        or request.target != plan.target
        or request.method != plan.method
        or request.arguments != original.arguments
        or capability_normalized_parameters_digest(request.arguments)
        != plan.normalized_parameters_digest
    ):
        raise WalkingMCPClaimReplayError(
            "WALK-005B2 replay request is not a fresh exact Plan materialization"
        )
    return WalkingMCPReplayApprovalReceipt(
        planId=plan.plan_id,
        planDigest=plan.plan_digest,
        claimId=plan.claim.claim_id,
        claimDigest=plan.claim.claim_digest,
        approval=base,
    )


class WalkingMCPClaimReplayProjection(StrictModel):
    """Non-confirming projection of one independently reproduced validity Claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    projection_id: str = Field(default="", alias="projectionId", max_length=110)
    projection_digest: str = Field(default="", alias="projectionDigest", max_length=64)
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    claim_id: str = Field(alias="claimId", min_length=1, max_length=200)
    claim_digest: _Sha256 = Field(alias="claimDigest")
    claim_type: Literal[AtomicClaimType.VALIDITY] = Field(alias="claimType")
    status: Literal[ClaimReplayStatus.REPRODUCED] = ClaimReplayStatus.REPRODUCED
    replay_run_id: str = Field(alias="replayRunId", min_length=1, max_length=200)
    replay_request_id: str = Field(alias="replayRequestId", min_length=1, max_length=200)
    replay_execution_digest: _Sha256 = Field(alias="replayExecutionDigest")
    replay_evidence: tuple[str, ...] = Field(alias="replayEvidence", min_length=1, max_length=10)
    independent_execution_attested: Literal[True] = Field(
        default=True, alias="independentExecutionAttested"
    )
    confirmation_eligible: Literal[False] = Field(default=False, alias="confirmationEligible")
    assessed_at: datetime = Field(alias="assessedAt")

    @model_validator(mode="after")
    def bind_projection(self) -> Self:
        if self.replay_evidence != tuple(sorted(set(self.replay_evidence))):
            raise ValueError("Walking MCP Claim replay evidence must be unique and sorted")
        assessed_at = _utc(self.assessed_at, label="MCP replay assessment time")
        object.__setattr__(self, "assessed_at", assessed_at)
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"projection_id", "projection_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-claim-replay-projection/v1", material)
        projection_id = f"walking-mcp-claim-replay_{digest}"
        if self.projection_digest and self.projection_digest != digest:
            raise ValueError("Walking MCP Claim replay projection Digest differs")
        if self.projection_id and self.projection_id != projection_id:
            raise ValueError("Walking MCP Claim replay projection ID differs")
        object.__setattr__(self, "projection_digest", digest)
        object.__setattr__(self, "projection_id", projection_id)
        return self


class WalkingMCPClaimReplayAuthority(StrictModel):
    """Complete B2 authority for a fresh Plan-bound validity reproduction."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-mcp-claim-replay/v1alpha1"] = Field(
        default=WALKING_MCP_CLAIM_REPLAY_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WalkingMCPClaimReplayAuthority"] = "WalkingMCPClaimReplayAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    plan: WalkingMCPReplayPlan
    approval: WalkingMCPReplayApprovalReceipt
    execution: SealedWalkingCapabilityExecution
    projection: WalkingMCPClaimReplayProjection
    validation_state: Literal["validity-reproduced-not-confirmed"] = Field(
        default="validity-reproduced-not-confirmed", alias="validationState"
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        original = self.plan.source.execution
        fresh = self.execution
        fresh_ids = (
            (fresh.run_id, original.run_id),
            (fresh.request.request_id, original.request.request_id),
            (fresh.approval.approval.approval_id, original.approval.approval.approval_id),
            (fresh.grant.grant_id, original.grant.grant_id),
            (fresh.permit.permit_id, original.permit.permit_id),
            (fresh.permit.dispatch_id, original.permit.dispatch_id),
            (fresh.worker_result.execution_id, original.worker_result.execution_id),
        )
        if any(current == prior for current, prior in fresh_ids):
            raise ValueError("Walking MCP Replay execution reuses an original freshness identity")
        if (
            self.campaign_digest != self.plan.campaign_digest
            or self.approval.plan_id != self.plan.plan_id
            or self.approval.plan_digest != self.plan.plan_digest
            or self.approval.claim_id != self.plan.claim.claim_id
            or self.approval.claim_digest != self.plan.claim.claim_digest
            or self.approval.approval.request_id != fresh.request.request_id
            or self.approval.approval.request_digest
            != capability_tool_request_digest(fresh.request)
            or self.approval.approval.capability_grant_digest
            != capability_grant_digest(fresh.grant)
        ):
            raise ValueError("Walking MCP Replay approval differs from Plan-bound execution")
        source_request = original.request
        if (
            fresh.request.agent_id != source_request.agent_id
            or fresh.request.tool_id != self.plan.tool_id
            or fresh.request.target != self.plan.target
            or fresh.request.method != self.plan.method
            or fresh.request.arguments != source_request.arguments
            or capability_normalized_parameters_digest(fresh.request.arguments)
            != self.plan.normalized_parameters_digest
        ):
            raise ValueError("Walking MCP Replay execution changes planned request semantics")
        replay_candidate = walking_candidate_from_execution(self.plan.source.replan, fresh)
        replay_validity_claims = tuple(
            claim
            for claim in candidate_atomic_claims(replay_candidate)
            if claim.claim_type is AtomicClaimType.VALIDITY
        )
        expected_projection = _replay_projection(self.plan, fresh)
        source_claim = self.plan.source.candidate.claim
        if (
            len(replay_validity_claims) != 1
            or replay_validity_claims[0].statement != self.plan.claim.statement
            or replay_candidate.claim.title != source_claim.title
            or replay_candidate.claim.summary != source_claim.summary
            or replay_candidate.claim.impact != source_claim.impact
            or replay_candidate.claim.target != source_claim.target
            or replay_candidate.claim.threat_class != source_claim.threat_class
            or self.projection != expected_projection
        ):
            raise ValueError("Walking MCP Replay result does not reproduce its validity Claim")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"authority_id", "authority_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-claim-replay-authority/v1", material)
        authority_id = f"walking-mcp-claim-replay_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking MCP Claim replay authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking MCP Claim replay authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Walking MCP Claim replay authority",
            max_bytes=_MAX_PLAN_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingMCPClaimReplayOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: WalkingMCPClaimReplayAuthority


class WalkingMCPClaimReplayRunner:
    """Verify and seal one B1 Plan-bound fresh replay without granting confirmation."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        plan_outcome: WalkingMCPReplayPlanOutcome,
        evidence: WalkingExecutionEvidence,
    ) -> WalkingMCPClaimReplayOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            plan = load_walking_mcp_replay_plan(authoritative_campaign, plan_outcome)
            execution = load_sealed_walking_capability_execution(plan.source.replan, evidence)
            receipt = walking_mcp_replay_approval_receipt(
                plan, execution.request, evidence.intent, evidence.approval, execution.grant
            )
            snapshot = load_verified_run_artifacts(
                evidence.run_path,
                requests={execution.evidence_path: _MAX_PLAN_BYTES},
                expected_run_id=execution.run_id,
            )
            receipt_events = [
                event
                for event in snapshot.events
                if event.event_type == "walking.mcp-replay-plan.approved"
                and event.payload == receipt.model_dump(mode="json", by_alias=True)
            ]
            claimed = [
                event
                for event in snapshot.events
                if event.event_type == "capability.dispatch.claimed"
                and event.payload.get("permitId") == execution.permit.permit_id
            ]
            if (
                len(receipt_events) != 1
                or len(claimed) != 1
                or receipt_events[0].occurred_at != evidence.approval.approved_at
                or receipt_events[0].sequence >= claimed[0].sequence
            ):
                raise ValueError("Walking MCP Replay Plan receipt was not sealed before dispatch")
            authority = WalkingMCPClaimReplayAuthority(
                campaignDigest=_campaign_digest(authoritative_campaign),
                plan=plan,
                approval=receipt,
                execution=execution,
                projection=_replay_projection(plan, execution),
            )
            source_evidence = snapshot.artifact_bytes(execution.evidence_path)
        except (
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            WalkingCandidateAdmissionError,
            WalkingMCPReplayPlanError,
        ) as exc:
            raise WalkingMCPClaimReplayError(
                "WALK-005B2 MCP Claim replay authority could not be verified"
            ) from exc
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-mcp-claim-replay",
            },
        )
        store.write_json(
            "campaign.json", authoritative_campaign.model_dump(mode="json", by_alias=True)
        )
        store.write_json(
            authority.execution.evidence_path,
            parse_strict_json_bytes(
                source_evidence,
                label="Walking MCP replay copied evidence",
                max_bytes=_MAX_PLAN_BYTES,
            ),
        )
        artifact_path = store.write_json(
            "walking-mcp-claim-replay-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.mcp-claim-replay-authority.created",
            {
                "artifact": artifact_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "planId": authority.plan.plan_id,
                "claimId": authority.projection.claim_id,
                "projectionId": authority.projection.projection_id,
                "validationState": authority.validation_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-mcp-claim-replay-sealed",
                "authorityId": authority.authority_id,
                "validationState": authority.validation_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-mcp-claim-replay", "artifact": artifact_path},
        )
        store.seal()
        return WalkingMCPClaimReplayOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_mcp_claim_replay_authority(
    campaign: CampaignManifest,
    outcome: WalkingMCPClaimReplayOutcome,
) -> WalkingMCPClaimReplayAuthority:
    """Rebuild WALK-005B2 from sealed authority, evidence, and publication event."""

    try:
        evidence_path = outcome.authority.execution.evidence_path
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_PLAN_BYTES,
                outcome.artifact_path: _MAX_PLAN_BYTES,
                evidence_path: _MAX_PLAN_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = WalkingMCPClaimReplayAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
    except (
        OSError,
        RunIntegrityError,
        ValidationError,
        ValueError,
        WalkingCandidateAdmissionError,
    ) as exc:
        raise WalkingMCPClaimReplayError(
            "WALK-005B2 MCP Claim replay authority is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or authority != outcome.authority:
        raise WalkingMCPClaimReplayError(
            "WALK-005B2 MCP Claim replay outcome differs from sealed authority"
        )
    if (
        sha256(snapshot.artifact_bytes(authority.execution.evidence_path)).hexdigest()
        != authority.execution.evidence_sha256
    ):
        raise WalkingMCPClaimReplayError("WALK-005B2 copied replay evidence differs")
    created = [
        event
        for event in snapshot.events
        if event.event_type == "walking.mcp-claim-replay-authority.created"
    ]
    expected = {
        "artifact": outcome.artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "planId": authority.plan.plan_id,
        "claimId": authority.projection.claim_id,
        "projectionId": authority.projection.projection_id,
        "validationState": authority.validation_state,
    }
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingMCPClaimReplayError("WALK-005B2 publication event differs")
    return authority.model_copy(deep=True)


def _replay_projection(
    plan: WalkingMCPReplayPlan,
    execution: SealedWalkingCapabilityExecution,
) -> WalkingMCPClaimReplayProjection:
    return WalkingMCPClaimReplayProjection(
        candidateId=plan.source.candidate.candidate_id,
        claimId=plan.claim.claim_id,
        claimDigest=plan.claim.claim_digest,
        claimType=AtomicClaimType.VALIDITY,
        replayRunId=execution.run_id,
        replayRequestId=execution.request.request_id,
        replayExecutionDigest=execution.execution_digest,
        replayEvidence=tuple(sorted(set(execution.result.evidence))),
        assessedAt=execution.terminal_event.occurred_at,
    )


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)
