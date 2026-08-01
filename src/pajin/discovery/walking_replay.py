"""Claim-bound, non-executable MCP Replay planning for WALK-005B1."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.capabilities.activation import capability_normalized_parameters_digest
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.walking import _campaign_digest
from pajin.discovery.walking_validation import (
    WalkingCandidateAdmissionAuthority,
    WalkingCandidateAdmissionError,
    WalkingCandidateAdmissionOutcome,
    load_walking_candidate_admission_authority,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.domain.validation import AtomicClaim, AtomicClaimType
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

WALKING_MCP_REPLAY_PLAN_API_VERSION: Literal["pajin.dev/walking-mcp-replay-plan/v1alpha1"] = (
    "pajin.dev/walking-mcp-replay-plan/v1alpha1"
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
