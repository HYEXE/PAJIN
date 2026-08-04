"""Non-executing Shadow Supervisor decision record for WALK-006."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.walking import _campaign_digest
from pajin.discovery.walking_closure import (
    WalkingMCPRetestAuthority,
    WalkingMCPRetestError,
    WalkingMCPRetestOutcome,
    load_walking_mcp_retest_authority,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

WALKING_SHADOW_SUPERVISOR_API_VERSION: Literal[
    "pajin.dev/walking-shadow-supervisor/v1alpha1"
] = "pajin.dev/walking-shadow-supervisor/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_AUTHORITY_BYTES = 12 * 1024 * 1024


class WalkingShadowSupervisorError(RuntimeError):
    """Raised when WALK-006 cannot prove a non-executing Shadow decision."""


class RegisteredWalkingShadowPolicy(StrictModel):
    """Code-owned policy for the first completed still-vulnerable Walking chain."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    policy_id: Literal["pajin.walk.shadow-supervisor.still-vulnerable.v1"] = Field(
        default="pajin.walk.shadow-supervisor.still-vulnerable.v1",
        alias="policyId",
    )
    policy_version: Literal["1.0.0"] = Field(default="1.0.0", alias="policyVersion")
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    required_lifecycle_state: Literal["retest-completed-still-vulnerable"] = Field(
        default="retest-completed-still-vulnerable",
        alias="requiredLifecycleState",
    )
    selected_task_kind: Literal["human-remediation-review"] = Field(
        default="human-remediation-review",
        alias="selectedTaskKind",
    )
    stop_action: Literal["stop-autonomous-execution"] = Field(
        default="stop-autonomous-execution",
        alias="stopAction",
    )

    @model_validator(mode="after")
    def bind_policy(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"policy_digest"})
        digest = discovery_digest("pajin.walking.shadow-supervisor-policy/v1", material)
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Walking Shadow Supervisor Policy Digest differs")
        object.__setattr__(self, "policy_digest", digest)
        return self


class WalkingShadowInputSnapshot(StrictModel):
    """Minimal immutable lifecycle projection visible to the Shadow policy."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    snapshot_id: str = Field(default="", alias="snapshotId", max_length=110)
    snapshot_digest: str = Field(default="", alias="snapshotDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source_authority_id: str = Field(alias="sourceAuthorityId", min_length=1, max_length=110)
    source_authority_digest: _Sha256 = Field(alias="sourceAuthorityDigest")
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: Literal["walking-mcp-retest-authority.json"] = Field(
        default="walking-mcp-retest-authority.json",
        alias="sourceArtifactPath",
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    finding_id: str = Field(alias="findingId", min_length=1, max_length=200)
    remediation_id: str = Field(alias="remediationId", min_length=1, max_length=110)
    remediation_digest: _Sha256 = Field(alias="remediationDigest")
    retest_assessment_id: str = Field(alias="retestAssessmentId", min_length=1, max_length=110)
    retest_assessment_digest: _Sha256 = Field(alias="retestAssessmentDigest")
    retest_status: Literal["still-vulnerable"] = Field(alias="retestStatus")
    autonomous_execution_state: Literal["stopped"] = Field(
        default="stopped",
        alias="autonomousExecutionState",
    )

    @model_validator(mode="after")
    def bind_snapshot(self) -> Self:
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"snapshot_id", "snapshot_digest"}
        )
        digest = discovery_digest("pajin.walking.shadow-input-snapshot/v1", material)
        snapshot_id = f"walking-shadow-snapshot_{digest}"
        if self.snapshot_digest and self.snapshot_digest != digest:
            raise ValueError("Walking Shadow input Snapshot Digest differs")
        if self.snapshot_id and self.snapshot_id != snapshot_id:
            raise ValueError("Walking Shadow input Snapshot ID differs")
        object.__setattr__(self, "snapshot_digest", digest)
        object.__setattr__(self, "snapshot_id", snapshot_id)
        return self


class WalkingShadowTaskProposal(StrictModel):
    """Human-only Task the Shadow policy would select without scheduling it."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    proposal_id: str = Field(default="", alias="proposalId", max_length=110)
    proposal_digest: str = Field(default="", alias="proposalDigest", max_length=64)
    policy_id: str = Field(alias="policyId", min_length=1, max_length=200)
    policy_digest: _Sha256 = Field(alias="policyDigest")
    snapshot_id: str = Field(alias="snapshotId", min_length=1, max_length=110)
    snapshot_digest: _Sha256 = Field(alias="snapshotDigest")
    task_kind: Literal["human-remediation-review"] = Field(alias="taskKind")
    title: Literal["Review and assign the sealed MCP remediation Plan"] = (
        "Review and assign the sealed MCP remediation Plan"
    )
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    finding_id: str = Field(alias="findingId", min_length=1, max_length=200)
    remediation_id: str = Field(alias="remediationId", min_length=1, max_length=110)
    assigned_role: Literal["human:remediation-owner"] = Field(
        default="human:remediation-owner",
        alias="assignedRole",
    )
    required_capabilities: tuple[str, ...] = Field(
        default=(),
        alias="requiredCapabilities",
        max_length=0,
    )
    execution_state: Literal["proposed-not-authorized"] = Field(
        default="proposed-not-authorized",
        alias="executionState",
    )

    @model_validator(mode="after")
    def bind_proposal(self) -> Self:
        if self.required_capabilities:
            raise ValueError("Walking Shadow Task cannot request a Capability")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"proposal_id", "proposal_digest"}
        )
        digest = discovery_digest("pajin.walking.shadow-task-proposal/v1", material)
        proposal_id = f"walking-shadow-task_{digest}"
        if self.proposal_digest and self.proposal_digest != digest:
            raise ValueError("Walking Shadow Task Proposal Digest differs")
        if self.proposal_id and self.proposal_id != proposal_id:
            raise ValueError("Walking Shadow Task Proposal ID differs")
        object.__setattr__(self, "proposal_digest", digest)
        object.__setattr__(self, "proposal_id", proposal_id)
        return self


class WalkingShadowStopDecision(StrictModel):
    """Non-executing decision to stop autonomy and require human escalation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    decision_id: str = Field(default="", alias="decisionId", max_length=110)
    decision_digest: str = Field(default="", alias="decisionDigest", max_length=64)
    policy_id: str = Field(alias="policyId", min_length=1, max_length=200)
    policy_digest: _Sha256 = Field(alias="policyDigest")
    snapshot_id: str = Field(alias="snapshotId", min_length=1, max_length=110)
    snapshot_digest: _Sha256 = Field(alias="snapshotDigest")
    selected_task_proposal_id: str = Field(
        alias="selectedTaskProposalId", min_length=1, max_length=110
    )
    selected_task_proposal_digest: _Sha256 = Field(alias="selectedTaskProposalDigest")
    action: Literal["stop-autonomous-execution"] = "stop-autonomous-execution"
    reason: Literal["confirmed-finding-remains-vulnerable"] = (
        "confirmed-finding-remains-vulnerable"
    )
    escalation_required: Literal[True] = Field(default=True, alias="escalationRequired")
    execution_allowed: Literal[False] = Field(default=False, alias="executionAllowed")

    @field_validator("escalation_required", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        return _require_literal_bool(value, expected=True)

    @field_validator("execution_allowed", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_decision(self) -> Self:
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"decision_id", "decision_digest"}
        )
        digest = discovery_digest("pajin.walking.shadow-stop-decision/v1", material)
        decision_id = f"walking-shadow-stop_{digest}"
        if self.decision_digest and self.decision_digest != digest:
            raise ValueError("Walking Shadow Stop Decision Digest differs")
        if self.decision_id and self.decision_id != decision_id:
            raise ValueError("Walking Shadow Stop Decision ID differs")
        object.__setattr__(self, "decision_digest", digest)
        object.__setattr__(self, "decision_id", decision_id)
        return self


class WalkingShadowSupervisorAuthority(StrictModel):
    """Complete WALK-006 record; no proposal is applied to an execution graph."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-shadow-supervisor/v1alpha1"] = Field(
        default=WALKING_SHADOW_SUPERVISOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingShadowSupervisorAuthority"] = "WalkingShadowSupervisorAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source: WalkingMCPRetestAuthority
    policy: RegisteredWalkingShadowPolicy
    snapshot: WalkingShadowInputSnapshot
    selected_task: WalkingShadowTaskProposal = Field(alias="selectedTask")
    stop_decision: WalkingShadowStopDecision = Field(alias="stopDecision")
    shadow_mode: Literal[True] = Field(default=True, alias="shadowMode")
    baseline_mutated: Literal[False] = Field(default=False, alias="baselineMutated")
    decision_state: Literal["recorded-not-applied"] = Field(
        default="recorded-not-applied",
        alias="decisionState",
    )

    @field_validator("shadow_mode", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        return _require_literal_bool(value, expected=True)

    @field_validator("baseline_mutated", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        expected_policy = walking_shadow_supervisor_policy()
        expected_task = _task_proposal(expected_policy, self.snapshot)
        expected_stop = _stop_decision(expected_policy, self.snapshot, expected_task)
        assessment = self.source.assessment
        if (
            self.campaign_digest != self.source.campaign_digest
            or self.snapshot.campaign_digest != self.campaign_digest
            or self.snapshot.source_authority_id != self.source.authority_id
            or self.snapshot.source_authority_digest != self.source.authority_digest
            or self.source.lifecycle_state != expected_policy.required_lifecycle_state
            or assessment.status != self.snapshot.retest_status
            or assessment.candidate_id != self.snapshot.candidate_id
            or assessment.finding_id != self.snapshot.finding_id
            or assessment.remediation_id != self.snapshot.remediation_id
            or assessment.remediation_digest != self.snapshot.remediation_digest
            or assessment.assessment_id != self.snapshot.retest_assessment_id
            or assessment.assessment_digest != self.snapshot.retest_assessment_digest
            or self.policy != expected_policy
            or self.selected_task != expected_task
            or self.stop_decision != expected_stop
        ):
            raise ValueError("Walking Shadow Supervisor Decision differs from its sealed input")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"authority_id", "authority_digest"}
        )
        digest = discovery_digest("pajin.walking.shadow-supervisor-authority/v1", material)
        authority_id = f"walking-shadow-supervisor_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking Shadow Supervisor Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking Shadow Supervisor Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Walking Shadow Supervisor authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingShadowSupervisorOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: WalkingShadowSupervisorAuthority


class WalkingShadowSupervisorRunner:
    """Record what the code-owned Shadow policy would select; never schedule it."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        source_outcome: WalkingMCPRetestOutcome,
    ) -> WalkingShadowSupervisorOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            source = load_walking_mcp_retest_authority(
                authoritative_campaign,
                source_outcome,
            )
            source_snapshot = load_verified_run_artifacts(
                source_outcome.run_path,
                requests={source_outcome.authority_path: _MAX_AUTHORITY_BYTES},
                expected_run_id=source_outcome.run_id,
            )
            source_artifact = source_snapshot.artifact_bytes(source_outcome.authority_path)
            if source_outcome.authority_path != "walking-mcp-retest-authority.json":
                raise ValueError("WALK-006 source artifact path differs")
            snapshot = _input_snapshot(
                authoritative_campaign,
                source,
                source_run_id=source_snapshot.verification.run_id,
                source_root_digest=source_snapshot.verification.root_digest,
                source_artifact_sha256=sha256(source_artifact).hexdigest(),
            )
            policy = walking_shadow_supervisor_policy()
            task = _task_proposal(policy, snapshot)
            stop = _stop_decision(policy, snapshot, task)
            authority = WalkingShadowSupervisorAuthority(
                campaignDigest=_campaign_digest(authoritative_campaign),
                source=source,
                policy=policy,
                snapshot=snapshot,
                selectedTask=task,
                stopDecision=stop,
            )
        except (
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            WalkingMCPRetestError,
        ) as exc:
            raise WalkingShadowSupervisorError(
                "WALK-006 Shadow Supervisor authority could not be verified"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-shadow-supervisor",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            "walking-shadow-supervisor-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.shadow-supervisor-authority.created",
            {
                "artifact": artifact_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "snapshotId": authority.snapshot.snapshot_id,
                "selectedTaskProposalId": authority.selected_task.proposal_id,
                "stopDecisionId": authority.stop_decision.decision_id,
                "decisionState": authority.decision_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-shadow-supervisor-sealed",
                "authorityId": authority.authority_id,
                "decisionState": authority.decision_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-shadow-supervisor", "artifact": artifact_path},
        )
        store.seal()
        return WalkingShadowSupervisorOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_shadow_supervisor_authority(
    campaign: CampaignManifest,
    outcome: WalkingShadowSupervisorOutcome,
) -> WalkingShadowSupervisorAuthority:
    """Rebuild WALK-006 from its sealed authority and exact publication event."""

    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_AUTHORITY_BYTES,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = WalkingShadowSupervisorAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise WalkingShadowSupervisorError(
            "WALK-006 Shadow Supervisor authority is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or authority != outcome.authority:
        raise WalkingShadowSupervisorError(
            "WALK-006 Shadow Supervisor outcome differs from sealed authority"
        )
    created = [
        event
        for event in snapshot.events
        if event.event_type == "walking.shadow-supervisor-authority.created"
    ]
    expected = {
        "artifact": outcome.artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "snapshotId": authority.snapshot.snapshot_id,
        "selectedTaskProposalId": authority.selected_task.proposal_id,
        "stopDecisionId": authority.stop_decision.decision_id,
        "decisionState": authority.decision_state,
    }
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingShadowSupervisorError("WALK-006 publication event differs")
    return authority.model_copy(deep=True)


def walking_shadow_supervisor_policy() -> RegisteredWalkingShadowPolicy:
    """Return the single code-registered WALK-006 Shadow policy."""

    return RegisteredWalkingShadowPolicy()


def _input_snapshot(
    campaign: CampaignManifest,
    source: WalkingMCPRetestAuthority,
    *,
    source_run_id: str,
    source_root_digest: str,
    source_artifact_sha256: str,
) -> WalkingShadowInputSnapshot:
    assessment = source.assessment
    return WalkingShadowInputSnapshot(
        campaignDigest=_campaign_digest(campaign),
        sourceAuthorityId=source.authority_id,
        sourceAuthorityDigest=source.authority_digest,
        sourceRunId=source_run_id,
        sourceRootDigest=source_root_digest,
        sourceArtifactPath="walking-mcp-retest-authority.json",
        sourceArtifactSha256=source_artifact_sha256,
        candidateId=assessment.candidate_id,
        findingId=assessment.finding_id,
        remediationId=assessment.remediation_id,
        remediationDigest=assessment.remediation_digest,
        retestAssessmentId=assessment.assessment_id,
        retestAssessmentDigest=assessment.assessment_digest,
        retestStatus=assessment.status,
    )


def _task_proposal(
    policy: RegisteredWalkingShadowPolicy,
    snapshot: WalkingShadowInputSnapshot,
) -> WalkingShadowTaskProposal:
    return WalkingShadowTaskProposal(
        policyId=policy.policy_id,
        policyDigest=policy.policy_digest,
        snapshotId=snapshot.snapshot_id,
        snapshotDigest=snapshot.snapshot_digest,
        taskKind=policy.selected_task_kind,
        candidateId=snapshot.candidate_id,
        findingId=snapshot.finding_id,
        remediationId=snapshot.remediation_id,
    )


def _stop_decision(
    policy: RegisteredWalkingShadowPolicy,
    snapshot: WalkingShadowInputSnapshot,
    task: WalkingShadowTaskProposal,
) -> WalkingShadowStopDecision:
    return WalkingShadowStopDecision(
        policyId=policy.policy_id,
        policyDigest=policy.policy_digest,
        snapshotId=snapshot.snapshot_id,
        snapshotDigest=snapshot.snapshot_digest,
        selectedTaskProposalId=task.proposal_id,
        selectedTaskProposalDigest=task.proposal_digest,
    )


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("Walking Shadow Supervisor boolean must be literal and exact")
    return expected
