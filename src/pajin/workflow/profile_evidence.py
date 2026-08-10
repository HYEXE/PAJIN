"""VAL-004A Profile-floor evaluation over sealed KISA Replay and Control evidence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.validation_depth import (
    ValidationDepth,
    ValidationDepthRequirement,
    resolve_validation_depth_requirement,
)
from pajin.domain.models import CampaignMode, StrictModel, ToolRequest
from pajin.domain.replay import (
    ReplayArtifactSet,
    ReplayAttemptStatus,
    ReplayExecutionStatus,
    ReplayOracleVerdict,
    ReplayPurpose,
    ReplaySessionPolicy,
)
from pajin.domain.validation import AtomicClaim, AtomicClaimType
from pajin.domain.validation_controls import (
    ClaimControlReconciliation,
    ValidationControlAttempt,
    ValidationControlAttemptStatus,
    ValidationControlContrast,
    ValidationControlKind,
    ValidationControlPlan,
    ValidationControlReceipt,
    build_validation_control_receipt,
    reconcile_claim_controls,
    validation_control_digest,
)
from pajin.modes.ai_redteam.replay import KISAReplayBatchOutcome, KISAReplayRecord
from pajin.modes.ai_redteam.validation_controls import (
    KISAValidationControlBatchOutcome,
    KISAValidationControlRunRecord,
    kisa_validation_control_materializers,
)
from pajin.policy.capability import CapabilityRecord
from pajin.replay.verified_result import load_verified_replay_result
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, load_verified_run_artifacts
from pajin.workflow.common_engine import _common_engine_digest
from pajin.workflow.profile_assurance import (
    ProfileAssuranceFloor,
    ProfileAssuranceFloorError,
    resolve_profile_assurance_floor,
)

PROFILE_VALIDATION_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/profile-validation-evidence/v1alpha1"
] = "pajin.dev/profile-validation-evidence/v1alpha1"

_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 12 * 1024 * 1024
_CONTROL_ARTIFACTS = (
    "run.json",
    "control-plan.json",
    "control-requests.json",
    "control-attempts.json",
    "control-receipts.json",
    "control-reconciliation.json",
    "capabilities.json",
)
_CONTROL_KINDS = tuple(ValidationControlKind)


class ProfileValidationEvidenceError(ValueError):
    """Raised when sealed evidence cannot satisfy one exact VAL-003 floor."""


class KISAReplayEvidence(StrictModel):
    """One exact sealed KISA validity Replay result and its bounded repetitions."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/kisa-replay-evidence/v1alpha1"] = Field(
        default="pajin.dev/kisa-replay-evidence/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["KISAReplayEvidence"] = "KISAReplayEvidence"
    evidence_id: str = Field(default="", alias="evidenceId", max_length=320)
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=r"^[a-f0-9]{64}$")
    replay_run_id: str = Field(alias="replayRunId", min_length=1, max_length=200)
    replay_root_digest: str = Field(alias="replayRootDigest", pattern=r"^[a-f0-9]{64}$")
    artifact_set_digest: str = Field(alias="artifactSetDigest", pattern=r"^[a-f0-9]{64}$")
    receipt_seal_root_digest: str = Field(
        alias="receiptSealRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    claim: AtomicClaim
    replay_record: KISAReplayRecord = Field(alias="replayRecord")
    artifact_set: ReplayArtifactSet = Field(alias="artifactSet")
    repetition_count: int = Field(alias="repetitionCount", ge=1, le=20)
    replay_request_ids: tuple[str, ...] = Field(
        alias="replayRequestIds",
        min_length=1,
        max_length=20,
    )
    materialized_session_digests: tuple[str, ...] = Field(
        alias="materializedSessionDigests",
        min_length=1,
        max_length=20,
    )
    replay_capability_grant_id: str = Field(
        alias="replayCapabilityGrantId",
        min_length=1,
        max_length=200,
    )
    evidence_references: tuple[str, ...] = Field(
        alias="evidenceReferences",
        min_length=1,
        max_length=100,
    )
    source_kind: Literal["kisa-claim-replay"] = Field(
        default="kisa-claim-replay",
        alias="sourceKind",
    )
    sealed_replay_verified: Literal[True] = Field(
        default=True,
        alias="sealedReplayVerified",
    )
    fresh_execution_lineage_verified: Literal[True] = Field(
        default=True,
        alias="freshExecutionLineageVerified",
    )

    @field_validator(
        "sealed_replay_verified",
        "fresh_execution_lineage_verified",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("KISA Replay evidence markers must be boolean true")
        return value

    @model_validator(mode="after")
    def bind_replay_evidence(self) -> Self:
        packet = self.artifact_set.validation_packet
        spec = self.artifact_set.spec
        outcome = self.artifact_set.outcome
        claim = packet.claim
        attempts = tuple(outcome.attempts)
        materializations = tuple(item.materialization for item in attempts)
        lineage = self.replay_record.replay_lineage
        if claim is None or claim.claim_type is not AtomicClaimType.VALIDITY:
            raise ValueError("VAL-004A KISA evidence requires one exact validity Claim")
        if (
            lineage is None
            or self.claim != claim
            or self.candidate_id != packet.candidate.candidate_id
            or self.candidate_id != claim.candidate_id
            or self.source_run_id != packet.candidate_run_id
            or self.source_root_digest != lineage.candidate_source_root_digest
            or self.artifact_set_digest != lineage.artifact_set_digest
            or self.receipt_seal_root_digest != lineage.receipt_seal_root_digest
        ):
            raise ValueError("KISA Replay evidence Claim or source lineage differs")
        if (
            self.replay_run_id != spec.binding.replay_run_id
            or self.replay_root_digest != self.receipt_seal_root_digest
            or self.replay_record.candidate_id != self.candidate_id
            or self.replay_record.replay_run_id != self.replay_run_id
            or self.replay_record.outcome_id != outcome.outcome_id
            or self.replay_record.execution_status is not ReplayExecutionStatus.SUCCEEDED
            or self.replay_record.oracle_verdict is not ReplayOracleVerdict.SUPPORTS
            or not self.replay_record.supports_claim
            or self.replay_record.contradicts_claim
            or not self.replay_record.all_attempts_succeeded
            or self.replay_record.receipt_seal_root_digest != self.receipt_seal_root_digest
        ):
            raise ValueError("KISA Replay evidence record differs from its sealed result")
        if (
            spec.purpose is not ReplayPurpose.CONFIRMATION
            or spec.session_policy is not ReplaySessionPolicy.FRESH_SESSION
            or outcome.execution_status is not ReplayExecutionStatus.SUCCEEDED
            or not outcome.supports_claim
            or outcome.oracle_result is None
            or outcome.oracle_result.verdict is not ReplayOracleVerdict.SUPPORTS
            or not attempts
            or any(item.status is not ReplayAttemptStatus.SUCCEEDED for item in attempts)
            or any(item is None for item in materializations)
        ):
            raise ValueError("KISA Replay evidence did not complete as fresh supporting Replay")
        session_digests = tuple(
            item.materialized_session_digest for item in materializations if item is not None
        )
        evidence_sets = tuple(set(item.evidence) for item in attempts)
        if any(
            left & right
            for index, left in enumerate(evidence_sets)
            for right in evidence_sets[index + 1 :]
        ):
            raise ValueError("KISA Replay repetitions must have disjoint evidence lineage")
        if (
            self.repetition_count != len(attempts)
            or self.repetition_count != spec.repetitions
            or self.replay_request_ids != tuple(outcome.replay_request_ids)
            or self.materialized_session_digests != session_digests
            or len(session_digests) != len(set(session_digests))
            or self.replay_capability_grant_id != spec.grant_id
            or self.evidence_references != tuple(outcome.evidence)
            or len(self.evidence_references) != len(set(self.evidence_references))
        ):
            raise ValueError("KISA Replay evidence summary differs from its artifact set")
        material = _canonical_evidence_material(
            self.model_dump(
                mode="python",
                by_alias=True,
                exclude={"evidence_id", "evidence_digest"},
            )
        )
        digest = _common_engine_digest(
            "pajin.validation.kisa-replay-evidence/v1",
            material,
            max_bytes=_MAX_EVIDENCE_BYTES,
        )
        evidence_id = f"kisa-replay-evidence:{self.candidate_id}:{digest}"
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("KISA Replay Evidence Digest differs")
        if self.evidence_id and self.evidence_id != evidence_id:
            raise ValueError("KISA Replay Evidence ID differs")
        object.__setattr__(self, "evidence_digest", digest)
        object.__setattr__(self, "evidence_id", evidence_id)
        return self


class KISAControlEvidence(StrictModel):
    """One exact sealed three-Control contrast over the same KISA validity Claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/kisa-control-evidence/v1alpha1"] = Field(
        default="pajin.dev/kisa-control-evidence/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["KISAControlEvidence"] = "KISAControlEvidence"
    evidence_id: str = Field(default="", alias="evidenceId", max_length=320)
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    control_run_id: str = Field(alias="controlRunId", min_length=1, max_length=200)
    control_root_digest: str = Field(
        alias="controlRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    record: KISAValidationControlRunRecord
    plan: ValidationControlPlan
    requests: tuple[ToolRequest, ...] = Field(min_length=3, max_length=3)
    attempts: tuple[ValidationControlAttempt, ...] = Field(min_length=3, max_length=3)
    receipts: tuple[ValidationControlReceipt, ...] = Field(min_length=3, max_length=3)
    reconciliation: ClaimControlReconciliation
    capabilities: tuple[CapabilityRecord, ...] = Field(min_length=4, max_length=4)
    run_artifact_sha256: str = Field(alias="runArtifactSha256", pattern=r"^[a-f0-9]{64}$")
    plan_artifact_sha256: str = Field(
        alias="planArtifactSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    requests_artifact_sha256: str = Field(
        alias="requestsArtifactSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    attempts_artifact_sha256: str = Field(
        alias="attemptsArtifactSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    receipts_artifact_sha256: str = Field(
        alias="receiptsArtifactSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    reconciliation_artifact_sha256: str = Field(
        alias="reconciliationArtifactSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    capabilities_artifact_sha256: str = Field(
        alias="capabilitiesArtifactSha256",
        pattern=r"^[a-f0-9]{64}$",
    )
    source_kind: Literal["kisa-validation-controls"] = Field(
        default="kisa-validation-controls",
        alias="sourceKind",
    )
    sealed_controls_verified: Literal[True] = Field(
        default=True,
        alias="sealedControlsVerified",
    )

    @field_validator("sealed_controls_verified", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("KISA Control evidence markers must be boolean true")
        return value

    @model_validator(mode="after")
    def bind_control_evidence(self) -> Self:
        kinds = tuple(ValidationControlKind)
        if (
            self.control_run_id != self.record.control_run_id
            or self.control_root_digest != self.record.control_run_root_digest
            or self.record.source_run_id != self.plan.source_run_id
            or self.record.candidate_id != self.plan.candidate_id
            or self.record.claim_id != self.plan.claim_id
            or self.record.plan_id != self.plan.plan_id
            or self.record.reconciliation_id != self.reconciliation.reconciliation_id
            or tuple(self.record.receipt_ids) != tuple(item.receipt_id for item in self.receipts)
            or not self.record.informational_only
            or self.record.confirmation_eligible
        ):
            raise ValueError("KISA Control record differs from its sealed artifacts")
        if (
            tuple(item.control_kind for item in self.plan.controls) != kinds
            or tuple(item.control_kind for item in self.attempts) != kinds
            or tuple(item.control_kind for item in self.receipts) != kinds
        ):
            raise ValueError("KISA Control evidence must retain canonical Control order")
        definitions = {item.control_kind: item for item in self.plan.controls}
        requests = {item.request_id: item for item in self.requests}
        if len(requests) != len(self.requests):
            raise ValueError("KISA Control evidence contains duplicate requests")
        for attempt, receipt in zip(self.attempts, self.receipts, strict=True):
            definition = definitions[attempt.control_kind]
            request = requests.get(attempt.request_id)
            if (
                request is None
                or attempt.plan_id != self.plan.plan_id
                or attempt.control_id != definition.control_id
                or attempt.request_digest != definition.request_digest
                or validation_control_digest(request.model_dump(mode="json"))
                != definition.request_digest
                or attempt.status is not ValidationControlAttemptStatus.SUCCEEDED
                or attempt.observed is not definition.expected_observed
                or receipt != build_validation_control_receipt(attempt)
            ):
                raise ValueError("KISA Control attempt or receipt differs from its Plan")
        if (
            self.reconciliation != reconcile_claim_controls(self.plan, list(self.receipts))
            or self.reconciliation.contrast is not ValidationControlContrast.OBSERVED
        ):
            raise ValueError("KISA Control evidence does not prove the planned contrast")
        evidence_sets = tuple(set(item.evidence) for item in self.receipts)
        if any(
            left & right
            for index, left in enumerate(evidence_sets)
            for right in evidence_sets[index + 1 :]
        ):
            raise ValueError("KISA Control evidence lineage must be disjoint")
        roots = [item for item in self.capabilities if item.grant.parent_grant_id is None]
        children = [item for item in self.capabilities if item.grant.parent_grant_id is not None]
        if len(roots) != 1 or len(children) != 3:
            raise ValueError("KISA Control evidence requires one root and three child Capabilities")
        root = roots[0]
        children_by_id = {item.grant.grant_id: item for item in children}
        if len(children_by_id) != len(children):
            raise ValueError("KISA Control child Capability IDs must be unique")
        for attempt in self.attempts:
            child = children_by_id.get(attempt.capability_grant_id)
            request = requests[attempt.request_id]
            if (
                child is None
                or attempt.capability_parent_grant_id != root.grant.grant_id
                or child.grant.parent_grant_id != root.grant.grant_id
                or not child.grant.attenuates(root.grant)
                or child.grant.subject != request.agent_id
                or child.grant.tools != {request.tool_id}
                or child.grant.targets != {request.target}
                or child.grant.max_calls != 1
                or child.remaining_calls != 0
                or child.grant.delegable
                or not child.revoked
            ):
                raise ValueError("KISA Control Capability lineage differs from execution")
        if (
            not root.revoked
            or root.revoke_reason != "validation Control Run completed"
            or not root.grant.delegable
            or root.remaining_calls != root.grant.max_calls - len(children)
        ):
            raise ValueError("KISA Control root Capability must be revoked after execution")
        material = _canonical_evidence_material(
            self.model_dump(
                mode="python",
                by_alias=True,
                exclude={"evidence_id", "evidence_digest"},
            )
        )
        digest = _common_engine_digest(
            "pajin.validation.kisa-control-evidence/v1",
            material,
            max_bytes=_MAX_EVIDENCE_BYTES,
        )
        evidence_id = f"kisa-control-evidence:{self.plan.candidate_id}:{digest}"
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("KISA Control Evidence Digest differs")
        if self.evidence_id and self.evidence_id != evidence_id:
            raise ValueError("KISA Control Evidence ID differs")
        object.__setattr__(self, "evidence_digest", digest)
        object.__setattr__(self, "evidence_id", evidence_id)
        return self


class ProfileValidationEvidenceAssessment(StrictModel):
    """Content-addressed proof that KISA evidence satisfies one exact Profile floor."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/profile-validation-evidence/v1alpha1"] = Field(
        default=PROFILE_VALIDATION_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ProfileValidationEvidenceAssessment"] = "ProfileValidationEvidenceAssessment"
    assessment_id: str = Field(default="", alias="assessmentId", max_length=320)
    assessment_digest: str = Field(default="", alias="assessmentDigest", max_length=64)
    profile_floor: ProfileAssuranceFloor = Field(alias="profileFloor")
    claim: AtomicClaim
    replay_evidence: KISAReplayEvidence = Field(alias="replayEvidence")
    control_evidence: KISAControlEvidence | None = Field(
        default=None,
        alias="controlEvidence",
    )
    achieved_depth: ValidationDepth = Field(alias="achievedDepth")
    achieved_requirement: ValidationDepthRequirement = Field(alias="achievedRequirement")
    validation_state: Literal["profile-floor-satisfied-not-confirmed"] = Field(
        default="profile-floor-satisfied-not-confirmed",
        alias="validationState",
    )
    evidence_source_constraint: Literal["kisa-ai-redteam-v1"] = Field(
        default="kisa-ai-redteam-v1",
        alias="evidenceSourceConstraint",
    )
    evidence_evaluation_performed: Literal[True] = Field(
        default=True,
        alias="evidenceEvaluationPerformed",
    )
    floor_satisfied: Literal[True] = Field(default=True, alias="floorSatisfied")
    profile_selection_attested: Literal[False] = Field(
        default=False,
        alias="profileSelectionAttested",
    )
    campaign_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="campaignMutationAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator("evidence_evaluation_performed", "floor_satisfied", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Profile evidence satisfaction markers must be boolean true")
        return value

    @field_validator(
        "profile_selection_attested",
        "campaign_mutation_authorized",
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Profile evidence authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_assessment(self) -> Self:
        floor = resolve_profile_assurance_floor(
            self.profile_floor.profile_id,
            self.profile_floor.profile_version,
        )
        achieved = _achieved_requirement(self.replay_evidence, self.control_evidence)
        if self.profile_floor != floor:
            raise ValueError("Profile evidence assessment Floor differs from code authority")
        if self.claim != self.replay_evidence.claim:
            raise ValueError("Profile evidence assessment Claim differs from Replay evidence")
        if self.control_evidence is not None:
            _validate_control_against_replay(self.control_evidence, self.replay_evidence)
        if (
            self.achieved_depth is not achieved.depth
            or self.achieved_requirement != achieved
            or ReplaySessionPolicy.FRESH_SESSION not in achieved.allowed_replay_session_policies
            or achieved.depth_ordinal < floor.minimum_depth_ordinal
        ):
            raise ValueError("Profile evidence does not satisfy the registered Floor")
        material = _canonical_evidence_material(
            self.model_dump(
                mode="python",
                by_alias=True,
                exclude={"assessment_id", "assessment_digest"},
            )
        )
        digest = _common_engine_digest(
            "pajin.validation.profile-validation-evidence/v1",
            material,
            max_bytes=_MAX_EVIDENCE_BYTES,
        )
        assessment_id = f"profile-validation-evidence:{floor.profile_id}:{digest}"
        if self.assessment_digest and self.assessment_digest != digest:
            raise ValueError("Profile Validation Evidence Digest differs")
        if self.assessment_id and self.assessment_id != assessment_id:
            raise ValueError("Profile Validation Evidence ID differs")
        object.__setattr__(self, "assessment_digest", digest)
        object.__setattr__(self, "assessment_id", assessment_id)
        return self


def evaluate_kisa_profile_validation_evidence(
    profile_id: str,
    profile_version: str,
    candidate_id: str,
    source_run_path: Path,
    replay_outcome: KISAReplayBatchOutcome,
    control_outcome: KISAValidationControlBatchOutcome | None = None,
) -> ProfileValidationEvidenceAssessment:
    """Verify sealed KISA evidence and emit a non-confirming Profile-floor assessment."""

    try:
        floor = resolve_profile_assurance_floor(profile_id, profile_version)
        replay = _load_kisa_replay_evidence(
            candidate_id,
            source_run_path,
            replay_outcome,
        )
        controls = (
            None
            if control_outcome is None
            else _load_kisa_control_evidence(candidate_id, control_outcome)
        )
        achieved = _achieved_requirement(replay, controls)
        if achieved.depth_ordinal < floor.minimum_depth_ordinal:
            raise ValueError("sealed KISA evidence is below the registered Profile floor")
        return ProfileValidationEvidenceAssessment(
            profileFloor=floor,
            claim=replay.claim,
            replayEvidence=replay,
            controlEvidence=controls,
            achievedDepth=achieved.depth,
            achievedRequirement=achieved,
        )
    except ProfileValidationEvidenceError:
        raise
    except (
        AttributeError,
        KeyError,
        OSError,
        ProfileAssuranceFloorError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise ProfileValidationEvidenceError(
            "VAL-004A could not verify KISA evidence against the registered Profile floor"
        ) from exc


def verify_kisa_profile_validation_evidence(
    assessment: ProfileValidationEvidenceAssessment,
    source_run_path: Path,
    replay_outcome: KISAReplayBatchOutcome,
    control_outcome: KISAValidationControlBatchOutcome | None = None,
) -> ProfileValidationEvidenceAssessment:
    """Rebuild and exact-match one VAL-004A assessment against sealed predecessors."""

    try:
        canonical = ProfileValidationEvidenceAssessment.model_validate(
            assessment.model_dump(mode="json", by_alias=True)
        )
        expected = evaluate_kisa_profile_validation_evidence(
            canonical.profile_floor.profile_id,
            canonical.profile_floor.profile_version,
            canonical.claim.candidate_id,
            source_run_path,
            replay_outcome,
            control_outcome,
        )
        if canonical != expected:
            raise ValueError("Profile evidence assessment differs from sealed predecessors")
        return canonical
    except ProfileValidationEvidenceError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ProfileValidationEvidenceError(
            "VAL-004A assessment could not be verified against sealed predecessors"
        ) from exc


def _load_kisa_replay_evidence(
    candidate_id: str,
    source_run_path: Path,
    outcome: KISAReplayBatchOutcome,
) -> KISAReplayEvidence:
    if outcome.purpose is not ReplayPurpose.CONFIRMATION:
        raise ValueError("VAL-004A accepts only KISA confirmation Replay evidence")
    records = outcome.verified_records(source_run_path)
    record_matches = [item for item in records if item.candidate_id == candidate_id]
    if len(record_matches) != 1:
        raise ValueError("KISA Replay evidence Candidate is absent or duplicated")
    verified_matches = []
    for stored in outcome.confirmation_results.values():
        verified = load_verified_replay_result(stored.run_path, tickets=outcome.tickets)
        if verified != stored:
            raise ValueError("KISA Replay outcome differs from its sealed result")
        packet = verified.artifact_set.validation_packet
        if (
            packet.candidate.candidate_id == candidate_id
            and packet.claim is not None
            and packet.claim.claim_type is AtomicClaimType.VALIDITY
        ):
            verified_matches.append(verified)
    if len(verified_matches) != 1:
        raise ValueError("KISA validity Replay result is absent or duplicated")
    verified = verified_matches[0]
    artifact = verified.artifact_set
    attempts = tuple(artifact.outcome.attempts)
    materializations = tuple(item.materialization for item in attempts)
    if any(item is None for item in materializations):
        raise ValueError("KISA Replay repetitions lack fresh-session materialization")
    claim = artifact.validation_packet.claim
    assert claim is not None
    return KISAReplayEvidence(
        sourceRunId=artifact.validation_packet.candidate_run_id,
        sourceRootDigest=verified.receipt.candidate_source_root_digest,
        replayRunId=verified.verification.run_id,
        replayRootDigest=verified.verification.root_digest,
        artifactSetDigest=verified.receipt.artifact_set_digest,
        receiptSealRootDigest=verified.receipt_seal_root_digest,
        candidateId=candidate_id,
        claim=claim,
        replayRecord=record_matches[0],
        artifactSet=artifact,
        repetitionCount=len(attempts),
        replayRequestIds=tuple(artifact.outcome.replay_request_ids),
        materializedSessionDigests=tuple(
            item.materialized_session_digest for item in materializations if item is not None
        ),
        replayCapabilityGrantId=artifact.spec.grant_id,
        evidenceReferences=tuple(artifact.outcome.evidence),
    )


def _load_kisa_control_evidence(
    candidate_id: str,
    outcome: KISAValidationControlBatchOutcome,
) -> KISAControlEvidence:
    record_candidate_ids = [item.candidate_id for item in outcome.records]
    records = [item for item in outcome.records if item.candidate_id == candidate_id]
    if (
        len(record_candidate_ids) != len(set(record_candidate_ids))
        or len(records) != 1
        or set(outcome.run_paths) != set(record_candidate_ids)
        or any(item.source_run_id != outcome.source_run_id for item in outcome.records)
    ):
        raise ValueError("KISA Control evidence Candidate mapping is incomplete or duplicated")
    record = records[0]
    run_path = outcome.run_paths[candidate_id]
    snapshot = load_verified_run_artifacts(
        run_path,
        requests={item: _MAX_ARTIFACT_BYTES for item in _CONTROL_ARTIFACTS},
        expected_run_id=record.control_run_id,
    )
    if snapshot.verification.root_digest != record.control_run_root_digest:
        raise ValueError("KISA Control Run root differs from its public record")
    payloads = {item: snapshot.artifact_bytes(item) for item in _CONTROL_ARTIFACTS}
    run_summary = _strict_object(payloads["run.json"], label="KISA Control run summary")
    expected_run_summary = {
        "runId": record.control_run_id,
        "status": "completed",
        "sourceRunId": record.source_run_id,
        "candidateId": record.candidate_id,
        "informationalOnly": True,
        "confirmationEligible": False,
    }
    _require_exact_booleans(
        run_summary,
        informationalOnly=True,
        confirmationEligible=False,
    )
    if run_summary != expected_run_summary:
        raise ValueError("KISA Control Run summary differs from its public record")
    plan_value = _strict_object(payloads["control-plan.json"], label="KISA Control Plan")
    _require_exact_booleans(
        plan_value,
        informationalOnly=True,
        confirmationEligible=False,
    )
    plan = ValidationControlPlan.model_validate(plan_value)
    requests = _strict_model_tuple(
        payloads["control-requests.json"],
        ToolRequest,
        label="KISA Control requests",
    )
    attempt_values = _strict_array(
        payloads["control-attempts.json"],
        label="KISA Control attempts",
    )
    if any(type(item.get("observed")) is not bool for item in attempt_values):
        raise ValueError("successful KISA Control observations must be boolean")
    attempts = tuple(ValidationControlAttempt.model_validate(item) for item in attempt_values)
    receipt_values = _strict_array(
        payloads["control-receipts.json"],
        label="KISA Control receipts",
    )
    for item in receipt_values:
        _require_exact_booleans(
            item,
            informationalOnly=True,
            confirmationEligible=False,
        )
        if type(item.get("observed")) is not bool:
            raise ValueError("successful KISA Control receipt observations must be boolean")
    receipts = tuple(ValidationControlReceipt.model_validate(item) for item in receipt_values)
    reconciliation_value = _strict_object(
        payloads["control-reconciliation.json"],
        label="KISA Control reconciliation",
    )
    _require_exact_booleans(
        reconciliation_value,
        informationalOnly=True,
        confirmationEligible=False,
        candidateDispositionUnchanged=True,
    )
    reconciliation = ClaimControlReconciliation.model_validate(reconciliation_value)
    capability_values = _strict_array(
        payloads["capabilities.json"],
        label="KISA Control capabilities",
    )
    if any(
        type(item.get("revoked")) is not bool or type(item.get("remaining_calls")) is not int
        for item in capability_values
    ):
        raise ValueError("KISA Control Capability markers must be boolean")
    capabilities = tuple(CapabilityRecord.model_validate(item) for item in capability_values)
    created = [item for item in snapshot.events if item.event_type == "control.run.started"]
    completed = [item for item in snapshot.events if item.event_type == "campaign.completed"]
    if len(created) != 1:
        raise ValueError("KISA Control creation event differs")
    _require_exact_booleans(created[0].payload, informationalOnly=True)
    if created[0].payload != {
        "sourceRunId": record.source_run_id,
        "candidateId": record.candidate_id,
        "planId": record.plan_id,
        "informationalOnly": True,
    }:
        raise ValueError("KISA Control creation event differs")
    if len(completed) != 1:
        raise ValueError("KISA Control completion event differs")
    _require_exact_booleans(completed[0].payload, informationalOnly=True)
    if type(completed[0].payload.get("controlCount")) is not int:
        raise ValueError("KISA Control completion count must be an integer")
    if completed[0].payload != {
        "controlCount": 3,
        "contrast": "contrast-observed",
        "informationalOnly": True,
    }:
        raise ValueError("KISA Control completion event differs")
    return KISAControlEvidence(
        controlRunId=record.control_run_id,
        controlRootDigest=record.control_run_root_digest,
        record=record,
        plan=plan,
        requests=requests,
        attempts=attempts,
        receipts=receipts,
        reconciliation=reconciliation,
        capabilities=capabilities,
        runArtifactSha256=sha256(payloads["run.json"]).hexdigest(),
        planArtifactSha256=sha256(payloads["control-plan.json"]).hexdigest(),
        requestsArtifactSha256=sha256(payloads["control-requests.json"]).hexdigest(),
        attemptsArtifactSha256=sha256(payloads["control-attempts.json"]).hexdigest(),
        receiptsArtifactSha256=sha256(payloads["control-receipts.json"]).hexdigest(),
        reconciliationArtifactSha256=sha256(payloads["control-reconciliation.json"]).hexdigest(),
        capabilitiesArtifactSha256=sha256(payloads["capabilities.json"]).hexdigest(),
    )


def _validate_control_against_replay(
    controls: KISAControlEvidence,
    replay: KISAReplayEvidence,
) -> None:
    plan = controls.plan
    artifact = replay.artifact_set
    packet = artifact.validation_packet
    spec = artifact.spec
    claim = replay.claim
    if (
        plan.source_run_id != replay.source_run_id
        or plan.source_root_digest != replay.source_root_digest
        or plan.candidate_id != replay.candidate_id
        or plan.candidate_claim_digest != claim.candidate_claim_digest
        or plan.claim_id != claim.claim_id
        or plan.claim_digest != claim.claim_digest
        or plan.scenario_id != packet.scenario_id
        or plan.original_request_id != spec.binding.original_request_id
        or plan.original_request_digest != spec.original_request_digest
    ):
        raise ValueError("KISA Control evidence belongs to another Claim or source")
    request_tool_ids = {item.tool_id for item in controls.requests}
    if len(request_tool_ids) != 1:
        raise ValueError("KISA Control requests must use one exact Tool")
    materializer = kisa_validation_control_materializers().resolve(
        materializer_id=plan.materializer_id,
        materializer_version=plan.materializer_version,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=plan.scenario_id,
        tool_id=next(iter(request_tool_ids)),
        scenario_digest=plan.scenario_digest,
    )
    nonce = _control_nonce(plan)
    expected = materializer.materialize(spec.arguments, nonce=nonce)
    by_kind = {item.control_kind: item for item in expected}
    definitions = {item.control_kind: item for item in plan.controls}
    requests = {item.request_id: item for item in controls.requests}
    for kind in _CONTROL_KINDS:
        definition = definitions[kind]
        request = requests[definition.request_id]
        variant = by_kind[kind]
        portable_kind = kind.value.replace("-", "_")
        if (
            definition.control_id != f"control_{nonce}:{kind.value}"
            or definition.request_id != f"control_{nonce}_{portable_kind}"
            or request.request_id != definition.request_id
            or request.agent_id != "agent:kisa-validation-control-executor"
            or request.tool_id != spec.binding.tool_id
            or request.target != spec.binding.target
            or request.method != spec.method
            or request.arguments != variant.arguments
            or definition.session_id != variant.session_id
            or definition.expected_observed is not variant.expected_observed
        ):
            raise ValueError("KISA Control materialization differs from code authority")
    control_request_ids = {item.request_id for item in controls.requests}
    control_grant_ids = {item.grant.grant_id for item in controls.capabilities}
    control_evidence = {reference for item in controls.receipts for reference in item.evidence}
    replay_evidence = set(replay.evidence_references)
    replay_session_digests = set(replay.materialized_session_digests)
    control_session_digests = {
        sha256(item.session_id.encode("utf-8")).hexdigest() for item in plan.controls
    }
    source_session = spec.arguments.get("session_id")
    if not isinstance(source_session, str):
        raise ValueError("KISA Replay source lacks an exact session identity")
    source_session_digest = sha256(source_session.encode("utf-8")).hexdigest()
    if (
        plan.original_request_id in control_request_ids
        or control_request_ids & set(replay.replay_request_ids)
        or replay.replay_capability_grant_id in control_grant_ids
        or control_evidence & replay_evidence
        or control_session_digests & replay_session_digests
        or source_session_digest in control_session_digests
    ):
        raise ValueError("KISA Replay and Control execution lineage is not independent")
    roots = [item for item in controls.capabilities if item.grant.parent_grant_id is None]
    if len(roots) != 1:
        raise ValueError("KISA Control evidence requires one root Capability")
    root = roots[0].grant
    if (
        root.subject != "supervisor:kisa-validation-control-executor"
        or root.campaign != spec.binding.campaign
        or root.tools != {spec.binding.tool_id}
        or root.targets != {spec.binding.target}
    ):
        raise ValueError("KISA Control root Capability differs from Replay semantics")


def _achieved_requirement(
    replay: KISAReplayEvidence,
    controls: KISAControlEvidence | None,
) -> ValidationDepthRequirement:
    if controls is None:
        depth = ValidationDepth.SINGLE_VALIDITY_REPLAY
    elif replay.repetition_count >= 2:
        depth = ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY
    else:
        depth = ValidationDepth.CONTROLLED_VALIDITY_REPLAY
    return resolve_validation_depth_requirement(depth)


def _control_nonce(plan: ValidationControlPlan) -> str:
    prefixes: set[str] = set()
    for definition in plan.controls:
        suffix = f":{definition.control_kind.value.replace('-', '_')}"
        if not definition.session_id.startswith(
            "pajin:control:"
        ) or not definition.session_id.endswith(suffix):
            raise ValueError("KISA Control session identity differs from code authority")
        prefixes.add(definition.session_id[len("pajin:control:") : -len(suffix)])
    if len(prefixes) != 1:
        raise ValueError("KISA Control sessions do not share one materialization nonce")
    nonce = prefixes.pop()
    if not nonce:
        raise ValueError("KISA Control materialization nonce is empty")
    return nonce


def _strict_object(value: bytes, *, label: str) -> dict[str, object]:
    parsed = parse_strict_json_bytes(value, label=label, max_bytes=_MAX_ARTIFACT_BYTES)
    if not isinstance(parsed, dict) or not all(isinstance(key, str) for key in parsed):
        raise ValueError(f"{label} must be a JSON object")
    return parsed


def _strict_array(value: bytes, *, label: str) -> tuple[dict[str, object], ...]:
    parsed = parse_strict_json_bytes(value, label=label, max_bytes=_MAX_ARTIFACT_BYTES)
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        raise ValueError(f"{label} must be a JSON object array")
    return tuple(parsed)


def _strict_model_tuple[T: StrictModel](
    value: bytes,
    model: type[T],
    *,
    label: str,
) -> tuple[T, ...]:
    return tuple(model.model_validate(item) for item in _strict_array(value, label=label))


def _require_exact_booleans(value: Mapping[str, object], **expected: bool) -> None:
    for field, required in expected.items():
        observed = value.get(field)
        if type(observed) is not bool or observed is not required:
            raise ValueError(f"{field} must be the exact boolean {required}")


def _canonical_evidence_material(value: object) -> object:
    """Normalize nested model values without process-specific set ordering."""

    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("Profile evidence contains a non-string mapping key")
        return {key: _canonical_evidence_material(value[key]) for key in sorted(value)}
    if isinstance(value, (set, frozenset)):
        items = [_canonical_evidence_material(item) for item in value]
        return sorted(items, key=_canonical_evidence_sort_key)
    if isinstance(value, (list, tuple)):
        return [_canonical_evidence_material(item) for item in value]
    if isinstance(value, Enum):
        return _canonical_evidence_material(value.value)
    if isinstance(value, datetime):
        normalized = (
            value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
        )
        return normalized.isoformat()
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Profile evidence contains unsupported type: {type(value).__name__}")


def _canonical_evidence_sort_key(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
