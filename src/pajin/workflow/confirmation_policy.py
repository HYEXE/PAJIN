"""Pure replay-confirmation policy and projection derivation.

This module evaluates already verified replay receipts.  It deliberately owns no
filesystem mutation, locking, recovery, or sealing behavior; those responsibilities
live in :mod:`pajin.workflow.confirmation_projection`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from pajin.domain.models import AgentPlan, CampaignManifest, ToolRequest
from pajin.domain.replay import (
    ReplayArtifactSet,
    ReplayExecutionStatus,
    ReplayOracleVerdict,
    replay_evidence_digest,
    replay_request_digest,
)
from pajin.domain.validation import (
    AtomicClaim,
    AtomicClaimType,
    CandidateFinding,
    ClaimReplayAssessment,
    ClaimReplayStatus,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    PublicFindingState,
    ReplayConfirmationLineage,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    VersionedClaimReplaySet,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
    build_claim_replay_assessment,
    candidate_atomic_claims,
)
from pajin.replay.runtime import VerifiedReplayResult
from pajin.reporting import escape_markdown_text, markdown_code_span
from pajin.runtime.safe_files import (
    load_bounded_strict_json,
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)
from pajin.runtime.store import RunIntegritySeal
from pajin.workflow.validation_artifacts import VERSIONED_VALIDATION_INDEX_PATH

_OBJECTIVE_REASONS = frozenset(
    {
        ValidationReasonCode.TARGET_UNDECLARED,
        ValidationReasonCode.TARGET_OUT_OF_SCOPE,
        ValidationReasonCode.THREAT_CLASS_UNDECLARED,
        ValidationReasonCode.EVIDENCE_MISSING,
        ValidationReasonCode.EVIDENCE_UNLINKED,
        ValidationReasonCode.EVIDENCE_FILE_MISSING,
        ValidationReasonCode.SOURCE_REQUEST_MISMATCH,
    }
)
_SEMANTIC_UNAVAILABLE_REASONS = frozenset(
    {
        ValidationReasonCode.VALIDATOR_UNAVAILABLE,
        ValidationReasonCode.VALIDATOR_CANCELLED,
    }
)
_STATUS_REASON = {
    ReplayExecutionStatus.FAILED: ValidationReasonCode.REPLAY_EXECUTION_FAILED,
    ReplayExecutionStatus.CANCELLED: ValidationReasonCode.REPLAY_CANCELLED,
    ReplayExecutionStatus.TIMED_OUT: ValidationReasonCode.REPLAY_TIMED_OUT,
    ReplayExecutionStatus.TARGET_UNAVAILABLE: ValidationReasonCode.REPLAY_TARGET_UNAVAILABLE,
    ReplayExecutionStatus.UNSUPPORTED: ValidationReasonCode.REPLAY_NOT_ELIGIBLE,
}
_MAX_SEALED_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_EVIDENCE_BYTES = 16 * 1024 * 1024
_MAX_RUN_LOG_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _ReplayDisposition:
    disposition: FindingDisposition
    reason: ValidationReasonCode
    summary: str
    confirmation_basis: ConfirmationBasis | None = None


@dataclass(frozen=True, slots=True)
class _ConfirmationProjection:
    validation: FindingValidationSet
    index: VersionedValidationIndex
    decision_set: VersionedValidationDecisionSet
    finding_set: VersionedConfirmedFindingSet
    claim_replay_set: VersionedClaimReplaySet
    report: str
    event_payload: dict[str, Any]
    evaluated_at: datetime


class _SuccessfulDisposition(Protocol):
    def __call__(
        self,
        source_decision: ValidationDecision,
        artifact_set: ReplayArtifactSet,
        *,
        allow_legacy_confirmation_contradiction: bool,
    ) -> _ReplayDisposition: ...


def _build_confirmation_projection(
    *,
    root: Path,
    source_run_id: str,
    source_validation: FindingValidationSet,
    campaign: CampaignManifest,
    plan: AgentPlan,
    verified_results: list[VerifiedReplayResult],
    evaluated_at: datetime,
    successful_replay_disposition: _SuccessfulDisposition | None = None,
) -> _ConfirmationProjection:
    """Derive the complete projection from sealed source and replay inputs."""

    if not verified_results:
        raise ValueError("confirmed gate requires at least one replay receipt")
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("confirmed gate decision time must include a UTC offset or Z")
    evaluated_at = evaluated_at.astimezone(UTC)
    if any(
        decision.disposition is FindingDisposition.CONFIRMED
        or decision.replay_request_ids
        or decision.replay_outcome_ids
        or decision.replay_lineage
        for decision in source_validation.decisions
    ):
        raise ValueError("source validation is not an unreproduced pre-confirmation snapshot")

    _validate_receipt_set(
        root=root,
        source_run_id=source_run_id,
        source_validation=source_validation,
        verified_results=verified_results,
        campaign=campaign,
        plan=plan,
    )
    source_root_digests = {
        result.receipt.candidate_source_root_digest for result in verified_results
    }
    if len(source_root_digests) != 1:
        raise ValueError("confirmed gate receipts must bind one Candidate source seal")
    candidate_source_root_digest = next(iter(source_root_digests))

    _validate_explicit_claim_coverage(
        candidates=source_validation.candidates,
        verified_results=verified_results,
    )
    results_by_candidate = _confirmation_authority_by_candidate(verified_results)
    source_decisions = {decision.candidate_id: decision for decision in source_validation.decisions}
    final_decisions: list[ValidationDecision] = []
    disposition_selector = successful_replay_disposition or _successful_replay_disposition
    for candidate in source_validation.candidates:
        source_decision = source_decisions[candidate.candidate_id]
        verified = results_by_candidate.get(candidate.candidate_id)
        if verified is None:
            final_decisions.append(source_decision)
            continue
        final_decisions.append(
            _decide_replay_confirmation(
                candidate=candidate,
                source_decision=source_decision,
                artifact_set=verified.artifact_set,
                lineage=_lineage(verified),
                decided_at=evaluated_at,
                allow_legacy_confirmation_contradiction=(
                    verified.receipt.api_version == "pajin.dev/replay-verification-receipt/v1"
                ),
                successful_replay_disposition=disposition_selector,
            )
        )

    confirmed_candidate_ids = [
        decision.candidate_id
        for decision in final_decisions
        if decision.disposition is FindingDisposition.CONFIRMED
    ]
    candidates_by_id = {
        candidate.candidate_id: candidate for candidate in source_validation.candidates
    }
    assessments = _build_claim_replay_assessments(
        candidates=source_validation.candidates,
        decisions=final_decisions,
        verified_results=verified_results,
        confirmation_results=results_by_candidate,
    )
    assessments_by_candidate: dict[str, list[ClaimReplayAssessment]] = {}
    for assessment in assessments:
        assessments_by_candidate.setdefault(assessment.candidate_id, []).append(assessment)
    public_states = {
        state: [
            decision.candidate_id
            for decision in final_decisions
            if _public_finding_state(
                decision,
                assessments_by_candidate.get(decision.candidate_id, []),
            )
            is state
        ]
        for state in PublicFindingState
    }
    validation = FindingValidationSet(
        candidates=source_validation.candidates,
        decisions=final_decisions,
        confirmed_findings=[
            candidates_by_id[candidate_id].claim.model_copy(update={"validated": True})
            for candidate_id in confirmed_candidate_ids
        ],
    )
    dispositions = {
        disposition: [
            decision.candidate_id
            for decision in final_decisions
            if decision.disposition is disposition
        ]
        for disposition in FindingDisposition
    }
    index = VersionedValidationIndex(
        sourceRunId=source_run_id,
        candidateSourceRootDigest=candidate_source_root_digest,
        claimReplaysPath="validation/v1alpha1/claim-replays.json",
        dispositions=dispositions,
        publicStates=public_states,
        confirmedCandidateIds=confirmed_candidate_ids,
        generatedAt=evaluated_at,
    )
    decision_set = VersionedValidationDecisionSet(
        sourceRunId=source_run_id,
        decisions=final_decisions,
    )
    finding_set = VersionedConfirmedFindingSet(
        sourceRunId=source_run_id,
        findings=validation.confirmed_findings,
    )
    claim_replay_set = VersionedClaimReplaySet(
        sourceRunId=source_run_id,
        assessments=assessments,
    )
    return _ConfirmationProjection(
        validation=validation,
        index=index,
        decision_set=decision_set,
        finding_set=finding_set,
        claim_replay_set=claim_replay_set,
        report=_render_confirmation_report(index, validation, claim_replay_set),
        event_payload={
            "apiVersion": index.api_version,
            "candidateSourceRootDigest": candidate_source_root_digest,
            "receiptCount": len(verified_results),
            "confirmedCount": len(validation.confirmed_findings),
            "confirmedCandidateIds": confirmed_candidate_ids,
            "partiallyConfirmedCount": len(public_states[PublicFindingState.PARTIALLY_CONFIRMED]),
            "notReproducedCount": len(public_states[PublicFindingState.NOT_REPRODUCED]),
            "index": VERSIONED_VALIDATION_INDEX_PATH,
        },
        evaluated_at=evaluated_at,
    )


def _confirmation_authority_by_candidate(
    verified_results: list[VerifiedReplayResult],
) -> dict[str, VerifiedReplayResult]:
    validity: dict[str, VerifiedReplayResult] = {}
    legacy: dict[str, VerifiedReplayResult] = {}
    claim_ids: set[str] = set()
    for result in verified_results:
        binding = result.artifact_set.outcome.binding
        claim = binding.claim
        if claim is None:
            if binding.candidate_id in legacy:
                raise ValueError("confirmed gate receipts contain duplicate legacy Candidates")
            legacy[binding.candidate_id] = result
            continue
        if claim.claim_id in claim_ids:
            raise ValueError("confirmed gate receipts contain duplicate Atomic Claims")
        claim_ids.add(claim.claim_id)
        if claim.claim_type is AtomicClaimType.VALIDITY:
            if binding.candidate_id in validity:
                raise ValueError("confirmed gate receipts contain duplicate validity Claims")
            validity[binding.candidate_id] = result
    if set(validity) & set(legacy):
        raise ValueError("confirmed gate cannot mix legacy and Claim-bound validity authority")
    return {**legacy, **validity}


def _validate_explicit_claim_coverage(
    *,
    candidates: list[CandidateFinding],
    verified_results: list[VerifiedReplayResult],
) -> None:
    candidates_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    claims_by_candidate: dict[str, set[str]] = {}
    explicit_candidates: set[str] = set()
    for result in verified_results:
        artifact_set = result.artifact_set
        binding = artifact_set.outcome.binding
        claim = binding.claim
        if claim is not None and claim.claim_type is not AtomicClaimType.VALIDITY:
            explicit_candidates.add(binding.candidate_id)
        if claim is not None:
            claims_by_candidate.setdefault(binding.candidate_id, set()).add(claim.claim_id)
    for candidate_id in explicit_candidates:
        candidate = candidates_by_id[candidate_id]
        expected = {claim.claim_id for claim in candidate_atomic_claims(candidate)}
        if claims_by_candidate.get(candidate_id, set()) != expected:
            raise ValueError(
                "explicit Claim replay receipts must cover every Candidate Atomic Claim"
            )


def _build_claim_replay_assessments(
    *,
    candidates: list[CandidateFinding],
    decisions: list[ValidationDecision],
    verified_results: list[VerifiedReplayResult],
    confirmation_results: dict[str, VerifiedReplayResult],
) -> list[ClaimReplayAssessment]:
    decisions_by_candidate = {decision.candidate_id: decision for decision in decisions}
    results_by_claim_id: dict[str, VerifiedReplayResult] = {}
    for result in verified_results:
        result_claim = result.artifact_set.outcome.binding.claim
        if result_claim is not None:
            results_by_claim_id[result_claim.claim_id] = result
    assessments: list[ClaimReplayAssessment] = []
    for candidate in candidates:
        decision = decisions_by_candidate[candidate.candidate_id]
        claims = candidate_atomic_claims(candidate)
        claim_bound = [claim for claim in claims if claim.claim_id in results_by_claim_id]
        if claim_bound:
            for claim in claim_bound:
                verified = results_by_claim_id[claim.claim_id]
                assessments.append(
                    _build_claim_replay_projection(
                        claim=claim,
                        decision=decision,
                        artifact_set=verified.artifact_set,
                        lineage=_lineage(verified),
                    )
                )
        elif decision.replay_lineage:
            assessments.append(
                _build_claim_replay_projection(
                    claim=claims[0],
                    decision=decision,
                    artifact_set=confirmation_results[candidate.candidate_id].artifact_set,
                    lineage=decision.replay_lineage[0],
                )
            )
    return assessments


def _build_claim_replay_projection(
    *,
    claim: AtomicClaim | None = None,
    candidate: CandidateFinding | None = None,
    decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    lineage: ReplayConfirmationLineage,
) -> ClaimReplayAssessment:
    if claim is None:
        if candidate is None:
            raise ValueError("Claim replay projection requires an Atomic Claim")
        claim = candidate_atomic_claims(candidate)[0]
    elif candidate is not None:
        raise ValueError("Claim replay projection accepts either Claim or Candidate")
    claim_binding = artifact_set.outcome.binding.claim
    if claim_binding is not None and (
        claim_binding.claim_id != claim.claim_id
        or claim_binding.claim_digest != claim.claim_digest
        or claim_binding.claim_type is not claim.claim_type
        or claim_binding.candidate_claim_digest != claim.candidate_claim_digest
        or claim_binding.statement != claim.statement
    ):
        raise ValueError("Claim replay artifact differs from its exact Atomic Claim")
    return build_claim_replay_assessment(
        claim=claim,
        lineage=lineage,
        status=(
            _claim_replay_status(decision, artifact_set)
            if claim.claim_type is AtomicClaimType.VALIDITY
            else _claim_replay_status_from_outcome(artifact_set)
        ),
        independent_execution_attested=(
            claim.claim_type is AtomicClaimType.VALIDITY
            and decision.confirmation_basis is ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
        ),
        assessed_at=decision.decided_at,
    )


def _claim_replay_status_from_outcome(
    artifact_set: ReplayArtifactSet,
) -> ClaimReplayStatus:
    outcome = artifact_set.outcome
    if outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED:
        return ClaimReplayStatus.NOT_ELIGIBLE
    if outcome.execution_status is not ReplayExecutionStatus.SUCCEEDED:
        return ClaimReplayStatus.INCONCLUSIVE
    oracle = outcome.oracle_result
    if oracle is None:
        raise ValueError("successful ReplayOutcome is missing its Mode Oracle result")
    if oracle.verdict is ReplayOracleVerdict.SUPPORTS:
        return ClaimReplayStatus.REPRODUCED
    if oracle.verdict is ReplayOracleVerdict.CONTRADICTS:
        return ClaimReplayStatus.NOT_REPRODUCED
    return ClaimReplayStatus.INCONCLUSIVE


def _claim_replay_status(
    decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
) -> ClaimReplayStatus:
    reason = decision.reason_codes[0]
    if (
        reason in _OBJECTIVE_REASONS
        or reason is ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED
    ):
        return ClaimReplayStatus.NOT_ELIGIBLE
    if reason is ValidationReasonCode.EXECUTION_FAILED:
        return ClaimReplayStatus.INCONCLUSIVE
    outcome = artifact_set.outcome
    if outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED:
        return ClaimReplayStatus.NOT_ELIGIBLE
    if outcome.execution_status is not ReplayExecutionStatus.SUCCEEDED:
        return ClaimReplayStatus.INCONCLUSIVE
    oracle = outcome.oracle_result
    if oracle is None:
        raise ValueError("successful ReplayOutcome is missing its Mode Oracle result")
    if oracle.verdict is ReplayOracleVerdict.SUPPORTS:
        return ClaimReplayStatus.REPRODUCED
    if oracle.verdict is ReplayOracleVerdict.CONTRADICTS:
        return ClaimReplayStatus.NOT_REPRODUCED
    return ClaimReplayStatus.INCONCLUSIVE


def _public_finding_state(
    decision: ValidationDecision,
    assessments: list[ClaimReplayAssessment] | ClaimReplayAssessment | None,
) -> PublicFindingState:
    if assessments is None:
        normalized: list[ClaimReplayAssessment] = []
    elif isinstance(assessments, ClaimReplayAssessment):
        normalized = [assessments]
    else:
        normalized = assessments
    if decision.disposition is FindingDisposition.CONFIRMED:
        return PublicFindingState.CONFIRMED
    if not normalized:
        return PublicFindingState(decision.disposition.value)
    reason = decision.reason_codes[0]
    if reason is ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED:
        validity = next(
            (
                assessment
                for assessment in normalized
                if assessment.claim_type is AtomicClaimType.VALIDITY
            ),
            None,
        )
        if validity is None or validity.status is not ClaimReplayStatus.NOT_REPRODUCED:
            raise ValueError("Oracle contradiction must project a not-reproduced Claim")
        return PublicFindingState.NOT_REPRODUCED
    if any(assessment.status is ClaimReplayStatus.REPRODUCED for assessment in normalized):
        return PublicFindingState.PARTIALLY_CONFIRMED
    if any(assessment.status is ClaimReplayStatus.NOT_REPRODUCED for assessment in normalized):
        return PublicFindingState.NOT_REPRODUCED
    if any(assessment.status is ClaimReplayStatus.INCONCLUSIVE for assessment in normalized):
        return PublicFindingState.INCONCLUSIVE
    return PublicFindingState(decision.disposition.value)


def decide_replay_confirmation(
    *,
    candidate: CandidateFinding,
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    lineage: ReplayConfirmationLineage,
    decided_at: datetime,
    independent_execution_attested: bool = False,
) -> ValidationDecision:
    """Pure reason-matrix evaluation over an already verified replay artifact set."""

    return _decide_replay_confirmation(
        candidate=candidate,
        source_decision=source_decision,
        artifact_set=artifact_set,
        lineage=lineage,
        decided_at=decided_at,
        allow_legacy_confirmation_contradiction=False,
        successful_replay_disposition=(
            _independently_attested_successful_replay_disposition
            if independent_execution_attested
            else _successful_replay_disposition
        ),
    )


def _decide_replay_confirmation(
    *,
    candidate: CandidateFinding,
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    lineage: ReplayConfirmationLineage,
    decided_at: datetime,
    allow_legacy_confirmation_contradiction: bool,
    successful_replay_disposition: _SuccessfulDisposition,
) -> ValidationDecision:
    """Evaluate one verified replay with a loader-derived legacy compatibility boundary."""

    outcome = artifact_set.outcome
    decided_at = _validated_decision_time(decided_at, source_decision, lineage)
    _validate_candidate_replay_binding(candidate, source_decision, artifact_set)
    _validate_replay_lineage_binding(candidate, artifact_set, lineage)
    selected = _select_replay_disposition(
        source_decision=source_decision,
        artifact_set=artifact_set,
        allow_legacy_confirmation_contradiction=allow_legacy_confirmation_contradiction,
        successful_replay_disposition=successful_replay_disposition,
    )
    checks = _replay_checks(
        source_decision=source_decision,
        outcome_status=outcome.execution_status,
        oracle_verdict=(
            outcome.oracle_result.verdict if outcome.oracle_result is not None else None
        ),
        disposition=selected.disposition,
        reason=selected.reason,
    )
    decision_material = (
        f"{source_decision.decision_id}|{outcome.outcome_id}|pajin.dev/validation/v1alpha1"
    )
    decision_id = "decision_replay_" + sha256(decision_material.encode("utf-8")).hexdigest()[:24]
    return ValidationDecision(
        decision_id=decision_id,
        supersedes_decision_id=source_decision.decision_id,
        candidate_id=candidate.candidate_id,
        validator_id="trusted-core:confirmed-gate",
        method=ValidationMethod.RESTRICTED_REPLAY_GATE,
        disposition=selected.disposition,
        confirmation_basis=selected.confirmation_basis,
        reason_codes=[selected.reason],
        decision_summary=selected.summary,
        supporting_evidence=source_decision.supporting_evidence,
        contradicting_evidence=source_decision.contradicting_evidence,
        replay_request_ids=outcome.replay_request_ids,
        replay_outcome_ids=[outcome.outcome_id],
        replay_lineage=[lineage],
        checks=checks,
        decided_at=decided_at,
    )


def _validated_decision_time(
    decided_at: datetime,
    source_decision: ValidationDecision,
    lineage: ReplayConfirmationLineage,
) -> datetime:
    if decided_at.tzinfo is None or decided_at.utcoffset() is None:
        raise ValueError("confirmed gate decision time must include a UTC offset or Z")
    normalized = decided_at.astimezone(UTC)
    if normalized < source_decision.decided_at or normalized < lineage.verified_at:
        raise ValueError("confirmed gate decision cannot predate its source Decision or receipt")
    return normalized


def _validate_candidate_replay_binding(
    candidate: CandidateFinding,
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
) -> None:
    if source_decision.candidate_id != candidate.candidate_id:
        raise ValueError("source Decision does not belong to the Candidate")
    if artifact_set.validation_packet.candidate != candidate:
        raise ValueError("replay ValidationPacket Candidate differs from the source Candidate")
    if artifact_set.outcome.binding.candidate_id != candidate.candidate_id:
        raise ValueError("ReplayOutcome does not belong to the source Candidate")


def _validate_replay_lineage_binding(
    candidate: CandidateFinding,
    artifact_set: ReplayArtifactSet,
    lineage: ReplayConfirmationLineage,
) -> None:
    outcome = artifact_set.outcome
    if lineage.replay_run_id != outcome.binding.replay_run_id:
        raise ValueError("replay lineage Run differs from the ReplayOutcome")
    if lineage.replay_outcome_id != outcome.outcome_id:
        raise ValueError("replay lineage Outcome differs from the ReplayOutcome")
    if lineage.replay_request_ids != outcome.replay_request_ids:
        raise ValueError("replay lineage requests differ from the ReplayOutcome")
    if lineage.replay_evidence != outcome.evidence:
        raise ValueError("replay lineage evidence differs from the ReplayOutcome")
    if set(candidate.source_request_ids) & set(outcome.replay_request_ids):
        raise ValueError("replay requests must be distinct from Candidate source requests")


def _select_replay_disposition(
    *,
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    allow_legacy_confirmation_contradiction: bool,
    successful_replay_disposition: _SuccessfulDisposition,
) -> _ReplayDisposition:
    source_barrier = _source_replay_barrier(source_decision)
    if source_barrier is not None:
        return source_barrier
    if artifact_set.outcome.execution_status is ReplayExecutionStatus.SUCCEEDED:
        return successful_replay_disposition(
            source_decision,
            artifact_set,
            allow_legacy_confirmation_contradiction=allow_legacy_confirmation_contradiction,
        )
    return _unsuccessful_replay_disposition(artifact_set)


def _source_replay_barrier(
    source_decision: ValidationDecision,
) -> _ReplayDisposition | None:
    if source_decision.disposition is FindingDisposition.REJECTED_OBJECTIVE or any(
        item in _OBJECTIVE_REASONS for item in source_decision.reason_codes
    ):
        return _ReplayDisposition(
            disposition=FindingDisposition.REJECTED_OBJECTIVE,
            reason=source_decision.reason_codes[0],
            summary="The source objective gate failed; replay cannot override that rejection.",
        )
    if ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED in source_decision.reason_codes:
        return _ReplayDisposition(
            disposition=FindingDisposition.NEEDS_REVIEW,
            reason=ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED,
            summary="Replay cannot override a missing trusted Candidate admission.",
        )
    if ValidationReasonCode.EXECUTION_FAILED in source_decision.reason_codes:
        return _ReplayDisposition(
            disposition=FindingDisposition.INCONCLUSIVE,
            reason=ValidationReasonCode.EXECUTION_FAILED,
            summary="The source execution was inconclusive, so replay cannot promote the claim.",
        )
    return None


def _successful_replay_disposition(
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    *,
    allow_legacy_confirmation_contradiction: bool,
) -> _ReplayDisposition:
    oracle = artifact_set.outcome.oracle_result
    if oracle is None:
        raise ValueError("successful ReplayOutcome is missing its Mode Oracle result")
    if oracle.verdict is ReplayOracleVerdict.CONTRADICTS:
        _validate_oracle_contradiction(
            required_contradiction_count=oracle.required_contradiction_count,
            contradiction_count=oracle.contradiction_count,
            support_count=oracle.support_count,
            contradicting_evidence_count=len(oracle.contradicting_evidence),
            supporting_evidence_count=len(oracle.supporting_evidence),
            allow_legacy=allow_legacy_confirmation_contradiction,
        )
        return _ReplayDisposition(
            disposition=FindingDisposition.REJECTED_OBJECTIVE,
            reason=ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED,
            summary="The typed Mode Oracle deterministically contradicted the exact claim.",
        )
    if oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE:
        return _ReplayDisposition(
            disposition=FindingDisposition.INCONCLUSIVE,
            reason=ValidationReasonCode.REPLAY_ORACLE_INCONCLUSIVE,
            summary="The Mode Oracle could not decide the Candidate-bound replayed claim.",
        )
    if artifact_set.contract.semantic_support_required and not _semantic_supported(source_decision):
        return _missing_semantic_support_disposition(source_decision)
    return _ReplayDisposition(
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason=ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING,
        summary=(
            "The Candidate-bound replay supports the claim, but its typed transcript, hashes, "
            "receipts, and seals prove internal consistency rather than independent target "
            "execution authenticity."
        ),
    )


def _independently_attested_successful_replay_disposition(
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    *,
    allow_legacy_confirmation_contradiction: bool,
) -> _ReplayDisposition:
    selected = _successful_replay_disposition(
        source_decision,
        artifact_set,
        allow_legacy_confirmation_contradiction=allow_legacy_confirmation_contradiction,
    )
    if selected.reason is not ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING:
        return selected
    return _ReplayDisposition(
        disposition=FindingDisposition.CONFIRMED,
        reason=ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED,
        confirmation_basis=ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY,
        summary=(
            "The exact Replay claim was reproduced with a challenge-bound Target receipt, "
            "host proxy observation, and independently keyed executor attestation."
        ),
    )


def _validate_oracle_contradiction(
    *,
    required_contradiction_count: int,
    contradiction_count: int,
    support_count: int,
    contradicting_evidence_count: int,
    supporting_evidence_count: int,
    allow_legacy: bool,
) -> None:
    legacy_contradiction = (
        allow_legacy
        and required_contradiction_count == 0
        and contradiction_count == 0
        and support_count == 0
        and contradicting_evidence_count == 0
        and supporting_evidence_count == 0
    )
    invalid = (
        required_contradiction_count <= 0
        or contradiction_count < required_contradiction_count
        or contradicting_evidence_count != contradiction_count
    )
    if not legacy_contradiction and invalid:
        raise ValueError(
            "new confirmation contradiction requires an explicit threshold and exact evidence"
        )


def _missing_semantic_support_disposition(
    source_decision: ValidationDecision,
) -> _ReplayDisposition:
    unavailable = next(
        (item for item in source_decision.reason_codes if item in _SEMANTIC_UNAVAILABLE_REASONS),
        None,
    )
    reason = unavailable or next(
        (
            item
            for item in source_decision.reason_codes
            if item is not ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
        ),
        ValidationReasonCode.VALIDATOR_DISAGREED,
    )
    return _ReplayDisposition(
        disposition=(
            FindingDisposition.INCONCLUSIVE
            if unavailable is not None
            else FindingDisposition.NEEDS_REVIEW
        ),
        reason=reason,
        summary="Replay supported the claim, but required semantic support is absent.",
    )


def _unsuccessful_replay_disposition(
    artifact_set: ReplayArtifactSet,
) -> _ReplayDisposition:
    status = artifact_set.outcome.execution_status
    try:
        reason = _STATUS_REASON[status]
    except KeyError as exc:
        raise ValueError("ReplayOutcome has an unsupported execution status") from exc
    return _ReplayDisposition(
        disposition=(
            FindingDisposition.NEEDS_REVIEW
            if status is ReplayExecutionStatus.UNSUPPORTED
            else FindingDisposition.INCONCLUSIVE
        ),
        reason=reason,
        summary=f"Candidate-bound replay ended as {status.value}.",
    )


def _validate_receipt_set(
    *,
    root: Path,
    source_run_id: str,
    source_validation: FindingValidationSet,
    verified_results: list[VerifiedReplayResult],
    campaign: CampaignManifest,
    plan: AgentPlan,
) -> None:
    candidates_by_id = {
        candidate.candidate_id: candidate for candidate in source_validation.candidates
    }
    candidate_ids: list[str] = []
    claim_ids: list[str] = []
    legacy_candidate_ids: list[str] = []
    replay_run_ids: list[str] = []
    outcome_ids: list[str] = []
    source_root_digests: list[str] = []
    for verified in verified_results:
        artifact_set = verified.artifact_set
        outcome = artifact_set.outcome
        binding = outcome.binding
        candidate = candidates_by_id.get(binding.candidate_id)
        if candidate is None:
            raise ValueError("replay receipt references an unknown source Candidate")
        if (
            binding.candidate_run_id != source_run_id
            or artifact_set.validation_packet.candidate_run_id != source_run_id
            or artifact_set.validation_packet.candidate != candidate
            or binding.target != candidate.claim.target
            or binding.threat_class != candidate.claim.threat_class
            or binding.original_request_id not in candidate.source_request_ids
            or binding.replay_run_id == source_run_id
            or verified.receipt.replay_run_id != binding.replay_run_id
        ):
            raise ValueError("replay receipt binding differs from the sealed source Candidate")
        claim_binding = binding.claim
        packet_claim = artifact_set.validation_packet.claim
        if claim_binding is None:
            if packet_claim is not None:
                raise ValueError("legacy replay binding cannot contain a packet Atomic Claim")
            legacy_candidate_ids.append(binding.candidate_id)
        else:
            expected_claim = next(
                (
                    claim
                    for claim in candidate_atomic_claims(candidate)
                    if claim.claim_id == claim_binding.claim_id
                ),
                None,
            )
            if (
                expected_claim is None
                or packet_claim != expected_claim
                or claim_binding.claim_digest != expected_claim.claim_digest
                or claim_binding.claim_type is not expected_claim.claim_type
                or claim_binding.candidate_claim_digest != expected_claim.candidate_claim_digest
                or claim_binding.statement != expected_claim.statement
            ):
                raise ValueError("replay receipt substituted its source Atomic Claim")
            claim_ids.append(claim_binding.claim_id)
        if set(candidate.source_request_ids) & set(outcome.replay_request_ids):
            raise ValueError("replay receipt reuses a Candidate source request identity")
        _validate_source_replay_binding(
            root=root,
            campaign=campaign,
            plan=plan,
            candidate=candidate,
            artifact_set=artifact_set,
        )
        candidate_ids.append(binding.candidate_id)
        replay_run_ids.append(binding.replay_run_id)
        outcome_ids.append(outcome.outcome_id)
        source_root_digests.append(verified.receipt.candidate_source_root_digest)

    for label, values in (
        ("Atomic Claim", claim_ids),
        ("legacy Candidate", legacy_candidate_ids),
        ("replay Run", replay_run_ids),
        ("ReplayOutcome", outcome_ids),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"confirmed gate receipts contain duplicate {label} identities")
    if set(legacy_candidate_ids) & {
        candidate_id
        for verified in verified_results
        if verified.artifact_set.outcome.binding.claim is not None
        for candidate_id in [verified.artifact_set.outcome.binding.candidate_id]
    }:
        raise ValueError("confirmed gate cannot mix legacy and Claim-bound Candidate receipts")

    seals = _read_seals(root)
    known_roots = {seal.root_digest for seal in seals}
    if any(root_digest not in known_roots for root_digest in source_root_digests):
        raise ValueError("replay receipt Candidate source root is not in the source seal chain")
    if len(set(source_root_digests)) == 1:
        source_root_digest = source_root_digests[0]
        bound_index = next(
            index for index, seal in enumerate(seals) if seal.root_digest == source_root_digest
        )
        sealed_paths = {
            artifact.path for seal in seals[: bound_index + 1] for artifact in seal.artifacts
        }
        required_paths = {
            "campaign.json",
            "run.json",
            "plan.json",
            "candidate-findings.json",
            "validation-decisions.json",
            "findings.json",
            *(
                reference
                for candidate_id in candidate_ids
                for reference in candidates_by_id[candidate_id].claim.evidence
            ),
        }
        if not required_paths <= sealed_paths:
            raise ValueError("replay receipt source seal predates required Candidate artifacts")


def _validate_source_replay_binding(
    *,
    root: Path,
    campaign: CampaignManifest,
    plan: AgentPlan,
    candidate: CandidateFinding,
    artifact_set: ReplayArtifactSet,
) -> None:
    binding = artifact_set.outcome.binding
    steps_by_request = {step.request.request_id: step for step in plan.steps}
    if any(request_id not in steps_by_request for request_id in candidate.source_request_ids):
        raise ValueError("Candidate source requests do not resolve to sealed Plan steps")
    source_step = steps_by_request[binding.original_request_id]
    target = next(
        (item for item in campaign.spec.targets if item.id == binding.target_id),
        None,
    )
    if (
        binding.campaign != campaign.metadata.name
        or binding.mode is not campaign.spec.mode
        or binding.threat_class not in campaign.spec.threat_classes
        or target is None
        or target.endpoint != binding.target
        or source_step.scenario_id != binding.scenario_id
        or binding.threat_class not in source_step.threat_classes
        or source_step.request.tool_id != binding.tool_id
        or source_step.request.target != binding.target
    ):
        raise ValueError("replay Mode, Scenario, Tool, or target differs from the sealed source")

    packet_evidence = {item.reference: item for item in artifact_set.validation_packet.evidence}
    for reference, excerpt in packet_evidence.items():
        evidence_path = (root / reference).resolve()
        if root not in evidence_path.parents or not evidence_path.is_file():
            raise ValueError("replay ValidationPacket evidence escaped or is missing")
        evidence_bytes = read_bounded_regular_bytes(
            evidence_path,
            max_bytes=_MAX_SOURCE_EVIDENCE_BYTES,
            label="replay ValidationPacket evidence",
        )
        if sha256(evidence_bytes).hexdigest() != excerpt.sha256:
            raise ValueError("replay ValidationPacket evidence digest differs from the source")

    original_requests: list[ToolRequest] = []
    original_evidence: list[str] = []
    for reference in candidate.claim.evidence:
        evidence_path = (root / reference).resolve()
        try:
            payload = load_bounded_strict_json(
                evidence_path,
                max_bytes=_MAX_SOURCE_EVIDENCE_BYTES,
                label="Candidate source evidence",
            )
        except (OSError, ValueError) as exc:
            raise ValueError("Candidate source evidence could not be loaded") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("request"), dict):
            continue
        request = ToolRequest.model_validate(payload["request"])
        if request.request_id == binding.original_request_id:
            original_requests.append(request)
            original_evidence.append(reference)
    if not original_requests or any(
        request != original_requests[0] for request in original_requests
    ):
        raise ValueError("replay original request does not resolve uniquely from source evidence")
    original_request = original_requests[0]
    if (
        original_request.model_dump(mode="json", exclude={"agent_id"})
        != source_step.request.model_dump(mode="json", exclude={"agent_id"})
        or artifact_set.spec.arguments != original_request.arguments
        or artifact_set.spec.method != original_request.method
        or artifact_set.spec.original_request_digest != replay_request_digest(original_request)
        or artifact_set.spec.original_evidence_digest != replay_evidence_digest(original_evidence)
        or not set(original_evidence) <= set(packet_evidence)
    ):
        raise ValueError("replay compilation differs from the sealed original request or evidence")


def _load_source_context(root: Path) -> tuple[CampaignManifest, AgentPlan]:
    try:
        return (
            CampaignManifest.model_validate(
                load_bounded_strict_json(
                    root / "campaign.json",
                    max_bytes=_MAX_SEALED_ARTIFACT_BYTES,
                    label="confirmed gate source Campaign",
                )
            ),
            AgentPlan.model_validate(
                load_bounded_strict_json(
                    root / "plan.json",
                    max_bytes=_MAX_SEALED_ARTIFACT_BYTES,
                    label="confirmed gate source Plan",
                )
            ),
        )
    except (OSError, ValueError) as exc:
        raise ValueError("confirmed gate source Campaign or Plan could not be loaded") from exc


def _lineage(verified: VerifiedReplayResult) -> ReplayConfirmationLineage:
    outcome = verified.artifact_set.outcome
    oracle = outcome.oracle_result
    return ReplayConfirmationLineage(
        replay_run_id=outcome.binding.replay_run_id,
        replay_outcome_id=outcome.outcome_id,
        replay_request_ids=outcome.replay_request_ids,
        replay_evidence=outcome.evidence,
        oracle_result_id=(oracle.oracle_result_id if oracle is not None else None),
        ticket_id=verified.receipt.ticket_id,
        candidate_source_root_digest=verified.receipt.candidate_source_root_digest,
        artifact_set_digest=verified.receipt.artifact_set_digest,
        artifact_seal_root_digest=verified.receipt.artifact_seal_root_digest,
        receipt_seal_root_digest=verified.receipt_seal_root_digest,
        verified_at=verified.receipt.verified_at,
    )


def _semantic_supported(decision: ValidationDecision) -> bool:
    return any(
        check.check_id == "candidate-bound-validator-assessment"
        and check.status is ValidationCheckStatus.PASS
        and check.reason_code is ValidationReasonCode.VALIDATOR_CONFIRMED
        for check in decision.checks
    )


def _replay_checks(
    *,
    source_decision: ValidationDecision,
    outcome_status: ReplayExecutionStatus,
    oracle_verdict: ReplayOracleVerdict | None,
    disposition: FindingDisposition,
    reason: ValidationReasonCode,
) -> list[ValidationCheckResult]:
    checks = [
        check
        for check in source_decision.checks
        if check.check_id
        not in {
            "independent-reproduction",
            "replay-receipt-integrity",
            "replay-lineage",
            "replay-oracle",
        }
    ]
    checks.extend(
        [
            ValidationCheckResult(
                check_id="replay-receipt-integrity",
                status=ValidationCheckStatus.PASS,
                summary="Replay artifacts, both seals, and ticket finalization were reloaded.",
            ),
            ValidationCheckResult(
                check_id="replay-lineage",
                status=ValidationCheckStatus.PASS,
                summary="Replay Candidate, Run, request, target, and evidence lineage are bound.",
            ),
        ]
    )
    if outcome_status is ReplayExecutionStatus.SUCCEEDED:
        oracle_status = (
            ValidationCheckStatus.PASS
            if oracle_verdict is ReplayOracleVerdict.SUPPORTS
            else (
                ValidationCheckStatus.FAIL
                if oracle_verdict is ReplayOracleVerdict.CONTRADICTS
                else ValidationCheckStatus.ERROR
            )
        )
        checks.append(
            ValidationCheckResult(
                check_id="replay-oracle",
                status=oracle_status,
                reason_code=reason if oracle_status is not ValidationCheckStatus.PASS else None,
                summary=(
                    f"Mode Oracle verdict: {oracle_verdict.value if oracle_verdict else 'missing'}."
                ),
            )
        )
    else:
        checks.append(
            ValidationCheckResult(
                check_id="replay-oracle",
                status=ValidationCheckStatus.NOT_APPLICABLE,
                reason_code=reason,
                summary="Mode Oracle could not support the claim after terminal replay status.",
            )
        )
    reproduction_passed = disposition is FindingDisposition.CONFIRMED
    checks.append(
        ValidationCheckResult(
            check_id="independent-reproduction",
            status=(
                ValidationCheckStatus.PASS
                if reproduction_passed
                else (
                    ValidationCheckStatus.NOT_APPLICABLE
                    if outcome_status is ReplayExecutionStatus.UNSUPPORTED
                    else ValidationCheckStatus.FAIL
                )
            ),
            reason_code=reason,
            summary=(
                "Verified Candidate-bound replay satisfied the confirmation invariant."
                if reproduction_passed
                else "Verified replay did not satisfy every confirmation condition."
            ),
        )
    )
    return checks


def _render_confirmation_report(
    index: VersionedValidationIndex,
    validation: FindingValidationSet,
    claim_replay_set: VersionedClaimReplaySet | None = None,
) -> str:
    counts = {
        disposition: sum(decision.disposition is disposition for decision in validation.decisions)
        for disposition in FindingDisposition
    }
    lines = [
        "# PAJIN Replay Validation Projection",
        "",
        f"- API version: {markdown_code_span(index.api_version)}",
        f"- Source Run: {markdown_code_span(index.source_run_id)}",
        f"- Candidate source seal: {markdown_code_span(index.candidate_source_root_digest)}",
        "- Validation semantics: " + markdown_code_span(index.confirmation_semantics),
        "- Replay receipts, hashes, and seals establish consistency and lineage; they do not "
        "independently attest target execution.",
        "- The sealed flat artifacts remain the immutable pre-replay source snapshot.",
        "",
        "## Dispositions",
        "",
        f"- Confirmed: `{counts[FindingDisposition.CONFIRMED]}`",
        f"- Needs review: `{counts[FindingDisposition.NEEDS_REVIEW]}`",
        f"- Inconclusive: `{counts[FindingDisposition.INCONCLUSIVE]}`",
        f"- Rejected objective: `{counts[FindingDisposition.REJECTED_OBJECTIVE]}`",
        "",
    ]
    if index.public_states is not None:
        public_counts = {state: len(index.public_states[state]) for state in PublicFindingState}
        lines.extend(
            [
                "## Public validation states",
                "",
                f"- Confirmed: `{public_counts[PublicFindingState.CONFIRMED]}`",
                f"- Partially confirmed: `{public_counts[PublicFindingState.PARTIALLY_CONFIRMED]}`",
                f"- Not reproduced: `{public_counts[PublicFindingState.NOT_REPRODUCED]}`",
                f"- Needs review: `{public_counts[PublicFindingState.NEEDS_REVIEW]}`",
                f"- Inconclusive: `{public_counts[PublicFindingState.INCONCLUSIVE]}`",
                f"- Rejected objective: `{public_counts[PublicFindingState.REJECTED_OBJECTIVE]}`",
                "",
                "`partially-confirmed` records Claim-scoped replay support only. It is not "
                "a product confirmation and remains excluded from confirmed findings.",
                "",
            ]
        )
    lines.extend(
        [
            "## Confirmed findings",
            "",
        ]
    )
    decisions_by_candidate = {decision.candidate_id: decision for decision in validation.decisions}
    confirmed_candidates = [
        candidate
        for candidate in validation.candidates
        if decisions_by_candidate[candidate.candidate_id].disposition
        is FindingDisposition.CONFIRMED
    ]
    if not confirmed_candidates:
        lines.append("No independently attested confirmed finding was produced.")
    for candidate in confirmed_candidates:
        decision = decisions_by_candidate[candidate.candidate_id]
        lineage = decision.replay_lineage[0]
        lines.extend(
            [
                f"### {escape_markdown_text(candidate.claim.title)}",
                "",
                f"- Finding ID: {markdown_code_span(candidate.claim.finding_id)}",
                f"- Candidate ID: {markdown_code_span(candidate.candidate_id)}",
                f"- Decision ID: {markdown_code_span(decision.decision_id)}",
                f"- Supersedes: {markdown_code_span(decision.supersedes_decision_id or '-')}",
                f"- Replay Run: {markdown_code_span(lineage.replay_run_id)}",
                f"- ReplayOutcome: {markdown_code_span(lineage.replay_outcome_id)}",
                f"- Receipt seal: {markdown_code_span(lineage.receipt_seal_root_digest)}",
                "- Replay requests: " + markdown_code_span(", ".join(lineage.replay_request_ids)),
                "",
            ]
        )
    replayed_candidates = [
        candidate
        for candidate in validation.candidates
        if decisions_by_candidate[candidate.candidate_id].replay_lineage
    ]
    assessments_by_candidate: dict[str, list[ClaimReplayAssessment]] = {}
    for assessment in claim_replay_set.assessments if claim_replay_set is not None else []:
        assessments_by_candidate.setdefault(assessment.candidate_id, []).append(assessment)
    lines.extend(["", "## Replay evidence decisions", ""])
    for candidate in replayed_candidates:
        decision = decisions_by_candidate[candidate.candidate_id]
        lineage = decision.replay_lineage[0]
        assessments = assessments_by_candidate.get(candidate.candidate_id, [])
        lines.extend(
            [
                f"### {escape_markdown_text(candidate.claim.title)}",
                "",
                f"- Candidate ID: {markdown_code_span(candidate.candidate_id)}",
                f"- Disposition: {markdown_code_span(decision.disposition.value)}",
                *(
                    [
                        "- Public state: "
                        + markdown_code_span(_public_finding_state(decision, assessments).value),
                        *[
                            "- Claim "
                            + markdown_code_span(assessment.claim_type.value)
                            + ": "
                            + markdown_code_span(assessment.claim_id)
                            + " / "
                            + markdown_code_span(assessment.status.value)
                            + " / Run "
                            + markdown_code_span(assessment.replay_run_id)
                            for assessment in assessments
                        ],
                    ]
                    if assessments
                    else []
                ),
                "- Reason: " + markdown_code_span(decision.reason_codes[0].value),
                f"- Replay Run: {markdown_code_span(lineage.replay_run_id)}",
                f"- ReplayOutcome: {markdown_code_span(lineage.replay_outcome_id)}",
                f"- Receipt seal: {markdown_code_span(lineage.receipt_seal_root_digest)}",
                "- Replay evidence count: " + markdown_code_span(str(len(lineage.replay_evidence))),
                "",
            ]
        )
    return "\n".join(lines)


def _read_seals(root: Path) -> list[RunIntegritySeal]:
    try:
        content = read_bounded_regular_bytes(
            root / "run-integrity.jsonl",
            max_bytes=_MAX_RUN_LOG_BYTES,
            label="source Run seal chain",
        )
        return [
            RunIntegritySeal.model_validate(
                parse_strict_json_bytes(line, label="source Run seal record")
            )
            for line in content.splitlines()
            if line.strip()
        ]
    except (OSError, ValueError) as exc:
        raise ValueError("source Run seal chain could not be loaded") from exc
