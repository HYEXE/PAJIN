"""Deterministic, fail-closed validation gate for validator findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath

from pajin.agents.base import CandidateAuthority, CandidateProduction
from pajin.domain.models import CampaignManifest, Finding, ToolResult
from pajin.domain.validation import (
    CandidateAssessment,
    CandidateFinding,
    FindingDisposition,
    FindingValidationSet,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    candidate_claim_digest,
)
from pajin.policy.scope import scope_matches
from pajin.runtime.safe_files import load_bounded_strict_json, parse_strict_json_bytes
from pajin.runtime.store import RunStore

_MAX_EVIDENCE_JSON_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class _EvidenceInspection:
    reference: str
    linked_results: tuple[ToolResult, ...]
    contained: bool
    file_exists: bool
    provenance_valid: bool | None


@dataclass(frozen=True)
class _CandidateSignal:
    candidate: CandidateFinding
    validator_finding: Finding | None
    validator_assessment: CandidateAssessment | None = None
    confirmation_block_reason: ValidationReasonCode | None = None


@dataclass(frozen=True)
class _CandidateEvaluationContext:
    signal: _CandidateSignal
    decision_id: str
    evidence_references: tuple[str, ...]
    linked_results: tuple[ToolResult, ...]


@dataclass(frozen=True)
class _ObjectiveEvaluation:
    checks: tuple[ValidationCheckResult, ...]
    reason_codes: tuple[ValidationReasonCode, ...]
    inspections: tuple[_EvidenceInspection, ...]


@dataclass(frozen=True)
class _DispositionEvaluation:
    disposition: FindingDisposition
    reason_codes: tuple[ValidationReasonCode, ...]
    summary: str
    checks: tuple[ValidationCheckResult, ...]


@dataclass(frozen=True)
class _EvidenceProjection:
    supporting: tuple[str, ...]
    contradicting: tuple[str, ...]


def validate_findings(
    campaign: CampaignManifest,
    results: list[ToolResult],
    findings: list[Finding],
    store: RunStore,
    validator_id: str,
    admitted_candidates: list[CandidateFinding] | None = None,
    producer_authoritative_request_claims: set[CandidateAuthority] | None = None,
    validator_unavailable_reason: ValidationReasonCode | None = None,
    validator_assessments: list[CandidateAssessment] | None = None,
    pinned_evidence: Mapping[str, bytes] | None = None,
) -> FindingValidationSet:
    """Reconcile admitted candidates and classify them through one objective gate.

    Objective checks are evaluated before the legacy ``Finding.validated`` signal.
    Any malformed scope or evidence input therefore fails closed instead of being
    promoted to a confirmed finding. A positive legacy Validator signal is evidence
    review only and remains ``needs-review`` until a Candidate-bound independent
    ReplayOutcome is available. Validator-only findings remain supported for
    compatibility, unless they overlap admitted same-Run evidence but fail strict
    one-to-one reconciliation.
    """

    _require_unavailability_reason(validator_unavailable_reason)

    evaluated_at = datetime.now(UTC)
    signals = _prepare_candidate_signals(
        findings=findings,
        admitted_candidates=admitted_candidates or [],
        results=results,
        evaluated_at=evaluated_at,
        store=store,
        validator_id=validator_id,
        producer_authoritative_request_claims=(producer_authoritative_request_claims or set()),
        validator_assessments=validator_assessments,
    )
    candidates: list[CandidateFinding] = []
    decisions: list[ValidationDecision] = []
    confirmed_findings: list[Finding] = []
    request_id_counts = Counter(result.request_id for result in results)

    for ordinal, signal in enumerate(signals, start=1):
        context = _build_evaluation_context(
            signal=signal,
            ordinal=ordinal,
            results=results,
        )
        _persist_validation_started(
            store=store,
            context=context,
            validator_id=validator_id,
        )
        objective = _evaluate_objective_checks(
            campaign=campaign,
            context=context,
            results=results,
            request_id_counts=request_id_counts,
            store=store,
            pinned_evidence=pinned_evidence,
        )
        disposition = _evaluate_disposition(
            context=context,
            objective=objective,
            validator_unavailable_reason=validator_unavailable_reason,
        )
        evidence = _project_evidence(objective.inspections)
        decision = _build_validation_decision(
            context=context,
            objective=objective,
            disposition=disposition,
            evidence=evidence,
            validator_id=validator_id,
            evaluated_at=evaluated_at,
        )
        decisions.append(decision)
        candidates.append(context.signal.candidate)
        _persist_validation_decided(
            store=store,
            context=context,
            decision=decision,
        )

    _persist_validation_summary(
        store=store,
        candidates=candidates,
        decisions=decisions,
        confirmed_findings=confirmed_findings,
    )

    return FindingValidationSet(
        candidates=candidates,
        decisions=decisions,
        confirmed_findings=confirmed_findings,
    )


def _require_unavailability_reason(reason: ValidationReasonCode | None) -> None:
    if reason is not None and reason not in {
        ValidationReasonCode.VALIDATOR_UNAVAILABLE,
        ValidationReasonCode.VALIDATOR_CANCELLED,
    }:
        raise ValueError("validator_unavailable_reason must describe unavailability")


def _build_evaluation_context(
    *,
    signal: _CandidateSignal,
    ordinal: int,
    results: list[ToolResult],
) -> _CandidateEvaluationContext:
    finding = signal.candidate.claim
    evidence_references = tuple(
        _ordered_unique(reference for reference in finding.evidence if reference)
    )
    linked_results = tuple(
        result
        for result in results
        if any(reference in result.evidence for reference in evidence_references)
    )
    return _CandidateEvaluationContext(
        signal=signal,
        decision_id=_bounded_identifier("decision", finding.finding_id, ordinal),
        evidence_references=evidence_references,
        linked_results=linked_results,
    )


def _evaluate_objective_checks(
    *,
    campaign: CampaignManifest,
    context: _CandidateEvaluationContext,
    results: list[ToolResult],
    request_id_counts: Counter[str],
    store: RunStore,
    pinned_evidence: Mapping[str, bytes] | None,
) -> _ObjectiveEvaluation:
    finding = context.signal.candidate.claim
    checks: list[ValidationCheckResult] = []
    reasons: list[ValidationReasonCode] = []
    inspections = tuple(
        _inspect_evidence(
            reference,
            finding=finding,
            results=results,
            request_id_counts=request_id_counts,
            store=store,
            pinned_evidence=pinned_evidence,
        )
        for reference in context.evidence_references
    )

    _append_check_and_reason(checks, reasons, *_target_declared_check(campaign, finding))
    _append_check_and_reason(checks, reasons, *_threat_class_check(campaign, finding))
    _append_check_and_reason(checks, reasons, *_scope_check(campaign, finding.target))

    has_evidence = bool(context.evidence_references)
    _append_check_and_reason(checks, reasons, *_evidence_present_check(has_evidence))
    _append_evidence_checks(
        checks,
        reasons,
        inspections=list(inspections),
        has_evidence=has_evidence,
    )
    _append_check_and_reason(
        checks,
        reasons,
        *_source_requests_check(
            context.signal.candidate,
            context.linked_results,
        ),
    )
    return _ObjectiveEvaluation(
        checks=tuple(checks),
        reason_codes=tuple(_ordered_unique_reasons(reasons)),
        inspections=inspections,
    )


def _target_declared_check(
    campaign: CampaignManifest,
    finding: Finding,
) -> tuple[ValidationCheckResult, ValidationReasonCode | None]:
    declared = any(target.endpoint == finding.target for target in campaign.spec.targets)
    reason = None if declared else ValidationReasonCode.TARGET_UNDECLARED
    return (
        _check(
            "target-declared",
            ValidationCheckStatus.PASS if declared else ValidationCheckStatus.FAIL,
            "Finding target exactly matches a declared campaign target."
            if declared
            else "Finding target does not exactly match a declared campaign target.",
            reason,
        ),
        reason,
    )


def _threat_class_check(
    campaign: CampaignManifest,
    finding: Finding,
) -> tuple[ValidationCheckResult, ValidationReasonCode | None]:
    constrained = bool(campaign.spec.threat_classes)
    declared = not constrained or finding.threat_class in campaign.spec.threat_classes
    reason = None if declared else ValidationReasonCode.THREAT_CLASS_UNDECLARED
    if not constrained:
        summary = "Campaign does not constrain finding threat classes."
    elif declared:
        summary = "Finding threat class is declared by the campaign."
    else:
        summary = "Finding threat class is not declared by the campaign."
    return (
        _check(
            "threat-class-declared",
            ValidationCheckStatus.PASS if declared else ValidationCheckStatus.FAIL,
            summary,
            reason,
        ),
        reason,
    )


def _evidence_present_check(
    has_evidence: bool,
) -> tuple[ValidationCheckResult, ValidationReasonCode | None]:
    reason = None if has_evidence else ValidationReasonCode.EVIDENCE_MISSING
    return (
        _check(
            "evidence-present",
            ValidationCheckStatus.PASS if has_evidence else ValidationCheckStatus.FAIL,
            "Finding includes at least one evidence reference."
            if has_evidence
            else "Finding does not include an evidence reference.",
            reason,
        ),
        reason,
    )


def _source_requests_check(
    candidate: CandidateFinding,
    linked_results: tuple[ToolResult, ...],
) -> tuple[ValidationCheckResult, ValidationReasonCode | None]:
    linked_request_ids = {result.request_id for result in linked_results}
    matches = set(candidate.source_request_ids) == linked_request_ids
    reason = None if matches else ValidationReasonCode.SOURCE_REQUEST_MISMATCH
    return (
        _check(
            "candidate-source-requests",
            ValidationCheckStatus.PASS if matches else ValidationCheckStatus.FAIL,
            "Candidate source requests exactly match its evidence-linked executions."
            if matches
            else "Candidate source requests do not match its evidence-linked executions.",
            reason,
        ),
        reason,
    )


def _append_check_and_reason(
    checks: list[ValidationCheckResult],
    reasons: list[ValidationReasonCode],
    check: ValidationCheckResult,
    reason: ValidationReasonCode | None,
) -> None:
    checks.append(check)
    if reason is not None:
        reasons.append(reason)


def _evaluate_disposition(
    *,
    context: _CandidateEvaluationContext,
    objective: _ObjectiveEvaluation,
    validator_unavailable_reason: ValidationReasonCode | None,
) -> _DispositionEvaluation:
    if objective.reason_codes:
        return _DispositionEvaluation(
            disposition=FindingDisposition.REJECTED_OBJECTIVE,
            reason_codes=objective.reason_codes,
            summary="Deterministic objective checks rejected the candidate finding.",
            checks=(
                _check(
                    "linked-executions",
                    ValidationCheckStatus.NOT_APPLICABLE,
                    "Execution outcome was not evaluated after an objective check failed.",
                ),
                _check(
                    "legacy-validator-signal",
                    ValidationCheckStatus.NOT_APPLICABLE,
                    "Legacy validator signal cannot override an objective check failure.",
                ),
            ),
        )
    if context.linked_results and all(not result.success for result in context.linked_results):
        return _DispositionEvaluation(
            disposition=FindingDisposition.INCONCLUSIVE,
            reason_codes=(ValidationReasonCode.EXECUTION_FAILED,),
            summary=(
                "All evidence-linked tool executions failed, so the candidate is inconclusive."
            ),
            checks=(
                _check(
                    "linked-executions",
                    ValidationCheckStatus.FAIL,
                    "Every evidence-linked tool execution failed.",
                    ValidationReasonCode.EXECUTION_FAILED,
                ),
                _check(
                    "legacy-validator-signal",
                    ValidationCheckStatus.NOT_APPLICABLE,
                    "Legacy validator signal was not used because execution failed.",
                ),
            ),
        )

    semantic = _evaluate_semantic_disposition(
        signal=context.signal,
        validator_unavailable_reason=validator_unavailable_reason,
    )
    return _DispositionEvaluation(
        disposition=semantic.disposition,
        reason_codes=semantic.reason_codes,
        summary=semantic.summary,
        checks=(
            _check(
                "linked-executions",
                ValidationCheckStatus.PASS,
                "At least one evidence-linked tool execution succeeded.",
            ),
            *semantic.checks,
        ),
    )


def _evaluate_semantic_disposition(
    *,
    signal: _CandidateSignal,
    validator_unavailable_reason: ValidationReasonCode | None,
) -> _DispositionEvaluation:
    if signal.validator_finding is None and validator_unavailable_reason is not None:
        return _DispositionEvaluation(
            disposition=FindingDisposition.INCONCLUSIVE,
            reason_codes=(validator_unavailable_reason,),
            summary="Objective checks passed, but validation did not complete.",
            checks=(
                _check(
                    "validator-availability",
                    ValidationCheckStatus.ERROR,
                    "Validator did not complete, so no semantic decision is available.",
                    validator_unavailable_reason,
                ),
            ),
        )
    if signal.confirmation_block_reason is not None:
        return _DispositionEvaluation(
            disposition=FindingDisposition.NEEDS_REVIEW,
            reason_codes=(signal.confirmation_block_reason,),
            summary=(
                "Objective checks passed, but the trusted Candidate Producer did not "
                "admit this Validator-only claim."
            ),
            checks=(
                _check(
                    "candidate-producer-admission",
                    ValidationCheckStatus.FAIL,
                    (
                        "Validator-only output falls inside a trusted Candidate "
                        "Producer authority boundary."
                    ),
                    signal.confirmation_block_reason,
                ),
            ),
        )
    if signal.validator_assessment is not None:
        return _assessment_disposition(signal.validator_assessment)
    return _legacy_disposition(signal.validator_finding)


def _assessment_disposition(assessment: CandidateAssessment) -> _DispositionEvaluation:
    if assessment.supports_claim:
        return _DispositionEvaluation(
            disposition=FindingDisposition.NEEDS_REVIEW,
            reason_codes=(ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING,),
            summary=(
                "Candidate-bound semantic review passed, but independent reproduction has not run."
            ),
            checks=(
                _check(
                    "candidate-bound-validator-assessment",
                    ValidationCheckStatus.PASS,
                    "Validator explicitly supported the exact Candidate claim digest.",
                    ValidationReasonCode.VALIDATOR_CONFIRMED,
                ),
                _independent_reproduction_missing_check(),
            ),
        )

    reason = assessment.reason_code
    omitted = reason is ValidationReasonCode.VALIDATOR_OMITTED
    return _DispositionEvaluation(
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason_codes=(reason,),
        summary=(
            "Objective checks passed, but the Candidate-bound validator omitted the claim."
            if omitted
            else "Objective checks passed, but the Candidate-bound validator disagreed."
        ),
        checks=(
            _check(
                "candidate-bound-validator-assessment",
                ValidationCheckStatus.FAIL,
                "Validator omitted the exact Candidate claim."
                if omitted
                else "Validator explicitly declined the exact Candidate claim digest.",
                reason,
            ),
        ),
    )


def _legacy_disposition(validator_finding: Finding | None) -> _DispositionEvaluation:
    if validator_finding is None:
        return _DispositionEvaluation(
            disposition=FindingDisposition.NEEDS_REVIEW,
            reason_codes=(ValidationReasonCode.VALIDATOR_OMITTED,),
            summary="Objective checks passed, but the validator omitted the admitted candidate.",
            checks=(
                _check(
                    "legacy-validator-signal",
                    ValidationCheckStatus.FAIL,
                    "Validator omitted the admitted candidate finding.",
                    ValidationReasonCode.VALIDATOR_OMITTED,
                ),
            ),
        )
    if validator_finding.validated:
        return _DispositionEvaluation(
            disposition=FindingDisposition.NEEDS_REVIEW,
            reason_codes=(ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING,),
            summary=(
                "Objective checks and semantic review passed, but independent reproduction "
                "has not run."
            ),
            checks=(
                _check(
                    "legacy-validator-signal",
                    ValidationCheckStatus.PASS,
                    "Legacy validator marked the finding as validated.",
                    ValidationReasonCode.VALIDATOR_CONFIRMED,
                ),
                _independent_reproduction_missing_check(),
            ),
        )
    return _DispositionEvaluation(
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason_codes=(ValidationReasonCode.VALIDATOR_DISAGREED,),
        summary=("Objective checks passed, but the legacy validator did not confirm the finding."),
        checks=(
            _check(
                "legacy-validator-signal",
                ValidationCheckStatus.FAIL,
                "Legacy validator did not mark the finding as validated.",
                ValidationReasonCode.VALIDATOR_DISAGREED,
            ),
        ),
    )


def _independent_reproduction_missing_check() -> ValidationCheckResult:
    return _check(
        "independent-reproduction",
        ValidationCheckStatus.FAIL,
        "No successful Candidate-bound independent ReplayOutcome is available.",
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING,
    )


def _project_evidence(
    inspections: tuple[_EvidenceInspection, ...],
) -> _EvidenceProjection:
    return _EvidenceProjection(
        supporting=tuple(
            inspection.reference
            for inspection in inspections
            if inspection.linked_results
            and inspection.contained
            and inspection.file_exists
            and inspection.provenance_valid is True
        ),
        contradicting=tuple(
            inspection.reference
            for inspection in inspections
            if not inspection.linked_results
            or not inspection.contained
            or not inspection.file_exists
            or inspection.provenance_valid is False
        ),
    )


def _build_validation_decision(
    *,
    context: _CandidateEvaluationContext,
    objective: _ObjectiveEvaluation,
    disposition: _DispositionEvaluation,
    evidence: _EvidenceProjection,
    validator_id: str,
    evaluated_at: datetime,
) -> ValidationDecision:
    return ValidationDecision(
        decision_id=context.decision_id,
        candidate_id=context.signal.candidate.candidate_id,
        validator_id=validator_id,
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=disposition.disposition,
        reason_codes=list(disposition.reason_codes),
        decision_summary=disposition.summary,
        supporting_evidence=list(evidence.supporting),
        contradicting_evidence=list(evidence.contradicting),
        replay_request_ids=[],
        checks=[*objective.checks, *disposition.checks],
        decided_at=evaluated_at,
    )


def _persist_validation_started(
    *,
    store: RunStore,
    context: _CandidateEvaluationContext,
    validator_id: str,
) -> None:
    payload = _validation_event_payload(
        candidate=context.signal.candidate,
        decision_id=context.decision_id,
        validator_id=validator_id,
        reason_codes=[],
    )
    store.append_event("candidate.finding.created", payload)
    store.append_event("validation.started", payload)


def _persist_validation_decided(
    *,
    store: RunStore,
    context: _CandidateEvaluationContext,
    decision: ValidationDecision,
) -> None:
    payload = _validation_event_payload(
        candidate=context.signal.candidate,
        decision_id=context.decision_id,
        validator_id=decision.validator_id,
        reason_codes=decision.reason_codes,
    )
    store.append_event(f"validation.{decision.disposition.value}", payload)
    # This legacy event is part of the sealed KISA lineage contract. The preceding
    # typed validation event carries the exact non-confirmed disposition.
    store.append_event(
        "finding.validated"
        if decision.disposition is FindingDisposition.CONFIRMED
        else "finding.rejected",
        payload,
    )


def _persist_validation_summary(
    *,
    store: RunStore,
    candidates: list[CandidateFinding],
    decisions: list[ValidationDecision],
    confirmed_findings: list[Finding],
) -> None:
    disposition_counts = {disposition.value: 0 for disposition in FindingDisposition}
    for decision in decisions:
        disposition_counts[decision.disposition.value] += 1
    store.append_event(
        "findings.validated",
        {
            "candidateCount": len(candidates),
            "confirmedCount": len(confirmed_findings),
            "dispositionCounts": disposition_counts,
        },
    )


def _prepare_candidate_signals(
    *,
    findings: list[Finding],
    admitted_candidates: list[CandidateFinding],
    results: list[ToolResult],
    evaluated_at: datetime,
    store: RunStore,
    validator_id: str,
    producer_authoritative_request_claims: set[CandidateAuthority],
    validator_assessments: list[CandidateAssessment] | None,
) -> list[_CandidateSignal]:
    candidate_ids = _validated_candidate_ids(
        admitted_candidates,
        producer_authoritative_request_claims,
    )
    assessments_by_candidate = _validated_assessments(
        admitted_candidates,
        validator_assessments,
    )
    matched_candidates, matched_findings, same_run_evidence = _reconcile_candidate_findings(
        admitted_candidates=admitted_candidates,
        findings=findings,
        results=results,
    )

    signals = [
        _CandidateSignal(
            candidate=candidate,
            validator_finding=(
                findings[matched_candidates[index]] if index in matched_candidates else None
            ),
            validator_assessment=assessments_by_candidate.get(candidate.candidate_id),
        )
        for index, candidate in enumerate(admitted_candidates)
    ]

    used_candidate_ids = set(candidate_ids)
    for finding_index, finding in enumerate(findings):
        if finding_index in matched_findings:
            continue
        signals.append(
            _legacy_candidate_signal(
                finding=finding,
                ordinal=finding_index + 1,
                admitted_candidates=admitted_candidates,
                results=results,
                same_run_evidence=same_run_evidence,
                used_candidate_ids=used_candidate_ids,
                producer_authoritative_request_claims=(producer_authoritative_request_claims),
                evaluated_at=evaluated_at,
                store=store,
                validator_id=validator_id,
            )
        )
    return signals


def _validated_candidate_ids(
    admitted_candidates: list[CandidateFinding],
    producer_authoritative_request_claims: set[CandidateAuthority],
) -> list[str]:
    candidate_ids = [candidate.candidate_id for candidate in admitted_candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("admitted candidate IDs must be unique")
    if any(candidate.claim.validated for candidate in admitted_candidates):
        raise ValueError("admitted candidate claims must have validated=False")
    production = CandidateProduction(
        candidates=tuple(admitted_candidates),
        authoritative_request_claims=frozenset(producer_authoritative_request_claims),
    )
    return [candidate.candidate_id for candidate in production.candidates]


def _reconcile_candidate_findings(
    *,
    admitted_candidates: list[CandidateFinding],
    findings: list[Finding],
    results: list[ToolResult],
) -> tuple[dict[int, int], set[int], set[str]]:
    same_run_evidence = {
        reference for result in results for reference in result.evidence if reference
    }
    eligible_by_candidate: dict[int, list[int]] = {
        index: [] for index in range(len(admitted_candidates))
    }
    eligible_by_finding: dict[int, list[int]] = {index: [] for index in range(len(findings))}
    for candidate_index, candidate in enumerate(admitted_candidates):
        candidate_evidence = set(candidate.claim.evidence) & same_run_evidence
        if not candidate_evidence:
            continue
        for finding_index, finding in enumerate(findings):
            if _candidate_matches_finding(candidate, finding, candidate_evidence):
                eligible_by_candidate[candidate_index].append(finding_index)
                eligible_by_finding[finding_index].append(candidate_index)

    matched_candidates: dict[int, int] = {}
    matched_findings: set[int] = set()
    for candidate_index, eligible_findings in eligible_by_candidate.items():
        if len(eligible_findings) != 1:
            continue
        finding_index = eligible_findings[0]
        if len(eligible_by_finding[finding_index]) == 1:
            matched_candidates[candidate_index] = finding_index
            matched_findings.add(finding_index)
    return matched_candidates, matched_findings, same_run_evidence


def _candidate_matches_finding(
    candidate: CandidateFinding,
    finding: Finding,
    candidate_evidence: set[str],
) -> bool:
    return bool(
        candidate.claim.target == finding.target
        and candidate.claim.threat_class == finding.threat_class
        and candidate_evidence.intersection(finding.evidence)
    )


def _legacy_candidate_signal(
    *,
    finding: Finding,
    ordinal: int,
    admitted_candidates: list[CandidateFinding],
    results: list[ToolResult],
    same_run_evidence: set[str],
    used_candidate_ids: set[str],
    producer_authoritative_request_claims: set[CandidateAuthority],
    evaluated_at: datetime,
    store: RunStore,
    validator_id: str,
) -> _CandidateSignal:
    overlapping_candidates = [
        candidate
        for candidate in admitted_candidates
        if set(candidate.claim.evidence) & set(finding.evidence) & same_run_evidence
    ]
    source_request_ids = _ordered_unique(
        result.request_id
        for result in results
        if any(reference in result.evidence for reference in finding.evidence)
    )
    producer_owned = _producer_owns_finding(
        finding=finding,
        source_request_ids=source_request_ids,
        overlapping_candidates=overlapping_candidates,
        authoritative_request_claims=producer_authoritative_request_claims,
    )
    _persist_unmatched_validator_output(
        store=store,
        finding=finding,
        validator_id=validator_id,
        overlapping_candidates=overlapping_candidates,
        producer_owned=producer_owned,
    )
    candidate_id = _unique_candidate_id(
        finding_id=finding.finding_id,
        ordinal=ordinal,
        used=used_candidate_ids,
    )
    used_candidate_ids.add(candidate_id)
    return _CandidateSignal(
        candidate=CandidateFinding(
            candidate_id=candidate_id,
            claim=finding,
            source="legacy-validator-output",
            source_agent_id=validator_id,
            source_request_ids=source_request_ids,
            created_at=evaluated_at,
        ),
        validator_finding=finding,
        confirmation_block_reason=(
            ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED if producer_owned else None
        ),
    )


def _producer_owns_finding(
    *,
    finding: Finding,
    source_request_ids: list[str],
    overlapping_candidates: list[CandidateFinding],
    authoritative_request_claims: set[CandidateAuthority],
) -> bool:
    return bool(
        overlapping_candidates
        or any(
            CandidateAuthority(
                request_id=request_id,
                target=finding.target,
                threat_class=finding.threat_class,
            )
            in authoritative_request_claims
            for request_id in source_request_ids
        )
    )


def _persist_unmatched_validator_output(
    *,
    store: RunStore,
    finding: Finding,
    validator_id: str,
    overlapping_candidates: list[CandidateFinding],
    producer_owned: bool,
) -> None:
    if overlapping_candidates:
        reason = "overlaps-admitted-same-run-evidence"
        candidate_ids = [candidate.candidate_id for candidate in overlapping_candidates]
    elif producer_owned:
        reason = "candidate-producer-not-admitted"
        candidate_ids = []
    else:
        return
    store.append_event(
        "validation.output.unmatched",
        {
            "findingId": finding.finding_id,
            "validatorId": validator_id,
            "reason": reason,
            "candidateIds": candidate_ids,
        },
    )


def _validated_assessments(
    admitted_candidates: list[CandidateFinding],
    assessments: list[CandidateAssessment] | None,
) -> dict[str, CandidateAssessment]:
    if assessments is None:
        return {}
    candidate_by_id = {candidate.candidate_id: candidate for candidate in admitted_candidates}
    assessment_ids = [assessment.candidate_id for assessment in assessments]
    if len(assessment_ids) != len(set(assessment_ids)):
        raise ValueError("Candidate assessment IDs must be unique")
    if set(assessment_ids) != set(candidate_by_id):
        raise ValueError("typed validator must assess every admitted Candidate exactly once")
    validated: dict[str, CandidateAssessment] = {}
    for assessment in assessments:
        candidate = candidate_by_id[assessment.candidate_id]
        if assessment.claim_digest != candidate_claim_digest(candidate):
            raise ValueError("Candidate assessment claim digest does not match the Candidate")
        if not set(assessment.supporting_evidence) <= set(candidate.claim.evidence):
            raise ValueError("Candidate assessment cites evidence outside the Candidate claim")
        validated[assessment.candidate_id] = assessment
    return validated


def _scope_check(
    campaign: CampaignManifest,
    target: str,
) -> tuple[ValidationCheckResult, ValidationReasonCode | None]:
    scheme = target.partition(":")[0].casefold()
    if scheme not in {"http", "https"}:
        in_scope = target in campaign.spec.scope.allow and target not in campaign.spec.scope.deny
        return (
            _check(
                "target-scope",
                ValidationCheckStatus.PASS if in_scope else ValidationCheckStatus.FAIL,
                "Non-HTTP target is explicitly allowed and is not denied."
                if in_scope
                else "Non-HTTP target is not explicitly allowed or is explicitly denied.",
                None if in_scope else ValidationReasonCode.TARGET_OUT_OF_SCOPE,
            ),
            None if in_scope else ValidationReasonCode.TARGET_OUT_OF_SCOPE,
        )

    try:
        deny_matches = [scope_matches(rule, target) for rule in campaign.spec.scope.deny]
        allow_matches = [scope_matches(rule, target) for rule in campaign.spec.scope.allow]
    except Exception:
        # Scope evaluation is a security boundary. Any matcher failure rejects the target.
        return (
            _check(
                "target-http-scope",
                ValidationCheckStatus.ERROR,
                "HTTP target scope could not be evaluated safely.",
                ValidationReasonCode.TARGET_OUT_OF_SCOPE,
            ),
            ValidationReasonCode.TARGET_OUT_OF_SCOPE,
        )

    in_scope = any(allow_matches) and not any(deny_matches)
    return (
        _check(
            "target-http-scope",
            ValidationCheckStatus.PASS if in_scope else ValidationCheckStatus.FAIL,
            "HTTP target is allowed and is not explicitly denied."
            if in_scope
            else "HTTP target is outside allow scope or matches an explicit deny rule.",
            None if in_scope else ValidationReasonCode.TARGET_OUT_OF_SCOPE,
        ),
        None if in_scope else ValidationReasonCode.TARGET_OUT_OF_SCOPE,
    )


def _inspect_evidence(
    reference: str,
    *,
    finding: Finding,
    results: list[ToolResult],
    request_id_counts: Counter[str],
    store: RunStore,
    pinned_evidence: Mapping[str, bytes] | None,
) -> _EvidenceInspection:
    linked_results = tuple(result for result in results if reference in result.evidence)
    candidate: Path | None
    evidence_bytes: bytes | None = None
    if pinned_evidence is not None:
        candidate = None
        contained = _is_contained_evidence_reference(reference)
        file_exists = contained and reference in pinned_evidence
        if file_exists:
            evidence_bytes = pinned_evidence[reference]
    else:
        evidence_root = store.evidence_path.resolve()
        try:
            candidate = (store.path / reference).resolve()
        except (OSError, RuntimeError):
            candidate = None
        contained = candidate is not None and (
            candidate == evidence_root or evidence_root in candidate.parents
        )
        file_exists = False
        if contained and candidate is not None:
            try:
                file_exists = candidate.is_file()
            except OSError:
                file_exists = False

    provenance_valid: bool | None = None
    if linked_results and contained and file_exists:
        provenance_valid = (
            len(linked_results) == 1
            and request_id_counts[linked_results[0].request_id] == 1
            and _evidence_provenance_matches(
                candidate,
                evidence_bytes=evidence_bytes,
                pinned=pinned_evidence is not None,
                reference=reference,
                finding=finding,
                linked_result=linked_results[0],
            )
        )
    return _EvidenceInspection(
        reference=reference,
        linked_results=linked_results,
        contained=contained,
        file_exists=file_exists,
        provenance_valid=provenance_valid,
    )


def _is_contained_evidence_reference(reference: str) -> bool:
    path = PurePosixPath(reference)
    return bool(
        not path.is_absolute()
        and len(path.parts) >= 2
        and path.parts[0] == "evidence"
        and all(part not in {"", ".", ".."} for part in path.parts)
        and path.as_posix() == reference
    )


def _evidence_provenance_matches(
    path: Path | None,
    *,
    evidence_bytes: bytes | None,
    pinned: bool,
    reference: str,
    finding: Finding,
    linked_result: ToolResult,
) -> bool:
    try:
        if pinned:
            if evidence_bytes is None:
                return False
            payload = parse_strict_json_bytes(
                evidence_bytes,
                max_bytes=_MAX_EVIDENCE_JSON_BYTES,
                label="finding evidence",
            )
        else:
            if path is None:
                return False
            payload = load_bounded_strict_json(
                path,
                max_bytes=_MAX_EVIDENCE_JSON_BYTES,
                label="finding evidence",
            )
    except (OSError, TypeError, ValueError, RecursionError):
        return False
    if not isinstance(payload, dict):
        return False
    request = payload.get("request")
    if not isinstance(request, dict):
        return False
    request_id = request.get("request_id")
    tool_id = request.get("tool_id")
    target = request.get("target")
    recorded_result = payload.get("result")
    if not isinstance(recorded_result, dict):
        return False
    try:
        evidence_result = ToolResult.model_validate(recorded_result)
    except ValueError:
        return False
    expected_result = linked_result.model_copy(
        update={"evidence": [item for item in linked_result.evidence if item != reference]}
    )
    return bool(
        isinstance(request_id, str)
        and isinstance(tool_id, str)
        and isinstance(target, str)
        and request_id == linked_result.request_id
        and tool_id == linked_result.tool_id
        and target == finding.target
        and evidence_result == expected_result
    )


def _append_evidence_checks(
    checks: list[ValidationCheckResult],
    objective_reasons: list[ValidationReasonCode],
    *,
    inspections: list[_EvidenceInspection],
    has_evidence: bool,
) -> None:
    if not has_evidence:
        for check_id, summary in (
            ("evidence-result-links", "No evidence references are available to link."),
            ("evidence-path-contained", "No evidence paths are available to inspect."),
            ("evidence-files", "No evidence files are available to inspect."),
            ("evidence-provenance", "No evidence provenance is available to inspect."),
        ):
            checks.append(_check(check_id, ValidationCheckStatus.NOT_APPLICABLE, summary))
        return

    links_valid = all(inspection.linked_results for inspection in inspections)
    checks.append(
        _check(
            "evidence-result-links",
            ValidationCheckStatus.PASS if links_valid else ValidationCheckStatus.FAIL,
            "Every evidence reference is listed on a tool result."
            if links_valid
            else "At least one evidence reference is not listed on a tool result.",
            None if links_valid else ValidationReasonCode.EVIDENCE_UNLINKED,
        )
    )
    if not links_valid:
        objective_reasons.append(ValidationReasonCode.EVIDENCE_UNLINKED)

    paths_contained = all(inspection.contained for inspection in inspections)
    checks.append(
        _check(
            "evidence-path-contained",
            ValidationCheckStatus.PASS if paths_contained else ValidationCheckStatus.FAIL,
            "Every evidence path resolves inside the Run evidence directory."
            if paths_contained
            else "At least one evidence path resolves outside the Run evidence directory.",
            None if paths_contained else ValidationReasonCode.EVIDENCE_UNLINKED,
        )
    )
    if not paths_contained:
        objective_reasons.append(ValidationReasonCode.EVIDENCE_UNLINKED)

    missing_files = any(
        inspection.contained and not inspection.file_exists for inspection in inspections
    )
    checks.append(
        _check(
            "evidence-files",
            ValidationCheckStatus.FAIL if missing_files else ValidationCheckStatus.PASS,
            "At least one in-Run evidence file is missing."
            if missing_files
            else "Every contained evidence reference identifies an existing file.",
            ValidationReasonCode.EVIDENCE_FILE_MISSING if missing_files else None,
        )
    )
    if missing_files:
        objective_reasons.append(ValidationReasonCode.EVIDENCE_FILE_MISSING)

    invalid_provenance = any(inspection.provenance_valid is False for inspection in inspections)
    provenance_available = all(
        inspection.provenance_valid is not None for inspection in inspections
    )
    if invalid_provenance:
        provenance_status = ValidationCheckStatus.FAIL
        provenance_summary = (
            "At least one evidence record does not match its tool request and finding target."
        )
        provenance_reason = ValidationReasonCode.EVIDENCE_UNLINKED
        objective_reasons.append(ValidationReasonCode.EVIDENCE_UNLINKED)
    elif provenance_available:
        provenance_status = ValidationCheckStatus.PASS
        provenance_summary = (
            "Every evidence record matches its linked tool request and finding target."
        )
        provenance_reason = None
    else:
        provenance_status = ValidationCheckStatus.NOT_APPLICABLE
        provenance_summary = "Evidence provenance could not be checked after a prerequisite failed."
        provenance_reason = None
    checks.append(
        _check(
            "evidence-provenance",
            provenance_status,
            provenance_summary,
            provenance_reason,
        )
    )


def _check(
    check_id: str,
    status: ValidationCheckStatus,
    summary: str,
    reason_code: ValidationReasonCode | None = None,
) -> ValidationCheckResult:
    return ValidationCheckResult(
        check_id=check_id,
        status=status,
        reason_code=reason_code,
        summary=summary,
    )


def _ordered_unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _ordered_unique_reasons(
    values: Iterable[ValidationReasonCode],
) -> list[ValidationReasonCode]:
    return list(dict.fromkeys(values))


def _bounded_identifier(prefix: str, finding_id: str, ordinal: int) -> str:
    readable = f"{prefix}_{ordinal}_{finding_id}"
    if len(readable) <= 200:
        return readable
    digest = sha256(f"{ordinal}:{finding_id}".encode()).hexdigest()
    return f"{prefix}_{ordinal}_{digest}"


def _unique_candidate_id(
    *,
    finding_id: str,
    ordinal: int,
    used: set[str],
) -> str:
    candidate_id = _bounded_identifier("candidate", finding_id, ordinal)
    collision = 0
    while candidate_id in used:
        collision += 1
        digest = sha256(f"{ordinal}:{finding_id}:{collision}".encode()).hexdigest()
        candidate_id = f"candidate_{ordinal}_{digest}"
    return candidate_id


def _validation_event_payload(
    *,
    candidate: CandidateFinding,
    decision_id: str,
    validator_id: str,
    reason_codes: list[ValidationReasonCode],
) -> dict[str, object]:
    return {
        "candidateId": candidate.candidate_id,
        "findingId": candidate.claim.finding_id,
        "decisionId": decision_id,
        "validatorId": validator_id,
        "reasonCodes": [reason.value for reason in reason_codes],
    }
