"""Deterministic, fail-closed validation gate for validator findings."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from pajin.domain.models import CampaignManifest, Finding, ToolResult
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    FindingValidationSet,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.policy.scope import scope_matches
from pajin.runtime.store import RunStore


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
    confirmation_block_reason: ValidationReasonCode | None = None


def validate_findings(
    campaign: CampaignManifest,
    results: list[ToolResult],
    findings: list[Finding],
    store: RunStore,
    validator_id: str,
    admitted_candidates: list[CandidateFinding] | None = None,
    producer_authoritative_request_ids: set[str] | None = None,
    producer_authoritative_claim_keys: set[tuple[str, str]] | None = None,
    validator_unavailable_reason: ValidationReasonCode | None = None,
) -> FindingValidationSet:
    """Reconcile admitted candidates and classify them through one objective gate.

    Objective checks are evaluated before the legacy ``Finding.validated`` signal.
    Any malformed scope or evidence input therefore fails closed instead of being
    promoted to a confirmed finding. Validator-only findings remain supported for
    compatibility, unless they overlap admitted same-Run evidence but fail strict
    one-to-one reconciliation.
    """

    unavailable_reasons = {
        ValidationReasonCode.VALIDATOR_UNAVAILABLE,
        ValidationReasonCode.VALIDATOR_CANCELLED,
    }
    if (
        validator_unavailable_reason is not None
        and validator_unavailable_reason not in unavailable_reasons
    ):
        raise ValueError("validator_unavailable_reason must describe unavailability")

    evaluated_at = datetime.now(UTC)
    signals = _prepare_candidate_signals(
        findings=findings,
        admitted_candidates=admitted_candidates or [],
        results=results,
        evaluated_at=evaluated_at,
        store=store,
        validator_id=validator_id,
        producer_authoritative_request_ids=(producer_authoritative_request_ids or set()),
        producer_authoritative_claim_keys=(producer_authoritative_claim_keys or set()),
    )
    candidates: list[CandidateFinding] = []
    decisions: list[ValidationDecision] = []
    confirmed_findings: list[Finding] = []
    request_id_counts = Counter(result.request_id for result in results)

    for ordinal, signal in enumerate(signals, start=1):
        candidate = signal.candidate
        finding = candidate.claim
        validator_finding = signal.validator_finding
        evidence_references = _ordered_unique(
            reference for reference in finding.evidence if reference
        )
        linked_results = [
            result
            for result in results
            if any(reference in result.evidence for reference in evidence_references)
        ]
        candidate_id = candidate.candidate_id
        decision_id = _bounded_identifier("decision", finding.finding_id, ordinal)
        pending_event_payload = _validation_event_payload(
            candidate=candidate,
            decision_id=decision_id,
            validator_id=validator_id,
            reason_codes=[],
        )
        store.append_event("candidate.finding.created", pending_event_payload)
        store.append_event("validation.started", pending_event_payload)

        inspections = [
            _inspect_evidence(
                reference,
                finding=finding,
                results=results,
                request_id_counts=request_id_counts,
                store=store,
            )
            for reference in evidence_references
        ]

        checks: list[ValidationCheckResult] = []
        objective_reasons: list[ValidationReasonCode] = []

        target_declared = any(target.endpoint == finding.target for target in campaign.spec.targets)
        checks.append(
            _check(
                "target-declared",
                ValidationCheckStatus.PASS if target_declared else ValidationCheckStatus.FAIL,
                "Finding target exactly matches a declared campaign target."
                if target_declared
                else "Finding target does not exactly match a declared campaign target.",
                None if target_declared else ValidationReasonCode.TARGET_UNDECLARED,
            )
        )
        if not target_declared:
            objective_reasons.append(ValidationReasonCode.TARGET_UNDECLARED)

        threat_class_declared = (
            not campaign.spec.threat_classes or finding.threat_class in campaign.spec.threat_classes
        )
        checks.append(
            _check(
                "threat-class-declared",
                (
                    ValidationCheckStatus.PASS
                    if threat_class_declared
                    else ValidationCheckStatus.FAIL
                ),
                (
                    "Finding threat class is declared by the campaign."
                    if campaign.spec.threat_classes and threat_class_declared
                    else (
                        "Campaign does not constrain finding threat classes."
                        if not campaign.spec.threat_classes
                        else "Finding threat class is not declared by the campaign."
                    )
                ),
                (None if threat_class_declared else ValidationReasonCode.THREAT_CLASS_UNDECLARED),
            )
        )
        if not threat_class_declared:
            objective_reasons.append(ValidationReasonCode.THREAT_CLASS_UNDECLARED)

        scope_check, scope_reason = _scope_check(campaign, finding.target)
        checks.append(scope_check)
        if scope_reason is not None:
            objective_reasons.append(scope_reason)

        has_evidence = bool(evidence_references)
        checks.append(
            _check(
                "evidence-present",
                ValidationCheckStatus.PASS if has_evidence else ValidationCheckStatus.FAIL,
                "Finding includes at least one evidence reference."
                if has_evidence
                else "Finding does not include an evidence reference.",
                None if has_evidence else ValidationReasonCode.EVIDENCE_MISSING,
            )
        )
        if not has_evidence:
            objective_reasons.append(ValidationReasonCode.EVIDENCE_MISSING)

        _append_evidence_checks(
            checks,
            objective_reasons,
            inspections=inspections,
            has_evidence=has_evidence,
        )

        linked_request_ids = {result.request_id for result in linked_results}
        source_requests_match = set(candidate.source_request_ids) == linked_request_ids
        checks.append(
            _check(
                "candidate-source-requests",
                (
                    ValidationCheckStatus.PASS
                    if source_requests_match
                    else ValidationCheckStatus.FAIL
                ),
                (
                    "Candidate source requests exactly match its evidence-linked executions."
                    if source_requests_match
                    else "Candidate source requests do not match its evidence-linked executions."
                ),
                (None if source_requests_match else ValidationReasonCode.SOURCE_REQUEST_MISMATCH),
            )
        )
        if not source_requests_match:
            objective_reasons.append(ValidationReasonCode.SOURCE_REQUEST_MISMATCH)

        if objective_reasons:
            checks.extend(
                [
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
                ]
            )
            disposition = FindingDisposition.REJECTED_OBJECTIVE
            reason_codes = _ordered_unique_reasons(objective_reasons)
            decision_summary = "Deterministic objective checks rejected the candidate finding."
        elif linked_results and all(not result.success for result in linked_results):
            checks.extend(
                [
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
                ]
            )
            disposition = FindingDisposition.INCONCLUSIVE
            reason_codes = [ValidationReasonCode.EXECUTION_FAILED]
            decision_summary = (
                "All evidence-linked tool executions failed, so the candidate is inconclusive."
            )
        else:
            checks.append(
                _check(
                    "linked-executions",
                    ValidationCheckStatus.PASS,
                    "At least one evidence-linked tool execution succeeded.",
                )
            )
            if validator_finding is None and validator_unavailable_reason is not None:
                checks.append(
                    _check(
                        "validator-availability",
                        ValidationCheckStatus.ERROR,
                        "Validator did not complete, so no semantic decision is available.",
                        validator_unavailable_reason,
                    )
                )
                disposition = FindingDisposition.INCONCLUSIVE
                reason_codes = [validator_unavailable_reason]
                decision_summary = "Objective checks passed, but validation did not complete."
            elif signal.confirmation_block_reason is not None:
                checks.append(
                    _check(
                        "candidate-producer-admission",
                        ValidationCheckStatus.FAIL,
                        (
                            "Validator-only output falls inside a trusted Candidate "
                            "Producer authority boundary."
                        ),
                        signal.confirmation_block_reason,
                    )
                )
                disposition = FindingDisposition.NEEDS_REVIEW
                reason_codes = [signal.confirmation_block_reason]
                decision_summary = (
                    "Objective checks passed, but the trusted Candidate Producer did not "
                    "admit this Validator-only claim."
                )
            elif validator_finding is None:
                checks.append(
                    _check(
                        "legacy-validator-signal",
                        ValidationCheckStatus.FAIL,
                        "Validator omitted the admitted candidate finding.",
                        ValidationReasonCode.VALIDATOR_OMITTED,
                    )
                )
                disposition = FindingDisposition.NEEDS_REVIEW
                reason_codes = [ValidationReasonCode.VALIDATOR_OMITTED]
                decision_summary = (
                    "Objective checks passed, but the validator omitted the admitted candidate."
                )
            elif validator_finding.validated:
                checks.append(
                    _check(
                        "legacy-validator-signal",
                        ValidationCheckStatus.PASS,
                        "Legacy validator marked the finding as validated.",
                        ValidationReasonCode.VALIDATOR_CONFIRMED,
                    )
                )
                disposition = FindingDisposition.CONFIRMED
                reason_codes = [ValidationReasonCode.VALIDATOR_CONFIRMED]
                decision_summary = (
                    "Objective checks passed and the legacy validator confirmed the finding."
                )
                confirmed_findings.append(finding.model_copy(update={"validated": True}))
            else:
                checks.append(
                    _check(
                        "legacy-validator-signal",
                        ValidationCheckStatus.FAIL,
                        "Legacy validator did not mark the finding as validated.",
                        ValidationReasonCode.VALIDATOR_DISAGREED,
                    )
                )
                disposition = FindingDisposition.NEEDS_REVIEW
                reason_codes = [ValidationReasonCode.VALIDATOR_DISAGREED]
                decision_summary = (
                    "Objective checks passed, but the legacy validator did not confirm the finding."
                )

        supporting_evidence = [
            inspection.reference
            for inspection in inspections
            if inspection.linked_results
            and inspection.contained
            and inspection.file_exists
            and inspection.provenance_valid is True
        ]
        contradicting_evidence = [
            inspection.reference
            for inspection in inspections
            if not inspection.linked_results
            or not inspection.contained
            or not inspection.file_exists
            or inspection.provenance_valid is False
        ]
        decision = ValidationDecision(
            decision_id=decision_id,
            candidate_id=candidate_id,
            validator_id=validator_id,
            method=ValidationMethod.HYBRID_LEGACY_GATE,
            disposition=disposition,
            reason_codes=reason_codes,
            decision_summary=decision_summary,
            supporting_evidence=supporting_evidence,
            contradicting_evidence=contradicting_evidence,
            replay_request_ids=[],
            checks=checks,
            decided_at=evaluated_at,
        )
        decisions.append(decision)
        candidates.append(candidate)
        decided_event_payload = _validation_event_payload(
            candidate=candidate,
            decision_id=decision_id,
            validator_id=validator_id,
            reason_codes=reason_codes,
        )
        store.append_event(f"validation.{disposition.value}", decided_event_payload)
        store.append_event(
            "finding.validated"
            if disposition is FindingDisposition.CONFIRMED
            else "finding.rejected",
            decided_event_payload,
        )

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

    return FindingValidationSet(
        candidates=candidates,
        decisions=decisions,
        confirmed_findings=confirmed_findings,
    )


def _prepare_candidate_signals(
    *,
    findings: list[Finding],
    admitted_candidates: list[CandidateFinding],
    results: list[ToolResult],
    evaluated_at: datetime,
    store: RunStore,
    validator_id: str,
    producer_authoritative_request_ids: set[str],
    producer_authoritative_claim_keys: set[tuple[str, str]],
) -> list[_CandidateSignal]:
    candidate_ids = [candidate.candidate_id for candidate in admitted_candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("admitted candidate IDs must be unique")
    if any(candidate.claim.validated for candidate in admitted_candidates):
        raise ValueError("admitted candidate claims must have validated=False")

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
            matches_identity = (
                candidate.claim.target == finding.target
                and candidate.claim.threat_class == finding.threat_class
            )
            if matches_identity and candidate_evidence.intersection(finding.evidence):
                eligible_by_candidate[candidate_index].append(finding_index)
                eligible_by_finding[finding_index].append(candidate_index)

    matched_findings: dict[int, int] = {}
    matched_candidates: dict[int, int] = {}
    for candidate_index, eligible_findings in eligible_by_candidate.items():
        if len(eligible_findings) != 1:
            continue
        finding_index = eligible_findings[0]
        if len(eligible_by_finding[finding_index]) != 1:
            continue
        matched_candidates[candidate_index] = finding_index
        matched_findings[finding_index] = candidate_index

    signals = [
        _CandidateSignal(
            candidate=candidate,
            validator_finding=(
                findings[matched_candidates[index]] if index in matched_candidates else None
            ),
        )
        for index, candidate in enumerate(admitted_candidates)
    ]

    used_candidate_ids = set(candidate_ids)
    for finding_index, finding in enumerate(findings):
        if finding_index in matched_findings:
            continue
        overlapping_candidates = [
            candidate
            for candidate in admitted_candidates
            if (set(candidate.claim.evidence) & set(finding.evidence) & same_run_evidence)
        ]
        source_request_ids = _ordered_unique(
            result.request_id
            for result in results
            if any(reference in result.evidence for reference in finding.evidence)
        )
        if overlapping_candidates:
            store.append_event(
                "validation.output.unmatched",
                {
                    "findingId": finding.finding_id,
                    "validatorId": validator_id,
                    "reason": "overlaps-admitted-same-run-evidence",
                    "candidateIds": [
                        candidate.candidate_id for candidate in overlapping_candidates
                    ],
                },
            )
        producer_owned = (
            bool(overlapping_candidates)
            or bool(set(source_request_ids) & producer_authoritative_request_ids)
            or (
                finding.target,
                finding.threat_class,
            )
            in producer_authoritative_claim_keys
        )
        if producer_owned and not overlapping_candidates:
            store.append_event(
                "validation.output.unmatched",
                {
                    "findingId": finding.finding_id,
                    "validatorId": validator_id,
                    "reason": "candidate-producer-not-admitted",
                    "candidateIds": [],
                },
            )
        legacy_ordinal = finding_index + 1
        candidate_id = _unique_candidate_id(
            finding_id=finding.finding_id,
            ordinal=legacy_ordinal,
            used=used_candidate_ids,
        )
        used_candidate_ids.add(candidate_id)
        signals.append(
            _CandidateSignal(
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
        )
    return signals


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
) -> _EvidenceInspection:
    linked_results = tuple(result for result in results if reference in result.evidence)
    evidence_root = store.evidence_path.resolve()
    candidate: Path | None
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
    if linked_results and contained and file_exists and candidate is not None:
        provenance_valid = (
            len(linked_results) == 1
            and request_id_counts[linked_results[0].request_id] == 1
            and _evidence_provenance_matches(
                candidate,
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


def _evidence_provenance_matches(
    path: Path,
    *,
    reference: str,
    finding: Finding,
    linked_result: ToolResult,
) -> bool:
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
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
