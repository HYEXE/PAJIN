"""Common post-replay confirmation gate over sealed source and receipt artifacts."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from pajin.domain.models import AgentPlan, CampaignManifest, ToolRequest
from pajin.domain.replay import (
    ReplayArtifactSet,
    ReplayExecutionStatus,
    ReplayOracleVerdict,
    replay_evidence_digest,
    replay_request_digest,
)
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ReplayConfirmationLineage,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
)
from pajin.replay.runtime import VerifiedReplayResult, load_verified_replay_result
from pajin.replay.tickets import ReplayTicketFinalizationVerifier
from pajin.runtime.store import RunIntegritySeal, RunStore, verify_run_integrity
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    LoadedValidationSnapshot,
    load_source_validation_artifacts,
    load_validation_snapshot,
)

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


def apply_confirmed_gate(
    *,
    source_run_path: Path,
    replay_run_paths: Sequence[Path],
    tickets: ReplayTicketFinalizationVerifier,
    decided_at: datetime | None = None,
) -> LoadedValidationSnapshot:
    """Reload verified receipts, apply one common gate, and append a sealed v1 projection.

    Mutable ``VerifiedReplayResult`` or Mode-specific convenience records are deliberately not
    accepted. Every replay is reopened from its Run path by the canonical receipt loader before
    any Decision is evaluated.
    """

    root = source_run_path.resolve()
    source_verification = verify_run_integrity(root)
    if (root / VERSIONED_VALIDATION_INDEX_PATH).exists():
        raise ValueError("source Run already has a versioned validation projection")
    source_validation = load_source_validation_artifacts(root)
    campaign, plan = _load_source_context(root)
    if not replay_run_paths:
        raise ValueError("confirmed gate requires at least one replay receipt")
    if any(
        decision.disposition is FindingDisposition.CONFIRMED
        or decision.replay_request_ids
        or decision.replay_outcome_ids
        or decision.replay_lineage
        for decision in source_validation.decisions
    ):
        raise ValueError("source validation is not an unreproduced pre-confirmation snapshot")

    resolved_replay_paths = [path.resolve() for path in replay_run_paths]
    if len(resolved_replay_paths) != len(set(resolved_replay_paths)):
        raise ValueError("confirmed gate replay Run paths must be unique")
    verified_results = [
        load_verified_replay_result(path, tickets=tickets) for path in resolved_replay_paths
    ]
    _validate_receipt_set(
        root=root,
        source_run_id=source_verification.run_id,
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
    evaluated_at = decided_at or datetime.now(UTC)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("confirmed gate decision time must include a UTC offset or Z")
    evaluated_at = evaluated_at.astimezone(UTC)

    results_by_candidate = {
        result.artifact_set.outcome.binding.candidate_id: result for result in verified_results
    }
    source_decisions = {decision.candidate_id: decision for decision in source_validation.decisions}
    final_decisions: list[ValidationDecision] = []
    for candidate in source_validation.candidates:
        source_decision = source_decisions[candidate.candidate_id]
        verified = results_by_candidate.get(candidate.candidate_id)
        if verified is None:
            final_decisions.append(source_decision)
            continue
        lineage = _lineage(verified)
        final_decisions.append(
            decide_replay_confirmation(
                candidate=candidate,
                source_decision=source_decision,
                artifact_set=verified.artifact_set,
                lineage=lineage,
                decided_at=evaluated_at,
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
        sourceRunId=source_verification.run_id,
        candidateSourceRootDigest=candidate_source_root_digest,
        dispositions=dispositions,
        confirmedCandidateIds=confirmed_candidate_ids,
        generatedAt=evaluated_at,
    )
    decision_set = VersionedValidationDecisionSet(
        sourceRunId=source_verification.run_id,
        decisions=final_decisions,
    )
    finding_set = VersionedConfirmedFindingSet(
        sourceRunId=source_verification.run_id,
        findings=validation.confirmed_findings,
    )
    report = _render_confirmation_report(index, validation)

    if verify_run_integrity(root).root_digest != source_verification.root_digest:
        raise ValueError("source Run changed while the confirmed gate was evaluating receipts")
    store = RunStore(source_verification.run_id, root)
    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        decision_set.model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_FINDINGS_PATH,
        finding_set.model_dump(mode="json", by_alias=True),
    )
    store.write_text(VERSIONED_VALIDATION_REPORT_PATH, report)
    store.write_json(
        VERSIONED_VALIDATION_INDEX_PATH,
        index.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "validation.confirmation-projection.created",
        {
            "apiVersion": index.api_version,
            "candidateSourceRootDigest": candidate_source_root_digest,
            "receiptCount": len(verified_results),
            "confirmedCount": len(validation.confirmed_findings),
            "confirmedCandidateIds": confirmed_candidate_ids,
            "index": VERSIONED_VALIDATION_INDEX_PATH,
        },
        occurred_at=evaluated_at,
    )
    store.seal()
    return load_validation_snapshot(root)


def decide_replay_confirmation(
    *,
    candidate: CandidateFinding,
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    lineage: ReplayConfirmationLineage,
    decided_at: datetime,
) -> ValidationDecision:
    """Pure reason-matrix evaluation over an already verified replay artifact set."""

    outcome = artifact_set.outcome
    if decided_at.tzinfo is None or decided_at.utcoffset() is None:
        raise ValueError("confirmed gate decision time must include a UTC offset or Z")
    decided_at = decided_at.astimezone(UTC)
    if decided_at < source_decision.decided_at or decided_at < lineage.verified_at:
        raise ValueError("confirmed gate decision cannot predate its source Decision or receipt")
    if source_decision.candidate_id != candidate.candidate_id:
        raise ValueError("source Decision does not belong to the Candidate")
    if artifact_set.validation_packet.candidate != candidate:
        raise ValueError("replay ValidationPacket Candidate differs from the source Candidate")
    if outcome.binding.candidate_id != candidate.candidate_id:
        raise ValueError("ReplayOutcome does not belong to the source Candidate")
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

    disposition: FindingDisposition
    reason: ValidationReasonCode
    summary: str
    confirmation_basis: ConfirmationBasis | None = None

    if source_decision.disposition is FindingDisposition.REJECTED_OBJECTIVE or any(
        item in _OBJECTIVE_REASONS for item in source_decision.reason_codes
    ):
        disposition = FindingDisposition.REJECTED_OBJECTIVE
        reason = source_decision.reason_codes[0]
        summary = "The source objective gate failed; replay cannot override that rejection."
    elif ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED in source_decision.reason_codes:
        disposition = FindingDisposition.NEEDS_REVIEW
        reason = ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED
        summary = "Replay cannot override a missing trusted Candidate admission."
    elif ValidationReasonCode.EXECUTION_FAILED in source_decision.reason_codes:
        disposition = FindingDisposition.INCONCLUSIVE
        reason = ValidationReasonCode.EXECUTION_FAILED
        summary = "The source execution was inconclusive, so replay cannot promote the claim."
    elif outcome.execution_status is ReplayExecutionStatus.SUCCEEDED:
        oracle = outcome.oracle_result
        if oracle is None:
            raise ValueError("successful ReplayOutcome is missing its Mode Oracle result")
        if oracle.verdict is ReplayOracleVerdict.CONTRADICTS:
            disposition = FindingDisposition.REJECTED_OBJECTIVE
            reason = ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED
            summary = "The typed Mode Oracle deterministically contradicted the exact claim."
        elif oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE:
            disposition = FindingDisposition.INCONCLUSIVE
            reason = ValidationReasonCode.REPLAY_ORACLE_INCONCLUSIVE
            summary = "The Mode Oracle could not decide the independently replayed claim."
        elif artifact_set.contract.semantic_support_required and not _semantic_supported(
            source_decision
        ):
            unavailable = next(
                (
                    item
                    for item in source_decision.reason_codes
                    if item in _SEMANTIC_UNAVAILABLE_REASONS
                ),
                None,
            )
            disposition = (
                FindingDisposition.INCONCLUSIVE
                if unavailable is not None
                else FindingDisposition.NEEDS_REVIEW
            )
            reason = unavailable or next(
                (
                    item
                    for item in source_decision.reason_codes
                    if item not in {ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING}
                ),
                ValidationReasonCode.VALIDATOR_DISAGREED,
            )
            summary = "Replay supported the claim, but required semantic support is absent."
        else:
            disposition = FindingDisposition.CONFIRMED
            reason = ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED
            confirmation_basis = ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
            summary = (
                "The objective gate and verified Candidate-bound independent replay support "
                "the claim."
            )
    else:
        try:
            reason = _STATUS_REASON[outcome.execution_status]
        except KeyError as exc:
            raise ValueError("ReplayOutcome has an unsupported execution status") from exc
        disposition = (
            FindingDisposition.NEEDS_REVIEW
            if outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED
            else FindingDisposition.INCONCLUSIVE
        )
        summary = f"Independent replay ended as {outcome.execution_status.value}."

    checks = _replay_checks(
        source_decision=source_decision,
        outcome_status=outcome.execution_status,
        oracle_verdict=(
            outcome.oracle_result.verdict if outcome.oracle_result is not None else None
        ),
        disposition=disposition,
        reason=reason,
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
        disposition=disposition,
        confirmation_basis=confirmation_basis,
        reason_codes=[reason],
        decision_summary=summary,
        supporting_evidence=source_decision.supporting_evidence,
        contradicting_evidence=source_decision.contradicting_evidence,
        replay_request_ids=outcome.replay_request_ids,
        replay_outcome_ids=[outcome.outcome_id],
        replay_lineage=[lineage],
        checks=checks,
        decided_at=decided_at,
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
        ("Candidate", candidate_ids),
        ("replay Run", replay_run_ids),
        ("ReplayOutcome", outcome_ids),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"confirmed gate receipts contain duplicate {label} identities")

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
        if sha256(evidence_path.read_bytes()).hexdigest() != excerpt.sha256:
            raise ValueError("replay ValidationPacket evidence digest differs from the source")

    original_requests: list[ToolRequest] = []
    original_evidence: list[str] = []
    for reference in candidate.claim.evidence:
        evidence_path = (root / reference).resolve()
        try:
            payload: object = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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
            CampaignManifest.model_validate_json((root / "campaign.json").read_bytes()),
            AgentPlan.model_validate_json((root / "plan.json").read_bytes()),
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
        check.check_id == "legacy-validator-signal"
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
) -> str:
    counts = {
        disposition: sum(decision.disposition is disposition for decision in validation.decisions)
        for disposition in FindingDisposition
    }
    lines = [
        "# PAJIN Reproduction-backed Validation Projection",
        "",
        f"- API version: `{index.api_version}`",
        f"- Source Run: `{index.source_run_id}`",
        f"- Candidate source seal: `{index.candidate_source_root_digest}`",
        "- Confirmation semantics: `verified-independent-replay`",
        "- The sealed flat artifacts remain the immutable pre-replay source snapshot.",
        "",
        "## Dispositions",
        "",
        f"- Confirmed: `{counts[FindingDisposition.CONFIRMED]}`",
        f"- Needs review: `{counts[FindingDisposition.NEEDS_REVIEW]}`",
        f"- Inconclusive: `{counts[FindingDisposition.INCONCLUSIVE]}`",
        f"- Rejected objective: `{counts[FindingDisposition.REJECTED_OBJECTIVE]}`",
        "",
        "## Confirmed findings",
        "",
    ]
    decisions_by_candidate = {decision.candidate_id: decision for decision in validation.decisions}
    confirmed_candidates = [
        candidate
        for candidate in validation.candidates
        if decisions_by_candidate[candidate.candidate_id].disposition
        is FindingDisposition.CONFIRMED
    ]
    if not confirmed_candidates:
        lines.append("No reproduction-backed confirmed finding was produced.")
    for candidate in confirmed_candidates:
        decision = decisions_by_candidate[candidate.candidate_id]
        lineage = decision.replay_lineage[0]
        lines.extend(
            [
                f"### {candidate.claim.title}",
                "",
                f"- Finding ID: `{candidate.claim.finding_id}`",
                f"- Candidate ID: `{candidate.candidate_id}`",
                f"- Decision ID: `{decision.decision_id}`",
                f"- Supersedes: `{decision.supersedes_decision_id}`",
                f"- Replay Run: `{lineage.replay_run_id}`",
                f"- ReplayOutcome: `{lineage.replay_outcome_id}`",
                f"- Receipt seal: `{lineage.receipt_seal_root_digest}`",
                f"- Replay requests: `{', '.join(lineage.replay_request_ids)}`",
                "",
            ]
        )
    return "\n".join(lines)


def _read_seals(root: Path) -> list[RunIntegritySeal]:
    try:
        return [
            RunIntegritySeal.model_validate_json(line)
            for line in (root / "run-integrity.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("source Run seal chain could not be loaded") from exc
