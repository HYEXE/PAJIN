from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from pajin.agents.base import CandidateAuthority, CandidateProduction
from pajin.domain.models import Finding, FindingSeverity
from pajin.domain.validation import (
    AtomicClaimType,
    AtomicClaimVerdict,
    CandidateAssessment,
    CandidateFinding,
    FindingDisposition,
    FindingValidationSet,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    ValidatorOutputArtifact,
    build_atomic_claim_decision,
    candidate_atomic_claims,
    candidate_claim_digest,
    validate_candidate_atomic_refinement,
)


def _finding(*, finding_id: str, summary: str = "Observed a bounded security signal.") -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Bounded validation finding",
        severity=FindingSeverity.HIGH,
        threat_class="A02",
        target="https://target.example/api/chat",
        summary=summary,
        reproduction=["Replay the authorized request."],
        evidence=["evidence/tool_1.json"],
        confidence=0.9,
    )


def _candidate(
    candidate_id: str,
    *,
    finding_id: str,
    claim: Finding | None = None,
) -> CandidateFinding:
    return CandidateFinding(
        candidate_id=candidate_id,
        claim=claim or _finding(finding_id=finding_id),
        source_agent_id="agent:legacy-validator:1",
        source_request_ids=["tool_request_1"],
        created_at=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
    )


def _decision(
    decision_id: str,
    candidate_id: str,
    disposition: FindingDisposition,
) -> ValidationDecision:
    reason = (
        ValidationReasonCode.VALIDATOR_CONFIRMED
        if disposition is FindingDisposition.CONFIRMED
        else ValidationReasonCode.VALIDATOR_DISAGREED
    )
    return ValidationDecision(
        decision_id=decision_id,
        candidate_id=candidate_id,
        validator_id="agent:deterministic-gate:1",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=disposition,
        reason_codes=[reason],
        decision_summary="The typed validation checks produced this disposition.",
        supporting_evidence=["evidence/tool_1.json"],
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[
            ValidationCheckResult(
                check_id="same-run-evidence",
                status=ValidationCheckStatus.PASS,
                summary="The evidence belongs to this validation set.",
            )
        ],
        decided_at=datetime(2026, 7, 14, 12, 1, tzinfo=UTC),
    )


def test_validation_enum_wire_values_are_stable() -> None:
    assert [item.value for item in FindingDisposition] == [
        "confirmed",
        "needs-review",
        "inconclusive",
        "rejected-objective",
    ]
    assert [item.value for item in ValidationMethod] == [
        "legacy-validator",
        "deterministic-gate",
        "hybrid-legacy-gate",
        "restricted-replay-gate",
    ]
    assert [item.value for item in ValidationCheckStatus] == [
        "pass",
        "fail",
        "error",
        "not-applicable",
    ]
    assert {item.value for item in ValidationReasonCode} == {
        "validator-confirmed",
        "independent-reproduction-missing",
        "independent-execution-attestation-missing",
        "independent-reproduction-confirmed",
        "replay-not-eligible",
        "replay-approval-required",
        "replay-cancelled",
        "replay-timed-out",
        "replay-rate-limited",
        "replay-target-unavailable",
        "replay-execution-failed",
        "replay-oracle-inconclusive",
        "replay-oracle-contradicted",
        "validator-disagreed",
        "validator-omitted",
        "validator-unavailable",
        "validator-cancelled",
        "candidate-producer-not-admitted",
        "target-undeclared",
        "target-out-of-scope",
        "threat-class-undeclared",
        "evidence-missing",
        "evidence-unlinked",
        "evidence-file-missing",
        "source-request-mismatch",
        "execution-failed",
    }


def test_candidate_production_requires_atomic_request_and_claim_authority() -> None:
    candidate = _candidate("candidate_1", finding_id="finding_1").model_copy(
        update={"source_request_ids": ["tool_request_1", "tool_request_2"]}
    )
    authorities = frozenset(
        CandidateAuthority(
            request_id=request_id,
            target=candidate.claim.target,
            threat_class=candidate.claim.threat_class,
        )
        for request_id in candidate.source_request_ids
    )

    production = CandidateProduction(
        candidates=(candidate,),
        authoritative_request_claims=authorities,
    )

    assert production.candidates == (candidate,)
    assert production.authoritative_request_ids == frozenset(candidate.source_request_ids)
    assert production.authoritative_claim_keys == frozenset(
        {(candidate.claim.target, candidate.claim.threat_class)}
    )
    with pytest.raises(ValueError, match="exact request-to-claim authority"):
        CandidateProduction(
            candidates=(candidate,),
            authoritative_request_claims=frozenset(
                authority for authority in authorities if authority.request_id == "tool_request_1"
            ),
        )
    with pytest.raises(ValueError, match="validated=False"):
        CandidateProduction(
            candidates=(
                candidate.model_copy(
                    update={"claim": candidate.claim.model_copy(update={"validated": True})}
                ),
            ),
            authoritative_request_claims=authorities,
        )


def test_candidate_production_rejects_cross_paired_request_and_claim_authority() -> None:
    claim_a = _finding(finding_id="finding_a")
    claim_b = claim_a.model_copy(
        update={
            "finding_id": "finding_b",
            "target": "https://other.example/api/chat",
            "threat_class": "M03",
        }
    )
    cross_paired = _candidate(
        "candidate_cross_paired",
        finding_id="finding_b",
        claim=claim_b,
    ).model_copy(update={"source_request_ids": ["tool_request_a"]})

    with pytest.raises(ValueError, match="exact request-to-claim authority"):
        CandidateProduction(
            candidates=(cross_paired,),
            authoritative_request_claims=frozenset(
                {
                    CandidateAuthority(
                        request_id="tool_request_a",
                        target=claim_a.target,
                        threat_class=claim_a.threat_class,
                    ),
                    CandidateAuthority(
                        request_id="tool_request_b",
                        target=claim_b.target,
                        threat_class=claim_b.threat_class,
                    ),
                }
            ),
        )


def test_candidate_production_rejects_candidate_without_source_requests() -> None:
    candidate = _candidate("candidate_without_source", finding_id="finding_without_source")
    candidate = candidate.model_copy(update={"source_request_ids": []})

    with pytest.raises(ValueError, match="source requests must not be empty"):
        CandidateProduction(
            candidates=(candidate,),
            authoritative_request_claims=frozenset(
                {
                    CandidateAuthority(
                        request_id="tool_request_1",
                        target=candidate.claim.target,
                        threat_class=candidate.claim.threat_class,
                    )
                }
            ),
        )


def test_supporting_validator_output_requires_evidence_and_a_validated_finding() -> None:
    candidate = _candidate("candidate_supported", finding_id="finding_supported")
    assessment_fields = {
        "candidate_id": candidate.candidate_id,
        "claim_digest": "a" * 64,
        "supports_claim": True,
        "reason_code": ValidationReasonCode.VALIDATOR_CONFIRMED,
        "rationale": "The Validator independently supported the exact claim.",
    }

    with pytest.raises(ValidationError, match="requires evidence"):
        CandidateAssessment(**assessment_fields)

    assessment = CandidateAssessment(
        **assessment_fields,
        supporting_evidence=candidate.claim.evidence,
    )
    with pytest.raises(ValidationError, match="requires a validated Finding"):
        ValidatorOutputArtifact(
            sourceRunId="run_supported",
            validatorId="agent:validator:supported",
            validationTaskId="task_supported",
            findings=[],
            assessments=[assessment],
        )


def test_atomic_claims_separate_validity_impact_and_severity_without_rewriting_candidate() -> None:
    candidate = _candidate(
        "candidate_atomic",
        finding_id="finding_atomic",
        claim=_finding(finding_id="finding_atomic").model_copy(
            update={"impact": "A protected record could be disclosed."}
        ),
    )
    claims = candidate_atomic_claims(candidate)

    assert [claim.claim_type for claim in claims] == [
        AtomicClaimType.VALIDITY,
        AtomicClaimType.IMPACT,
        AtomicClaimType.SEVERITY,
    ]
    decisions = [
        build_atomic_claim_decision(
            claims[0],
            verdict=AtomicClaimVerdict.SUPPORTS,
            rationale="The same-run observation supports the core behavior.",
            supporting_evidence=claims[0].evidence,
        ),
        build_atomic_claim_decision(
            claims[1],
            verdict=AtomicClaimVerdict.INSUFFICIENT,
            rationale="The evidence does not establish the proposed impact.",
        ),
        build_atomic_claim_decision(
            claims[2],
            verdict=AtomicClaimVerdict.CONTRADICTS,
            rationale="The evidence contradicts the proposed severity.",
            contradicting_evidence=claims[2].evidence,
        ),
    ]

    validate_candidate_atomic_refinement(
        [candidate],
        claims,
        decisions,
        required=True,
    )
    artifact = ValidatorOutputArtifact(
        sourceRunId="run_atomic",
        validatorId="agent:validator:atomic",
        validationTaskId="task_atomic",
        findings=[],
        assessments=[
            CandidateAssessment(
                candidate_id=candidate.candidate_id,
                claim_digest=candidate_claim_digest(candidate),
                supports_claim=True,
                reason_code=ValidationReasonCode.VALIDATOR_CONFIRMED,
                rationale=decisions[0].rationale,
                supporting_evidence=decisions[0].supporting_evidence,
            )
        ],
        atomicClaims=claims,
        claimDecisions=decisions,
    )

    assert artifact.findings == []
    assert artifact.claim_decisions == decisions
    assert candidate.claim.severity is FindingSeverity.HIGH
    assert candidate.claim.validated is False


def test_atomic_claim_refinement_rejects_tampered_claims_and_unbound_evidence() -> None:
    candidate = _candidate("candidate_atomic_tamper", finding_id="finding_atomic_tamper")
    claims = candidate_atomic_claims(candidate)
    tampered = claims[0].model_dump(mode="python", by_alias=True)
    tampered["statement"] = "Substituted claim text"
    with pytest.raises(ValidationError, match="digest"):
        type(claims[0]).model_validate(tampered)

    decisions = [
        build_atomic_claim_decision(
            claim,
            verdict=(
                AtomicClaimVerdict.SUPPORTS
                if claim.claim_type is AtomicClaimType.VALIDITY
                else AtomicClaimVerdict.INSUFFICIENT
            ),
            rationale="Bounded semantic assessment.",
            supporting_evidence=(
                ["evidence/outside-candidate.json"]
                if claim.claim_type is AtomicClaimType.VALIDITY
                else []
            ),
        )
        for claim in claims
    ]
    with pytest.raises(ValueError, match="outside its Claim"):
        validate_candidate_atomic_refinement(
            [candidate],
            claims,
            decisions,
            required=True,
        )


def test_validation_models_use_internal_snake_case_json_and_normalize_utc() -> None:
    candidate = CandidateFinding(
        candidate_id="candidate_1",
        claim=_finding(finding_id="finding_1"),
        source_agent_id="agent:validator:1",
        source_request_ids=[],
        created_at=datetime(
            2026,
            7,
            14,
            21,
            0,
            tzinfo=timezone(timedelta(hours=9)),
        ),
    )

    assert candidate.source == "legacy-validator-output"
    assert candidate.created_at == datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    payload = candidate.model_dump(mode="json", by_alias=True)
    assert "candidate_id" in payload
    assert "candidateId" not in payload
    assert payload["created_at"] == "2026-07-14T12:00:00Z"


@pytest.mark.parametrize("field", ["created_at", "decided_at"])
def test_validation_timestamps_reject_naive_values(field: str) -> None:
    if field == "created_at":
        with pytest.raises(ValidationError, match="created_at must include a UTC offset"):
            CandidateFinding(
                candidate_id="candidate_1",
                claim=_finding(finding_id="finding_1"),
                source_agent_id="agent:validator:1",
                source_request_ids=[],
                created_at=datetime(2026, 7, 14, 12, 0),
            )
        return

    values = _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED).model_dump()
    values["decided_at"] = datetime(2026, 7, 14, 12, 0)
    with pytest.raises(ValidationError, match="decided_at must include a UTC offset"):
        ValidationDecision.model_validate(values)


def test_finding_validation_set_accepts_one_decision_per_candidate() -> None:
    confirmed = _candidate("candidate_1", finding_id="finding_1")
    review = _candidate("candidate_2", finding_id="finding_2")
    validation_set = FindingValidationSet(
        candidates=[confirmed, review],
        decisions=[
            _decision("decision_2", "candidate_2", FindingDisposition.NEEDS_REVIEW),
            _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED),
        ],
        confirmed_findings=[confirmed.claim.model_copy(update={"validated": True})],
    )

    restored = FindingValidationSet.model_validate_json(validation_set.model_dump_json())
    assert restored == validation_set
    assert restored.confirmed_findings == [confirmed.claim.model_copy(update={"validated": True})]


def test_finding_validation_set_preserves_duplicate_claim_ids_in_candidate_order() -> None:
    first_claim = _finding(
        finding_id="finding_shared",
        summary="First independently returned claim.",
    )
    second_claim = _finding(
        finding_id="finding_shared",
        summary="Second independently returned claim.",
    )
    first = _candidate(
        "candidate_1",
        finding_id="finding_shared",
        claim=first_claim,
    )
    second = _candidate(
        "candidate_2",
        finding_id="finding_shared",
        claim=second_claim,
    )
    decisions = [
        _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED),
        _decision("decision_2", "candidate_2", FindingDisposition.CONFIRMED),
    ]

    validation_set = FindingValidationSet(
        candidates=[first, second],
        decisions=decisions,
        confirmed_findings=[
            first_claim.model_copy(update={"validated": True}),
            second_claim.model_copy(update={"validated": True}),
        ],
    )

    assert [candidate.claim for candidate in validation_set.candidates] == [
        first_claim,
        second_claim,
    ]
    assert validation_set.decisions == decisions
    assert validation_set.confirmed_findings == [
        first_claim.model_copy(update={"validated": True}),
        second_claim.model_copy(update={"validated": True}),
    ]
    with pytest.raises(ValidationError, match="confirmed_findings must exactly match"):
        FindingValidationSet(
            candidates=[first, second],
            decisions=decisions,
            confirmed_findings=[
                second_claim.model_copy(update={"validated": True}),
                first_claim.model_copy(update={"validated": True}),
            ],
        )


@pytest.mark.parametrize(
    ("candidates", "decisions", "confirmed", "message"),
    [
        (
            [
                _candidate("candidate_1", finding_id="finding_1"),
                _candidate("candidate_1", finding_id="finding_2"),
            ],
            [],
            [],
            "candidate IDs must be unique",
        ),
        (
            [_candidate("candidate_1", finding_id="finding_1")],
            [
                _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED),
                _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED),
            ],
            [],
            "decision IDs must be unique",
        ),
        (
            [_candidate("candidate_1", finding_id="finding_1")],
            [_decision("decision_1", "candidate_unknown", FindingDisposition.INCONCLUSIVE)],
            [],
            "decision references unknown candidate",
        ),
        (
            [_candidate("candidate_1", finding_id="finding_1")],
            [],
            [],
            "candidate must have exactly one decision",
        ),
        (
            [_candidate("candidate_1", finding_id="finding_1")],
            [
                _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED),
                _decision("decision_2", "candidate_1", FindingDisposition.CONFIRMED),
            ],
            [],
            "candidate must have exactly one decision",
        ),
    ],
)
def test_finding_validation_set_rejects_broken_identity_links(
    candidates: list[CandidateFinding],
    decisions: list[ValidationDecision],
    confirmed: list[Finding],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        FindingValidationSet(
            candidates=candidates,
            decisions=decisions,
            confirmed_findings=confirmed,
        )


def test_confirmed_findings_must_exactly_match_validated_candidate_projections() -> None:
    candidate = _candidate("candidate_1", finding_id="finding_1")
    decision = _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED)

    with pytest.raises(ValidationError, match="confirmed_findings must exactly match"):
        FindingValidationSet(
            candidates=[candidate],
            decisions=[decision],
            confirmed_findings=[],
        )

    changed = candidate.claim.model_copy(
        update={"summary": "A different claim.", "validated": True}
    )
    with pytest.raises(ValidationError, match="confirmed_findings must exactly match"):
        FindingValidationSet(
            candidates=[candidate],
            decisions=[decision],
            confirmed_findings=[changed],
        )


def test_validation_models_reject_duplicate_nested_identifiers_and_extra_fields() -> None:
    with pytest.raises(ValidationError, match="source_request_ids must be unique"):
        CandidateFinding(
            candidate_id="candidate_1",
            claim=_finding(finding_id="finding_1"),
            source_agent_id="agent:validator:1",
            source_request_ids=["tool_1", "tool_1"],
            created_at=datetime.now(UTC),
        )

    values = _decision("decision_1", "candidate_1", FindingDisposition.CONFIRMED).model_dump()
    values["checks"] = [values["checks"][0], values["checks"][0]]
    with pytest.raises(ValidationError, match="validation check IDs must be unique"):
        ValidationDecision.model_validate(values)

    check = ValidationCheckResult(
        check_id="scope",
        status=ValidationCheckStatus.FAIL,
        reason_code=ValidationReasonCode.TARGET_OUT_OF_SCOPE,
        summary="The target is outside the campaign scope.",
    )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ValidationCheckResult.model_validate({**check.model_dump(), "unexpected": True})
