import json
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
    ClaimReplayStatus,
    ClaimReviewOutcome,
    FindingDisposition,
    FindingValidationSet,
    PublicFindingState,
    ReplayConfirmationLineage,
    SeverityDerivationStatus,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    ValidatorOutputArtifact,
    blind_evidence_packets,
    build_atomic_claim_decision,
    build_blind_evidence_decision,
    build_claim_replay_assessment,
    build_independent_severity_decision,
    build_provider_model_review_binding,
    candidate_atomic_claims,
    candidate_claim_digest,
    reconcile_claim_reviews,
    reconcile_independent_severity,
    severity_derivation_packets,
    validate_candidate_atomic_refinement,
    validate_candidate_blind_refinement,
    validate_independent_severity_refinement,
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
    assert [item.value for item in PublicFindingState] == [
        "confirmed",
        "partially-confirmed",
        "not-reproduced",
        "needs-review",
        "inconclusive",
        "rejected-objective",
    ]
    assert [item.value for item in ClaimReplayStatus] == [
        "reproduced",
        "not-reproduced",
        "inconclusive",
        "not-eligible",
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


def test_claim_replay_assessment_binds_exact_validity_claim_and_lineage() -> None:
    candidate = _candidate("candidate_claim_replay", finding_id="finding_claim_replay")
    claims = candidate_atomic_claims(candidate)
    lineage = ReplayConfirmationLineage(
        replay_run_id="run_claim_replay",
        replay_outcome_id="outcome_claim_replay",
        replay_request_ids=["request_claim_replay"],
        replay_evidence=["evidence/request_claim_replay.json"],
        oracle_result_id="oracle_claim_replay",
        ticket_id="ticket_claim_replay",
        candidate_source_root_digest="a" * 64,
        artifact_set_digest="b" * 64,
        artifact_seal_root_digest="c" * 64,
        receipt_seal_root_digest="d" * 64,
        verified_at=datetime(2026, 7, 23, 12, 0, tzinfo=UTC),
    )
    assessment = build_claim_replay_assessment(
        claim=claims[0],
        lineage=lineage,
        status=ClaimReplayStatus.REPRODUCED,
        independent_execution_attested=False,
        assessed_at=datetime(2026, 7, 23, 12, 1, tzinfo=UTC),
    )

    assert assessment.claim_id == claims[0].claim_id
    assert assessment.claim_digest == claims[0].claim_digest
    assert assessment.replay_outcome_id == lineage.replay_outcome_id

    tampered = assessment.model_dump(mode="python", by_alias=True)
    tampered["claimDigest"] = "e" * 64
    with pytest.raises(ValidationError, match="assessment ID"):
        type(assessment).model_validate(tampered)

    with pytest.raises(ValueError, match="validity Claims only"):
        build_claim_replay_assessment(
            claim=claims[1],
            lineage=lineage,
            status=ClaimReplayStatus.REPRODUCED,
            independent_execution_attested=False,
            assessed_at=datetime(2026, 7, 23, 12, 1, tzinfo=UTC),
        )


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


def test_blind_evidence_review_excludes_candidate_metadata_and_reconciles_claims() -> None:
    candidate = _candidate(
        "candidate_blind",
        finding_id="finding_blind",
        claim=_finding(finding_id="finding_blind").model_copy(
            update={"impact": "A protected record could be disclosed."}
        ),
    )
    claims = candidate_atomic_claims(candidate)
    primary = [
        build_atomic_claim_decision(
            claims[0],
            verdict=AtomicClaimVerdict.SUPPORTS,
            rationale="Primary review supports the validity claim.",
            supporting_evidence=claims[0].evidence,
        ),
        build_atomic_claim_decision(
            claims[1],
            verdict=AtomicClaimVerdict.SUPPORTS,
            rationale="Primary review supports the impact claim.",
            supporting_evidence=claims[1].evidence,
        ),
        build_atomic_claim_decision(
            claims[2],
            verdict=AtomicClaimVerdict.CONTRADICTS,
            rationale="Primary review contradicts the severity claim.",
            contradicting_evidence=claims[2].evidence,
        ),
    ]
    packets = blind_evidence_packets(claims)
    packet_payload = packets[0].model_dump(mode="json", by_alias=True)

    assert "candidateId" not in packet_payload
    assert "candidateClaimDigest" not in packet_payload
    assert "disposition" not in packet_payload
    assert "primaryDecisionId" not in packet_payload
    assert len(packets) == 2
    assert all(packet.claim_type is not AtomicClaimType.SEVERITY for packet in packets)

    blind = [
        build_blind_evidence_decision(
            packets[0],
            reviewer_id="blind-reviewer:test",
            verdict=AtomicClaimVerdict.CONTRADICTS,
            rationale="Independent review contradicts the validity claim.",
            contradicting_evidence=packets[0].evidence,
        ),
        build_blind_evidence_decision(
            packets[1],
            reviewer_id="blind-reviewer:test",
            verdict=AtomicClaimVerdict.SUPPORTS,
            rationale="Independent review also supports the impact claim.",
            supporting_evidence=packets[1].evidence,
        ),
    ]
    reconciliations = [
        reconcile_claim_reviews(
            {decision.claim_id: decision for decision in primary}[blind_decision.claim_id],
            blind_decision,
        )
        for blind_decision in blind
    ]

    validate_candidate_blind_refinement(
        claims,
        primary,
        packets,
        blind,
        reconciliations,
        required=True,
    )

    assert [item.outcome for item in reconciliations] == [
        ClaimReviewOutcome.CONTESTED,
        ClaimReviewOutcome.CORROBORATED,
    ]
    assert candidate.claim.severity is FindingSeverity.HIGH
    assert candidate.claim.validated is False


def test_blind_evidence_refinement_rejects_tampering_and_primary_validator_reuse() -> None:
    candidate = _candidate("candidate_blind_tamper", finding_id="finding_blind_tamper")
    claims = candidate_atomic_claims(candidate)
    primary = [
        build_atomic_claim_decision(
            claim,
            verdict=AtomicClaimVerdict.INSUFFICIENT,
            rationale="Primary evidence is insufficient.",
        )
        for claim in claims
    ]
    packets = blind_evidence_packets(claims)
    tampered_packet = packets[0].model_dump(mode="python", by_alias=True)
    tampered_packet["statement"] = "Substituted blind-review statement"
    with pytest.raises(ValidationError, match="digest"):
        type(packets[0]).model_validate(tampered_packet)

    blind = [
        build_blind_evidence_decision(
            packet,
            reviewer_id="agent:validator:same",
            verdict=AtomicClaimVerdict.INSUFFICIENT,
            rationale="Blind evidence is insufficient.",
        )
        for packet in packets
    ]
    reconciliations = [
        reconcile_claim_reviews(
            {decision.claim_id: decision for decision in primary}[blind_decision.claim_id],
            blind_decision,
        )
        for blind_decision in blind
    ]
    assessments = [
        CandidateAssessment(
            candidate_id=candidate.candidate_id,
            claim_digest=candidate_claim_digest(candidate),
            supports_claim=False,
            reason_code=ValidationReasonCode.VALIDATOR_OMITTED,
            rationale=primary[0].rationale,
        )
    ]
    with pytest.raises(ValidationError, match="must differ"):
        ValidatorOutputArtifact(
            sourceRunId="run_blind",
            validatorId="agent:validator:same",
            validationTaskId="task_blind",
            findings=[],
            assessments=assessments,
            atomicClaims=claims,
            claimDecisions=primary,
            blindEvidencePackets=packets,
            blindEvidenceDecisions=blind,
            claimReviewReconciliations=reconciliations,
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


def test_independent_severity_derivation_withholds_proposed_severity_and_is_informational() -> None:
    candidate = _candidate(
        "candidate_severity",
        finding_id="finding_severity",
        claim=_finding(finding_id="finding_severity").model_copy(
            update={"impact": "A protected system prompt was disclosed to an untrusted user."}
        ),
    )
    claims = candidate_atomic_claims(candidate)
    packets = severity_derivation_packets(claims)
    binding = build_provider_model_review_binding(
        primary_provider_id="primary-provider",
        primary_endpoint="https://primary.example/v1/chat/completions",
        primary_model="primary-model",
        reviewer_id="diverse-reviewer:review-provider:review-model",
        review_provider_id="review-provider",
        review_endpoint="https://review.example/v1/chat/completions",
        review_model="review-model",
    )
    packet_text = json.dumps(
        packets[0].model_dump(mode="json", by_alias=True),
        sort_keys=True,
    )
    assert candidate.candidate_id not in packet_text
    assert '"claimType": "severity"' not in packet_text
    assert f'"statement": "{FindingSeverity.HIGH.value}"' not in packet_text

    evidence = packets[0].context_packets[0].evidence
    decisions = [
        build_independent_severity_decision(
            packets[0],
            binding,
            status=SeverityDerivationStatus.DERIVED,
            severity=FindingSeverity.MEDIUM,
            rationale="Minimal validity and impact evidence supports medium severity.",
            evidence=evidence,
        )
    ]
    severity_claim = next(claim for claim in claims if claim.claim_type is AtomicClaimType.SEVERITY)
    reconciliations = [reconcile_independent_severity(severity_claim, decisions[0])]

    validate_independent_severity_refinement(
        claims,
        packets,
        decisions,
        reconciliations,
        binding,
        required=True,
    )

    assert reconciliations[0].outcome is ClaimReviewOutcome.CONTESTED
    assert decisions[0].informational_only is True
    assert decisions[0].confirmation_eligible is False
    assert decisions[0].mutates_candidate is False
    assert candidate.claim.severity is FindingSeverity.HIGH
    assert candidate.claim.validated is False


def test_provider_model_review_binding_requires_distinct_provider_endpoint_and_model() -> None:
    with pytest.raises(ValidationError, match="Provider ID and endpoint"):
        build_provider_model_review_binding(
            primary_provider_id="same-provider",
            primary_endpoint="https://same.example/v1/chat/completions",
            primary_model="primary-model",
            reviewer_id="reviewer",
            review_provider_id="same-provider",
            review_endpoint="https://same.example/v1/chat/completions",
            review_model="review-model",
        )

    with pytest.raises(ValidationError, match="review model must differ"):
        build_provider_model_review_binding(
            primary_provider_id="primary-provider",
            primary_endpoint="https://primary.example/v1/chat/completions",
            primary_model="same-model",
            reviewer_id="reviewer",
            review_provider_id="review-provider",
            review_endpoint="https://review.example/v1/chat/completions",
            review_model="same-model",
        )
