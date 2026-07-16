from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from pajin.agents.base import CandidateProduction
from pajin.domain.models import Finding, FindingSeverity
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
    candidate = _candidate("candidate_1", finding_id="finding_1")
    claim_key = (candidate.claim.target, candidate.claim.threat_class)

    production = CandidateProduction(
        candidates=(candidate,),
        authoritative_request_ids=frozenset(candidate.source_request_ids),
        authoritative_claim_keys=frozenset({claim_key}),
    )

    assert production.candidates == (candidate,)
    with pytest.raises(ValueError, match="source requests"):
        CandidateProduction(
            candidates=(candidate,),
            authoritative_claim_keys=frozenset({claim_key}),
        )
    with pytest.raises(ValueError, match="claim must be inside"):
        CandidateProduction(
            candidates=(candidate,),
            authoritative_request_ids=frozenset(candidate.source_request_ids),
        )
    with pytest.raises(ValueError, match="validated=False"):
        CandidateProduction(
            candidates=(
                candidate.model_copy(
                    update={"claim": candidate.claim.model_copy(update={"validated": True})}
                ),
            ),
            authoritative_request_ids=frozenset(candidate.source_request_ids),
            authoritative_claim_keys=frozenset({claim_key}),
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
