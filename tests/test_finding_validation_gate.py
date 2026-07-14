import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.domain.models import (
    CampaignManifest,
    Finding,
    FindingSeverity,
    ToolRequest,
    ToolResult,
)
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    ValidationCheckStatus,
    ValidationReasonCode,
)
from pajin.policy.engine import PolicyDecision
from pajin.runtime.store import RunStore
from pajin.workflow.validation import validate_findings


def _tool_result(request_id: str, *, success: bool = True) -> ToolResult:
    now = datetime.now(UTC)
    return ToolResult(
        request_id=request_id,
        tool_id="mock.agent-probe",
        success=success,
        started_at=now,
        finished_at=now,
        error=None if success else "bounded execution failed",
    )


def _gateway_payload(
    *,
    target: str,
    result: ToolResult,
) -> dict[str, object]:
    request = ToolRequest(
        request_id=result.request_id,
        agent_id="agent:specialist:1",
        tool_id=result.tool_id,
        target=target,
        method="POST",
    )
    decision = PolicyDecision(
        allowed=True,
        reason="all policy checks passed",
        policy="allow",
    )
    return {
        "request": request.model_dump(mode="json"),
        "policyDecision": decision.model_dump(mode="json"),
        "result": result.model_dump(mode="json"),
    }


def _gateway_result(
    store: RunStore,
    *,
    target: str,
    request_id: str = "tool_request_1",
    success: bool = True,
) -> tuple[ToolResult, str]:
    result = _tool_result(request_id, success=success)
    reference = store.write_json(
        f"evidence/{request_id}.json",
        _gateway_payload(target=target, result=result),
    )
    return result.model_copy(update={"evidence": [reference]}), reference


def _finding(
    *,
    target: str,
    evidence: list[str],
    finding_id: str = "finding_1",
    validated: bool = True,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Bounded validation finding",
        severity=FindingSeverity.HIGH,
        threat_class="A02",
        target=target,
        summary="A bounded security signal was observed.",
        reproduction=["Replay the authorized request."],
        evidence=evidence,
        confidence=0.9,
        validated=validated,
    )


def _admitted_candidate(
    claim: Finding,
    *,
    candidate_id: str = "producer_candidate_1",
) -> CandidateFinding:
    return CandidateFinding(
        candidate_id=candidate_id,
        claim=claim,
        source="trusted-core:test-candidate-producer",
        source_agent_id="trusted-core:test-candidate-producer",
        source_request_ids=["tool_request_1"],
        created_at=datetime.now(UTC),
    )


def _event_records(store: RunStore) -> list[dict[str, object]]:
    return [json.loads(line) for line in store.events_path.read_text(encoding="utf-8").splitlines()]


def test_gate_preserves_every_candidate_and_uses_legacy_signal_after_objective_checks(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    first_result, first_evidence = _gateway_result(
        store,
        target=target,
        request_id="tool_request_1",
    )
    second_result, second_evidence = _gateway_result(
        store,
        target=target,
        request_id="tool_request_2",
    )
    confirmed = _finding(
        target=target,
        evidence=[second_evidence, first_evidence],
        finding_id="finding_confirmed",
    )
    review = _finding(
        target=target,
        evidence=[second_evidence],
        finding_id="finding_review",
        validated=False,
    )

    validation = validate_findings(
        sample_campaign,
        [first_result, second_result],
        [confirmed, review],
        store,
        "agent:validator:1",
    )

    assert [candidate.claim for candidate in validation.candidates] == [confirmed, review]
    assert validation.candidates[0].source_request_ids == [
        "tool_request_1",
        "tool_request_2",
    ]
    assert validation.candidates[1].source_request_ids == ["tool_request_2"]
    assert [decision.disposition for decision in validation.decisions] == [
        FindingDisposition.CONFIRMED,
        FindingDisposition.NEEDS_REVIEW,
    ]
    assert validation.decisions[0].reason_codes == [ValidationReasonCode.VALIDATOR_CONFIRMED]
    assert validation.decisions[1].reason_codes == [ValidationReasonCode.VALIDATOR_DISAGREED]
    assert validation.confirmed_findings == [confirmed]

    events = _event_records(store)
    assert [event["event_type"] for event in events] == [
        "candidate.finding.created",
        "validation.started",
        "validation.confirmed",
        "finding.validated",
        "candidate.finding.created",
        "validation.started",
        "validation.needs-review",
        "finding.rejected",
        "findings.validated",
    ]
    candidate_payload = events[2]["payload"]
    assert isinstance(candidate_payload, dict)
    assert set(candidate_payload) == {
        "candidateId",
        "findingId",
        "decisionId",
        "validatorId",
        "reasonCodes",
    }
    summary = events[-1]["payload"]
    assert isinstance(summary, dict)
    assert summary["candidateCount"] == 2
    assert summary["confirmedCount"] == 1
    assert summary["dispositionCounts"] == {
        "confirmed": 1,
        "needs-review": 1,
        "inconclusive": 0,
        "rejected-objective": 0,
    }


def test_gate_preserves_duplicate_finding_ids_with_ordered_unique_candidate_ids(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    first = _finding(
        target=target,
        evidence=[evidence],
        finding_id="finding_shared",
    ).model_copy(update={"summary": "First validator-returned claim."})
    second = _finding(
        target=target,
        evidence=[evidence],
        finding_id="finding_shared",
    ).model_copy(update={"summary": "Second validator-returned claim."})

    validation = validate_findings(
        sample_campaign,
        [result],
        [first, second],
        store,
        "agent:validator:1",
    )

    assert [candidate.claim for candidate in validation.candidates] == [first, second]
    assert [candidate.candidate_id for candidate in validation.candidates] == [
        "candidate_1_finding_shared",
        "candidate_2_finding_shared",
    ]
    assert [decision.decision_id for decision in validation.decisions] == [
        "decision_1_finding_shared",
        "decision_2_finding_shared",
    ]
    assert [decision.candidate_id for decision in validation.decisions] == [
        validation.candidates[0].candidate_id,
        validation.candidates[1].candidate_id,
    ]
    assert validation.confirmed_findings == [first, second]


def test_gate_preserves_validator_omitted_admitted_candidate_for_review(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(
        target=target,
        evidence=[evidence],
        finding_id="producer_finding_1",
        validated=False,
    )
    candidate = _admitted_candidate(claim)

    validation = validate_findings(
        sample_campaign,
        [result],
        [],
        store,
        "agent:validator:1",
        admitted_candidates=[candidate],
    )

    assert validation.candidates == [candidate]
    assert validation.candidates[0].claim.validated is False
    assert validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    assert validation.decisions[0].reason_codes == [ValidationReasonCode.VALIDATOR_OMITTED]
    assert not validation.confirmed_findings


@pytest.mark.parametrize(
    "unavailable_reason",
    [
        ValidationReasonCode.VALIDATOR_UNAVAILABLE,
        ValidationReasonCode.VALIDATOR_CANCELLED,
    ],
)
def test_gate_keeps_candidate_inconclusive_when_validator_does_not_complete(
    unavailable_reason: ValidationReasonCode,
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    candidate = _admitted_candidate(
        _finding(
            target=target,
            evidence=[evidence],
            finding_id="producer_finding_unavailable",
            validated=False,
        )
    )

    validation = validate_findings(
        sample_campaign,
        [result],
        [],
        store,
        "agent:validator:unavailable",
        admitted_candidates=[candidate],
        validator_unavailable_reason=unavailable_reason,
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.INCONCLUSIVE
    assert decision.reason_codes == [unavailable_reason]
    assert not validation.confirmed_findings


def test_gate_rejects_admitted_candidate_with_mismatched_source_requests(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(
        target=target,
        evidence=[evidence],
        finding_id="producer_finding_wrong_source",
        validated=False,
    )
    candidate = _admitted_candidate(claim).model_copy(
        update={"source_request_ids": ["tool_unrelated_request"]}
    )

    validation = validate_findings(
        sample_campaign,
        [result],
        [],
        store,
        "agent:validator:1",
        admitted_candidates=[candidate],
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert decision.reason_codes == [ValidationReasonCode.SOURCE_REQUEST_MISMATCH]
    source_check = next(
        check for check in decision.checks if check.check_id == "candidate-source-requests"
    )
    assert source_check.status is ValidationCheckStatus.FAIL
    assert not validation.confirmed_findings


@pytest.mark.parametrize("authority_kind", ["request", "claim"])
def test_gate_blocks_validator_only_confirmation_inside_producer_authority(
    authority_kind: str,
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    validator_finding = _finding(
        target=target,
        evidence=[evidence],
        finding_id=f"validator_only_{authority_kind}",
        validated=True,
    )

    validation = validate_findings(
        sample_campaign,
        [result],
        [validator_finding],
        store,
        "agent:validator:1",
        producer_authoritative_request_ids=(
            {result.request_id} if authority_kind == "request" else set()
        ),
        producer_authoritative_claim_keys=(
            {(target, validator_finding.threat_class)} if authority_kind == "claim" else set()
        ),
    )

    assert len(validation.candidates) == 1
    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.NEEDS_REVIEW
    assert decision.reason_codes == [ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED]
    assert not validation.confirmed_findings
    unmatched = [
        event
        for event in _event_records(store)
        if event["event_type"] == "validation.output.unmatched"
    ]
    assert unmatched[0]["payload"]["reason"] == "candidate-producer-not-admitted"


def test_gate_rejects_finding_with_undeclared_threat_class(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    finding = _finding(target=target, evidence=[evidence]).model_copy(
        update={"threat_class": "M03"}
    )

    validation = validate_findings(
        sample_campaign,
        [result],
        [finding],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert ValidationReasonCode.THREAT_CLASS_UNDECLARED in decision.reason_codes
    assert not validation.confirmed_findings


@pytest.mark.parametrize(
    ("invalid_admission", "message"),
    [
        ("duplicate-id", "admitted candidate IDs must be unique"),
        ("prevalidated", "admitted candidate claims must have validated=False"),
    ],
)
def test_gate_rejects_invalid_admitted_candidate_contracts(
    invalid_admission: str,
    message: str,
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    claim = _finding(target=target, evidence=[], validated=False)
    candidate = _admitted_candidate(claim)
    admitted_candidates = (
        [candidate, candidate]
        if invalid_admission == "duplicate-id"
        else [_admitted_candidate(claim.model_copy(update={"validated": True}))]
    )

    with pytest.raises(ValueError, match=message):
        validate_findings(
            sample_campaign,
            [],
            [],
            store,
            "agent:validator:1",
            admitted_candidates=admitted_candidates,
        )


def test_gate_reconciles_rephrased_validator_signal_to_admitted_candidate(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(
        target=target,
        evidence=[evidence],
        finding_id="producer_finding_1",
        validated=False,
    )
    candidate = _admitted_candidate(claim)
    validator_finding = claim.model_copy(
        update={
            "finding_id": "validator_finding_rephrased",
            "title": "Validator rephrased the candidate",
            "validated": True,
        }
    )

    validation = validate_findings(
        sample_campaign,
        [result],
        [validator_finding],
        store,
        "agent:validator:1",
        admitted_candidates=[candidate],
    )

    assert validation.candidates == [candidate]
    assert validation.candidates[0].claim == claim
    assert validation.candidates[0].claim.validated is False
    assert validation.decisions[0].disposition is FindingDisposition.CONFIRMED
    assert validation.confirmed_findings == [claim.model_copy(update={"validated": True})]
    assert validation.confirmed_findings[0].title == claim.title


def test_gate_blocks_mismatched_validator_output_from_legacy_confirmation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(
        target=target,
        evidence=[evidence],
        finding_id="producer_finding_1",
        validated=False,
    )
    candidate = _admitted_candidate(claim)
    mismatched = claim.model_copy(
        update={
            "finding_id": "validator_bypass_attempt",
            "threat_class": "M03",
            "validated": True,
        }
    )

    validation = validate_findings(
        sample_campaign,
        [result],
        [mismatched],
        store,
        "agent:validator:1",
        admitted_candidates=[candidate],
    )

    assert validation.candidates[0] == candidate
    assert validation.candidates[1].claim == mismatched
    assert validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    assert validation.decisions[0].reason_codes == [ValidationReasonCode.VALIDATOR_OMITTED]
    assert validation.decisions[1].disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert ValidationReasonCode.THREAT_CLASS_UNDECLARED in validation.decisions[1].reason_codes
    assert not validation.confirmed_findings
    unmatched_events = [
        event
        for event in _event_records(store)
        if event["event_type"] == "validation.output.unmatched"
    ]
    assert len(unmatched_events) == 1
    assert unmatched_events[0]["payload"] == {
        "findingId": "validator_bypass_attempt",
        "validatorId": "agent:validator:1",
        "reason": "overlaps-admitted-same-run-evidence",
        "candidateIds": [candidate.candidate_id],
    }


def test_gate_treats_ambiguous_validator_outputs_as_candidate_omission(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(
        target=target,
        evidence=[evidence],
        finding_id="producer_finding_1",
        validated=False,
    )
    candidate = _admitted_candidate(claim)
    validator_findings = [
        claim.model_copy(update={"finding_id": f"validator_finding_{index}", "validated": True})
        for index in range(1, 3)
    ]

    validation = validate_findings(
        sample_campaign,
        [result],
        validator_findings,
        store,
        "agent:validator:1",
        admitted_candidates=[candidate],
    )

    assert validation.candidates[0] == candidate
    assert [candidate.claim for candidate in validation.candidates[1:]] == validator_findings
    assert validation.decisions[0].reason_codes == [ValidationReasonCode.VALIDATOR_OMITTED]
    assert all(
        decision.disposition is FindingDisposition.NEEDS_REVIEW
        and decision.reason_codes == [ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED]
        for decision in validation.decisions[1:]
    )
    assert not validation.confirmed_findings
    assert (
        sum(event["event_type"] == "validation.output.unmatched" for event in _event_records(store))
        == 2
    )


def test_gate_still_applies_objective_checks_to_matched_admitted_candidate(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    campaign = sample_campaign.model_copy(
        update={
            "spec": sample_campaign.spec.model_copy(
                update={
                    "scope": sample_campaign.spec.scope.model_copy(
                        update={
                            "allow": ["https://other.example.invalid/**"],
                            "deny": [],
                        }
                    )
                }
            )
        }
    )
    store = RunStore.create(tmp_path, campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)
    claim = _finding(
        target=target,
        evidence=[evidence],
        finding_id="producer_finding_1",
        validated=False,
    )
    candidate = _admitted_candidate(claim)
    validator_finding = claim.model_copy(update={"validated": True})

    validation = validate_findings(
        campaign,
        [result],
        [validator_finding],
        store,
        "agent:validator:1",
        admitted_candidates=[candidate],
    )

    assert validation.decisions[0].disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert ValidationReasonCode.TARGET_OUT_OF_SCOPE in validation.decisions[0].reason_codes
    assert not validation.confirmed_findings


def test_gate_rejects_empty_evidence_and_an_undeclared_target(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    declared_target = sample_campaign.spec.targets[0].endpoint
    undeclared_target = "https://staging.example.invalid/api/other"
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=undeclared_target)
    no_evidence = _finding(
        target=declared_target,
        evidence=[],
        finding_id="finding_empty",
    )
    undeclared = _finding(
        target=undeclared_target,
        evidence=[evidence],
        finding_id="finding_undeclared",
    )

    validation = validate_findings(
        sample_campaign,
        [result],
        [no_evidence, undeclared],
        store,
        "agent:validator:1",
    )

    assert all(
        decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
        for decision in validation.decisions
    )
    assert ValidationReasonCode.EVIDENCE_MISSING in validation.decisions[0].reason_codes
    assert ValidationReasonCode.TARGET_UNDECLARED in validation.decisions[1].reason_codes
    assert not validation.confirmed_findings


def test_gate_rechecks_explicit_http_deny_scope(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    scope = sample_campaign.spec.scope.model_copy(
        update={"deny": ["https://staging.example.invalid/api/**"]}
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"scope": scope})}
    )
    store = RunStore.create(tmp_path, campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)

    validation = validate_findings(
        campaign,
        [result],
        [_finding(target=target, evidence=[evidence])],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert ValidationReasonCode.TARGET_OUT_OF_SCOPE in decision.reason_codes


@pytest.mark.parametrize("failure", ["unlinked", "missing", "outside"])
def test_gate_rejects_untrusted_evidence_references(
    failure: str,
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)

    if failure == "unlinked":
        linked_result, reference = _gateway_result(store, target=target)
        result = linked_result.model_copy(update={"evidence": []})
    elif failure == "missing":
        reference = "evidence/missing.json"
        result = _tool_result("tool_request_1").model_copy(update={"evidence": [reference]})
    else:
        outside = tmp_path / "outside-evidence.json"
        result = _tool_result("tool_request_1")
        outside.write_text(
            json.dumps(_gateway_payload(target=target, result=result)),
            encoding="utf-8",
        )
        reference = str(outside.resolve())
        result = result.model_copy(update={"evidence": [reference]})

    validation = validate_findings(
        sample_campaign,
        [result],
        [_finding(target=target, evidence=[reference])],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    if failure == "missing":
        assert ValidationReasonCode.EVIDENCE_FILE_MISSING in decision.reason_codes
    else:
        assert ValidationReasonCode.EVIDENCE_UNLINKED in decision.reason_codes
        assert ValidationReasonCode.EVIDENCE_FILE_MISSING not in decision.reason_codes


@pytest.mark.parametrize(
    "tamper",
    [
        "invalid-json",
        "request-id-mismatch",
        "tool-id-mismatch",
        "target-mismatch",
        "result-mismatch",
    ],
)
def test_gate_rejects_evidence_with_invalid_gateway_provenance(
    tamper: str,
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, reference = _gateway_result(store, target=target)
    evidence_path = store.path / reference
    if tamper == "invalid-json":
        evidence_path.write_text("{not-json", encoding="utf-8")
    elif tamper == "result-mismatch":
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["result"]["success"] = False
        evidence_path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        request = payload["request"]
        replacements = {
            "request-id-mismatch": ("request_id", "tool_other"),
            "tool-id-mismatch": ("tool_id", "other.tool"),
            "target-mismatch": (
                "target",
                "https://staging.example.invalid/api/other",
            ),
        }
        field, value = replacements[tamper]
        request[field] = value
        evidence_path.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_findings(
        sample_campaign,
        [result],
        [_finding(target=target, evidence=[reference])],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert ValidationReasonCode.EVIDENCE_UNLINKED in decision.reason_codes
    assert ValidationReasonCode.EVIDENCE_FILE_MISSING not in decision.reason_codes


def test_gate_rejects_duplicate_tool_result_request_identity(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    first, evidence = _gateway_result(store, target=target, request_id="tool_duplicate")
    second, overwritten = _gateway_result(
        store,
        target=target,
        request_id="tool_duplicate",
    )
    assert overwritten == evidence

    validation = validate_findings(
        sample_campaign,
        [first, second],
        [_finding(target=target, evidence=[evidence])],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert ValidationReasonCode.EVIDENCE_UNLINKED in decision.reason_codes


def test_gate_marks_all_failed_linked_executions_inconclusive(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target, success=False)

    validation = validate_findings(
        sample_campaign,
        [result],
        [_finding(target=target, evidence=[evidence], validated=True)],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.INCONCLUSIVE
    assert decision.reason_codes == [ValidationReasonCode.EXECUTION_FAILED]
    assert not validation.confirmed_findings


def test_gate_fails_closed_when_http_scope_matcher_rejects_a_rule(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].endpoint
    invalid_scope = sample_campaign.spec.scope.model_copy(
        update={"allow": ["https://staging.example.invalid:invalid/api/**"]}
    )
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"scope": invalid_scope})}
    )
    store = RunStore.create(tmp_path, campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)

    validation = validate_findings(
        campaign,
        [result],
        [_finding(target=target, evidence=[evidence])],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    scope_check = next(check for check in decision.checks if check.check_id == "target-http-scope")
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert scope_check.status is ValidationCheckStatus.ERROR
    assert scope_check.reason_code is ValidationReasonCode.TARGET_OUT_OF_SCOPE


def test_gate_keeps_declared_non_http_lab_targets_supported(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = "lab://challenge-01"
    declared_target = sample_campaign.spec.targets[0].model_copy(update={"endpoint": target})
    campaign = sample_campaign.model_copy(
        update={
            "spec": sample_campaign.spec.model_copy(
                update={
                    "targets": [declared_target],
                    "scope": sample_campaign.spec.scope.model_copy(
                        update={"allow": [target], "deny": []}
                    ),
                }
            )
        }
    )
    store = RunStore.create(tmp_path, campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)

    validation = validate_findings(
        campaign,
        [result],
        [_finding(target=target, evidence=[evidence])],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    scope_check = next(check for check in decision.checks if check.check_id == "target-scope")
    assert decision.disposition is FindingDisposition.CONFIRMED
    assert scope_check.status is ValidationCheckStatus.PASS
    assert validation.confirmed_findings == [validation.candidates[0].claim]


def test_gate_requires_explicit_non_http_scope_and_honors_deny(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    target = "lab://challenge-01"
    declared_target = sample_campaign.spec.targets[0].model_copy(update={"endpoint": target})
    scope = sample_campaign.spec.scope.model_copy(update={"allow": [target], "deny": [target]})
    campaign = sample_campaign.model_copy(
        update={
            "spec": sample_campaign.spec.model_copy(
                update={"targets": [declared_target], "scope": scope}
            )
        }
    )
    store = RunStore.create(tmp_path, campaign.metadata.name)
    result, evidence = _gateway_result(store, target=target)

    validation = validate_findings(
        campaign,
        [result],
        [_finding(target=target, evidence=[evidence])],
        store,
        "agent:validator:1",
    )

    decision = validation.decisions[0]
    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert ValidationReasonCode.TARGET_OUT_OF_SCOPE in decision.reason_codes
