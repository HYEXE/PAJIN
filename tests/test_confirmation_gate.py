from datetime import UTC, datetime, timedelta

import pytest

from pajin.domain.models import CampaignMode, Finding, FindingSeverity, ToolRiskTier
from pajin.domain.replay import (
    CompiledReplaySpec,
    ModeReplayContract,
    ReplayArtifactSet,
    ReplayAttempt,
    ReplayAttemptStatus,
    ReplayBinding,
    ReplayExecutionStatus,
    ReplayOracleResult,
    ReplayOracleVerdict,
    ReplaySessionPolicy,
    ValidationEvidenceExcerpt,
    ValidationPacket,
    replay_argument_digest,
)
from pajin.domain.validation import (
    CandidateFinding,
    ClaimReplayStatus,
    ConfirmationBasis,
    FindingDisposition,
    PublicFindingState,
    ReplayConfirmationLineage,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.workflow.confirmation import decide_replay_confirmation
from pajin.workflow.confirmation_policy import (
    _build_claim_replay_projection,
    _public_finding_state,
)

NOW = datetime(2026, 7, 16, 9, 0, tzinfo=UTC)
SOURCE_REQUEST_ID = "tool_source_1"
REPLAY_REQUEST_ID = "tool_replay_1"
SOURCE_EVIDENCE = f"evidence/{SOURCE_REQUEST_ID}.json"
REPLAY_EVIDENCE = f"evidence/{REPLAY_REQUEST_ID}.json"


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        candidate_id="candidate_confirmation_1",
        claim=Finding(
            finding_id="finding_confirmation_1",
            title="Replay-confirmed bounded observation",
            severity=FindingSeverity.HIGH,
            threat_class="A02",
            target="https://target.example.test/v1/chat",
            summary="The bounded source execution produced a security-relevant observation.",
            reproduction=["Replay the exact typed operation."],
            evidence=[SOURCE_EVIDENCE],
            confidence=0.9,
            validated=False,
        ),
        source="trusted-core:test-candidate-producer",
        source_agent_id="trusted-core:test-candidate-producer",
        source_request_ids=[SOURCE_REQUEST_ID],
        created_at=NOW,
    )


def _binding(candidate: CandidateFinding) -> ReplayBinding:
    return ReplayBinding(
        candidate_id=candidate.candidate_id,
        campaign="confirmation-gate-test",
        candidate_run_id="run_source_1",
        replay_run_id="run_replay_1",
        original_request_id=SOURCE_REQUEST_ID,
        mode=CampaignMode.AI_REDTEAM,
        scenario_id="test.confirmation-gate",
        threat_class=candidate.claim.threat_class,
        tool_id="mock.agent-probe",
        tool_version="1.0.0",
        target_id="target_confirmation_1",
        target=candidate.claim.target,
    )


def _source_decision(
    candidate: CandidateFinding,
    *,
    semantic_supported: bool = True,
) -> ValidationDecision:
    reason = (
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
        if semantic_supported
        else ValidationReasonCode.VALIDATOR_OMITTED
    )
    return ValidationDecision(
        decision_id="decision_source_1",
        candidate_id=candidate.candidate_id,
        validator_id="agent:semantic-validator:1",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason_codes=[reason],
        decision_summary="The source objective and semantic validation stage completed.",
        supporting_evidence=[SOURCE_EVIDENCE],
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[
            ValidationCheckResult(
                check_id="candidate-bound-validator-assessment",
                status=(
                    ValidationCheckStatus.PASS if semantic_supported else ValidationCheckStatus.FAIL
                ),
                reason_code=(
                    ValidationReasonCode.VALIDATOR_CONFIRMED
                    if semantic_supported
                    else ValidationReasonCode.VALIDATOR_OMITTED
                ),
                summary=(
                    "Semantic Validator supported the Candidate."
                    if semantic_supported
                    else "Semantic Validator omitted the Candidate."
                ),
            ),
            ValidationCheckResult(
                check_id="independent-reproduction",
                status=ValidationCheckStatus.FAIL,
                reason_code=ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING,
                summary="Independent replay had not run at the source decision stage.",
            ),
        ],
        decided_at=NOW + timedelta(seconds=1),
    )


def _artifact_set(
    candidate: CandidateFinding,
    *,
    execution_status: ReplayExecutionStatus = ReplayExecutionStatus.SUCCEEDED,
    oracle_verdict: ReplayOracleVerdict = ReplayOracleVerdict.SUPPORTS,
    semantic_support_required: bool = True,
) -> ReplayArtifactSet:
    binding = _binding(candidate)
    required_contradictions = 1 if oracle_verdict is ReplayOracleVerdict.CONTRADICTS else 0
    contract = ModeReplayContract(
        contract_id="replay-contract:test-confirmation:v1",
        mode=CampaignMode.AI_REDTEAM,
        scenario_id=binding.scenario_id,
        tool_id=binding.tool_id,
        tool_version=binding.tool_version,
        method="POST",
        risk_tier=ToolRiskTier.T1,
        automatic=True,
        replay_safe=True,
        idempotent=True,
        session_policy=ReplaySessionPolicy.STATELESS,
        repetitions=1,
        required_successes=1,
        required_contradictions=required_contradictions,
        oracle_id="test.confirmation-oracle",
        oracle_version="1.0.0",
        observation_schema="pajin.test/confirmation-observation/v1",
        semantic_support_required=semantic_support_required,
        allowed_argument_fields={"simulation"},
    )
    packet = ValidationPacket(
        packet_id="validation-packet_confirmation_1",
        candidate_run_id=binding.candidate_run_id,
        candidate=candidate,
        mode=binding.mode,
        scenario_id=binding.scenario_id,
        target_id=binding.target_id,
        target=binding.target,
        threat_class=binding.threat_class,
        original_request_ids=candidate.source_request_ids,
        evidence=[
            ValidationEvidenceExcerpt(
                reference=SOURCE_EVIDENCE,
                sha256="a" * 64,
                excerpt="Redacted source observation.",
            )
        ],
        semantic_support_required=semantic_support_required,
        replay_contract_id=contract.contract_id,
        created_at=NOW + timedelta(seconds=2),
    )
    arguments = {"simulation": True}
    spec = CompiledReplaySpec(
        spec_id="compiled-replay_confirmation_1",
        contract_id=contract.contract_id,
        original_plan_step_id="step_confirmation_1",
        binding=binding,
        method=contract.method,
        arguments=arguments,
        argument_digest=replay_argument_digest(arguments),
        original_request_digest="b" * 64,
        original_evidence_digest="c" * 64,
        source_capability_digest="9" * 64,
        risk_tier=contract.risk_tier,
        replay_safe=True,
        idempotent=True,
        session_policy=contract.session_policy,
        repetitions=contract.repetitions,
        required_successes=contract.required_successes,
        required_contradictions=contract.required_contradictions,
        oracle_id=contract.oracle_id,
        oracle_version=contract.oracle_version,
        observation_schema=contract.observation_schema,
        semantic_support_required=semantic_support_required,
        grant_id="grant_replay_confirmation_1",
        max_calls=1,
        compiled_at=NOW + timedelta(seconds=3),
        expires_at=NOW + timedelta(minutes=5),
    )

    if execution_status is ReplayExecutionStatus.UNSUPPORTED:
        attempts: list[ReplayAttempt] = []
    else:
        attempt_status = {
            ReplayExecutionStatus.SUCCEEDED: ReplayAttemptStatus.SUCCEEDED,
            ReplayExecutionStatus.FAILED: ReplayAttemptStatus.FAILED,
            ReplayExecutionStatus.CANCELLED: ReplayAttemptStatus.CANCELLED,
            ReplayExecutionStatus.TIMED_OUT: ReplayAttemptStatus.TIMED_OUT,
            ReplayExecutionStatus.TARGET_UNAVAILABLE: ReplayAttemptStatus.TARGET_UNAVAILABLE,
        }[execution_status]
        attempts = [
            ReplayAttempt(
                attempt_id="replay-attempt_confirmation_1",
                spec_id=spec.spec_id,
                binding=binding,
                attempt_number=1,
                replay_request_id=REPLAY_REQUEST_ID,
                status=attempt_status,
                observation_schema=spec.observation_schema,
                observation=(
                    {"supportsClaim": oracle_verdict is ReplayOracleVerdict.SUPPORTS}
                    if attempt_status is ReplayAttemptStatus.SUCCEEDED
                    else {}
                ),
                evidence=(
                    [REPLAY_EVIDENCE] if attempt_status is ReplayAttemptStatus.SUCCEEDED else []
                ),
                error=(
                    None
                    if attempt_status is ReplayAttemptStatus.SUCCEEDED
                    else f"replay ended as {execution_status.value}"
                ),
                started_at=NOW + timedelta(seconds=4),
                finished_at=NOW + timedelta(seconds=5),
            )
        ]

    oracle = None
    if execution_status is ReplayExecutionStatus.SUCCEEDED:
        supports = oracle_verdict is ReplayOracleVerdict.SUPPORTS
        contradicts = oracle_verdict is ReplayOracleVerdict.CONTRADICTS
        oracle = ReplayOracleResult(
            oracle_result_id="replay-oracle_confirmation_1",
            spec_id=spec.spec_id,
            binding=binding,
            oracle_id=spec.oracle_id,
            oracle_version=spec.oracle_version,
            observation_schema=spec.observation_schema,
            verdict=oracle_verdict,
            attempt_ids=[attempt.attempt_id for attempt in attempts],
            supporting_evidence=[REPLAY_EVIDENCE] if supports else [],
            contradicting_evidence=[REPLAY_EVIDENCE] if contradicts else [],
            support_count=1 if supports else 0,
            required_support_count=1,
            contradiction_count=1 if contradicts else 0,
            required_contradiction_count=required_contradictions,
            summary="The typed Mode Oracle evaluated the replay observation.",
            evaluated_at=NOW + timedelta(seconds=6),
        )

    outcome = {
        "outcome_id": "replay-outcome_confirmation_1",
        "spec_id": spec.spec_id,
        "binding": binding,
        "execution_status": execution_status,
        "attempts": attempts,
        "attempt_ids": [attempt.attempt_id for attempt in attempts],
        "replay_request_ids": [attempt.replay_request_id for attempt in attempts],
        "evidence": [reference for attempt in attempts for reference in attempt.evidence],
        "oracle_result": oracle,
        "completed_at": NOW + timedelta(seconds=7),
    }
    return ReplayArtifactSet(
        validation_packet=packet,
        contract=contract,
        spec=spec,
        outcome=outcome,
    )


def _lineage(artifact_set: ReplayArtifactSet) -> ReplayConfirmationLineage:
    outcome = artifact_set.outcome
    return ReplayConfirmationLineage(
        replay_run_id=outcome.binding.replay_run_id,
        replay_outcome_id=outcome.outcome_id,
        replay_request_ids=outcome.replay_request_ids,
        replay_evidence=outcome.evidence,
        oracle_result_id=(
            outcome.oracle_result.oracle_result_id if outcome.oracle_result is not None else None
        ),
        ticket_id="replay-ticket_confirmation_1",
        candidate_source_root_digest="d" * 64,
        artifact_set_digest="e" * 64,
        artifact_seal_root_digest="f" * 64,
        receipt_seal_root_digest="1" * 64,
        verified_at=NOW + timedelta(seconds=8),
    )


def _decide(
    *,
    execution_status: ReplayExecutionStatus = ReplayExecutionStatus.SUCCEEDED,
    oracle_verdict: ReplayOracleVerdict = ReplayOracleVerdict.SUPPORTS,
    semantic_supported: bool = True,
    semantic_support_required: bool = True,
    independent_execution_attested: bool = False,
) -> ValidationDecision:
    candidate = _candidate()
    artifact_set = _artifact_set(
        candidate,
        execution_status=execution_status,
        oracle_verdict=oracle_verdict,
        semantic_support_required=semantic_support_required,
    )
    return decide_replay_confirmation(
        candidate=candidate,
        source_decision=_source_decision(
            candidate,
            semantic_supported=semantic_supported,
        ),
        artifact_set=artifact_set,
        lineage=_lineage(artifact_set),
        decided_at=NOW + timedelta(seconds=9),
        independent_execution_attested=independent_execution_attested,
    )


def test_supporting_replay_needs_independent_execution_attestation() -> None:
    decision = _decide()

    assert decision.disposition is FindingDisposition.NEEDS_REVIEW
    assert decision.reason_codes == [ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING]
    assert decision.confirmation_basis is None
    assert decision.method is ValidationMethod.RESTRICTED_REPLAY_GATE
    assert decision.supersedes_decision_id == "decision_source_1"
    assert decision.replay_request_ids == [REPLAY_REQUEST_ID]
    assert decision.replay_outcome_ids == ["replay-outcome_confirmation_1"]
    assert len(decision.replay_lineage) == 1
    assert decision.replay_lineage[0].replay_request_ids == [REPLAY_REQUEST_ID]
    assert decision.replay_lineage[0].replay_evidence == [REPLAY_EVIDENCE]


def test_independently_attested_supporting_replay_is_confirmed() -> None:
    decision = _decide(independent_execution_attested=True)

    assert decision.disposition is FindingDisposition.CONFIRMED
    assert decision.confirmation_basis is ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
    assert decision.reason_codes == [ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED]


def test_independent_attestation_cannot_override_oracle_contradiction() -> None:
    decision = _decide(
        oracle_verdict=ReplayOracleVerdict.CONTRADICTS,
        independent_execution_attested=True,
    )

    assert decision.disposition is FindingDisposition.REJECTED_OBJECTIVE
    assert decision.reason_codes == [ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED]
    assert decision.confirmation_basis is None


@pytest.mark.parametrize(
    ("execution_status", "oracle_verdict", "claim_status", "public_state"),
    [
        (
            ReplayExecutionStatus.SUCCEEDED,
            ReplayOracleVerdict.SUPPORTS,
            ClaimReplayStatus.REPRODUCED,
            PublicFindingState.PARTIALLY_CONFIRMED,
        ),
        (
            ReplayExecutionStatus.SUCCEEDED,
            ReplayOracleVerdict.CONTRADICTS,
            ClaimReplayStatus.NOT_REPRODUCED,
            PublicFindingState.NOT_REPRODUCED,
        ),
        (
            ReplayExecutionStatus.SUCCEEDED,
            ReplayOracleVerdict.INCONCLUSIVE,
            ClaimReplayStatus.INCONCLUSIVE,
            PublicFindingState.INCONCLUSIVE,
        ),
        (
            ReplayExecutionStatus.FAILED,
            ReplayOracleVerdict.SUPPORTS,
            ClaimReplayStatus.INCONCLUSIVE,
            PublicFindingState.INCONCLUSIVE,
        ),
        (
            ReplayExecutionStatus.UNSUPPORTED,
            ReplayOracleVerdict.SUPPORTS,
            ClaimReplayStatus.NOT_ELIGIBLE,
            PublicFindingState.NEEDS_REVIEW,
        ),
    ],
)
def test_claim_replay_projection_preserves_partial_and_negative_public_states(
    execution_status: ReplayExecutionStatus,
    oracle_verdict: ReplayOracleVerdict,
    claim_status: ClaimReplayStatus,
    public_state: PublicFindingState,
) -> None:
    candidate = _candidate()
    artifact_set = _artifact_set(
        candidate,
        execution_status=execution_status,
        oracle_verdict=oracle_verdict,
    )
    lineage = _lineage(artifact_set)
    decision = decide_replay_confirmation(
        candidate=candidate,
        source_decision=_source_decision(candidate),
        artifact_set=artifact_set,
        lineage=lineage,
        decided_at=NOW + timedelta(seconds=9),
    )

    assessment = _build_claim_replay_projection(
        candidate=candidate,
        decision=decision,
        artifact_set=artifact_set,
        lineage=lineage,
    )

    assert assessment.status is claim_status
    assert assessment.candidate_id == candidate.candidate_id
    assert assessment.replay_outcome_id == artifact_set.outcome.outcome_id
    assert assessment.independent_execution_attested is False
    assert _public_finding_state(decision, assessment) is public_state


def test_supporting_replay_stays_needs_review_without_required_semantic_support() -> None:
    decision = _decide(semantic_supported=False)

    assert decision.disposition is FindingDisposition.NEEDS_REVIEW
    assert decision.reason_codes == [ValidationReasonCode.VALIDATOR_OMITTED]
    assert decision.confirmation_basis is None
    assert decision.replay_outcome_ids == ["replay-outcome_confirmation_1"]


@pytest.mark.parametrize(
    ("oracle_verdict", "expected_disposition", "expected_reason"),
    [
        (
            ReplayOracleVerdict.INCONCLUSIVE,
            FindingDisposition.INCONCLUSIVE,
            ValidationReasonCode.REPLAY_ORACLE_INCONCLUSIVE,
        ),
        (
            ReplayOracleVerdict.CONTRADICTS,
            FindingDisposition.REJECTED_OBJECTIVE,
            ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED,
        ),
    ],
)
def test_successful_replay_uses_typed_oracle_reason_matrix(
    oracle_verdict: ReplayOracleVerdict,
    expected_disposition: FindingDisposition,
    expected_reason: ValidationReasonCode,
) -> None:
    decision = _decide(oracle_verdict=oracle_verdict)

    assert decision.disposition is expected_disposition
    assert decision.reason_codes == [expected_reason]
    assert decision.confirmation_basis is None


def test_confirmation_rejects_unthresholded_contradiction_copy() -> None:
    candidate = _candidate()
    artifact_set = _artifact_set(
        candidate,
        oracle_verdict=ReplayOracleVerdict.CONTRADICTS,
    )
    oracle = artifact_set.outcome.oracle_result
    assert oracle is not None
    unthresholded = oracle.model_copy(
        update={
            "contradiction_count": 0,
            "required_contradiction_count": 0,
            "contradicting_evidence": [],
        }
    )
    unsafe_artifact_set = artifact_set.model_copy(
        update={"outcome": artifact_set.outcome.model_copy(update={"oracle_result": unthresholded})}
    )

    with pytest.raises(ValueError, match="explicit threshold and exact evidence"):
        decide_replay_confirmation(
            candidate=candidate,
            source_decision=_source_decision(candidate),
            artifact_set=unsafe_artifact_set,
            lineage=_lineage(unsafe_artifact_set),
            decided_at=NOW + timedelta(seconds=9),
        )


@pytest.mark.parametrize(
    ("execution_status", "expected_reason"),
    [
        (
            ReplayExecutionStatus.FAILED,
            ValidationReasonCode.REPLAY_EXECUTION_FAILED,
        ),
        (ReplayExecutionStatus.CANCELLED, ValidationReasonCode.REPLAY_CANCELLED),
        (ReplayExecutionStatus.TIMED_OUT, ValidationReasonCode.REPLAY_TIMED_OUT),
        (
            ReplayExecutionStatus.TARGET_UNAVAILABLE,
            ValidationReasonCode.REPLAY_TARGET_UNAVAILABLE,
        ),
    ],
)
def test_terminal_replay_statuses_are_inconclusive_with_bounded_reasons(
    execution_status: ReplayExecutionStatus,
    expected_reason: ValidationReasonCode,
) -> None:
    decision = _decide(execution_status=execution_status)

    assert decision.disposition is FindingDisposition.INCONCLUSIVE
    assert decision.reason_codes == [expected_reason]
    assert decision.confirmation_basis is None


def test_unsupported_replay_stays_needs_review() -> None:
    decision = _decide(execution_status=ReplayExecutionStatus.UNSUPPORTED)

    assert decision.disposition is FindingDisposition.NEEDS_REVIEW
    assert decision.reason_codes == [ValidationReasonCode.REPLAY_NOT_ELIGIBLE]
    assert decision.confirmation_basis is None


def test_confirmation_decision_cannot_predate_verified_receipt() -> None:
    candidate = _candidate()
    artifact_set = _artifact_set(candidate)

    with pytest.raises(ValueError, match="cannot predate"):
        decide_replay_confirmation(
            candidate=candidate,
            source_decision=_source_decision(candidate),
            artifact_set=artifact_set,
            lineage=_lineage(artifact_set),
            decided_at=NOW + timedelta(seconds=7),
        )
