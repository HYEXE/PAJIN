from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.domain.models import CampaignMode, Finding, FindingSeverity, ToolRiskTier
from pajin.domain.replay import (
    CompiledReplaySpec,
    ModeReplayContract,
    ReplayArtifactSet,
    ReplayAttempt,
    ReplayAttemptStatus,
    ReplayBinding,
    ReplayExecutionStatus,
    ReplayIntent,
    ReplayMaterialization,
    ReplayOracleResult,
    ReplayOracleVerdict,
    ReplayOutcome,
    ReplaySessionPolicy,
    ValidationEvidenceExcerpt,
    ValidationPacket,
    replay_argument_digest,
)
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)

NOW = datetime(2026, 7, 15, 6, 0, tzinfo=UTC)


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        candidate_id="candidate_kisa_1",
        claim=Finding(
            finding_id="finding_kisa_1",
            title="System prompt sentinel exposed",
            severity=FindingSeverity.HIGH,
            threat_class="M03",
            target="https://ai.example.test/v1/chat",
            summary="A bounded transcript exposed the catalog sentinel.",
            reproduction=["Run the exact catalog probe."],
            evidence=["evidence/tool_original_1.json"],
            confidence=1,
        ),
        source="trusted-core:candidate-producer",
        source_agent_id="trusted-core:kisa-candidate-producer",
        source_request_ids=["tool_original_1"],
        created_at=NOW,
    )


def _packet(**updates: object) -> ValidationPacket:
    values: dict[str, object] = {
        "packet_id": "validation-packet_1",
        "candidate_run_id": "run_candidate_1",
        "candidate": _candidate(),
        "mode": CampaignMode.AI_REDTEAM,
        "scenario_id": "kisa.model.system-prompt-disclosure",
        "target_id": "ai-chat-lab",
        "target": "https://ai.example.test/v1/chat",
        "threat_class": "M03",
        "original_request_ids": ["tool_original_1"],
        "evidence": [
            ValidationEvidenceExcerpt(
                reference="evidence/tool_original_1.json",
                sha256="a" * 64,
                excerpt="Redacted assistant response containing the catalog sentinel.",
            )
        ],
        "semantic_support_required": True,
        "replay_contract_id": "replay-contract:kisa-m03:v1",
        "created_at": NOW,
    }
    values.update(updates)
    return ValidationPacket.model_validate(values)


def _binding(**updates: object) -> ReplayBinding:
    values: dict[str, object] = {
        "candidate_id": "candidate_kisa_1",
        "campaign": "kisa-ai-chat-lab-assessment",
        "candidate_run_id": "run_candidate_1",
        "replay_run_id": "run_replay_1",
        "original_request_id": "tool_original_1",
        "mode": CampaignMode.AI_REDTEAM,
        "scenario_id": "kisa.model.system-prompt-disclosure",
        "threat_class": "M03",
        "tool_id": "ai.chat-probe",
        "tool_version": "1.0.0",
        "target_id": "ai-chat-lab",
        "target": "https://ai.example.test/v1/chat",
    }
    values.update(updates)
    return ReplayBinding.model_validate(values)


def _contract(**updates: object) -> ModeReplayContract:
    values: dict[str, object] = {
        "contract_id": "replay-contract:kisa-m03:v1",
        "mode": CampaignMode.AI_REDTEAM,
        "scenario_id": "kisa.model.system-prompt-disclosure",
        "tool_id": "ai.chat-probe",
        "tool_version": "1.0.0",
        "method": "POST",
        "risk_tier": ToolRiskTier.T2,
        "automatic": True,
        "replay_safe": True,
        "idempotent": True,
        "session_policy": ReplaySessionPolicy.FRESH_SESSION,
        "materializer_id": "kisa.ai-chat-fresh-session",
        "materializer_version": "1.0.0",
        "ephemeral_argument_fields": {"session_id"},
        "repetitions": 2,
        "required_successes": 2,
        "oracle_id": "kisa.exact-marker",
        "oracle_version": "1.0.0",
        "observation_schema": "pajin.ai-chat-probe-output/v1",
        "semantic_support_required": True,
        "allowed_argument_fields": {
            "scenario_id",
            "threat_class",
            "session_id",
            "turns",
            "checks",
        },
    }
    values.update(updates)
    return ModeReplayContract.model_validate(values)


def _intent(**updates: object) -> ReplayIntent:
    values: dict[str, object] = {
        "intent_id": "replay-intent_1",
        "replay_contract_id": "replay-contract:kisa-m03:v1",
        "candidate_id": "candidate_kisa_1",
        "candidate_run_id": "run_candidate_1",
        "original_request_id": "tool_original_1",
        "mode": CampaignMode.AI_REDTEAM,
        "scenario_id": "kisa.model.system-prompt-disclosure",
        "threat_class": "M03",
        "comparison_goals": ["Re-evaluate the exact catalog sentinel over a fresh transcript."],
        "rationale": "The original observation requires independent reproduction.",
        "created_at": NOW,
    }
    values.update(updates)
    return ReplayIntent.model_validate(values)


def _arguments() -> dict[str, object]:
    return {
        "scenario_id": "kisa.model.system-prompt-disclosure",
        "threat_class": "M03",
        "session_id": "pajin:replay:fresh:1",
        "turns": [{"name": "probe", "messages": [{"role": "user", "content": "probe"}]}],
        "checks": [
            {
                "check_id": "system-prompt-sentinel",
                "kind": "response-contains",
                "turn": 0,
                "value": "PAJIN_SYSTEM_SENTINEL_COBALT",
                "sensitive": True,
            }
        ],
    }


def _spec(**updates: object) -> CompiledReplaySpec:
    arguments = _arguments()
    values: dict[str, object] = {
        "spec_id": "compiled-replay_1",
        "intent_id": "replay-intent_1",
        "contract_id": "replay-contract:kisa-m03:v1",
        "original_plan_step_id": "step_m03_1",
        "binding": _binding(),
        "method": "POST",
        "arguments": arguments,
        "argument_digest": replay_argument_digest(arguments),
        "original_request_digest": "b" * 64,
        "original_evidence_digest": "c" * 64,
        "secret_lease_ids": [],
        "risk_tier": ToolRiskTier.T2,
        "replay_safe": True,
        "idempotent": True,
        "session_policy": ReplaySessionPolicy.FRESH_SESSION,
        "materializer_id": "kisa.ai-chat-fresh-session",
        "materializer_version": "1.0.0",
        "ephemeral_argument_fields": {"session_id"},
        "repetitions": 2,
        "required_successes": 2,
        "oracle_id": "kisa.exact-marker",
        "oracle_version": "1.0.0",
        "observation_schema": "pajin.ai-chat-probe-output/v1",
        "semantic_support_required": True,
        "grant_id": "grant_replay_1",
        "max_calls": 2,
        "compiled_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(updates)
    return CompiledReplaySpec.model_validate(values)


def _attempt(
    attempt_number: int,
    *,
    request_id: str | None = None,
    binding: ReplayBinding | None = None,
) -> ReplayAttempt:
    source_arguments = _arguments()
    materialized_arguments = {
        **source_arguments,
        "session_id": f"pajin:replay:attempt:{attempt_number}",
    }
    replay_request_id = request_id or f"tool_replay_{attempt_number}"
    return ReplayAttempt(
        attempt_id=f"replay-attempt_{attempt_number}",
        spec_id="compiled-replay_1",
        binding=binding or _binding(),
        attempt_number=attempt_number,
        replay_request_id=replay_request_id,
        status=ReplayAttemptStatus.SUCCEEDED,
        observation_schema="pajin.ai-chat-probe-output/v1",
        materialization=ReplayMaterialization(
            materialization_id=f"replay-materialization_{attempt_number}",
            spec_id="compiled-replay_1",
            attempt_number=attempt_number,
            replay_request_id=replay_request_id,
            materializer_id="kisa.ai-chat-fresh-session",
            materializer_version="1.0.0",
            changed_fields={"session_id"},
            source_argument_digest=replay_argument_digest(source_arguments),
            arguments=materialized_arguments,
            argument_digest=replay_argument_digest(materialized_arguments),
            source_session_digest=sha256(str(source_arguments["session_id"]).encode()).hexdigest(),
            materialized_session_digest=sha256(
                str(materialized_arguments["session_id"]).encode()
            ).hexdigest(),
            materialized_at=NOW,
        ),
        observation={"scenarioId": "kisa.model.system-prompt-disclosure"},
        evidence=[f"evidence/tool_replay_{attempt_number}.json"],
        started_at=NOW + timedelta(seconds=attempt_number),
        finished_at=NOW + timedelta(seconds=attempt_number + 1),
    )


def _oracle(attempts: list[ReplayAttempt]) -> ReplayOracleResult:
    return ReplayOracleResult(
        oracle_result_id="replay-oracle_1",
        spec_id="compiled-replay_1",
        binding=_binding(),
        oracle_id="kisa.exact-marker",
        oracle_version="1.0.0",
        observation_schema="pajin.ai-chat-probe-output/v1",
        verdict=ReplayOracleVerdict.SUPPORTS,
        attempt_ids=[attempt.attempt_id for attempt in attempts],
        supporting_evidence=[reference for attempt in attempts for reference in attempt.evidence],
        support_count=2,
        required_support_count=2,
        summary="Both fresh transcripts contain the exact catalog sentinel.",
        evaluated_at=NOW + timedelta(seconds=4),
    )


def _outcome(**updates: object) -> ReplayOutcome:
    attempts = [_attempt(1), _attempt(2)]
    values: dict[str, object] = {
        "outcome_id": "replay-outcome_1",
        "spec_id": "compiled-replay_1",
        "binding": _binding(),
        "execution_status": ReplayExecutionStatus.SUCCEEDED,
        "attempts": attempts,
        "attempt_ids": [attempt.attempt_id for attempt in attempts],
        "replay_request_ids": [attempt.replay_request_id for attempt in attempts],
        "evidence": [reference for attempt in attempts for reference in attempt.evidence],
        "oracle_result": _oracle(attempts),
        "completed_at": NOW + timedelta(seconds=5),
    }
    values.update(updates)
    return ReplayOutcome.model_validate(values)


def _artifact_set(**updates: object) -> ReplayArtifactSet:
    values: dict[str, object] = {
        "validation_packet": _packet(),
        "contract": _contract(),
        "intent": _intent(),
        "spec": _spec(),
        "outcome": _outcome(),
    }
    values.update(updates)
    return ReplayArtifactSet.model_validate(values)


def test_validation_packet_is_bounded_redacted_and_candidate_bound() -> None:
    packet = _packet()

    wire = packet.model_dump(mode="json", by_alias=True)
    assert wire["apiVersion"] == "pajin.dev/replay/v1alpha1"
    assert wire["kind"] == "ValidationPacket"
    assert packet.evidence[0].redacted is True
    assert packet.evidence[0].untrusted is True

    values = packet.model_dump()
    values["original_request_ids"] = ["tool_foreign"]
    with pytest.raises(ValidationError, match="original request IDs"):
        ValidationPacket.model_validate(values)

    values = packet.model_dump()
    values["evidence"] = [
        ValidationEvidenceExcerpt(
            reference="evidence/foreign.json",
            sha256="b" * 64,
            excerpt="Foreign evidence must not enter the packet.",
        )
    ]
    with pytest.raises(ValidationError, match="candidate evidence"):
        ValidationPacket.model_validate(values)

    with pytest.raises(ValidationError, match="target must match the candidate"):
        _packet(target="https://different.example/v1/chat")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command", ["curl", "https://target.example"]),
        ("url", "https://attacker.example"),
        ("tool_request", {"tool_id": "shell"}),
        ("capability_grant", {"tools": ["shell"]}),
        ("arguments", {"payload": "execute me"}),
    ],
)
def test_replay_intent_rejects_executable_or_authority_fields(
    field: str,
    value: object,
) -> None:
    values = _intent().model_dump()
    values[field] = value

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ReplayIntent.model_validate(values)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"replay_safe": False}, "replay-safe"),
        ({"idempotent": False}, "idempotent"),
        ({"risk_tier": ToolRiskTier.T3}, "T0-T2"),
        ({"required_successes": 3}, "required successes"),
    ],
)
def test_automatic_mode_contract_fails_closed(
    updates: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _contract(**updates)


def test_compiled_spec_binds_digest_budget_and_short_lived_authority() -> None:
    spec = _spec()
    assert spec.method == "POST"
    assert spec.argument_digest == replay_argument_digest(spec.arguments)

    with pytest.raises(ValidationError, match="argument digest"):
        _spec(argument_digest="0" * 64)
    with pytest.raises(ValidationError, match="call budget"):
        _spec(max_calls=3)
    with pytest.raises(ValidationError, match="expire after"):
        _spec(expires_at=NOW)


def test_replay_artifact_set_round_trips_complete_candidate_bound_lineage() -> None:
    artifacts = _artifact_set()

    restored = ReplayArtifactSet.model_validate_json(artifacts.model_dump_json(by_alias=True))

    assert restored == artifacts
    assert restored.outcome.supports_claim is True
    assert restored.outcome.replay_request_ids == ["tool_replay_1", "tool_replay_2"]
    assert restored.model_dump(mode="json", by_alias=True)["apiVersion"] == (
        "pajin.dev/replay/v1alpha1"
    )

    future_wire = artifacts.model_dump(mode="json", by_alias=True)
    future_wire["apiVersion"] = "pajin.dev/replay/v2"
    with pytest.raises(ValidationError, match=r"pajin\.dev/replay/v1alpha1"):
        ReplayArtifactSet.model_validate(future_wire)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_id", "candidate_foreign"),
        ("candidate_run_id", "run_foreign"),
        ("original_request_id", "tool_foreign"),
        ("target", "https://different.example/v1/chat"),
    ],
)
def test_compiled_replay_rejects_candidate_packet_substitution(
    field: str,
    value: object,
) -> None:
    spec = _spec(binding=_binding(**{field: value}))

    with pytest.raises(ValidationError, match="validation packet"):
        _artifact_set(spec=spec)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_id", "candidate_substituted"),
        ("campaign", "foreign-campaign"),
        ("replay_run_id", "run_foreign"),
        ("scenario_id", "kisa.model.jailbreak-policy-bypass"),
        ("tool_id", "shell.exec"),
        ("target", "https://different.example/v1/chat"),
        ("threat_class", "M06"),
    ],
)
def test_replay_artifact_set_rejects_binding_substitution(
    field: str,
    value: object,
) -> None:
    values = _outcome().model_dump()
    values["binding"][field] = value
    for attempt in values["attempts"]:
        attempt["binding"][field] = value
    values["oracle_result"]["binding"][field] = value
    changed = ReplayOutcome.model_validate(values)

    with pytest.raises(ValidationError, match="outcome binding"):
        _artifact_set(outcome=changed)


def test_replay_outcome_rejects_duplicate_or_original_request_identity() -> None:
    attempts = [_attempt(1), _attempt(2, request_id="tool_replay_1")]
    with pytest.raises(ValidationError, match="replay request IDs must be unique"):
        _outcome(
            attempts=attempts,
            attempt_ids=[attempt.attempt_id for attempt in attempts],
            replay_request_ids=[attempt.replay_request_id for attempt in attempts],
            evidence=[reference for attempt in attempts for reference in attempt.evidence],
            oracle_result=_oracle(attempts),
        )

    with pytest.raises(ValidationError, match="must differ from the original request"):
        _attempt(1, request_id="tool_original_1")


def test_replay_outcome_rejects_foreign_attempt_binding_and_evidence_substitution() -> None:
    foreign = _attempt(1, binding=_binding(replay_run_id="run_foreign"))
    with pytest.raises(ValidationError, match="attempt binding"):
        _outcome(
            attempts=[foreign, _attempt(2)],
            attempt_ids=[foreign.attempt_id, "replay-attempt_2"],
            replay_request_ids=[foreign.replay_request_id, "tool_replay_2"],
            evidence=[*foreign.evidence, "evidence/tool_replay_2.json"],
        )

    with pytest.raises(ValidationError, match="evidence must exactly match"):
        _outcome(evidence=["evidence/substituted.json"])


def test_validation_decision_reads_legacy_payload_and_tracks_replay_outcomes() -> None:
    legacy = {
        "decision_id": "decision_legacy_1",
        "candidate_id": "candidate_kisa_1",
        "validator_id": "agent:deterministic-gate:1",
        "method": ValidationMethod.HYBRID_LEGACY_GATE,
        "disposition": FindingDisposition.NEEDS_REVIEW,
        "reason_codes": [ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING],
        "decision_summary": "Replay had not been implemented.",
        "supporting_evidence": ["evidence/tool_original_1.json"],
        "contradicting_evidence": [],
        "replay_request_ids": [],
        "checks": [],
        "decided_at": NOW,
    }

    decision = ValidationDecision.model_validate(legacy)
    assert decision.replay_outcome_ids == []

    values = decision.model_dump()
    values["replay_outcome_ids"] = ["replay-outcome_1", "replay-outcome_1"]
    with pytest.raises(ValidationError, match="replay_outcome_ids must be unique"):
        ValidationDecision.model_validate(values)
