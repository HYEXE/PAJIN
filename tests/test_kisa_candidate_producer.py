import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.domain.manifest import load_manifest
from pajin.domain.models import AgentPlan, CampaignManifest, ToolResult
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime
from pajin.tools.ai import AIChatProbeInput


def _campaign() -> CampaignManifest:
    return load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))


def _plan(campaign: CampaignManifest, *, repetitions: int = 2) -> AgentPlan:
    return asyncio.run(
        KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=repetitions)).plan(campaign)
    )


def _result_for_step(plan: AgentPlan, index: int) -> ToolResult:
    step = plan.steps[index]
    probe = AIChatProbeInput.model_validate(step.request.arguments)
    raw_turns: list[dict[str, object]] = []
    for turn_index, turn in enumerate(probe.turns):
        markers = [check.value for check in probe.checks if check.turn == turn_index]
        raw_turns.append(
            {
                "index": turn_index,
                "name": turn.name,
                "request": {
                    "sessionId": probe.session_id,
                    "messages": [message.model_dump(mode="json") for message in turn.messages],
                },
                "response": {
                    "sessionId": probe.session_id,
                    "message": {
                        "role": "assistant",
                        "content": " ".join(["observed", *markers]),
                    },
                },
            }
        )
    now = datetime.now(UTC)
    return ToolResult(
        request_id=step.request.request_id,
        tool_id=step.request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        evidence=[f"evidence/{step.request.request_id}.json"],
        data={
            "target": step.request.target,
            "scenarioId": probe.scenario_id,
            "threatClass": probe.threat_class,
            "sessionId": probe.session_id,
            "purpose": "attack",
            # These Worker verdicts are deliberately false. The producer must use
            # the raw transcript, not either self-reported verdict.
            "vulnerable": False,
            "observation": "The Worker verdict is typed but deliberately untrusted.",
            "turns": raw_turns,
            "checks": [
                {
                    "checkId": check.check_id,
                    "kind": check.kind.value,
                    "turn": check.turn,
                    "matched": False,
                    "sensitive": check.sensitive,
                }
                for check in probe.checks
            ],
            "sensitiveExposureCount": 0,
            "meanResponseLatencySeconds": 0.01,
            "regressionPassed": None,
            "networkPerformed": True,
        },
    )


def test_producer_rechecks_all_catalog_transcripts_and_groups_repetitions() -> None:
    campaign = _campaign()
    plan = _plan(campaign)
    results = [_result_for_step(plan, index) for index in range(len(plan.steps))]

    production = KISACandidateProducer().produce(campaign, plan, results)
    candidates = list(production.candidates)

    assert [candidate.claim.threat_class for candidate in candidates] == [
        "M03",
        "M06",
        "A04",
    ]
    assert all(candidate.claim.validated is False for candidate in candidates)
    assert all(candidate.source == "trusted-core:candidate-producer" for candidate in candidates)
    assert all(
        candidate.source_agent_id == "trusted-core:kisa-candidate-producer"
        for candidate in candidates
    )
    for candidate, expected_steps in zip(
        candidates,
        (plan.steps[0:2], plan.steps[2:4], plan.steps[4:6]),
        strict=True,
    ):
        expected_request_ids = [step.request.request_id for step in expected_steps]
        assert candidate.source_request_ids == expected_request_ids
        assert candidate.claim.evidence == [
            f"evidence/{request_id}.json" for request_id in expected_request_ids
        ]
    assert production.authoritative_request_ids == frozenset(
        step.request.request_id for step in plan.steps
    )
    assert production.authoritative_claim_keys == frozenset(
        (campaign.spec.targets[0].endpoint, threat_class) for threat_class in ("M03", "M06", "A04")
    )


def test_producer_treats_empty_campaign_threat_list_as_unconstrained() -> None:
    campaign = _campaign()
    plan = _plan(campaign, repetitions=1)
    results = [_result_for_step(plan, index) for index in range(len(plan.steps))]
    unconstrained = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"threat_classes": []})}
    )

    production = KISACandidateProducer().produce(unconstrained, plan, results)

    assert len(production.candidates) == 3
    assert production.authoritative_request_ids == {step.request.request_id for step in plan.steps}
    assert production.authoritative_claim_keys == {
        (campaign.spec.targets[0].endpoint, threat_class) for threat_class in ("M03", "M06", "A04")
    }


def test_producer_rejects_worker_verdict_when_transcript_has_no_marker() -> None:
    campaign = _campaign()
    full_plan = _plan(campaign, repetitions=1)
    plan = full_plan.model_copy(update={"steps": [full_plan.steps[0]]})
    result = _result_for_step(plan, 0)
    raw_turns = result.data["turns"]
    assert isinstance(raw_turns, list)
    raw_turn = raw_turns[0]
    assert isinstance(raw_turn, dict)
    response = raw_turn["response"]
    assert isinstance(response, dict)
    message = response["message"]
    assert isinstance(message, dict)
    message["content"] = "I cannot disclose protected instructions."
    result.data["vulnerable"] = True
    raw_checks = result.data["checks"]
    assert isinstance(raw_checks, list)
    raw_check = raw_checks[0]
    assert isinstance(raw_check, dict)
    raw_check["matched"] = True

    production = KISACandidateProducer().produce(campaign, plan, [result])
    assert production.candidates == ()
    assert production.authoritative_request_ids == {plan.steps[0].request.request_id}
    assert (
        plan.steps[0].request.target,
        "M03",
    ) in production.authoritative_claim_keys


@pytest.mark.parametrize(
    "mutation",
    [
        "step-metadata",
        "request-template",
        "result-target",
        "result-session",
        "regression-purpose",
        "offline-result",
        "missing-evidence",
        "result-check-contract",
    ],
)
def test_producer_rejects_non_exact_or_untrusted_observations(mutation: str) -> None:
    campaign = _campaign()
    full_plan = _plan(campaign, repetitions=1)
    step = full_plan.steps[0]
    result = _result_for_step(full_plan, 0)

    if mutation == "step-metadata":
        step = step.model_copy(update={"attack_surface": "untrusted-surface"})
    elif mutation == "request-template":
        arguments = dict(step.request.arguments)
        raw_turns = [dict(turn) for turn in arguments["turns"]]
        first_turn = dict(raw_turns[0])
        messages = [dict(message) for message in first_turn["messages"]]
        messages[0]["content"] = "not the catalog probe"
        first_turn["messages"] = messages
        raw_turns[0] = first_turn
        arguments["turns"] = raw_turns
        step = step.model_copy(
            update={"request": step.request.model_copy(update={"arguments": arguments})}
        )
    elif mutation == "result-target":
        result.data["target"] = "https://different.example.test/v1/chat"
    elif mutation == "result-session":
        result.data["sessionId"] = "pajin:different:session"
    elif mutation == "regression-purpose":
        result.data["purpose"] = "regression"
    elif mutation == "offline-result":
        result.data["networkPerformed"] = False
    elif mutation == "missing-evidence":
        result = result.model_copy(update={"evidence": []})
    elif mutation == "result-check-contract":
        raw_checks = result.data["checks"]
        assert isinstance(raw_checks, list)
        raw_check = raw_checks[0]
        assert isinstance(raw_check, dict)
        raw_check["checkId"] = "forged-check"

    plan = full_plan.model_copy(update={"steps": [step]})
    assert KISACandidateProducer().produce(campaign, plan, [result]).candidates == ()


def test_producer_rejects_ambiguous_duplicate_result_request_ids() -> None:
    campaign = _campaign()
    full_plan = _plan(campaign, repetitions=1)
    plan = full_plan.model_copy(update={"steps": [full_plan.steps[0]]})
    result = _result_for_step(plan, 0)

    production = KISACandidateProducer().produce(campaign, plan, [result, result])
    assert production.candidates == ()
    assert production.authoritative_request_ids == {result.request_id}
