"""Shared trusted checks over raw KISA AI chat transcripts."""

from __future__ import annotations

from dataclasses import dataclass

from pajin.domain.models import ToolRequest
from pajin.modes.ai_redteam.models import KISAScenarioDefinition
from pajin.tools.ai import (
    AIChatProbeInput,
    AIChatProbeOutput,
    ProbePurpose,
    evaluate_probe_check,
)


@dataclass(frozen=True, slots=True)
class KISATranscriptEvaluation:
    """Typed transcript and independently recomputed catalog checks."""

    output: AIChatProbeOutput
    check_support: tuple[bool, ...]

    @property
    def supports_claim(self) -> bool:
        return bool(self.check_support) and all(self.check_support)


def evaluate_kisa_transcript(
    *,
    scenario: KISAScenarioDefinition,
    request: ToolRequest,
    output_value: object,
) -> KISATranscriptEvaluation:
    """Validate exact request/transcript identity and recompute every catalog check."""

    if scenario.probe is None or scenario.tool_id != "ai.chat-probe":
        raise ValueError("scenario does not define a replayable AI chat probe")
    probe = AIChatProbeInput.model_validate(request.arguments)
    output = AIChatProbeOutput.model_validate(output_value)
    if not scenario.matches_replay_arguments(request.arguments):
        raise ValueError("AI probe request does not match the catalog template")
    threat_class = next(iter(scenario.threat_classes))
    if (
        request.tool_id != scenario.tool_id
        or request.method != scenario.method
        or output.target != request.target
        or output.scenario_id != scenario.scenario_id
        or output.scenario_id != probe.scenario_id
        or output.threat_class != threat_class
        or output.threat_class != probe.threat_class
        or output.session_id != probe.session_id
        or output.purpose is not ProbePurpose.ATTACK
        or not output.network_performed
    ):
        raise ValueError("AI probe transcript identity does not match its request")

    if len(output.turns) != len(scenario.probe.turns):
        raise ValueError("AI probe transcript turn count does not match the catalog")
    expected_messages = [
        [message.model_dump(mode="json") for message in turn.messages]
        for turn in scenario.probe.turns
    ]
    for index, turn in enumerate(output.turns):
        metadata = turn.request.metadata
        if (
            turn.index != index
            or turn.name != scenario.probe.turns[index].name
            or turn.request.session_id != probe.session_id
            or turn.response.session_id != probe.session_id
            or [message.model_dump(mode="json") for message in turn.request.messages]
            != expected_messages[index]
            or (
                metadata is not None
                and (metadata.scenario_id != scenario.scenario_id or metadata.turn != index)
            )
        ):
            raise ValueError("AI probe transcript turn identity does not match the catalog")

    if len(output.checks) != len(scenario.probe.checks):
        raise ValueError("AI probe check count does not match the catalog")
    for observed, expected in zip(output.checks, scenario.probe.checks, strict=True):
        if (
            observed.check_id != expected.check_id
            or observed.kind is not expected.kind
            or observed.turn != expected.turn
            or observed.sensitive is not expected.sensitive
        ):
            raise ValueError("AI probe check identity does not match the catalog")

    turns = [turn.model_dump(mode="json", by_alias=True) for turn in output.turns]
    support = tuple(evaluate_probe_check(check, turns) for check in scenario.probe.checks)
    return KISATranscriptEvaluation(output=output, check_support=support)
