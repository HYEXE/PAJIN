"""KISA scenario-aware Planner and independent Validator adapters."""

from __future__ import annotations

import json

from pajin.agents.base import CandidateValidation, ValidatorRuntime
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    PlannedStep,
    ToolRequest,
    ToolResult,
)
from pajin.domain.validation import (
    CandidateAssessment,
    CandidateFinding,
    ValidationReasonCode,
    candidate_claim_digest,
    validator_finding_matches_candidate_claim,
)
from pajin.modes.ai_redteam.catalog import KISA_CATALOG, KISACatalog
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.tools.ai import (
    AIChatProbeInput,
    AIChatRegressionInput,
    ChatMessage,
    ChatRole,
    ProbeCheck,
    ProbeCheckKind,
    ProbeTurn,
)


class KISAPlannerRuntime:
    """Select executable KISA scenarios from target type and requested threat classes."""

    def __init__(
        self,
        *,
        catalog: KISACatalog = KISA_CATALOG,
        thresholds: EvaluationThresholds | None = None,
    ) -> None:
        self._catalog = catalog
        self.thresholds = thresholds or EvaluationThresholds()

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        requested = set(campaign.spec.threat_classes)
        for threat in requested:
            try:
                self._catalog.threat(threat)
            except KeyError as exc:
                raise ValueError(f"campaign requests unknown KISA threat: {threat}") from exc
        steps: list[PlannedStep] = []
        selected_ids: set[str] = set()
        for target in campaign.spec.targets:
            scenarios = self._catalog.select_scenarios(
                target_type=target.type,
                requested_threats=requested,
            )
            for scenario in scenarios:
                selected_ids.add(scenario.scenario_id)
                for repetition in range(1, self.thresholds.repetitions + 1):
                    arguments: dict[str, object] = {}
                    if scenario.probe is not None:
                        session_id = (
                            f"pajin:{campaign.metadata.name}:"
                            f"{scenario.scenario_id.rsplit('.', 1)[-1]}:{repetition}"
                        )
                        arguments = AIChatProbeInput(
                            scenario_id=scenario.scenario_id,
                            threat_class=sorted(scenario.threat_classes)[0],
                            session_id=session_id,
                            turns=scenario.probe.turns,
                            checks=scenario.probe.checks,
                        ).model_dump(mode="json")
                    elif target.type == "mock-agent":
                        arguments["simulation"] = target.simulation
                    steps.append(
                        PlannedStep(
                            title=f"{scenario.name} ({repetition}/{self.thresholds.repetitions})",
                            rationale=(
                                "KISA 위협 분류와 사전 정의된 판정 기준에 따라 반복 실행하여 "
                                "공격 성공률과 재현율을 측정한다."
                            ),
                            request=ToolRequest(
                                agent_id="agent:kisa-planner-untrusted",
                                tool_id=scenario.tool_id,
                                target=target.endpoint,
                                method=scenario.method,
                                arguments=arguments,
                            ),
                            scenario_id=scenario.scenario_id,
                            threat_classes=scenario.threat_classes,
                            attack_surface=scenario.attack_surface,
                            persona=scenario.persona.persona_id.value,
                        )
                    )
        if not steps:
            raise ValueError(
                "no executable KISA scenario matches the campaign target types and threats"
            )
        return AgentPlan(
            summary=(
                "Execute KISA-aligned scenarios with repeated observations: "
                + ", ".join(sorted(selected_ids))
            ),
            steps=steps,
        )


class KISAValidatorRuntime:
    """Wrap an independent validator and merge repeated observations into one finding."""

    def __init__(self, delegate: ValidatorRuntime) -> None:
        self._delegate = delegate

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        candidates = await self._delegate.validate(campaign, plan, results)
        grouped: dict[str, Finding] = {}
        for finding in candidates:
            key = self._aggregation_claim_key(finding)
            current = grouped.get(key)
            if current is None:
                grouped[key] = finding
                continue
            evidence = list(dict.fromkeys([*current.evidence, *finding.evidence]))
            grouped[key] = current.model_copy(
                update={
                    "evidence": evidence,
                    "confidence": min(current.confidence, finding.confidence),
                    "validated": current.validated and finding.validated,
                }
            )
        return list(grouped.values())

    @staticmethod
    def _aggregation_claim_key(finding: Finding) -> str:
        """Group repetitions only when every non-evidence claim field is identical."""

        claim = finding.model_dump(mode="json")
        claim.pop("finding_id")
        claim.pop("evidence")
        return json.dumps(
            claim,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

    async def validate_candidates(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        candidates: list[CandidateFinding],
    ) -> CandidateValidation:
        """Bind legacy delegate findings to exact KISA Candidate identities in trusted code."""

        findings = await self.validate(campaign, plan, results)
        eligible_by_candidate: dict[str, list[tuple[int, Finding]]] = {
            candidate.candidate_id: [] for candidate in candidates
        }
        eligible_candidate_counts = [0] * len(findings)
        for candidate in candidates:
            for finding_index, finding in enumerate(findings):
                if self._same_semantic_claim(candidate.claim, finding):
                    eligible_by_candidate[candidate.candidate_id].append((finding_index, finding))
                    eligible_candidate_counts[finding_index] += 1

        assessments: list[CandidateAssessment] = []
        for candidate in candidates:
            eligible = eligible_by_candidate[candidate.candidate_id]
            matched = (
                eligible[0][1]
                if len(eligible) == 1 and eligible_candidate_counts[eligible[0][0]] == 1
                else None
            )
            supported = matched is not None and matched.validated
            assessments.append(
                CandidateAssessment(
                    candidate_id=candidate.candidate_id,
                    claim_digest=candidate_claim_digest(candidate),
                    supports_claim=supported,
                    reason_code=(
                        ValidationReasonCode.VALIDATOR_CONFIRMED
                        if supported
                        else (
                            ValidationReasonCode.VALIDATOR_DISAGREED
                            if matched is not None
                            else ValidationReasonCode.VALIDATOR_OMITTED
                        )
                    ),
                    rationale=(
                        "Independent KISA validator output matched the exact Candidate semantics."
                        if supported
                        else (
                            "No unique validated KISA output matched the exact Candidate semantics."
                        )
                    ),
                    supporting_evidence=(
                        list(dict.fromkeys(matched.evidence)) if supported and matched else []
                    ),
                )
            )
        return CandidateValidation(findings=findings, assessments=assessments)

    @staticmethod
    def _same_semantic_claim(candidate: Finding, validator: Finding) -> bool:
        return validator_finding_matches_candidate_claim(candidate, validator)


class KISARetestPlannerRuntime:
    """Plan only isolated normal-function regression Tasks for a KISA retest.

    Security attacks are deliberately absent from the parent retest Run.  A
    baseline-bound ``KISARetestReplayCoordinator`` executes them through the
    Restricted Replay boundary, so an untrusted planner cannot duplicate raw
    attacks or turn an ordinary negative observation into remediation proof.
    """

    def __init__(
        self,
        *,
        catalog: KISACatalog = KISA_CATALOG,
        thresholds: EvaluationThresholds | None = None,
        normal_prompt: str = "Provide the normal lab service response.",
        expected_contains: str = "Request processed without exposing protected state.",
    ) -> None:
        # Keep the catalog argument for a stable public constructor, but do not
        # delegate to the attack planner.  Retest attacks require a sealed
        # Confirmed baseline and therefore cannot be generated from a campaign
        # alone.
        self._catalog = catalog
        self.thresholds = thresholds or EvaluationThresholds()
        self._normal_prompt = normal_prompt
        self._expected_contains = expected_contains

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        regression_steps: list[PlannedStep] = []
        for target in campaign.spec.targets:
            if target.type not in {"ai-chat-api", "rag-chat-api"}:
                continue
            for repetition in range(1, self.thresholds.repetitions + 1):
                probe = AIChatRegressionInput(
                    session_id=(f"pajin:{campaign.metadata.name}:normal-function:{repetition}"),
                    turns=[
                        ProbeTurn(
                            name="normal-chat-function",
                            messages=[ChatMessage(role=ChatRole.USER, content=self._normal_prompt)],
                        )
                    ],
                    checks=[
                        ProbeCheck(
                            check_id="normal-response-preserved",
                            kind=ProbeCheckKind.RESPONSE_CONTAINS,
                            turn=0,
                            value=self._expected_contains,
                        )
                    ],
                )
                regression_steps.append(
                    PlannedStep(
                        title=(
                            f"정상 채팅 기능 회귀 검증 ({repetition}/{self.thresholds.repetitions})"
                        ),
                        rationale=(
                            "보안 조치 이후 허가된 정상 요청의 핵심 기능이 유지되는지 "
                            "공격 지표와 분리하여 검증한다."
                        ),
                        request=ToolRequest(
                            agent_id="agent:kisa-retest-planner-untrusted",
                            tool_id="ai.normal-probe",
                            target=target.endpoint,
                            method="POST",
                            arguments=probe.model_dump(mode="json"),
                        ),
                        attack_surface="chat-api",
                        persona="general-user",
                    )
                )
        if not regression_steps:
            raise ValueError("KISA retest requires an ai-chat-api or rag-chat-api target")
        return AgentPlan(
            summary=(
                "Repeat only the normal chat function for post-remediation regression "
                "evidence; baseline-bound attacks run through Restricted Replay"
            ),
            steps=regression_steps,
        )
