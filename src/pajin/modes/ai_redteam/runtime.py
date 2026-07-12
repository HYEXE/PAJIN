"""KISA scenario-aware Planner and independent Validator adapters."""

from __future__ import annotations

from pajin.agents.base import ValidatorRuntime
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    PlannedStep,
    ToolRequest,
    ToolResult,
)
from pajin.modes.ai_redteam.catalog import KISA_CATALOG, KISACatalog
from pajin.modes.ai_redteam.models import EvaluationThresholds


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
                    if target.type == "mock-agent":
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
        grouped: dict[tuple[str, str, str], Finding] = {}
        for finding in candidates:
            key = (finding.title, finding.threat_class, finding.target)
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
