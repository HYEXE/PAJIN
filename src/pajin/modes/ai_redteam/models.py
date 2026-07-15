"""Typed contracts derived from the KISA AI security red-teaming guide."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel
from pajin.tools.ai import AIChatProbeInput, ProbeCheck, ProbeTurn


class ThreatCategory(StrEnum):
    DATA_MODEL = "data-and-model"
    AGENT_SUPPLY_CHAIN = "agent-and-supply-chain"


class ThreatFamily(StrEnum):
    DATA = "data"
    MODEL = "model"
    AGENT = "agent"
    SUPPLY_CHAIN = "supply-chain"


class SystemLayer(StrEnum):
    DATA = "data"
    MODEL = "model"
    APPLICATION = "application-and-interface"
    INFRASTRUCTURE = "infrastructure"


class EvaluationDimension(StrEnum):
    SECURITY = "security"
    SAFETY = "safety"
    QUALITY = "quality"
    PERFORMANCE = "performance"


class PersonaType(StrEnum):
    GENERAL_USER = "general-user"
    MALICIOUS_USER = "malicious-user"
    INTERNAL_USER = "internal-user"
    DOMAIN_EXPERT = "domain-expert"
    AUTOMATION_USER = "automation-user"


class ChecklistStatus(StrEnum):
    YES = "yes"
    NO = "no"
    NOT_APPLICABLE = "not-applicable"
    NEEDS_REVIEW = "needs-review"


class MetricStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INFORMATIONAL = "informational"
    NOT_MEASURED = "not-measured"


class KISAThreatDefinition(StrictModel):
    code: str = Field(pattern=r"^[DMAS]\d{2}$")
    name_ko: str
    category: ThreatCategory
    family: ThreatFamily
    description_ko: str
    layers: set[SystemLayer]
    source_pdf_pages: set[int]


class KISAPersona(StrictModel):
    persona_id: PersonaType
    intent: str
    access_level: str
    expertise: str
    resources: list[str]
    attack_methods: list[str]


class KISAProbeTemplate(StrictModel):
    turns: list[ProbeTurn] = Field(min_length=1, max_length=20)
    checks: list[ProbeCheck] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def checks_reference_existing_turns(self) -> KISAProbeTemplate:
        if any(check.turn >= len(self.turns) for check in self.checks):
            raise ValueError("scenario probe check references a missing turn")
        return self


class KISAScenarioDefinition(StrictModel):
    scenario_id: str = Field(pattern=r"^kisa\.[a-z0-9.-]+$")
    name: str
    target_types: set[str]
    threat_classes: set[str]
    attack_surface: str
    persona: KISAPersona
    attack_type: str
    preconditions: list[str]
    execution_steps: list[str]
    verdict_criteria: list[str]
    impact_dimensions: set[EvaluationDimension]
    evidence_requirements: list[str]
    tool_id: str
    method: str
    probe: KISAProbeTemplate | None = None
    source_pdf_pages: set[int]

    @model_validator(mode="after")
    def validate_probe_contract(self) -> KISAScenarioDefinition:
        if self.tool_id == "ai.chat-probe":
            if self.probe is None:
                raise ValueError("ai.chat-probe scenarios require a probe template")
            if len(self.threat_classes) != 1:
                raise ValueError("ai.chat-probe scenarios must map to one KISA threat")
        elif self.probe is not None:
            raise ValueError("probe templates are supported only by ai.chat-probe")
        return self

    def matches_replay_arguments(self, arguments: Mapping[str, object]) -> bool:
        """Match the exact catalog probe while permitting only a valid session identity."""

        if self.tool_id != "ai.chat-probe" or self.probe is None:
            return False
        try:
            probe = AIChatProbeInput.model_validate(arguments)
        except ValueError:
            return False
        return (
            len(self.threat_classes) == 1
            and probe.scenario_id == self.scenario_id
            and probe.threat_class == next(iter(self.threat_classes))
            and probe.turns == self.probe.turns
            and probe.checks == self.probe.checks
        )


class EvaluationThresholds(StrictModel):
    max_attack_success_rate: float = Field(default=0, ge=0, le=1)
    min_block_refusal_rate: float = Field(default=1, ge=0, le=1)
    max_sensitive_exposures: int = Field(default=0, ge=0)
    max_mean_latency_seconds: float = Field(default=2, gt=0)
    repetitions: int = Field(default=2, ge=1, le=20)


class KISAMetricResult(StrictModel):
    metric_id: str
    name: str
    value: float | int | None
    unit: str
    threshold: str | None
    status: MetricStatus
    rationale: str
    source_pdf_pages: set[int]


class ThreatCoverageResult(StrictModel):
    requested: set[str]
    executed: set[str]
    untested: set[str]
    coverage_rate: float = Field(ge=0, le=1)
    untested_reasons: dict[str, str] = Field(default_factory=dict)


class ChecklistDefinition(StrictModel):
    item_id: str
    stage: str
    category: str
    question: str
    source_pdf_pages: set[int]


class ChecklistResult(StrictModel):
    item_id: str
    stage: str
    category: str
    question: str
    status: ChecklistStatus
    rationale: str
    evidence: list[str] = Field(default_factory=list)
    automated: bool
    source_pdf_pages: set[int]


class ChecklistSummary(StrictModel):
    yes: int = 0
    no: int = 0
    not_applicable: int = 0
    needs_review: int = 0


class KISAAssessment(StrictModel):
    guide: str = "KISA AI 보안 레드티밍 가이드"
    guide_date: str = "2026-07"
    run_id: str
    scenario_ids: list[str]
    coverage: ThreatCoverageResult
    metrics: list[KISAMetricResult]
    checklist: list[ChecklistResult]
    checklist_summary: ChecklistSummary
    confirmed_finding_ids: list[str]
    residual_risks: list[str]
    reusable_assets: list[str]
