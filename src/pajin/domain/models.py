"""Typed contracts for campaigns, capabilities, tools, and findings."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    """Base model that rejects unknown security-sensitive fields."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class CampaignMode(StrEnum):
    AI_REDTEAM = "ai-redteam"
    BUG_BOUNTY = "bug-bounty"
    CTF = "ctf"


class AutonomyLevel(StrEnum):
    MANUAL = "manual"
    ASSISTED = "assisted"
    SUPERVISED = "supervised"
    POLICY_AUTONOMOUS = "policy-autonomous"
    LAB_AUTONOMOUS = "lab-autonomous"


class ToolRiskTier(IntEnum):
    T0 = 0
    T1 = 1
    T2 = 2
    T3 = 3
    T4 = 4

    @classmethod
    def parse(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            normalized = value.upper()
            if normalized.startswith("T"):
                return cls(int(normalized[1:]))
        return cls(int(value))


class FindingSeverity(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CampaignMetadata(StrictModel):
    name: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    description: str | None = Field(default=None, max_length=500)


class Target(StrictModel):
    type: str = Field(min_length=1, max_length=50)
    id: str = Field(min_length=1, max_length=100)
    endpoint: str
    simulation: dict[str, Any] = Field(default_factory=dict)


class Scope(StrictModel):
    allow: list[str] = Field(min_length=1)
    deny: list[str] = Field(default_factory=list)


class Authorization(StrictModel):
    approved_by: str = Field(alias="approvedBy", min_length=1)
    approved_at: datetime = Field(alias="approvedAt")
    expires_at: datetime = Field(alias="expiresAt")
    evidence: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_window(self) -> Authorization:
        if self.expires_at <= self.approved_at:
            raise ValueError("authorization expiresAt must be after approvedAt")
        return self

    def is_active(self, at: datetime | None = None) -> bool:
        now = at or datetime.now(UTC)
        approved_at = self.approved_at
        expires_at = self.expires_at
        if approved_at.tzinfo is None:
            approved_at = approved_at.replace(tzinfo=UTC)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return approved_at <= now < expires_at


class RulesOfEngagement(StrictModel):
    max_tool_risk_tier: ToolRiskTier = Field(alias="maxToolRiskTier")
    allowed_methods: set[str] = Field(
        default_factory=lambda: {"GET", "HEAD", "POST"}, alias="allowedMethods"
    )
    prohibit: set[str] = Field(default_factory=set)
    stop_on: set[str] = Field(default_factory=set, alias="stopOn")
    allow_private_networks: bool = Field(default=False, alias="allowPrivateNetworks")

    @field_validator("max_tool_risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @field_validator("allowed_methods", mode="before")
    @classmethod
    def normalize_methods(cls, value: list[str] | set[str]) -> set[str]:
        return {item.upper() for item in value}


class Budgets(StrictModel):
    duration_seconds: int = Field(default=600, alias="durationSeconds", ge=1, le=86_400)
    max_cost_usd: float = Field(default=5.0, alias="maxCostUsd", ge=0, le=10_000)
    max_agents: int = Field(default=4, alias="maxAgents", ge=1, le=100)
    max_spawn_depth: int = Field(default=1, alias="maxSpawnDepth", ge=0, le=10)
    max_tool_calls: int = Field(default=100, alias="maxToolCalls", ge=1, le=1_000_000)


class CampaignSpec(StrictModel):
    mode: CampaignMode
    autonomy: AutonomyLevel = AutonomyLevel.SUPERVISED
    authorization: Authorization
    targets: list[Target] = Field(min_length=1)
    scope: Scope
    access_profile: str = Field(default="blackbox", alias="accessProfile")
    objectives: list[str] = Field(min_length=1)
    threat_classes: list[str] = Field(default_factory=list, alias="threatClasses")
    rules_of_engagement: RulesOfEngagement = Field(alias="rulesOfEngagement")
    budgets: Budgets = Field(default_factory=Budgets)
    outputs: list[str] = Field(default_factory=lambda: ["markdown-report", "json-findings"])

    @field_validator("threat_classes")
    @classmethod
    def validate_threat_classes(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) < 2 or value[0] not in "DMAS" or not value[1:].isdigit():
                raise ValueError(f"invalid KISA threat class: {value}")
        return values


class CampaignManifest(StrictModel):
    api_version: str = Field(alias="apiVersion", pattern=r"^pajin\.dev/v\d+(alpha\d+|beta\d+)?$")
    kind: str = Field(pattern=r"^Campaign$")
    metadata: CampaignMetadata
    spec: CampaignSpec


class CapabilityGrant(StrictModel):
    grant_id: str = Field(default_factory=lambda: f"grant_{uuid4().hex}")
    parent_grant_id: str | None = None
    subject: str
    campaign: str
    tools: set[str] = Field(default_factory=set)
    targets: set[str] = Field(default_factory=set)
    max_risk_tier: ToolRiskTier
    max_calls: int = Field(ge=0)
    expires_at: datetime
    delegable: bool = False
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    depth: int = Field(default=0, ge=0, le=100)

    @field_validator("max_risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @model_validator(mode="after")
    def validate_lineage_shape(self) -> CapabilityGrant:
        expires_at = (
            self.expires_at
            if self.expires_at.tzinfo is not None
            else self.expires_at.replace(tzinfo=UTC)
        )
        issued_at = (
            self.issued_at
            if self.issued_at.tzinfo is not None
            else self.issued_at.replace(tzinfo=UTC)
        )
        if expires_at <= issued_at:
            raise ValueError("capability must expire after it is issued")
        if self.parent_grant_id is None and self.depth != 0:
            raise ValueError("root capability depth must be zero")
        if self.parent_grant_id is not None and self.depth == 0:
            raise ValueError("delegated capability depth must be greater than zero")
        return self

    def attenuates(self, parent: CapabilityGrant) -> bool:
        """Return whether this grant is a strict subset of its parent authority."""

        child_expiry = (
            self.expires_at
            if self.expires_at.tzinfo is not None
            else self.expires_at.replace(tzinfo=UTC)
        )
        parent_expiry = (
            parent.expires_at
            if parent.expires_at.tzinfo is not None
            else parent.expires_at.replace(tzinfo=UTC)
        )
        return (
            self.campaign == parent.campaign
            and self.subject != parent.subject
            and self.tools <= parent.tools
            and self.targets <= parent.targets
            and self.max_risk_tier <= parent.max_risk_tier
            and self.max_calls <= parent.max_calls
            and child_expiry <= parent_expiry
            and self.depth == parent.depth + 1
            and self.parent_grant_id == parent.grant_id
            and parent.delegable
        )


class ToolRequest(StrictModel):
    request_id: str = Field(default_factory=lambda: f"tool_{uuid4().hex}")
    agent_id: str
    tool_id: str
    target: str
    method: str = "GET"
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()


class ToolResult(StrictModel):
    request_id: str
    tool_id: str
    success: bool
    started_at: datetime
    finished_at: datetime
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    evidence: list[str] = Field(default_factory=list)


class PlannedStep(StrictModel):
    step_id: str = Field(default_factory=lambda: f"step_{uuid4().hex}")
    title: str
    rationale: str
    request: ToolRequest
    scenario_id: str | None = None
    threat_classes: set[str] = Field(default_factory=set)
    attack_surface: str | None = None
    persona: str | None = None


class AgentPlan(StrictModel):
    summary: str
    steps: list[PlannedStep] = Field(min_length=1)


class Finding(StrictModel):
    finding_id: str = Field(default_factory=lambda: f"finding_{uuid4().hex}")
    title: str
    severity: FindingSeverity
    threat_class: str
    target: str
    summary: str
    reproduction: list[str]
    evidence: list[str]
    confidence: float = Field(ge=0, le=1)
    validated: bool = False
