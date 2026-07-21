"""Typed contracts for campaigns, capabilities, tools, and findings."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, time
from enum import IntEnum, StrEnum
from typing import Annotated, Any, cast
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

_SAFE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SAFE_PORTABLE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"
_MAX_CAMPAIGN_TARGETS = 100
_MAX_CAMPAIGN_SCOPE_RULES = 500
_MAX_CAMPAIGN_OBJECTIVES = 100
_MAX_CAMPAIGN_THREAT_CLASSES = 100
_MAX_CAMPAIGN_POLICY_LABELS = 100
_MAX_CAMPAIGN_TESTING_WINDOWS = 100
_MAX_CAMPAIGN_OUTPUTS = 100
_MAX_CAMPAIGN_CANONICAL_BYTES = 1_048_576
_MAX_SIMULATION_DEPTH = 32
_MAX_SIMULATION_NODES = 20_000
_MAX_SIMULATION_BYTES = 65_536

_ScopeRule = Annotated[str, Field(min_length=1, max_length=2_000)]
_CampaignText = Annotated[str, Field(min_length=1, max_length=5_000)]
_PolicyLabel = Annotated[str, Field(min_length=1, max_length=200)]
_HTTPMethod = Annotated[str, Field(min_length=1, max_length=20)]
_ThreatClass = Annotated[str, Field(min_length=2, max_length=20)]


def _require_json_utf8_text(value: str, *, label: str) -> None:
    if len(value) > _MAX_SIMULATION_BYTES:
        raise ValueError(f"{label} text exceeds the canonical byte limit")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} contains invalid UTF-8 text") from exc
    if len(encoded) > _MAX_SIMULATION_BYTES:
        raise ValueError(f"{label} text exceeds the canonical byte limit")


@dataclass(slots=True)
class _BoundedSimulationWalker:
    """Validate a decoded simulation graph before Pydantic can coerce it."""

    active_containers: set[int] = dataclass_field(default_factory=set)
    node_count: int = 0

    def visit(self, item: object, *, depth: int = 0) -> None:
        self._count_node(depth)
        if item is None or type(item) is bool:
            return
        if isinstance(item, str):
            _require_json_utf8_text(item, label="target simulation")
            return
        if isinstance(item, int):
            self._require_bounded_integer(item)
            return
        if isinstance(item, float):
            self._require_finite_number(item)
            return
        if type(item) is list:
            self._visit_list(cast(list[object], item), depth=depth)
            return
        if type(item) is dict:
            self._visit_object(cast(dict[object, object], item), depth=depth)
            return
        raise ValueError("target simulation contains a non-JSON value")

    def _count_node(self, depth: int) -> None:
        self.node_count += 1
        if self.node_count > _MAX_SIMULATION_NODES:
            raise ValueError("target simulation exceeds the JSON node-count limit")
        if depth > _MAX_SIMULATION_DEPTH:
            raise ValueError("target simulation exceeds the JSON nesting-depth limit")

    def _visit_list(self, item: list[object], *, depth: int) -> None:
        self._visit_container(item, values=item, depth=depth)

    def _visit_object(self, item: dict[object, object], *, depth: int) -> None:
        for key in item:
            self._count_node(depth + 1)
            if not isinstance(key, str):
                raise ValueError("target simulation object keys must be strings")
            _require_json_utf8_text(key, label="target simulation")
        self._visit_container(item, values=item.values(), depth=depth)

    def _visit_container(
        self,
        item: list[object] | dict[object, object],
        *,
        values: Iterable[object],
        depth: int,
    ) -> None:
        identity = id(item)
        if identity in self.active_containers:
            raise ValueError("target simulation cannot contain cycles")
        self.active_containers.add(identity)
        try:
            for nested in values:
                self.visit(nested, depth=depth + 1)
        finally:
            self.active_containers.remove(identity)

    @staticmethod
    def _require_bounded_integer(value: int) -> None:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("target simulation integer is outside the signed 64-bit range")

    @staticmethod
    def _require_finite_number(value: float) -> None:
        if not math.isfinite(value):
            raise ValueError("target simulation numbers must be finite")


def _canonical_json_bytes(value: object, *, label: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc


def _validate_bounded_simulation(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError("target simulation must be a JSON object")
    _BoundedSimulationWalker().visit(value)
    if len(_canonical_json_bytes(value, label="target simulation")) > _MAX_SIMULATION_BYTES:
        raise ValueError("target simulation exceeds the canonical byte limit")
    return cast(dict[str, Any], value)


_BoundedSimulation = Annotated[
    dict[str, JsonValue],
    BeforeValidator(_validate_bounded_simulation),
]


def _require_bounded_collection(
    value: object,
    *,
    label: str,
    max_items: int,
) -> list[object] | tuple[object, ...] | set[object] | frozenset[object]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{label} must be a collection")
    if len(value) > max_items:
        raise ValueError(f"{label} exceeds the {max_items}-item limit")
    return value


def _authority_timestamp(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


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


class Weekday(StrEnum):
    MONDAY = "monday"
    TUESDAY = "tuesday"
    WEDNESDAY = "wednesday"
    THURSDAY = "thursday"
    FRIDAY = "friday"
    SATURDAY = "saturday"
    SUNDAY = "sunday"


_WEEKDAYS = tuple(Weekday)


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
    endpoint: str = Field(min_length=1, max_length=2_000)
    simulation: _BoundedSimulation = Field(default_factory=dict, max_length=100)


class Scope(StrictModel):
    allow: list[_ScopeRule] = Field(min_length=1, max_length=_MAX_CAMPAIGN_SCOPE_RULES)
    deny: list[_ScopeRule] = Field(default_factory=list, max_length=_MAX_CAMPAIGN_SCOPE_RULES)


class Authorization(StrictModel):
    approved_by: str = Field(alias="approvedBy", min_length=1, max_length=200)
    approved_at: datetime = Field(alias="approvedAt")
    expires_at: datetime = Field(alias="expiresAt")
    evidence: str = Field(min_length=1, max_length=2_000)

    @field_validator("approved_at", "expires_at")
    @classmethod
    def require_explicit_timezone(cls, value: datetime) -> datetime:
        return _authority_timestamp(value, label="authorization timestamp")

    @model_validator(mode="after")
    def validate_window(self) -> Authorization:
        if self.expires_at <= self.approved_at:
            raise ValueError("authorization expiresAt must be after approvedAt")
        return self

    def is_active(self, at: datetime | None = None) -> bool:
        now = _authority_timestamp(
            at or datetime.now(UTC),
            label="authorization evaluation timestamp",
        )
        return self.approved_at <= now < self.expires_at


class WeeklyTestingWindow(StrictModel):
    """An enforceable recurring testing window in an IANA time zone."""

    days: set[Weekday] = Field(min_length=1, max_length=7)
    start_time: time = Field(alias="startTime")
    end_time: time = Field(alias="endTime")
    timezone: str = Field(min_length=1, max_length=100)

    @field_validator("days", mode="before")
    @classmethod
    def require_bounded_days(cls, value: object) -> object:
        return _require_bounded_collection(value, label="testing window days", max_items=7)

    @model_validator(mode="after")
    def validate_window(self) -> WeeklyTestingWindow:
        if self.start_time == self.end_time and self.start_time != time(0, 0):
            raise ValueError(
                "equal testing-window times are supported only as a 00:00-00:00 full day"
            )
        if self.start_time.tzinfo is not None or self.end_time.tzinfo is not None:
            raise ValueError("testing window times must be local wall-clock times")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown IANA timezone: {self.timezone}") from exc
        return self

    def is_active(self, at: datetime | None = None) -> bool:
        evaluated_at = at or datetime.now(UTC)
        if evaluated_at.tzinfo is None:
            evaluated_at = evaluated_at.replace(tzinfo=UTC)
        local = evaluated_at.astimezone(ZoneInfo(self.timezone))
        local_time = local.time().replace(tzinfo=None)
        today = _WEEKDAYS[local.weekday()]
        if self.start_time == self.end_time:
            return today in self.days
        if self.start_time < self.end_time:
            return today in self.days and self.start_time <= local_time < self.end_time

        if local_time >= self.start_time:
            return today in self.days
        previous_day = _WEEKDAYS[(local.weekday() - 1) % len(_WEEKDAYS)]
        return local_time < self.end_time and previous_day in self.days


class RulesOfEngagement(StrictModel):
    max_tool_risk_tier: ToolRiskTier = Field(alias="maxToolRiskTier")
    allowed_methods: set[_HTTPMethod] = Field(
        default_factory=lambda: {"GET", "HEAD", "POST"},
        alias="allowedMethods",
        max_length=20,
    )
    allowed_tool_categories: set[_PolicyLabel] = Field(
        default_factory=set,
        alias="allowedToolCategories",
        max_length=_MAX_CAMPAIGN_POLICY_LABELS,
    )
    prohibit: set[_PolicyLabel] = Field(
        default_factory=set,
        max_length=_MAX_CAMPAIGN_POLICY_LABELS,
    )
    stop_on: set[_PolicyLabel] = Field(
        default_factory=set,
        alias="stopOn",
        max_length=_MAX_CAMPAIGN_POLICY_LABELS,
    )
    allow_private_networks: bool = Field(default=False, alias="allowPrivateNetworks")
    max_requests_per_minute: int | None = Field(
        default=None,
        alias="maxRequestsPerMinute",
        ge=1,
        le=60_000,
    )
    testing_windows: list[WeeklyTestingWindow] = Field(
        default_factory=list,
        alias="testingWindows",
        max_length=_MAX_CAMPAIGN_TESTING_WINDOWS,
    )

    @field_validator("max_tool_risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @field_validator("allowed_methods", mode="before")
    @classmethod
    def normalize_methods(cls, value: object) -> set[str]:
        items = _require_bounded_collection(value, label="allowedMethods", max_items=20)
        if any(not isinstance(item, str) for item in items):
            raise ValueError("allowedMethods values must be strings")
        return {item.upper() for item in items if isinstance(item, str)}

    @field_validator("allowed_tool_categories", "prohibit", "stop_on", mode="before")
    @classmethod
    def require_bounded_policy_labels(cls, value: object) -> object:
        return _require_bounded_collection(
            value,
            label="campaign policy labels",
            max_items=_MAX_CAMPAIGN_POLICY_LABELS,
        )


class Budgets(StrictModel):
    duration_seconds: int = Field(default=600, alias="durationSeconds", ge=1, le=86_400)
    max_cost_usd: float = Field(default=5.0, alias="maxCostUsd", ge=0, le=10_000)
    max_agents: int = Field(default=4, alias="maxAgents", ge=1, le=100)
    max_spawn_depth: int = Field(default=1, alias="maxSpawnDepth", ge=0, le=10)
    max_tool_calls: int = Field(default=100, alias="maxToolCalls", ge=1, le=1_000_000)
    max_model_calls: int = Field(default=20, alias="maxModelCalls", ge=0, le=100_000)
    max_model_tokens: int = Field(
        default=1_000_000,
        alias="maxModelTokens",
        ge=0,
        le=1_000_000_000,
    )


class CampaignSpec(StrictModel):
    mode: CampaignMode
    autonomy: AutonomyLevel = AutonomyLevel.SUPERVISED
    authorization: Authorization
    targets: list[Target] = Field(min_length=1, max_length=_MAX_CAMPAIGN_TARGETS)
    scope: Scope
    access_profile: _PolicyLabel = Field(default="blackbox", alias="accessProfile")
    objectives: list[_CampaignText] = Field(min_length=1, max_length=_MAX_CAMPAIGN_OBJECTIVES)
    threat_classes: list[_ThreatClass] = Field(
        default_factory=list,
        alias="threatClasses",
        max_length=_MAX_CAMPAIGN_THREAT_CLASSES,
    )
    rules_of_engagement: RulesOfEngagement = Field(alias="rulesOfEngagement")
    budgets: Budgets = Field(default_factory=Budgets)
    outputs: list[_PolicyLabel] = Field(
        default_factory=lambda: ["markdown-report", "json-findings"],
        max_length=_MAX_CAMPAIGN_OUTPUTS,
    )

    @field_validator("threat_classes")
    @classmethod
    def validate_threat_classes(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) < 2 or value[0] not in "DMAS" or not value[1:].isdigit():
                raise ValueError(f"invalid KISA threat class: {value}")
        return values


class CampaignManifest(StrictModel):
    api_version: str = Field(
        alias="apiVersion",
        max_length=50,
        pattern=r"^pajin\.dev/v\d+(alpha\d+|beta\d+)?$",
    )
    kind: str = Field(max_length=20, pattern=r"^Campaign$")
    metadata: CampaignMetadata
    spec: CampaignSpec

    @model_validator(mode="after")
    def require_bounded_canonical_size(self) -> CampaignManifest:
        canonical = _canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="campaign manifest",
        )
        if len(canonical) > _MAX_CAMPAIGN_CANONICAL_BYTES:
            raise ValueError("campaign manifest exceeds the canonical byte limit")
        return self


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

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_explicit_timezone(cls, value: datetime) -> datetime:
        return _authority_timestamp(value, label="capability timestamp")

    @model_validator(mode="after")
    def validate_lineage_shape(self) -> CapabilityGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("capability must expire after it is issued")
        if self.parent_grant_id is None and self.depth != 0:
            raise ValueError("root capability depth must be zero")
        if self.parent_grant_id is not None and self.depth == 0:
            raise ValueError("delegated capability depth must be greater than zero")
        return self

    def attenuates(self, parent: CapabilityGrant) -> bool:
        """Return whether this grant is a strict subset of its parent authority."""

        child_expiry = _authority_timestamp(self.expires_at, label="child capability expiry")
        parent_expiry = _authority_timestamp(parent.expires_at, label="parent capability expiry")
        child_issued_at = _authority_timestamp(
            self.issued_at,
            label="child capability issuance",
        )
        parent_issued_at = _authority_timestamp(
            parent.issued_at,
            label="parent capability issuance",
        )
        return (
            self.campaign == parent.campaign
            and self.subject != parent.subject
            and self.tools <= parent.tools
            and self.targets <= parent.targets
            and self.max_risk_tier <= parent.max_risk_tier
            and self.max_calls <= parent.max_calls
            and parent_issued_at <= child_issued_at
            and child_expiry <= parent_expiry
            and self.depth == parent.depth + 1
            and self.parent_grant_id == parent.grant_id
            and parent.delegable
        )


class ToolRequest(StrictModel):
    request_id: str = Field(
        default_factory=lambda: f"tool_{uuid4().hex}",
        pattern=_SAFE_PORTABLE_IDENTIFIER_PATTERN,
    )
    agent_id: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
    tool_id: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
    target: str = Field(min_length=1, max_length=2_000)
    method: str = "GET"
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()


class ToolResult(StrictModel):
    request_id: str = Field(pattern=_SAFE_PORTABLE_IDENTIFIER_PATTERN)
    tool_id: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
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

    @model_validator(mode="after")
    def require_unique_request_ids(self) -> AgentPlan:
        request_ids = [step.request.request_id for step in self.steps]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("agent plan request IDs must be unique")
        return self


class Finding(StrictModel):
    finding_id: str = Field(default_factory=lambda: f"finding_{uuid4().hex}")
    title: str
    severity: FindingSeverity
    threat_class: str
    target: str
    summary: str
    impact: str | None = None
    affected_component: str | None = None
    root_cause: str | None = None
    reproduction: list[str]
    evidence: list[str]
    remediation: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    validated: bool = False
