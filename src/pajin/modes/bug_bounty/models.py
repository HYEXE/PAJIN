"""Typed Bug Bounty program policy and scope-review contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from re import fullmatch
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from pajin.domain.models import Budgets, StrictModel, ToolRiskTier, WeeklyTestingWindow
from pajin.policy.scope import normalize_scope_pattern, normalize_target_url, scope_matches

DEFAULT_PROHIBITED_TECHNIQUES = frozenset(
    {
        "credential-stuffing",
        "data-exfiltration",
        "denial-of-service",
        "persistence",
        "real-user-data-access",
        "social-engineering",
    }
)
DEFAULT_STOP_CONDITIONS = frozenset(
    {
        "out-of-scope-attempt",
        "real-user-data-observed",
        "service-degradation",
        "sensitive-data-exposure",
    }
)
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_SUPPORTED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})


class BugBountyAssetType(StrEnum):
    WEB = "web"
    API = "api"


class BugBountyProbeProfile(StrEnum):
    GENERIC_HTTP = "generic-http"
    BOOLEAN_SQLI_LAB = "boolean-sqli-lab"


class BugBountyProgramMetadata(StrictModel):
    name: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    display_name: str = Field(alias="displayName", min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=80)


class BugBountyPolicySource(StrictModel):
    uri: str = Field(min_length=1, max_length=2_048)
    retrieved_at: datetime = Field(alias="retrievedAt")
    raw_text: str = Field(alias="rawText", min_length=1, max_length=500_000)

    @field_validator("uri")
    @classmethod
    def require_https_source(cls, value: str) -> str:
        normalized = normalize_target_url(value)
        if not normalized.startswith("https://"):
            raise ValueError("bug bounty policy source must use HTTPS")
        return normalized

    @field_validator("retrieved_at")
    @classmethod
    def require_retrieval_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("retrievedAt must include a UTC offset or Z")
        return value


class BugBountyAsset(StrictModel):
    asset_id: str = Field(alias="assetId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    asset_type: BugBountyAssetType = Field(alias="assetType")
    pattern: str
    entry_points: list[str] = Field(default_factory=list, alias="entryPoints")
    probe_profile: BugBountyProbeProfile = Field(
        default=BugBountyProbeProfile.GENERIC_HTTP,
        alias="probeProfile",
    )
    eligible_for_bounty: bool = Field(default=True, alias="eligibleForBounty")
    notes: str | None = Field(default=None, max_length=500)

    @field_validator("pattern")
    @classmethod
    def normalize_pattern(cls, value: str) -> str:
        return normalize_scope_pattern(value)

    @field_validator("entry_points")
    @classmethod
    def normalize_entry_points(cls, values: list[str]) -> list[str]:
        return [normalize_target_url(value) for value in values]


class BugBountyExcludedAsset(StrictModel):
    asset_id: str = Field(alias="assetId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    pattern: str
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("pattern")
    @classmethod
    def normalize_pattern(cls, value: str) -> str:
        return normalize_scope_pattern(value)


class BugBountyScope(StrictModel):
    in_scope: list[BugBountyAsset] = Field(alias="inScope", min_length=1)
    out_of_scope: list[BugBountyExcludedAsset] = Field(
        default_factory=list,
        alias="outOfScope",
    )

    @model_validator(mode="after")
    def validate_executable_scope(self) -> BugBountyScope:
        asset_ids = [asset.asset_id for asset in self.in_scope]
        asset_ids.extend(asset.asset_id for asset in self.out_of_scope)
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("bug bounty assetId values must be unique")

        allow = [asset.pattern for asset in self.in_scope]
        deny = [asset.pattern for asset in self.out_of_scope]
        if set(allow) & set(deny):
            raise ValueError("the same scope pattern cannot be both in-scope and out-of-scope")

        entry_points: list[str] = []
        for asset in self.in_scope:
            for entry_point in asset.entry_points:
                if not scope_matches(asset.pattern, entry_point):
                    raise ValueError(
                        f"entry point {entry_point!r} does not match asset {asset.asset_id!r}"
                    )
                if any(scope_matches(rule, entry_point) for rule in deny):
                    raise ValueError(
                        f"entry point {entry_point!r} matches an explicit out-of-scope rule"
                    )
                entry_points.append(entry_point)
        if not entry_points:
            raise ValueError("at least one concrete in-scope entry point is required")
        if len(entry_points) != len(set(entry_points)):
            raise ValueError("bug bounty entry points must be unique")
        return self


class BugBountyRules(StrictModel):
    max_tool_risk_tier: ToolRiskTier = Field(default=ToolRiskTier.T2, alias="maxToolRiskTier")
    allowed_methods: set[str] = Field(
        default_factory=lambda: {"GET", "HEAD"},
        alias="allowedMethods",
        min_length=1,
    )
    allowed_tool_categories: set[str] = Field(
        alias="allowedToolCategories",
        min_length=1,
    )
    prohibited_techniques: set[str] = Field(
        default_factory=set,
        alias="prohibitedTechniques",
    )
    stop_on: set[str] = Field(default_factory=set, alias="stopOn")
    max_requests_per_minute: int = Field(
        default=30,
        alias="maxRequestsPerMinute",
        ge=1,
        le=600,
    )
    testing_windows: list[WeeklyTestingWindow] = Field(
        default_factory=list,
        alias="testingWindows",
    )
    allow_private_networks: bool = Field(default=False, alias="allowPrivateNetworks")

    @field_validator("max_tool_risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @field_validator("allowed_methods", mode="before")
    @classmethod
    def normalize_methods(cls, values: list[str] | set[str]) -> set[str]:
        normalized = {value.upper() for value in values}
        unsupported = normalized - _SUPPORTED_METHODS
        if unsupported:
            raise ValueError(f"unsupported HTTP methods: {sorted(unsupported)}")
        return normalized

    @field_validator("allowed_tool_categories", "prohibited_techniques", "stop_on")
    @classmethod
    def validate_policy_labels(cls, values: set[str]) -> set[str]:
        for value in values:
            if not fullmatch(r"[a-z0-9][a-z0-9-]*", value):
                raise ValueError(f"invalid policy label: {value!r}")
        return values

    @model_validator(mode="after")
    def enforce_safe_mvp_ceiling(self) -> BugBountyRules:
        if self.max_tool_risk_tier > ToolRiskTier.T2:
            raise ValueError("Bug Bounty Scope Parser MVP cannot compile T3 or T4 tools")
        prohibited = self.prohibited_techniques | DEFAULT_PROHIBITED_TECHNIQUES
        conflict = self.allowed_tool_categories & prohibited
        if conflict:
            raise ValueError(
                f"tool categories conflict with mandatory prohibitions: {sorted(conflict)}"
            )
        return self

    @property
    def state_changing_methods(self) -> set[str]:
        return self.allowed_methods & _STATE_CHANGING_METHODS


class BugBountyDataHandling(StrictModel):
    test_accounts_only: bool = Field(default=True, alias="testAccountsOnly")
    max_evidence_retention_days: int = Field(
        default=14,
        alias="maxEvidenceRetentionDays",
        ge=1,
        le=90,
    )
    redact_secrets: bool = Field(default=True, alias="redactSecrets")

    @model_validator(mode="after")
    def require_safe_data_defaults(self) -> BugBountyDataHandling:
        if not self.test_accounts_only:
            raise ValueError("Bug Bounty MVP requires testAccountsOnly: true")
        if not self.redact_secrets:
            raise ValueError("Bug Bounty MVP requires redactSecrets: true")
        return self


class BugBountyReporting(StrictModel):
    severity_standard: str = Field(alias="severityStandard", min_length=1, max_length=50)
    required_fields: set[str] = Field(alias="requiredFields", min_length=1)
    duplicate_check_required: bool = Field(default=True, alias="duplicateCheckRequired")

    @field_validator("required_fields")
    @classmethod
    def validate_required_fields(cls, values: set[str]) -> set[str]:
        supported = {
            "affected-component",
            "confidence",
            "evidence",
            "impact",
            "remediation",
            "reproduction",
            "root-cause",
            "severity",
            "summary",
            "target",
            "title",
            "vulnerability-class",
        }
        unsupported = values - supported
        if unsupported:
            raise ValueError(f"unsupported Bug Bounty report fields: {sorted(unsupported)}")
        return values


class BugBountyProgramSpec(StrictModel):
    policy: BugBountyPolicySource
    scope: BugBountyScope
    rules: BugBountyRules
    data_handling: BugBountyDataHandling = Field(alias="dataHandling")
    reporting: BugBountyReporting
    objectives: list[str] = Field(min_length=1)
    budgets: Budgets = Field(default_factory=Budgets)


class BugBountyProgramManifest(StrictModel):
    api_version: str = Field(alias="apiVersion", pattern=r"^pajin\.dev/v\d+(alpha\d+|beta\d+)?$")
    kind: str = Field(pattern=r"^BugBountyProgram$")
    metadata: BugBountyProgramMetadata
    spec: BugBountyProgramSpec

    @model_validator(mode="after")
    def restrict_private_lab_scope(self) -> BugBountyProgramManifest:
        if not self.spec.rules.allow_private_networks:
            return self
        if self.metadata.platform != "local-lab":
            raise ValueError("private-network Bug Bounty execution requires platform: local-lab")
        executable_assets = [asset for asset in self.spec.scope.in_scope if asset.entry_points]
        for asset in executable_assets:
            if asset.probe_profile is not BugBountyProbeProfile.BOOLEAN_SQLI_LAB:
                raise ValueError(
                    "private-network Bug Bounty assets require the fixed boolean-sqli-lab profile"
                )
            for entry_point in asset.entry_points:
                if urlsplit(entry_point).hostname != "host.docker.internal":
                    raise ValueError(
                        "private-network Bug Bounty lab entry points must use host.docker.internal"
                    )
        return self


class BugBountyScopeReview(StrictModel):
    program_name: str
    generated_at: datetime
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    allow: list[str]
    deny: list[str]
    entry_points: list[str]
    allowed_methods: set[str]
    allowed_tool_categories: set[str]
    prohibited_techniques: set[str]
    stop_on: set[str]
    max_requests_per_minute: int
    testing_windows: list[WeeklyTestingWindow]
    warnings: list[str]
    manual_controls: list[str]
    approval_required: bool = True


class BugBountyScopeApproval(StrictModel):
    scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_by: str = Field(min_length=1, max_length=120)
    approved_at: datetime
    expires_at: datetime
    evidence: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_window(self) -> BugBountyScopeApproval:
        for field_name, value in (
            ("approved_at", self.approved_at),
            ("expires_at", self.expires_at),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{field_name} must include a UTC offset or Z")
        if self.expires_at <= self.approved_at:
            raise ValueError("scope approval expires_at must be after approved_at")
        return self
