"""Non-executing, code-owned Codex advisory routes for assessment stages."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pajin.discovery.canonicalization import discovery_digest

CODEX_ADVISORY_ROUTING_API_VERSION: Final = "pajin.dev/codex-advisory-routing/v1alpha1"
_ROUTING_DIGEST_DOMAIN: Final = "pajin.codex-advisory-routing/v1alpha1"


class CodexAdvisoryStage(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    PENETRATION_REVIEW = "penetration-review"
    VULNERABILITY_ANALYSIS = "vulnerability-analysis"
    REPORT_DRAFT = "report-draft"


_STAGE_MODELS: Final[Mapping[CodexAdvisoryStage, tuple[str, str]]] = MappingProxyType(
    {
        CodexAdvisoryStage.RECONNAISSANCE: ("gpt-6-luna", "high"),
        CodexAdvisoryStage.PENETRATION_REVIEW: ("gpt-6-sol", "medium"),
        CodexAdvisoryStage.VULNERABILITY_ANALYSIS: ("gpt-6-sol", "medium"),
        CodexAdvisoryStage.REPORT_DRAFT: ("gpt-6-sol", "medium"),
    }
)


class CodexAdvisoryWireModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )


class CodexAdvisoryRoute(CodexAdvisoryWireModel):
    stage: CodexAdvisoryStage = Field(strict=False)
    model_id: Literal["gpt-6-luna", "gpt-6-sol"] = Field(alias="modelId")
    reasoning_effort: Literal["high", "medium"] = Field(alias="reasoningEffort")
    max_task_tokens: int = Field(alias="maxTaskTokens", ge=1, le=1_000_000)
    budget_enforced: Literal[False] = Field(alias="budgetEnforced")
    model_dispatch_authority: Literal[False] = Field(alias="modelDispatchAuthority")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    gateway_authority: Literal[False] = Field(alias="gatewayAuthority")
    target_execution_authority: Literal[False] = Field(alias="targetExecutionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    graph_write_authority: Literal[False] = Field(alias="graphWriteAuthority")
    publication_authority: Literal[False] = Field(alias="publicationAuthority")

    @model_validator(mode="after")
    def require_code_owned_route(self) -> Self:
        if (self.model_id, self.reasoning_effort) != _STAGE_MODELS[self.stage]:
            raise ValueError("Codex advisory stage differs from its code-owned model route")
        return self


class CodexAdvisoryRoutingPlan(CodexAdvisoryWireModel):
    api_version: Literal["pajin.dev/codex-advisory-routing/v1alpha1"] = Field(alias="apiVersion")
    auth_method: Literal["chatgpt-subscription"] = Field(alias="authMethod")
    api_key_fallback: Literal[False] = Field(alias="apiKeyFallback")
    hosted_transfer_authorized: Literal[False] = Field(alias="hostedTransferAuthorized")
    max_task_tokens: int = Field(alias="maxTaskTokens", ge=1, le=1_000_000)
    routes: tuple[CodexAdvisoryRoute, ...] = Field(min_length=4, max_length=4, strict=False)
    plan_digest: str = Field(alias="planDigest", pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_complete_inert_policy(self) -> Self:
        if tuple(route.stage for route in self.routes) != tuple(CodexAdvisoryStage):
            raise ValueError("Codex advisory stages must occur exactly once in code-owned order")
        if any(route.max_task_tokens != self.max_task_tokens for route in self.routes):
            raise ValueError("Codex advisory stages must share one planned token ceiling")
        if self.plan_digest != discovery_digest(
            _ROUTING_DIGEST_DOMAIN,
            self.model_dump(mode="json", by_alias=True, exclude={"plan_digest"}),
        ):
            raise ValueError("Codex advisory routing plan digest differs from its content")
        return self


def code_owned_codex_advisory_routing_plan(*, max_task_tokens: int) -> CodexAdvisoryRoutingPlan:
    """Build an inert route plan; no Codex or target call occurs."""

    routes = [
        {
            "stage": stage,
            "modelId": model_id,
            "reasoningEffort": reasoning_effort,
            "maxTaskTokens": max_task_tokens,
            "budgetEnforced": False,
            "modelDispatchAuthority": False,
            "scopeExpansionAuthority": False,
            "capabilityAuthority": False,
            "permitAuthority": False,
            "gatewayAuthority": False,
            "targetExecutionAuthority": False,
            "findingAuthority": False,
            "graphWriteAuthority": False,
            "publicationAuthority": False,
        }
        for stage, (model_id, reasoning_effort) in _STAGE_MODELS.items()
    ]
    payload = {
        "apiVersion": CODEX_ADVISORY_ROUTING_API_VERSION,
        "authMethod": "chatgpt-subscription",
        "apiKeyFallback": False,
        "hostedTransferAuthorized": False,
        "maxTaskTokens": max_task_tokens,
        "routes": routes,
    }
    return CodexAdvisoryRoutingPlan.model_validate(
        {
            **payload,
            "planDigest": discovery_digest(_ROUTING_DIGEST_DOMAIN, payload),
        }
    )
