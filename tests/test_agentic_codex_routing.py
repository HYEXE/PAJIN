"""The Codex model split is a non-executing, code-owned routing contract."""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import ValidationError

from pajin.agentic.codex_routing import (
    CodexAdvisoryRoutingPlan,
    code_owned_codex_advisory_routing_plan,
)
from pajin.discovery.canonicalization import discovery_digest


def _recompute_digest(raw: dict[str, object]) -> dict[str, object]:
    raw["planDigest"] = discovery_digest(
        "pajin.codex-advisory-routing/v1alpha1",
        {key: value for key, value in raw.items() if key != "planDigest"},
    )
    return raw


def test_codex_routes_share_one_planned_token_ceiling_without_authority() -> None:
    plan = code_owned_codex_advisory_routing_plan(max_task_tokens=65_536)

    assert [route.model_id for route in plan.routes] == [
        "gpt-6-luna",
        "gpt-6-sol",
        "gpt-6-sol",
        "gpt-6-sol",
    ]
    assert [route.reasoning_effort for route in plan.routes] == [
        "high",
        "medium",
        "medium",
        "medium",
    ]
    assert {route.max_task_tokens for route in plan.routes} == {65_536}
    assert not plan.hosted_transfer_authorized
    assert not plan.api_key_fallback
    assert all(
        not route.budget_enforced
        and not route.model_dispatch_authority
        and not route.scope_expansion_authority
        and not route.capability_authority
        and not route.permit_authority
        and not route.gateway_authority
        and not route.target_execution_authority
        and not route.finding_authority
        and not route.graph_write_authority
        and not route.publication_authority
        for route in plan.routes
    )
    assert (
        CodexAdvisoryRoutingPlan.model_validate(plan.model_dump(mode="json", by_alias=True)) == plan
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("modelId", "gpt-6-sol"),
        ("reasoningEffort", "medium"),
        ("maxTaskTokens", 32_768),
        ("budgetEnforced", True),
        ("modelDispatchAuthority", True),
        ("scopeExpansionAuthority", True),
        ("capabilityAuthority", True),
        ("permitAuthority", True),
        ("gatewayAuthority", True),
        ("targetExecutionAuthority", True),
        ("findingAuthority", True),
        ("graphWriteAuthority", True),
        ("publicationAuthority", True),
    ],
)
def test_recon_route_cannot_change_model_budget_or_authority(field: str, value: object) -> None:
    raw = code_owned_codex_advisory_routing_plan(max_task_tokens=65_536).model_dump(
        mode="json", by_alias=True
    )
    raw["routes"][0][field] = value

    with pytest.raises(ValidationError):
        CodexAdvisoryRoutingPlan.model_validate(_recompute_digest(raw))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("apiKeyFallback", True),
        ("hostedTransferAuthorized", True),
        ("planDigest", "0" * 64),
    ],
)
def test_plan_cannot_claim_a_new_auth_or_transfer_boundary(field: str, value: object) -> None:
    raw = code_owned_codex_advisory_routing_plan(max_task_tokens=65_536).model_dump(
        mode="json", by_alias=True
    )
    raw[field] = value

    if field != "planDigest":
        raw = _recompute_digest(raw)
    with pytest.raises(ValidationError):
        CodexAdvisoryRoutingPlan.model_validate(raw)


def test_duplicate_or_reordered_stage_is_rejected() -> None:
    raw = code_owned_codex_advisory_routing_plan(max_task_tokens=65_536).model_dump(
        mode="json", by_alias=True
    )
    raw["routes"][1] = raw["routes"][0]

    with pytest.raises(ValidationError):
        CodexAdvisoryRoutingPlan.model_validate(_recompute_digest(raw))


@pytest.mark.parametrize("limit", [0, 1_000_001, True])
def test_planned_token_ceiling_must_be_a_bounded_integer(limit: object) -> None:
    with pytest.raises(ValidationError):
        code_owned_codex_advisory_routing_plan(max_task_tokens=cast(int, limit))
