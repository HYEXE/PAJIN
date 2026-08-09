from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    AttackSurface,
    AttackSurfaceSet,
    HTTPInternalAPISurfaceLocator,
    MCPURLArgument,
    MCPURLToolSurfaceLocator,
    SurfaceObservation,
    attack_surface,
    attack_surface_set,
    http_internal_api_surface_locator,
    http_route_surface_locator,
    http_surface_locator,
    mcp_url_tool_surface_locator,
    surface_observation,
    tool_interface_surface_locator,
)

NOW = datetime(2026, 7, 23, 1, 0, tzinfo=UTC)
ROOT_DIGEST = "a" * 64
REQUEST_DIGEST = "b" * 64
RESULT_DIGEST = "c" * 64


def test_chain003_foundation_locators_are_explicit_non_value_contracts() -> None:
    route = http_route_surface_locator(
        base_url="https://api.example.test",
        path_template="/internal/status",
        method="GET",
    )
    internal_api = http_internal_api_surface_locator(route=route)
    url_tool = mcp_url_tool_surface_locator(
        server_id="demo-security",
        tool_name="inspect_url",
        input_schema_digest=ROOT_DIGEST,
        url_arguments=(MCPURLArgument(name="url", required=True),),
    )

    assert internal_api.declaration == "openapi-x-pajin-internal-api"
    assert internal_api.route == route
    assert url_tool.url_arguments == (MCPURLArgument(name="url", required=True),)
    assert (
        HTTPInternalAPISurfaceLocator.model_validate(internal_api.model_dump(mode="json"))
        == internal_api
    )
    assert MCPURLToolSurfaceLocator.model_validate(url_tool.model_dump(mode="json")) == url_tool


def test_chain003_foundation_locators_reject_forged_declaration_and_arguments() -> None:
    route = http_route_surface_locator(
        base_url="https://api.example.test",
        path_template="/internal/status",
        method="GET",
    )
    with pytest.raises(ValidationError):
        HTTPInternalAPISurfaceLocator.model_validate(
            {
                "route": route.model_dump(mode="json"),
                "declaration": "description-inference",
            }
        )
    with pytest.raises(ValidationError, match="unique and sorted"):
        MCPURLToolSurfaceLocator(
            server_id="demo-security",
            tool_name="inspect_url",
            input_schema_digest=ROOT_DIGEST,
            url_arguments=(
                MCPURLArgument(name="url", required=True),
                MCPURLArgument(name="callback", required=False),
            ),
        )
    with pytest.raises(ValidationError, match="must be a boolean"):
        MCPURLArgument.model_validate({"name": "url", "required": 1})


def _observation(
    *,
    request_id: str = "tool_recon_1",
    observed_at: datetime = NOW,
    locator: object | None = None,
    evidence: list[object] | None = None,
    target_id: str = "ai-lab",
    source_root_digest: str = ROOT_DIGEST,
) -> SurfaceObservation:
    return surface_observation(
        campaign="discovery-lab",
        run_id="run_discovery_1",
        source_root_digest=source_root_digest,
        target_id=target_id,
        request_id=request_id,
        request_target="https://ai.example.test/",
        tool_id="http.recon",
        source_request_digest=REQUEST_DIGEST,
        source_result_digest=RESULT_DIGEST,
        locator=locator
        or http_surface_locator(
            url="https://api.example.test:443/v1/%63hat",
            method="post",
        ),
        evidence=evidence
        or [
            {
                "reference": f"evidence/{request_id}.json",
                "sha256": "d" * 64,
                "media_type": "application/json",
            }
        ],
        observed_at=observed_at,
    )


def _surface(
    observations: list[SurfaceObservation],
    *,
    locator: object | None = None,
    target_id: str = "ai-lab",
    confidence: float = 0.9,
) -> AttackSurface:
    return attack_surface(
        campaign="discovery-lab",
        target_id=target_id,
        locator=locator or observations[0].locator,
        observations=observations,
        confidence=confidence,
    )


def _surface_set(
    observations: list[SurfaceObservation],
    surfaces: list[AttackSurface],
    *,
    generated_at: datetime = NOW + timedelta(minutes=1),
    source_root_digest: str = ROOT_DIGEST,
) -> AttackSurfaceSet:
    return attack_surface_set(
        campaign="discovery-lab",
        run_id="run_discovery_1",
        source_root_digest=source_root_digest,
        observations=observations,
        surfaces=surfaces,
        generated_at=generated_at,
    )


def test_http_locator_canonicalizes_concrete_operation_and_stabilizes_identity() -> None:
    first = http_surface_locator(
        url="HTTPS://API.Example.Test.:443/v1/%63hat?mode=%66ast",
        method="post",
    )
    second = http_surface_locator(
        url="https://api.example.test/v1/chat?mode=fast",
        method="POST",
    )
    assert first == second
    assert first.url == "https://api.example.test/v1/chat?mode=fast"
    assert first.method == "POST"

    observation = _observation(locator=first)
    same_surface = _surface([observation], locator=second, confidence=0.1)
    changed_confidence = _surface([observation], locator=first, confidence=1)
    assert same_surface.surface_id == changed_confidence.surface_id


def test_http_locator_preserves_semantically_ambiguous_query_order() -> None:
    first = http_surface_locator(
        url="https://api.example.test/v1/chat?a=1&b=2",
        method="GET",
    )
    second = http_surface_locator(
        url="https://api.example.test/v1/chat?b=2&a=1",
        method="GET",
    )
    assert first != second


@pytest.mark.parametrize(
    "url",
    [
        "ftp://api.example.test/v1/chat",
        "https://user:password@api.example.test/v1/chat",
        "https://api.example.test/v1/../admin",
        "https://api.example.test/v1/%252e%252e/admin",
        "https://api.example.test/v1/chat#response",
        "https://*.example.test/v1/chat",
    ],
)
def test_http_locator_rejects_ambiguous_or_unenforceable_urls(url: str) -> None:
    with pytest.raises(ValueError):
        http_surface_locator(url=url, method="GET")


def test_tool_interface_identity_binds_registry_version_and_schema() -> None:
    first = tool_interface_surface_locator(
        registry_id="mcp:trusted-registry",
        tool_id="rag.search",
        tool_version="1.2.0",
        input_schema_digest="e" * 64,
    )
    same = tool_interface_surface_locator(
        registry_id="mcp:trusted-registry",
        tool_id="rag.search",
        tool_version="1.2.0",
        input_schema_digest="e" * 64,
    )
    changed_schema = tool_interface_surface_locator(
        registry_id="mcp:trusted-registry",
        tool_id="rag.search",
        tool_version="1.2.0",
        input_schema_digest="f" * 64,
    )
    observation = _observation(locator=first)
    assert first == same
    assert _surface([observation], locator=first).surface_id == _surface(
        [observation], locator=same
    ).surface_id
    changed_observation = _observation(locator=changed_schema)
    assert _surface([observation], locator=first).surface_id != _surface(
        [changed_observation], locator=changed_schema
    ).surface_id


def test_observation_binds_exact_request_result_evidence_and_time() -> None:
    observation = _observation()
    serialized = observation.model_dump(mode="json", by_alias=True)
    assert serialized["apiVersion"] == "pajin.dev/discovery/v1alpha1"
    assert observation.observation_id.startswith("surface-observation_")

    assert _observation().observation_id == observation.observation_id
    assert _observation(observed_at=NOW + timedelta(seconds=1)).observation_id != (
        observation.observation_id
    )

    serialized["source_result_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="differs from canonical authority"):
        SurfaceObservation.model_validate(serialized)


def test_observation_factory_sorts_evidence_but_contract_rejects_noncanonical_order() -> None:
    evidence = [
        {
            "reference": "evidence/z.json",
            "sha256": "e" * 64,
            "media_type": "application/json",
        },
        {
            "reference": "evidence/a.json",
            "sha256": "f" * 64,
            "media_type": "application/json",
        },
    ]
    observation = _observation(evidence=evidence)
    assert [item.reference for item in observation.evidence] == [
        "evidence/a.json",
        "evidence/z.json",
    ]

    payload = observation.model_dump(mode="json")
    payload["observation_id"] = ""
    payload["evidence"].reverse()
    with pytest.raises(ValidationError, match="canonically sorted"):
        SurfaceObservation.model_validate(payload)


@pytest.mark.parametrize(
    "reference",
    [
        "../evidence/result.json",
        "/evidence/result.json",
        "evidence\\result.json",
        "evidence/./result.json",
        "evidence//result.json",
        " evidence/result.json",
        "evidence/result.json\n",
    ],
)
def test_observation_rejects_unsafe_evidence_references(reference: str) -> None:
    with pytest.raises(ValidationError):
        _observation(
            evidence=[
                {
                    "reference": reference,
                    "sha256": "d" * 64,
                    "media_type": "application/json",
                }
            ]
        )


def test_observation_rejects_duplicate_or_excessive_evidence() -> None:
    duplicate = {
        "reference": "evidence/result.json",
        "sha256": "d" * 64,
        "media_type": "application/json",
    }
    with pytest.raises(ValidationError, match="must be unique"):
        _observation(evidence=[duplicate, duplicate])

    conflicting = {
        **duplicate,
        "sha256": "e" * 64,
    }
    with pytest.raises(ValidationError, match="must be unique"):
        _observation(evidence=[duplicate, conflicting])

    excessive = [
        {
            "reference": f"evidence/result-{index}.json",
            "sha256": f"{index:064x}",
            "media_type": "application/json",
        }
        for index in range(51)
    ]
    with pytest.raises(ValidationError, match="at most 50"):
        _observation(evidence=excessive)


def test_discovery_contracts_reject_unknown_fields_and_naive_timestamps() -> None:
    payload = _observation().model_dump(mode="json")
    payload["execution_authority"] = {"command": "scan everything"}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SurfaceObservation.model_validate(payload)

    payload = _observation().model_dump(mode="json")
    payload["observation_id"] = ""
    payload["observed_at"] = "2026-07-23T01:00:00"
    with pytest.raises(ValidationError, match="explicit UTC offset"):
        SurfaceObservation.model_validate(payload)


def test_discovery_contract_rejects_unknown_surface_kinds() -> None:
    payload = _observation().model_dump(mode="json")
    payload["observation_id"] = ""
    payload["locator"] = {
        "kind": "rag-source",
        "url": "https://rag.example.test/index",
    }
    with pytest.raises(ValidationError, match="does not match any of the expected tags"):
        SurfaceObservation.model_validate(payload)


def test_surface_set_links_every_observation_to_exactly_one_canonical_surface() -> None:
    first = _observation(request_id="tool_recon_1", observed_at=NOW)
    second = _observation(
        request_id="tool_recon_2",
        observed_at=NOW + timedelta(seconds=30),
        evidence=[
            {
                "reference": "evidence/tool_recon_2.json",
                "sha256": "e" * 64,
                "media_type": "application/json",
            }
        ],
    )
    surface = _surface([second, first])
    snapshot = _surface_set([second, first], [surface])

    assert snapshot.observations == sorted(
        [first, second],
        key=lambda item: item.observation_id,
    )
    assert surface.observation_ids == sorted(
        [first.observation_id, second.observation_id]
    )
    assert surface.first_observed_at == NOW
    assert surface.last_observed_at == NOW + timedelta(seconds=30)
    assert snapshot.surface_set_id.startswith("attack-surface-set_")
    assert AttackSurfaceSet.model_validate(snapshot.model_dump(mode="json")) == snapshot


def test_surface_set_identity_covers_projection_content() -> None:
    observation = _observation()
    low_confidence = _surface([observation], confidence=0.4)
    high_confidence = _surface([observation], confidence=0.8)
    first = _surface_set([observation], [low_confidence])
    second = _surface_set([observation], [high_confidence])
    later = _surface_set(
        [observation],
        [low_confidence],
        generated_at=NOW + timedelta(minutes=2),
    )
    assert low_confidence.surface_id == high_confidence.surface_id
    assert first.surface_set_id != second.surface_set_id
    assert first.surface_set_id != later.surface_set_id


def test_surface_set_rejects_orphan_duplicate_and_cross_root_observations() -> None:
    observation = _observation()
    surface = _surface([observation])

    with pytest.raises(ValidationError, match="exactly one Attack Surface"):
        _surface_set([observation], [])
    with pytest.raises(ValidationError, match="observation IDs must be unique"):
        _surface_set([observation, observation], [surface])
    with pytest.raises(ValidationError, match="another source root"):
        _surface_set([observation], [surface], source_root_digest="f" * 64)


def test_surface_set_rejects_locator_target_and_time_lineage_drift() -> None:
    observation = _observation()
    different_locator = http_surface_locator(
        url="https://api.example.test/v1/admin",
        method="GET",
    )
    wrong_locator_surface = AttackSurface(
        campaign="discovery-lab",
        target_id="ai-lab",
        locator=different_locator,
        observation_ids=[observation.observation_id],
        confidence=0.9,
        first_observed_at=NOW,
        last_observed_at=NOW,
    )
    with pytest.raises(ValidationError, match="locator differs"):
        _surface_set([observation], [wrong_locator_surface])

    wrong_target_surface = AttackSurface(
        campaign="discovery-lab",
        target_id="other-target",
        locator=observation.locator,
        observation_ids=[observation.observation_id],
        confidence=0.9,
        first_observed_at=NOW,
        last_observed_at=NOW,
    )
    with pytest.raises(ValidationError, match="target differs"):
        _surface_set([observation], [wrong_target_surface])

    payload = _surface([observation]).model_dump(mode="json")
    payload["surface_id"] = ""
    payload["first_observed_at"] = (NOW - timedelta(seconds=1)).isoformat()
    drifted_time_surface = AttackSurface.model_validate(payload)
    with pytest.raises(ValidationError, match="first observation time differs"):
        _surface_set([observation], [drifted_time_surface])


def test_surface_set_rejects_tampered_id_and_future_observation() -> None:
    observation = _observation()
    surface = _surface([observation])
    snapshot = _surface_set([observation], [surface])
    payload = snapshot.model_dump(mode="json")
    payload["surface_set_id"] = "attack-surface-set_" + "0" * 64
    with pytest.raises(ValidationError, match="differs from canonical authority"):
        AttackSurfaceSet.model_validate(payload)

    with pytest.raises(ValidationError, match="cannot predate"):
        _surface_set(
            [observation],
            [surface],
            generated_at=NOW - timedelta(seconds=1),
        )


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), -0.1, 1.1])
def test_surface_confidence_must_be_finite_probability(confidence: float) -> None:
    observation = _observation()
    with pytest.raises(ValidationError):
        _surface([observation], confidence=confidence)


def test_empty_surface_set_is_a_valid_versioned_no_discovery_snapshot() -> None:
    snapshot = _surface_set([], [])
    assert snapshot.observations == []
    assert snapshot.surfaces == []
    assert snapshot.surface_set_id.startswith("attack-surface-set_")
