from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from pajin.web_assessment.adapter_catalog import (
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    production_adapter_implementation_catalog,
)
from pajin.web_assessment.governed_adapter_profile import (
    _LOCAL_FIXTURE_ADAPTER_REFERENCE,
    _LOCAL_FIXTURE_ORIGIN,
    GOVERNED_JUICE_SHOP_ADAPTER_ID,
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    GOVERNED_JUICE_SHOP_ADAPTER_VERSION,
    GOVERNED_JUICE_SHOP_ORIGIN,
    GOVERNED_JUICE_SHOP_PLAN_DIGEST,
    GOVERNED_WEB_CAMPAIGN_ID,
    GOVERNED_WEB_TARGET_ID,
    GovernedWebAdapterProfileError,
    GovernedWebAdapterProfileRegistry,
    _testing_governed_web_adapter_profile_registry,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_models import WebAssessmentAdapterManifest
from pajin.web_assessment.recipes import juice_shop_plan

_NOW = datetime(2026, 9, 15, 6, tzinfo=UTC)


def test_production_registry_contains_only_exact_legacy_juice_shop_profile() -> None:
    registry = production_governed_web_adapter_profile_registry()

    assert registry.references() == (
        (GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE, GOVERNED_JUICE_SHOP_ORIGIN),
    )
    resolved = registry.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )

    assert resolved.adapter_reference == "juice-shop-local/v1"
    assert resolved.origin == "http://127.0.0.1:3000"
    assert resolved.adapter_id == "pajin.adapter.juice-shop.local"
    assert resolved.adapter_version == "1.0.0"
    assert resolved.implementation_id == JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID
    assert resolved.implementation_digest == JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
    assert resolved.plan == juice_shop_plan(GOVERNED_JUICE_SHOP_ORIGIN)
    assert resolved.plan_digest == GOVERNED_JUICE_SHOP_PLAN_DIGEST
    assert resolved.campaign_id == "juice-shop-governed-local"
    assert resolved.target_id == "owasp-juice-shop-local"
    assert resolved.description == (
        "Governed authenticated assessment of the approved local Juice Shop lab."
    )
    assert resolved.objective == (
        "Execute the code-owned authenticated Juice Shop diagnostics twice and reconcile them."
    )
    assert resolved.campaign_description == resolved.description
    assert resolved.catalog_digest == registry.catalog_digest
    assert resolved.registry_digest == registry.registry_digest
    assert len(resolved.profile_digest) == 64

    assert resolved.adapter_id == GOVERNED_JUICE_SHOP_ADAPTER_ID
    assert resolved.adapter_version == GOVERNED_JUICE_SHOP_ADAPTER_VERSION
    assert resolved.campaign_id == GOVERNED_WEB_CAMPAIGN_ID
    assert resolved.target_id == GOVERNED_WEB_TARGET_ID


def test_profile_builds_only_secret_free_exact_manifest_input() -> None:
    profile = production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    manifest_input = profile.manifest_input(
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=30),
    )

    assert set(manifest_input) == {
        "adapterId",
        "adapterVersion",
        "origin",
        "implementationId",
        "implementationDigest",
        "recipeDigest",
        "issuedAt",
        "expiresAt",
    }
    assert not {
        "callable",
        "password",
        "payload",
        "routes",
        "selectors",
        "token",
        "username",
    }.intersection(manifest_input)
    manifest = WebAssessmentAdapterManifest.model_validate(manifest_input)
    assert manifest.adapter_id == profile.adapter_id
    assert manifest.adapter_version == profile.adapter_version
    assert manifest.origin == profile.origin
    assert manifest.implementation_id == profile.implementation_id
    assert manifest.implementation_digest == profile.implementation_digest
    assert manifest.recipe_digest == profile.plan_digest


def test_public_metadata_is_detached_and_contains_no_execution_recipe() -> None:
    profile = production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    metadata = profile.public_metadata()

    assert metadata == {
        "adapterReference": profile.adapter_reference,
        "adapterId": profile.adapter_id,
        "adapterVersion": profile.adapter_version,
        "origin": profile.origin,
        "implementationId": profile.implementation_id,
        "implementationDigest": profile.implementation_digest,
        "catalogDigest": profile.catalog_digest,
        "profileDigest": profile.profile_digest,
        "registryDigest": profile.registry_digest,
        "planDigest": profile.plan_digest,
        "campaignId": profile.campaign_id,
        "targetId": profile.target_id,
        "targetType": "web-application",
        "targetProduct": "OWASP Juice Shop",
        "description": profile.description,
        "objective": profile.objective,
    }
    assert not {"payloads", "routes", "selectors"}.intersection(metadata)
    metadata["origin"] = "http://127.0.0.1:9999"
    assert profile.origin == GOVERNED_JUICE_SHOP_ORIGIN


@pytest.mark.parametrize(
    ("adapter_reference", "origin", "message"),
    (
        ("unknown-local/v1", GOVERNED_JUICE_SHOP_ORIGIN, "not installed"),
        (
            GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
            "http://127.0.0.1:3001",
            "not installed",
        ),
        (
            GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
            "http://localhost:3000",
            "exact loopback",
        ),
        (
            GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
            "http://127.0.0.1:3000/",
            "exact loopback",
        ),
        ("../juice-shop-local/v1", GOVERNED_JUICE_SHOP_ORIGIN, "reference is invalid"),
    ),
)
def test_resolution_fails_closed_on_wrong_alias_or_origin(
    adapter_reference: str,
    origin: str,
    message: str,
) -> None:
    registry = production_governed_web_adapter_profile_registry()

    with pytest.raises(GovernedWebAdapterProfileError, match=message):
        registry.resolve(adapter_reference=adapter_reference, origin=origin)


def test_resolution_accepts_no_caller_authored_recipe_or_callable() -> None:
    registry = production_governed_web_adapter_profile_registry()

    with pytest.raises(TypeError):
        registry.resolve(
            adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
            origin=GOVERNED_JUICE_SHOP_ORIGIN,
            routes=("/#/caller-route",),  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError, match="code-owned factory"):
        GovernedWebAdapterProfileRegistry(
            _profiles=(),
            _catalog=production_adapter_implementation_catalog(),
        )
    assert not hasattr(registry, "register")


def test_private_test_registry_proves_a_distinct_second_code_owned_adapter() -> None:
    registry = _testing_governed_web_adapter_profile_registry()

    assert registry.references() == tuple(
        sorted(
            (
                (GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE, GOVERNED_JUICE_SHOP_ORIGIN),
                (_LOCAL_FIXTURE_ADAPTER_REFERENCE, _LOCAL_FIXTURE_ORIGIN),
            )
        )
    )
    fixture = registry.resolve(
        adapter_reference=_LOCAL_FIXTURE_ADAPTER_REFERENCE,
        origin=_LOCAL_FIXTURE_ORIGIN,
    )
    assert fixture.adapter_reference == "local-fixture/v1"
    assert fixture.origin == "http://127.0.0.1:3001"
    assert fixture.plan.name == "juice-shop-local-fixture-assessment"
    assert fixture.plan.adapter_implementation_id == fixture.implementation_id
    assert fixture.plan_digest != GOVERNED_JUICE_SHOP_PLAN_DIGEST


def test_test_profile_fails_closed_when_implementation_is_not_in_selected_catalog() -> None:
    with pytest.raises(
        GovernedWebAdapterProfileError,
        match="implementation is not installed",
    ):
        _testing_governed_web_adapter_profile_registry(
            adapter_references=(_LOCAL_FIXTURE_ADAPTER_REFERENCE,),
            catalog=production_adapter_implementation_catalog(),
        )


def test_resolved_plan_mutation_is_detected_and_cannot_change_registry_state() -> None:
    registry = _testing_governed_web_adapter_profile_registry(
        adapter_references=(GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,),
        catalog=production_adapter_implementation_catalog(),
    )
    first = registry.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    first.plan.route_ready_selectors["/#/search"] = "caller-controlled"

    with pytest.raises(GovernedWebAdapterProfileError, match="identity changed"):
        first.public_metadata()
    second = registry.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    assert second.plan.route_ready_selectors["/#/search"] == "app-search-result"
    assert second.plan_digest == GOVERNED_JUICE_SHOP_PLAN_DIGEST


def test_resolved_and_registry_digest_mutation_fail_closed() -> None:
    profile_registry = _testing_governed_web_adapter_profile_registry(
        adapter_references=(GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,),
        catalog=production_adapter_implementation_catalog(),
    )
    resolved = profile_registry.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )

    with pytest.raises(FrozenInstanceError):
        resolved.origin = "http://127.0.0.1:9999"  # type: ignore[misc]
    object.__setattr__(resolved, "registry_digest", "0" * 64)
    with pytest.raises(GovernedWebAdapterProfileError, match="identity changed"):
        resolved.manifest_input(
            issued_at=_NOW,
            expires_at=_NOW + timedelta(minutes=30),
        )

    object.__setattr__(
        profile_registry,
        "_GovernedWebAdapterProfileRegistry__registry_digest",
        "0" * 64,
    )
    with pytest.raises(GovernedWebAdapterProfileError, match="registry identity changed"):
        profile_registry.resolve(
            adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
            origin=GOVERNED_JUICE_SHOP_ORIGIN,
        )


def test_profile_and_registry_digests_are_deterministic_for_same_inventory() -> None:
    production = production_governed_web_adapter_profile_registry()
    rebuilt = _testing_governed_web_adapter_profile_registry(
        adapter_references=(GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,),
        catalog=production_adapter_implementation_catalog(),
    )
    production_profile = production.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    rebuilt_profile = rebuilt.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )

    assert rebuilt.catalog_digest == production.catalog_digest
    assert rebuilt.registry_digest == production.registry_digest
    assert rebuilt_profile.profile_digest == production_profile.profile_digest
