from __future__ import annotations

import pytest

from pajin.web_assessment.adapter_catalog import (
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
)
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.worker_process import require_code_owned_worker_plan

ORIGIN = "http://127.0.0.1:3000"


def test_worker_independently_reresolves_exact_code_owned_plan() -> None:
    require_code_owned_worker_plan(
        plan=juice_shop_plan(ORIGIN),
        implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        origin=ORIGIN,
    )


@pytest.mark.parametrize(
    ("implementation_id", "implementation_digest", "origin", "message"),
    (
        (
            "pajin.web-assessment.uninstalled.v1",
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
            ORIGIN,
            "not installed",
        ),
        (
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            "0" * 64,
            ORIGIN,
            "not installed",
        ),
        (
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
            "http://127.0.0.1:3001",
            "serialized Plan differs",
        ),
    ),
)
def test_worker_rejects_uninstalled_or_plan_mismatched_adapter_authority(
    implementation_id: str,
    implementation_digest: str,
    origin: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        require_code_owned_worker_plan(
            plan=juice_shop_plan(ORIGIN),
            implementation_id=implementation_id,
            implementation_digest=implementation_digest,
            origin=origin,
        )


def test_worker_rejects_serialized_recipe_tampering_after_catalog_resolution() -> None:
    material = juice_shop_plan(ORIGIN).model_dump(mode="json")
    material["routes"] = ["/#/about"]
    material["route_ready_selectors"] = {"/#/about": "app-about"}
    changed = type(juice_shop_plan(ORIGIN)).model_validate(material)

    with pytest.raises(ValueError, match="serialized Plan differs"):
        require_code_owned_worker_plan(
            plan=changed,
            implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
            origin=ORIGIN,
        )
