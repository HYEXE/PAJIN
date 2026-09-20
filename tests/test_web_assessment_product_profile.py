from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from pajin.web_assessment.models import WebAssessmentPlan
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    issue_local_web_assessment_authorization,
    provision_local_web_assessment_account,
)

ORIGIN = "http://127.0.0.1:3000"
LEGACY_JUICE_SHOP_PLAN_DIGEST = (
    "3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96"
)


def _alternate_plan() -> WebAssessmentPlan:
    raw = juice_shop_plan(ORIGIN).model_dump(mode="json")
    raw.update(
        {
            "name": "synthetic-shop-web-assessment",
            "target_product": "Synthetic Shop",
            "fingerprint_version_path": "metadata.release.version",
            "adapter_implementation_id": "pajin.web-assessment.synthetic-shop.v1",
        }
    )
    return WebAssessmentPlan.model_validate(raw)


def test_juice_shop_identity_defaults_preserve_legacy_plan_digest_and_loader() -> None:
    current = juice_shop_plan(ORIGIN)
    legacy_raw = current.model_dump(mode="json")
    legacy_raw.pop("target_product")
    legacy_raw.pop("fingerprint_version_path")
    legacy_raw.pop("adapter_implementation_id")

    legacy = WebAssessmentPlan.model_validate(legacy_raw)

    assert current.plan_digest == legacy.plan_digest == LEGACY_JUICE_SHOP_PLAN_DIGEST
    assert legacy.target_product == "OWASP Juice Shop"
    assert legacy.fingerprint_version_path == "version"
    assert legacy.adapter_implementation_id == "pajin.web-assessment.juice-shop.v1"


def test_non_default_product_fingerprint_path_and_adapter_are_digest_bound() -> None:
    default = juice_shop_plan(ORIGIN)
    alternate = _alternate_plan()

    assert alternate.plan_digest != default.plan_digest
    for field in (
        "target_product",
        "fingerprint_version_path",
        "adapter_implementation_id",
    ):
        raw = alternate.model_dump(mode="json")
        raw[field] = default.model_dump(mode="json")[field]
        assert WebAssessmentPlan.model_validate(raw).plan_digest != alternate.plan_digest

    raw = alternate.model_dump(mode="json")
    raw["fingerprint_version_path"] = "metadata..version"
    with pytest.raises(ValidationError):
        WebAssessmentPlan.model_validate(raw)


@pytest.mark.asyncio
async def test_provisioning_uses_alternate_version_json_path_and_product_receipt() -> None:
    plan = _alternate_plan()
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == plan.fingerprint_endpoint:
            return httpx.Response(
                200,
                json={"metadata": {"release": {"version": "synthetic-2026.09"}}},
            )
        if request.method == "POST" and request.url.path == plan.registration.endpoint:
            return httpx.Response(201, json={"status": "created"})
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    transport = httpx.MockTransport(handler)
    account = await provision_local_web_assessment_account(
        plan=plan,
        authorization=authorization,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
    )
    receipt = account.receipt()

    assert account.target_version == "synthetic-2026.09"
    assert account.target_product == plan.target_product
    assert account.fingerprint_version_path == plan.fingerprint_version_path
    assert account.adapter_implementation_id == plan.adapter_implementation_id
    assert receipt["targetProduct"] == plan.target_product
    assert receipt["targetVersion"] == "synthetic-2026.09"
    assert receipt["planDigest"] == plan.plan_digest
