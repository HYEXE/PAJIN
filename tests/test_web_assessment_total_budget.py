from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import cast

import pytest

from pajin.web_assessment.network import (
    AssessmentBoundaryError,
    AssessmentNetwork,
    PassiveMetadataCompletion,
)
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import assessment_policy


@pytest.mark.asyncio
async def test_total_request_budget_cannot_be_reset_by_starting_a_new_phase() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan, total_request_ceiling=2)
    policy = assessment_policy(plan, max_requests=2)
    try:
        network.begin_phase("first", policy)
        first = await network.reserve("GET", plan.origin + "/")
        await network.fail(first, reason="test-complete")
        network.begin_phase("second", policy)
        second = await network.reserve("GET", plan.origin + "/")
        await network.fail(second, reason="test-complete")
        network.begin_phase("third", policy)

        with pytest.raises(AssessmentBoundaryError, match="total-request-budget"):
            await network.reserve("GET", plan.origin + "/")

        assert network.phase_requests == 0
        assert network.total_requests == 2
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_rejected_request_does_not_consume_total_budget() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan, total_request_ceiling=1)
    network.begin_phase("bounded", assessment_policy(plan, max_requests=2))
    try:
        with pytest.raises(AssessmentBoundaryError, match="outside-approved-origin"):
            await network.reserve("GET", "http://127.0.0.1:3001/")

        reservation = await network.reserve("GET", plan.origin + "/")
        await network.fail(reservation, reason="test-complete")

        assert network.phase_requests == 1
        assert network.total_requests == 1
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_concurrent_reservations_share_one_atomic_total_budget() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan, total_request_ceiling=3)
    network.begin_phase("concurrent", assessment_policy(plan, max_requests=10))

    async def attempt() -> bool:
        try:
            reservation = await network.reserve("GET", plan.origin + "/")
        except AssessmentBoundaryError as error:
            assert str(error) == "total-request-budget"
            return False
        await network.fail(reservation, reason="test-complete")
        return True

    try:
        accepted = await asyncio.gather(*(attempt() for _ in range(10)))

        assert accepted.count(True) == 3
        assert accepted.count(False) == 7
        assert network.phase_requests == 3
        assert network.total_requests == 3
    finally:
        await network.close()


@pytest.mark.parametrize("value", (0, 501, True, 1.0, "100"))
def test_total_request_ceiling_requires_a_bounded_integer(value: object) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")

    with pytest.raises(ValueError, match="between 1 and 500"):
        AssessmentNetwork(plan, total_request_ceiling=value)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_passive_metadata_retains_no_body_but_consumes_response_body_budget() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=2).model_copy(update={"allowed_methods": {"GET"}}),
    )
    try:
        reservation = await network.reserve("GET", plan.origin + "/")
        evidence = await network.complete_passive_metadata(
            reservation,
            status=200,
            headers={"content-type": " Text/HTML ; charset=utf-8; token=not-retained"},
            observed_response_bytes=4_096,
        )

        assert evidence.response_bytes == 0
        assert evidence.response_sha256 == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert evidence.media_type == "text/html"
        assert network.total_bytes == 4_096
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_passive_metadata_can_return_a_bound_receipt_without_changing_evidence_list() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=2).model_copy(update={"allowed_methods": {"GET"}}),
    )
    try:
        reservation = await network.reserve("GET", plan.origin + "/asset.js")
        completion = await network.complete_passive_metadata(
            reservation,
            status=200,
            headers={"content-type": "application/javascript"},
            observed_response_bytes=4_096,
            return_boundary_receipt=True,
        )

        assert isinstance(completion, PassiveMetadataCompletion)
        assert network.evidence == [completion.evidence]
        receipt = completion.boundary_receipt
        assert receipt.evidence_id == completion.evidence.evidence_id
        assert receipt.reservation_sequence == reservation.sequence
        assert receipt.evidence_sequence == reservation.sequence
        assert receipt.canonical_origin == plan.origin
        assert receipt.method == "GET"
        assert receipt.query_present is False
        assert receipt.request_bytes == 0
        assert receipt.redirect_hops == 0
        assert receipt.path == "/asset.js"
        assert receipt.status == 200
        assert receipt.observed_response_body_bytes == 4_096
        assert receipt.retained_response_bytes == 0
        assert receipt.retained_response_sha256 == completion.evidence.response_sha256
        assert receipt.media_type == completion.evidence.media_type
        assert len(receipt.receipt_digest) == 64
    finally:
        await network.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url_suffix", "content", "redirect_hops", "reason"),
    (
        ("/asset.js?", None, 0, "query-values"),
        ("/asset.js?v=1", None, 0, "query-values"),
        ("/asset.js", b"payload", 0, "request-body-disabled"),
        ("/asset.js", None, 1, "redirect-disabled"),
    ),
)
async def test_passive_discovery_reservation_refuses_unsafe_request_boundary_facts(
    url_suffix: str,
    content: bytes | None,
    redirect_hops: int,
    reason: str,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=2).model_copy(update={"allowed_methods": {"GET"}}),
    )
    try:
        with pytest.raises(AssessmentBoundaryError, match=reason):
            await network.reserve(
                "GET",
                plan.origin + url_suffix,
                content=content,
                redirect_hops=redirect_hops,
            )

        assert network.evidence == []
        assert network.phase_requests == 0
        assert network.total_requests == 0
        assert network.failures == {}
    finally:
        await network.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url_suffix", "reason"),
    (
        ("/profiles/alice%40example.test", "value-bearing-path"),
        ("/objects/550e8400-e29b-41d4-a716-446655440000", "value-bearing-path"),
        (
            "/sessions/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
            "value-bearing-path",
        ),
        ("/assets/Az7kLm4Np9Qr2St5Uv8Wx1Yb3Cd6Ef0G", "value-bearing-path"),
        ("/orders/history", "sensitive-path"),
        ("/objects/42", "numeric-object-route"),
    ),
)
async def test_passive_discovery_never_reserves_target_driven_value_paths(
    url_suffix: str,
    reason: str,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=2).model_copy(update={"allowed_methods": {"GET"}}),
    )
    try:
        with pytest.raises(AssessmentBoundaryError, match=f"^{reason}$"):
            await network.reserve("GET", plan.origin + url_suffix)

        assert network.phase_requests == 0
        assert network.total_requests == 0
        assert network.evidence == []
    finally:
        await network.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    (("HEAD", "/"), ("POST", "/rest/user/login")),
)
async def test_passive_discovery_reservation_refuses_non_get_before_send(
    method: str,
    path: str,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=2).model_copy(
            update={"allowed_methods": {"GET", "HEAD", "POST"}}
        ),
    )
    try:
        with pytest.raises(AssessmentBoundaryError, match="unapproved-method"):
            await network.reserve(method, plan.origin + path)

        assert network.phase_requests == 0
        assert network.total_requests == 0
        assert network.evidence == []
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_passive_discovery_reservation_refuses_external_origin_before_send() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=2).model_copy(update={"allowed_methods": {"GET"}}),
    )
    try:
        with pytest.raises(AssessmentBoundaryError, match="outside-approved-origin"):
            await network.reserve("GET", "http://127.0.0.1:3001/asset.js")

        assert network.phase_requests == 0
        assert network.total_requests == 0
        assert network.evidence == []
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_passive_metadata_rejects_a_copied_open_reservation() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=2).model_copy(update={"allowed_methods": {"GET"}}),
    )
    reservation = await network.reserve("GET", plan.origin + "/asset.js")
    try:
        with pytest.raises(AssessmentBoundaryError, match="unknown-request-reservation"):
            await network.complete_passive_metadata(
                replace(reservation),
                status=200,
                headers={},
                observed_response_bytes=1,
                return_boundary_receipt=True,
            )

        assert network.evidence == []
        await network.fail(reservation, reason="test-complete")
        assert network.failures == {"test-complete": 1}
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_passive_metadata_completion_is_confined_to_discovery_gets() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase("ordinary", assessment_policy(plan, max_requests=2))
    try:
        reservation = await network.reserve("GET", plan.origin + "/")
        with pytest.raises(
            AssessmentBoundaryError,
            match="passive-metadata-outside-discovery",
        ):
            await network.complete_passive_metadata(
                reservation,
                status=200,
                headers={},
                observed_response_bytes=1,
            )

        assert network.evidence == []
        assert network.failures == {"passive-metadata-outside-discovery": 1}
    finally:
        await network.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", (-1, True, 1.5, "1"))
async def test_passive_metadata_requires_a_non_negative_observed_size(value: object) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(plan)
    network.begin_phase(
        "browser-passive-discovery",
        assessment_policy(plan, max_requests=1).model_copy(update={"allowed_methods": {"GET"}}),
    )
    try:
        reservation = await network.reserve("GET", plan.origin + "/")
        with pytest.raises(AssessmentBoundaryError, match="invalid-response-size"):
            await network.complete_passive_metadata(
                reservation,
                status=200,
                headers={},
                observed_response_bytes=cast(int, value),
            )
        assert network.evidence == []
    finally:
        await network.close()
