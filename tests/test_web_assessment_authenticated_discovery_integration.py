from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from pajin.runtime.store import RunStore
from pajin.web_assessment.browser import (
    BrowserAssessmentObservation,
    BrowserCredentials,
    PlaywrightAssessmentBrowser,
)
from pajin.web_assessment.discovery import (
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    DiscoveredBrowserRoute,
)
from pajin.web_assessment.models import BrowserPageEvidence, ProbeTrial
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import assessment_policy


def _page(
    index: int,
    phase: Literal[
        "authenticated-navigation",
        "dom-xss-control",
        "dom-xss-source",
        "dom-xss-replay",
    ],
) -> BrowserPageEvidence:
    return BrowserPageEvidence(
        phase=phase,
        route=f"/#/page-{index}",
        title=f"page {index}",
        ready_selector="body",
        dom_sha256=hashlib.sha256(f"dom-{index}".encode()).hexdigest(),
        dom_bytes=10,
        screenshot_reference=f"evidence/browser-{index:02d}.png",
        screenshot_sha256=hashlib.sha256(f"png-{index}".encode()).hexdigest(),
        screenshot_bytes=10,
        marker_executed=None if index == 1 else index in {3, 5},
        captured_at=datetime.now(UTC),
    )


def _trial(
    repetition: Literal["source", "replay"],
    pages: tuple[BrowserPageEvidence, BrowserPageEvidence],
) -> ProbeTrial:
    return ProbeTrial(
        check="dom-xss",
        repetition=repetition,
        reproduced=True,
        controls_passed=True,
        evidence_ids=tuple(page.evidence_id for page in pages),
        facts={
            "controlMarkerExecuted": False,
            "probeMarkerExecuted": True,
            "externalTransmission": False,
        },
    )


def _browser(tmp_path: Path) -> tuple[PlaywrightAssessmentBrowser, AssessmentNetwork]:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    network = AssessmentNetwork(
        plan,
        transport=httpx.MockTransport(lambda _: httpx.Response(200)),
    )
    browser = PlaywrightAssessmentBrowser(
        plan=plan,
        network=network,
        store=RunStore.create(tmp_path, "authenticated-discovery-test"),
        navigation_policy=assessment_policy(plan, max_requests=100),
        xss_policy=assessment_policy(plan, max_requests=40),
    )
    return browser, network


@pytest.mark.asyncio
async def test_browser_run_discovers_structure_in_the_authenticated_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser, network = _browser(tmp_path)
    login_page_handle = MagicMock(name="login-page")
    context = MagicMock(name="authenticated-context")
    call_order: list[str] = []
    page_scoped_session = {"authenticated": True}
    login_page = _page(1, "authenticated-navigation")
    source_pages = (_page(2, "dom-xss-control"), _page(3, "dom-xss-source"))
    replay_pages = (_page(4, "dom-xss-control"), _page(5, "dom-xss-replay"))

    async def retire_document(
        url: str,
        *,
        wait_until: Literal["domcontentloaded"],
        timeout: float,
    ) -> None:
        assert url == "about:blank"
        assert wait_until == "domcontentloaded"
        assert timeout > 0
        assert page_scoped_session == {"authenticated": True}
        call_order.append("retire-document")

    login_page_handle.goto = AsyncMock(side_effect=retire_document)
    login_page_handle.close = AsyncMock(
        side_effect=lambda: page_scoped_session.clear()
    )
    context.new_page = AsyncMock()

    async def start() -> None:
        call_order.append("start")
        browser._context = cast(Any, context)
        browser._page = cast(Any, login_page_handle)

    async def close() -> None:
        call_order.append("close")

    async def login(_: BrowserCredentials) -> tuple[int, BrowserPageEvidence]:
        call_order.append("login")
        return 7, login_page

    async def explore() -> list[BrowserPageEvidence]:
        call_order.append("explore")
        return []

    async def discover(
        received_page: object,
        *,
        plan: BrowserDiscoveryPlan,
    ) -> BrowserDiscoveryResult:
        call_order.append("discover")
        assert received_page is login_page_handle
        assert page_scoped_session == {"authenticated": True}
        assert plan.origin == browser.plan.origin
        assert plan.seed_routes == (browser.plan.routes[0],)
        assert plan.authentication_sentinel_selector == browser.plan.login.success_selector
        assert (
            plan.authentication_sentinel_activation_selector
            == browser.plan.login.success_activation_selector
        )
        assert (
            plan.authentication_sentinel_activation_mode
            == browser.plan.login.success_activation_mode
        )
        assert plan.max_routes == 4
        reservation = await network.reserve("GET", browser.plan.origin + "/")
        completion = await network.complete_passive_metadata(
            reservation,
            status=200,
            headers={"content-type": "text/html; charset=utf-8"},
            observed_response_bytes=1_024,
            return_boundary_receipt=True,
        )
        browser._passive_completions[completion.evidence.evidence_id] = completion
        browser._completed_browser_requests += 1
        return BrowserDiscoveryResult(
            plan_digest=plan.plan_digest,
            origin=browser.plan.origin,
            routes=(
                DiscoveredBrowserRoute(
                    route=browser.plan.routes[0],
                    depth=0,
                    source="seed",
                ),
            ),
            route_limit_reached=False,
            form_limit_reached=False,
            field_limit_reached=False,
        )

    async def probe(
        repetition: Literal["source", "replay"],
    ) -> tuple[ProbeTrial, tuple[BrowserPageEvidence, BrowserPageEvidence]]:
        call_order.append(f"xss-{repetition}")
        assert browser._require_page() is login_page_handle
        assert page_scoped_session == {"authenticated": True}
        selected = source_pages if repetition == "source" else replay_pages
        return _trial(repetition, selected), selected

    monkeypatch.setattr(browser, "_start", start)
    monkeypatch.setattr(browser, "_close", close)
    monkeypatch.setattr(browser, "_login", login)
    monkeypatch.setattr(browser, "_explore_routes", explore)
    monkeypatch.setattr(browser, "_probe_dom_xss", probe)
    monkeypatch.setattr(browser, "_settle", AsyncMock())
    monkeypatch.setattr(
        "pajin.web_assessment.browser.discover_browser_routes_and_forms",
        discover,
    )
    try:
        observation: BrowserAssessmentObservation = await browser.run(
            BrowserCredentials("disposable@example.test", "test-password")
        )
    finally:
        await network.close()

    assert call_order == [
        "start",
        "login",
        "explore",
        "retire-document",
        "discover",
        "retire-document",
        "xss-source",
        "xss-replay",
        "close",
    ]
    assert observation.discovery_evidence is not None
    assert observation.discovery_evidence.browser_closed is True
    assert observation.discovery_evidence.discovery_result.routes[0].route == browser.plan.routes[0]
    assert context.new_page.await_count == 0
    login_page_handle.close.assert_not_awaited()
    assert page_scoped_session == {"authenticated": True}
    assert observation.discovery_evidence.request_evidence[0].response_bytes == 0
    assert observation.discovery_evidence.boundary_receipts[0].observed_response_body_bytes == 1_024


@pytest.mark.asyncio
async def test_passive_browser_response_records_only_metadata(
    tmp_path: Path,
) -> None:
    browser, network = _browser(tmp_path)
    network.begin_phase("browser-passive-discovery", browser.discovery_policy)
    request = MagicMock()
    request.sizes = AsyncMock(return_value={"responseBodySize": 512})
    reservation = await network.reserve("GET", browser.plan.origin + "/")
    browser._reservations[id(request)] = reservation
    response = MagicMock()
    response.request = request
    response.status = 200
    response.body = AsyncMock(side_effect=AssertionError("body must not be retained"))
    response.all_headers = AsyncMock(
        return_value={"content-type": "text/html; credential=not-retained"}
    )
    try:
        await browser._record_response(response)
    finally:
        await network.close()

    response.body.assert_not_awaited()
    completion = next(iter(browser._passive_completions.values()))
    assert completion.evidence.response_bytes == 0
    assert completion.evidence.media_type == "text/html"
    assert completion.boundary_receipt.observed_response_body_bytes == 512


@pytest.mark.asyncio
async def test_assessment_browser_blocks_value_bearing_passive_subresource_before_send(
    tmp_path: Path,
) -> None:
    browser, network = _browser(tmp_path)
    network.begin_phase("browser-passive-discovery", browser.discovery_policy)
    request = MagicMock()
    request.method = "GET"
    request.url = (
        browser.plan.origin
        + "/sessions/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123"
    )
    request.post_data_buffer = None
    request.redirected_from = None
    route = MagicMock()
    route.abort = AsyncMock()
    route.continue_ = AsyncMock()
    try:
        await browser._gate_route(route, request)
    finally:
        await network.close()

    route.abort.assert_awaited_once_with("blockedbyclient")
    route.continue_.assert_not_awaited()
    assert browser._reservations == {}
    assert network.evidence == []
    assert network.phase_requests == 0
    assert network.blocked == {"value-bearing-path": 1}
