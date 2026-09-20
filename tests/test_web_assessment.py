from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar, cast
from unittest.mock import AsyncMock, MagicMock, call, patch

import httpx
import pytest
from playwright.async_api import Request, Route
from pydantic import ValidationError
from typer.testing import CliRunner

from pajin.capabilities.models import capability_definition_digest
from pajin.capabilities.web_browser_assessment import (
    WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
)
from pajin.cli import app
from pajin.cli_support.common import (
    verified_cli_event_types,
    verified_cli_run_contains_secret,
)
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.web_assessment.browser import (
    BrowserAssessmentError,
    BrowserAssessmentObservation,
    BrowserCredentials,
    PlaywrightAssessmentBrowser,
)
from pajin.web_assessment.diagnostic_catalog import _testing_diagnostic_bundle_catalog
from pajin.web_assessment.diagnostics import (
    diagnose_object_access,
    diagnose_sql_login,
    dom_xss_issue,
)
from pajin.web_assessment.governed_models import JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
from pajin.web_assessment.login_activation import (
    LoginActivationError,
    prepare_login_activation,
    prepare_login_success_activation,
)
from pajin.web_assessment.models import (
    AssessmentIssue,
    AttackPath,
    BrowserPageEvidence,
    BrowserSessionSummary,
    LocalWebAssessmentResult,
    LoginRecipe,
    ProbeTrial,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentBoundaryError, AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.report import render_local_web_assessment_report
from pajin.web_assessment.runner import (
    LocalWebAssessmentError,
    assessment_policy,
    issue_local_web_assessment_authorization,
    provision_local_web_assessment_account,
    run_local_web_assessment,
)


def _json_response(status: int, value: object) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/json"},
        content=json.dumps(value).encode(),
    )


def _mock_transport(
    plan: WebAssessmentPlan,
    registrations: list[dict[str, object]],
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == plan.fingerprint_endpoint:
            return _json_response(200, {"version": "19.2.1-test"})
        if request.method == "POST" and path == "/api/Users/":
            payload = json.loads(request.content)
            assert isinstance(payload, dict)
            registrations.append(payload)
            return _json_response(201, {"status": "success"})
        if request.method == "POST" and path == plan.login.endpoint:
            payload = json.loads(request.content)
            assert isinstance(payload, dict)
            assert plan.sql_login is not None
            if payload.get(plan.login.username_field) == plan.sql_login.true_expression:
                return _json_response(
                    200,
                    {"authentication": {"token": "transient-token", "bid": 1}},
                )
            return _json_response(401, {"error": "invalid credentials"})
        if request.method == "GET" and path == "/api/Users/":
            assert request.headers.get("authorization") == "Bearer transient-token"
            return _json_response(200, {"data": [{"id": 1}, {"id": 2}]})
        if request.method == "GET" and path.startswith("/rest/basket/"):
            object_id = int(path.rsplit("/", 1)[1])
            if object_id == 2_147_483_647:
                return _json_response(200, {"data": None})
            return _json_response(
                200,
                {
                    "data": {
                        "id": object_id,
                        "UserId": object_id,
                        "Products": [],
                    }
                },
            )
        if request.method == "GET" and path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b"<html><title>Juice Shop</title></html>",
            )
        raise AssertionError(f"unexpected request: {request.method} {path}")

    return httpx.MockTransport(handler)


class _FakeBrowser:
    captured_credentials: ClassVar[list[BrowserCredentials]] = []

    def __init__(
        self,
        *,
        plan: WebAssessmentPlan,
        network: AssessmentNetwork,
        store: object,
        navigation_policy: object,
        xss_policy: object,
        headless: bool,
    ) -> None:
        from pajin.runtime.store import RunStore
        from pajin.runtime.worker import EgressPolicy

        assert isinstance(store, RunStore)
        assert isinstance(navigation_policy, EgressPolicy)
        assert isinstance(xss_policy, EgressPolicy)
        self.plan = plan
        self.network = network
        self.store = store
        self.navigation_policy = navigation_policy
        self.headless = headless

    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        self.captured_credentials.append(credentials)
        self.network.begin_phase("fake-browser", self.navigation_policy)
        response = await self.network.json_request("GET", "/")
        assert response.status == 200
        pages = tuple(self._page(index) for index in range(1, 5))
        return BrowserAssessmentObservation(
            object_id=7,
            summary=BrowserSessionSummary(
                authenticated=True,
                ephemeral_account_created=True,
                pages=pages,
                requests_completed=1,
                browser_closed=True,
            ),
            dom_xss_trials=(
                ProbeTrial(
                    check="dom-xss",
                    repetition="source",
                    reproduced=True,
                    controls_passed=True,
                    evidence_ids=(pages[0].evidence_id, pages[1].evidence_id),
                    facts={
                        "controlMarkerExecuted": False,
                        "probeMarkerExecuted": True,
                        "externalTransmission": False,
                    },
                ),
                ProbeTrial(
                    check="dom-xss",
                    repetition="replay",
                    reproduced=True,
                    controls_passed=True,
                    evidence_ids=(pages[2].evidence_id, pages[3].evidence_id),
                    facts={
                        "controlMarkerExecuted": False,
                        "probeMarkerExecuted": True,
                        "externalTransmission": False,
                    },
                ),
            ),
        )

    def _page(self, index: int) -> BrowserPageEvidence:
        screenshot = f"fake-png-{index}".encode()
        reference = self.store.write_bytes(f"evidence/fake-{index}.png", screenshot)
        dom = f"<html>page-{index}</html>".encode()
        phases = {
            1: "dom-xss-control",
            2: "dom-xss-source",
            3: "dom-xss-control",
            4: "dom-xss-replay",
        }
        assert self.plan.dom_xss is not None
        route_prefix = self.plan.dom_xss.route_template.partition("{payload}")[0]
        return BrowserPageEvidence(
            phase=phases[index],
            route=route_prefix + ("<control-redacted>" if index in {1, 3} else "<probe-redacted>"),
            title="Juice Shop",
            ready_selector="app-search-result",
            dom_sha256=hashlib.sha256(dom).hexdigest(),
            dom_bytes=len(dom),
            screenshot_reference=reference,
            screenshot_sha256=hashlib.sha256(screenshot).hexdigest(),
            screenshot_bytes=len(screenshot),
            marker_executed=index in {2, 4},
            captured_at=datetime.now(UTC),
        )


def _login_browser_harness(
    *,
    submit_enabled: bool,
    success_enabled: bool = True,
) -> tuple[
    PlaywrightAssessmentBrowser,
    MagicMock,
    dict[str, MagicMock],
    BrowserPageEvidence,
]:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    locators: dict[str, MagicMock] = {}
    for selector in (
        plan.login.username_selector,
        plan.login.password_selector,
        plan.login.submit_selector,
        plan.login.success_activation_selector,
        plan.login.success_selector,
    ):
        assert selector is not None
        locator = MagicMock()
        locator.fill = AsyncMock()
        locator.wait_for = AsyncMock()
        locator.is_enabled = AsyncMock(return_value=True)
        locator.press = AsyncMock()
        locator.click = AsyncMock()
        locators[selector] = locator

    locators[plan.login.submit_selector].is_enabled = AsyncMock(return_value=submit_enabled)
    success_activation_selector = plan.login.success_activation_selector
    assert success_activation_selector is not None
    locators[success_activation_selector].is_enabled = AsyncMock(return_value=success_enabled)

    page = MagicMock()
    page.url = plan.origin + "/#/search"
    page.goto = AsyncMock()
    page.locator.side_effect = locators.__getitem__
    page.keyboard.press = AsyncMock()

    response = MagicMock()
    response.body = AsyncMock(
        return_value=json.dumps(
            {"authentication": {"token": "transient-browser-token", "bid": 7}}
        ).encode()
    )
    response_value: asyncio.Future[MagicMock] = asyncio.get_running_loop().create_future()
    response_value.set_result(response)
    response_info = MagicMock()
    response_info.value = response_value
    response_context = MagicMock()
    response_context.__aenter__ = AsyncMock(return_value=response_info)
    response_context.__aexit__ = AsyncMock(return_value=False)
    page.expect_response.return_value = response_context

    browser = PlaywrightAssessmentBrowser(
        plan=plan,
        network=cast(AssessmentNetwork, object()),
        store=cast(RunStore, object()),
        navigation_policy=assessment_policy(plan, max_requests=1),
        xss_policy=assessment_policy(plan, max_requests=1),
    )
    browser._page = page
    captured_page = cast(BrowserPageEvidence, object())
    return browser, page, locators, captured_page


@pytest.mark.asyncio
async def test_browser_login_activates_password_input_with_enter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser, page, locators, captured_page = _login_browser_harness(submit_enabled=True)
    monkeypatch.setattr(browser, "_dismiss_login_obstructions", AsyncMock())
    monkeypatch.setattr(browser, "_settle", AsyncMock())
    monkeypatch.setattr(browser, "_capture_page", AsyncMock(return_value=captured_page))
    credentials = BrowserCredentials(username="disposable@example.test", password="test-secret")

    object_id, evidence = await browser._login(credentials)

    submit = locators[browser.plan.login.submit_selector]
    password = locators[browser.plan.login.password_selector]
    submit.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=browser.plan.request_timeout_seconds * 1_000,
    )
    submit.is_enabled.assert_awaited_once_with()
    password.press.assert_awaited_once_with(
        "Enter",
        timeout=browser.plan.request_timeout_seconds * 1_000,
    )
    success_activation_selector = browser.plan.login.success_activation_selector
    assert success_activation_selector is not None
    success_activation = locators[success_activation_selector]
    success_activation.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=browser.plan.request_timeout_seconds * 1_000,
    )
    success_activation.is_enabled.assert_awaited_once_with()
    success_activation.press.assert_awaited_once_with(
        "Enter",
        timeout=browser.plan.request_timeout_seconds * 1_000,
    )
    success_activation.click.assert_not_awaited()
    submit.press.assert_not_awaited()
    submit.click.assert_not_awaited()
    page.keyboard.press.assert_awaited_once_with("Escape")
    assert object_id == 7
    assert evidence is captured_page


@pytest.mark.asyncio
async def test_browser_login_rejects_disabled_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser, _, locators, _ = _login_browser_harness(submit_enabled=False)
    monkeypatch.setattr(browser, "_dismiss_login_obstructions", AsyncMock())
    monotonic = MagicMock(side_effect=(0.0, 13.0))
    monkeypatch.setattr("pajin.web_assessment.login_activation.monotonic", monotonic)
    credentials = BrowserCredentials(username="disposable@example.test", password="test-secret")

    with pytest.raises(BrowserAssessmentError, match="login form did not become valid"):
        await browser._login(credentials)

    submit = locators[browser.plan.login.submit_selector]
    password = locators[browser.plan.login.password_selector]
    submit.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=browser.plan.request_timeout_seconds * 1_000,
    )
    submit.is_enabled.assert_awaited_once_with()
    submit.press.assert_not_awaited()
    submit.click.assert_not_awaited()
    password.press.assert_not_awaited()


@pytest.mark.asyncio
async def test_browser_login_rejects_disabled_success_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser, page, locators, _ = _login_browser_harness(
        submit_enabled=True,
        success_enabled=False,
    )
    monkeypatch.setattr(browser, "_dismiss_login_obstructions", AsyncMock())
    monotonic = MagicMock(side_effect=(0.0, 0.0, 13.0))
    monkeypatch.setattr("pajin.web_assessment.login_activation.monotonic", monotonic)
    credentials = BrowserCredentials(username="disposable@example.test", password="test-secret")

    with pytest.raises(BrowserAssessmentError, match="login success activation failed"):
        await browser._login(credentials)

    password = locators[browser.plan.login.password_selector]
    password.press.assert_awaited_once_with(
        "Enter",
        timeout=browser.plan.request_timeout_seconds * 1_000,
    )
    success_activation_selector = browser.plan.login.success_activation_selector
    assert success_activation_selector is not None
    success_activation = locators[success_activation_selector]
    success_activation.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=browser.plan.request_timeout_seconds * 1_000,
    )
    success_activation.is_enabled.assert_awaited_once_with()
    success_activation.press.assert_not_awaited()
    success_activation.click.assert_not_awaited()
    page.keyboard.press.assert_not_awaited()


@pytest.mark.asyncio
async def test_login_activation_waits_for_actionability_and_is_single_use() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    submit = MagicMock()
    submit.wait_for = AsyncMock()
    submit.is_enabled = AsyncMock(side_effect=(False, False, True))
    submit.click = AsyncMock()
    password = MagicMock()
    password.press = AsyncMock()
    page = MagicMock()
    page.locator.side_effect = {
        plan.login.submit_selector: submit,
        plan.login.password_selector: password,
    }.__getitem__

    sleep = AsyncMock()
    with patch("pajin.web_assessment.login_activation.asyncio.sleep", sleep):
        activation = await prepare_login_activation(
            page, plan.login, timeout_milliseconds=plan.request_timeout_seconds * 1_000
        )
    await activation.activate_once()

    submit.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=plan.request_timeout_seconds * 1_000,
    )
    assert submit.is_enabled.await_count == 3
    assert sleep.await_count == 2
    submit.click.assert_not_awaited()
    password.press.assert_awaited_once_with(
        "Enter",
        timeout=plan.request_timeout_seconds * 1_000,
    )
    with pytest.raises(LoginActivationError, match="already consumed"):
        await activation.activate_once()
    assert password.press.await_count == 1


@pytest.mark.asyncio
async def test_login_activation_rejects_permanently_disabled_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    submit = MagicMock()
    submit.wait_for = AsyncMock()
    submit.is_enabled = AsyncMock(return_value=False)
    submit.click = AsyncMock()
    password = MagicMock()
    password.press = AsyncMock()
    page = MagicMock()
    page.locator.side_effect = {
        plan.login.submit_selector: submit,
        plan.login.password_selector: password,
    }.__getitem__
    monotonic = MagicMock(side_effect=(0.0, 2.0))
    monkeypatch.setattr("pajin.web_assessment.login_activation.monotonic", monotonic)

    with pytest.raises(LoginActivationError, match="did not become actionable"):
        await prepare_login_activation(page, plan.login, timeout_milliseconds=1_000)

    submit.wait_for.assert_awaited_once_with(state="visible", timeout=1_000)
    submit.is_enabled.assert_awaited_once_with()
    submit.click.assert_not_awaited()
    password.press.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_login_activation_clicks_submit_exactly_once() -> None:
    recipe = LoginRecipe(
        route="/#/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_selector="#logout",
        endpoint="/login",
    )
    assert recipe.activation_mode is None
    submit = MagicMock()
    submit.wait_for = AsyncMock()
    submit.is_enabled = AsyncMock(return_value=True)
    submit.click = AsyncMock()
    password = MagicMock()
    password.press = AsyncMock()
    page = MagicMock()
    page.locator.side_effect = {
        recipe.submit_selector: submit,
        recipe.password_selector: password,
    }.__getitem__

    activation = await prepare_login_activation(page, recipe, timeout_milliseconds=1_000)
    await activation.activate_once()

    submit.wait_for.assert_awaited_once_with(state="visible", timeout=1_000)
    submit.is_enabled.assert_awaited_once_with()
    assert submit.click.await_args_list == [call(timeout=1_000)]
    password.press.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_success_activation_clicks_control_exactly_once() -> None:
    recipe = LoginRecipe(
        route="/#/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_selector="#logout",
        success_activation_selector="#account-menu",
        endpoint="/login",
    )
    assert recipe.success_activation_mode is None
    control = MagicMock()
    control.wait_for = AsyncMock()
    control.is_enabled = AsyncMock(return_value=True)
    control.click = AsyncMock()
    control.press = AsyncMock()
    page = MagicMock()
    page.locator.return_value = control

    activation = await prepare_login_success_activation(
        page,
        recipe,
        timeout_milliseconds=1_000,
    )
    assert activation is not None
    await activation.activate_once()

    control.wait_for.assert_awaited_once_with(state="visible", timeout=1_000)
    control.is_enabled.assert_awaited_once_with()
    assert control.click.await_args_list == [call(timeout=1_000)]
    control.press.assert_not_awaited()
    with pytest.raises(LoginActivationError, match="already consumed"):
        await activation.activate_once()
    assert control.click.await_count == 1


@pytest.mark.asyncio
async def test_missing_success_activation_selector_is_a_noop() -> None:
    recipe = LoginRecipe(
        route="/#/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="#submit",
        success_selector="#logout",
        endpoint="/login",
    )
    page = MagicMock()

    activation = await prepare_login_success_activation(
        page,
        recipe,
        timeout_milliseconds=1_000,
    )

    assert activation is None
    page.locator.assert_not_called()


def test_login_activation_mode_is_recipe_digest_bound() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    assert plan.login.activation_mode == "password-enter"
    assert plan.login.success_activation_mode == "enter"
    assert plan.plan_digest == WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST
    raw = plan.model_dump(mode="json")
    raw["login"]["activation_mode"] = "submit-click"
    click_plan = WebAssessmentPlan.model_validate(raw)

    assert click_plan.plan_digest != plan.plan_digest

    raw["login"]["activation_mode"] = "script"
    with pytest.raises(ValidationError):
        WebAssessmentPlan.model_validate(raw)

    raw = plan.model_dump(mode="json")
    raw["login"]["success_activation_mode"] = "click"
    click_success_plan = WebAssessmentPlan.model_validate(raw)

    assert click_success_plan.plan_digest != plan.plan_digest

    raw["login"]["success_activation_mode"] = "script"
    with pytest.raises(ValidationError):
        WebAssessmentPlan.model_validate(raw)

    raw = plan.model_dump(mode="json")
    raw["login"]["success_activation_selector"] = None
    with pytest.raises(ValidationError, match="mode requires a selector"):
        WebAssessmentPlan.model_validate(raw)


def test_plan_without_success_activation_mode_retains_prior_digest() -> None:
    raw = juice_shop_plan("http://127.0.0.1:3000").model_dump(mode="json")
    raw["login"].pop("success_activation_mode")

    prior = WebAssessmentPlan.model_validate(raw)

    assert prior.login.activation_mode == "password-enter"
    assert prior.login.success_activation_mode is None
    assert prior.plan_digest == ("59d34eddce0443bcf98b78a0e2188ca52f80c4343feedf5644f91a8caa68e142")


def test_legacy_plan_without_activation_modes_retains_v1alpha1_digest() -> None:
    raw = juice_shop_plan("http://127.0.0.1:3000").model_dump(mode="json")
    raw["login"].pop("activation_mode")
    raw["login"].pop("success_activation_mode")

    legacy = WebAssessmentPlan.model_validate(raw)

    assert legacy.login.activation_mode is None
    assert legacy.login.success_activation_mode is None
    assert legacy.plan_digest == (
        "bdf954aab61d6fd6081656029a3ca5019e844746d1ab8c98bc6af54e23c32521"
    )


def test_enter_activation_adapter_implementation_revision_is_bound() -> None:
    assert (
        capability_definition_digest(
            "pajin.web-assessment.implementation/v1",
            {
                "implementationType": "pajin.web_assessment.recipes.juice_shop_plan",
                "implementationVersion": "1.0.2",
                "provisioningMode": "preprovisioned-only",
            },
        )
        == JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
    )


def test_local_plan_rejects_implicit_or_non_loopback_origins() -> None:
    for origin in (
        "http://localhost:3000",
        "http://127.0.0.2:3000",
        "http://example.test",
        "http://user:pass@127.0.0.1:3000",
        "http://127.0.0.1:3000/path",
    ):
        with pytest.raises(ValidationError):
            juice_shop_plan(origin)

    plan = juice_shop_plan("http://127.0.0.1:3000")
    expanded = plan.model_dump(mode="json")
    expanded["allowed_post_paths"].append("/api/Products/")
    with pytest.raises(ValidationError, match="only login and registration"):
        WebAssessmentPlan.model_validate(expanded)


def test_local_authorization_is_explicit_exact_and_short_lived() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    now = datetime(2026, 9, 14, tzinfo=UTC)
    with pytest.raises(LocalWebAssessmentError, match="explicit"):
        issue_local_web_assessment_authorization(
            plan,
            operator_confirmed_authorized_local_lab=False,
            now=now,
        )
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=now,
    )
    authorization.require_current(plan=plan, now=now + timedelta(minutes=1))
    with pytest.raises(ValueError, match="not current"):
        authorization.require_current(plan=plan, now=authorization.expires_at)
    other = juice_shop_plan("http://127.0.0.1:3001")
    with pytest.raises(ValueError, match="differs"):
        authorization.require_current(plan=other, now=now + timedelta(minutes=1))


@pytest.mark.asyncio
async def test_network_blocks_scope_expansion_and_ambiguous_paths() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    observed_cookies: list[str | None] = []

    def respond(request: httpx.Request) -> httpx.Response:
        observed_cookies.append(request.headers.get("cookie"))
        response = _json_response(200, {})
        response.headers["set-cookie"] = "ambient-session=must-not-persist"
        return response

    transport = httpx.MockTransport(respond)
    network = AssessmentNetwork(plan, transport=transport)
    network.begin_phase("boundary-test", assessment_policy(plan, max_requests=2))
    try:

        class RedirectRoute:
            aborted_with: str | None = None
            continued = False

            async def abort(self, reason: str) -> None:
                self.aborted_with = reason

            async def continue_(self) -> None:
                self.continued = True

        class RedirectRequest:
            redirected_from = object()

        browser = PlaywrightAssessmentBrowser(
            plan=plan,
            network=network,
            store=cast(RunStore, object()),
            navigation_policy=assessment_policy(plan, max_requests=2),
            xss_policy=assessment_policy(plan, max_requests=2),
        )
        redirect_route = RedirectRoute()
        await browser._gate_route(
            cast(Route, redirect_route),
            cast(Request, RedirectRequest()),
        )
        assert redirect_route.aborted_with == "blockedbyclient"
        assert redirect_route.continued is False
        assert network.blocked["redirect-disabled"] == 1

        rejected = (
            ("GET", "http://127.0.0.1:3001/"),
            ("GET", plan.origin + "/rest/user/%72eset-password"),
            ("GET", plan.origin + "/#fragment"),
            ("POST", plan.origin + "/api/Products/"),
            ("DELETE", plan.origin + "/"),
        )
        for method, url in rejected:
            with pytest.raises(AssessmentBoundaryError):
                await network.reserve(method, url)
        reservation = await network.reserve("GET", plan.origin + "/")
        with pytest.raises(AssessmentBoundaryError, match="open-requests"):
            network.begin_phase("next", assessment_policy(plan, max_requests=1))
        await network.fail(reservation, reason="test-release")
        network.begin_phase("budget-test", assessment_policy(plan, max_requests=1))
        await network.exchange("GET", plan.origin + "/")
        with pytest.raises(AssessmentBoundaryError, match="request-budget"):
            await network.exchange("GET", plan.origin + "/")
        network.begin_phase("cookie-test", assessment_policy(plan, max_requests=1))
        await network.exchange("GET", plan.origin + "/")
        assert observed_cookies == [None, None]
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_network_rechecks_authorization_expiry_at_phase_and_request_boundaries() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    expired = datetime.now(UTC) - timedelta(seconds=1)

    phase_network = AssessmentNetwork(
        plan,
        transport=httpx.MockTransport(lambda _: _json_response(200, {})),
    )
    phase_network.bind_authorization_deadline(expired)
    try:
        with pytest.raises(AssessmentBoundaryError, match="authorization-expired"):
            phase_network.begin_phase("expired", assessment_policy(plan, max_requests=1))
    finally:
        await phase_network.close()

    request_network = AssessmentNetwork(
        plan,
        transport=httpx.MockTransport(lambda _: _json_response(200, {})),
    )
    request_network.begin_phase("before-expiry", assessment_policy(plan, max_requests=1))
    request_network.bind_authorization_deadline(expired)
    try:
        with pytest.raises(AssessmentBoundaryError, match="authorization-expired"):
            await request_network.reserve("GET", plan.origin + "/")
    finally:
        await request_network.close()


@pytest.mark.asyncio
async def test_negative_diagnostics_do_not_claim_observed_exploitation() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")

    def respond(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == plan.login.endpoint:
            return _json_response(401, {"error": "invalid credentials"})
        if request.method == "GET" and request.url.path.startswith("/rest/basket/"):
            object_id = int(request.url.path.rsplit("/", 1)[1])
            if object_id == 1:
                return _json_response(200, {"data": {"id": 1, "Products": []}})
            return _json_response(200, {"data": None})
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    policy = assessment_policy(plan, max_requests=20)
    try:
        sql = await diagnose_sql_login(network=network, plan=plan, policy=policy)
        object_issue = await diagnose_object_access(
            network=network,
            plan=plan,
            policy=policy,
            attack_token="controlled-token",
            attack_object_id=1,
            target_object_id=7,
        )
    finally:
        await network.close()

    assert sql.issue.status == "not-reproduced"
    assert "not reproduced" in sql.issue.title.lower()
    assert "did not establish" in sql.issue.observed_impact.lower()
    assert object_issue.status == "not-reproduced"
    assert "not reproduced" in object_issue.title.lower()
    assert "did not return" in object_issue.observed_impact.lower()

    negative_dom_trials = (
        ProbeTrial(
            check="dom-xss",
            repetition="source",
            reproduced=False,
            controls_passed=True,
            evidence_ids=(),
            facts={},
        ),
        ProbeTrial(
            check="dom-xss",
            repetition="replay",
            reproduced=False,
            controls_passed=True,
            evidence_ids=(),
            facts={},
        ),
    )
    dom_issue = dom_xss_issue(negative_dom_trials)
    assert dom_issue.status == "not-reproduced"
    assert "not reproduced" in dom_issue.title.lower()
    assert "did not set" in dom_issue.observed_impact.lower()

    inconclusive_dom_trials = (
        negative_dom_trials[0].model_copy(update={"controls_passed": False}),
        negative_dom_trials[1],
    )
    inconclusive_dom = dom_xss_issue(inconclusive_dom_trials)
    assert inconclusive_dom.status == "inconclusive"
    assert "inconclusive" in inconclusive_dom.title.lower()
    assert "did not support" in inconclusive_dom.observed_impact.lower()

    success_worded_negative = dom_issue.model_dump(mode="json")
    success_worded_negative["title"] = "Search input executes script in the application origin"
    success_worded_negative["observed_impact"] = "Same-origin JavaScript execution was observed."
    with pytest.raises(ValidationError, match="narrative differs"):
        AssessmentIssue.model_validate(success_worded_negative)


@pytest.mark.asyncio
async def test_local_web_flow_seals_secret_free_diagnostics_and_attack_paths(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    registrations: list[dict[str, object]] = []
    transport = _mock_transport(plan, registrations)
    _FakeBrowser.captured_credentials = []
    artifacts = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=tmp_path,
        browser_factory=_FakeBrowser,
        network_factory=lambda selected: AssessmentNetwork(
            selected,
            transport=transport,
        ),
        diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
    )

    assert [issue.status for issue in artifacts.result.issues] == [
        "locally-reproduced",
        "locally-reproduced",
        "locally-reproduced",
    ]
    assert [path.status for path in artifacts.result.attack_paths] == [
        "locally-validated",
        "locally-validated",
    ]
    assert artifacts.result.browser.authenticated is True
    assert artifacts.result.credentials_persisted is False
    assert artifacts.result.external_delivery_performed is False
    assert artifacts.result.finding_authority is False
    assert verify_run_integrity(artifacts.run_path).root_digest == artifacts.root_digest
    assert verified_cli_event_types(artifacts.run_path, artifacts.result.run_id) == [
        "web-assessment.started",
        "web-assessment.completed",
    ]
    assert len(registrations) == 1
    credentials = _FakeBrowser.captured_credentials[0]
    assert registrations[0]["email"] == credentials.username
    assert not verified_cli_run_contains_secret(
        artifacts.run_path,
        artifacts.result.run_id,
        credentials.username,
    )
    assert not verified_cli_run_contains_secret(
        artifacts.run_path,
        artifacts.result.run_id,
        credentials.password,
    )
    assert not verified_cli_run_contains_secret(
        artifacts.run_path,
        artifacts.result.run_id,
        "transient-token",
    )
    report = artifacts.report_path.read_text(encoding="utf-8")
    assert "not a confirmed PAJIN Finding" in report
    assert "External delivery performed: `false`" in report

    changed = artifacts.result.model_dump(mode="json")
    changed["target_version"] = "tampered"
    with pytest.raises(ValidationError, match="Result Digest differs"):
        LocalWebAssessmentResult.model_validate(changed)

    dangling = artifacts.result.model_dump(mode="json")
    dangling["result_digest"] = ""
    missing_evidence_id = dangling["issues"][0]["trials"][0]["evidence_ids"][0]
    dangling["requests"] = [
        request for request in dangling["requests"] if request["evidence_id"] != missing_evidence_id
    ]
    with pytest.raises(ValidationError, match="unknown Evidence"):
        LocalWebAssessmentResult.model_validate(dangling)

    misstated_issue = artifacts.result.model_dump(mode="json")
    misstated_issue["result_digest"] = ""
    misstated_issue["issues"][0]["status"] = "not-reproduced"
    with pytest.raises(ValidationError, match="status differs"):
        LocalWebAssessmentResult.model_validate(misstated_issue)

    misstated_path = artifacts.result.model_dump(mode="json")
    misstated_path["result_digest"] = ""
    misstated_path["attack_paths"][0]["path_id"] = ""
    misstated_path["attack_paths"][0]["status"] = "incomplete"
    misstated_path["attack_paths"][0]["stages"][1]["state"] = "potential"
    misstated_path["attack_paths"][0]["stages"][1]["summary"] = (
        "The controlled trials did not reproduce a stable session-minting bypass."
    )
    misstated_path["attack_paths"][0]["title"] = (
        "Login-injection to cross-account basket chain was incomplete"
    )
    misstated_path["attack_paths"][0]["observed_impact"] = (
        "The full chain was not reproduced in both controlled trials."
    )
    with pytest.raises(ValidationError, match="stage state differs"):
        LocalWebAssessmentResult.model_validate(misstated_path)

    unlinked_diagnostic_stage = artifacts.result.model_dump(mode="json")
    unlinked_diagnostic_stage["result_digest"] = ""
    unlinked_diagnostic_stage["attack_paths"][0]["path_id"] = ""
    unlinked_diagnostic_stage["attack_paths"][0]["stages"][1]["issue_id"] = None
    with pytest.raises(ValidationError, match="diagnostic attack path stages require"):
        LocalWebAssessmentResult.model_validate(unlinked_diagnostic_stage)

    swapped_issue = artifacts.result.model_dump(mode="json")
    swapped_issue["result_digest"] = ""
    swapped_issue["attack_paths"][0]["path_id"] = ""
    swapped_issue["attack_paths"][0]["stages"][1]["issue_id"] = swapped_issue["issues"][2][
        "issue_id"
    ]
    with pytest.raises(ValidationError, match="issue sequence differs"):
        LocalWebAssessmentResult.model_validate(swapped_issue)

    incomplete_with_success_impact = artifacts.result.attack_paths[1].model_dump(mode="json")
    incomplete_with_success_impact["path_id"] = ""
    incomplete_with_success_impact["status"] = "incomplete"
    incomplete_with_success_impact["title"] = (
        "Crafted search-route script-execution chain was incomplete"
    )
    incomplete_with_success_impact["stages"][1]["state"] = "potential"
    incomplete_with_success_impact["stages"][1]["summary"] = (
        "The controlled trials did not reproduce stable DOM-marker execution."
    )
    with pytest.raises(ValidationError, match="narrative differs"):
        AttackPath.model_validate(incomplete_with_success_impact)

    forged_report_input = artifacts.result.model_copy(
        update={
            "attack_paths": (
                artifacts.result.attack_paths[0],
                artifacts.result.attack_paths[1].model_copy(
                    update={"observed_impact": "Arbitrary unvalidated impact claim."}
                ),
            )
        }
    )
    with pytest.raises(ValidationError, match="narrative differs"):
        render_local_web_assessment_report(forged_report_input)


@pytest.mark.asyncio
async def test_preprovisioned_account_keeps_write_outside_assessment_action(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    registrations: list[dict[str, object]] = []
    transport = _mock_transport(plan, registrations)
    account = await provision_local_web_assessment_account(
        plan=plan,
        authorization=authorization,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
    )

    assert len(registrations) == 1
    serialized_receipt = json.dumps(account.receipt(), sort_keys=True)
    assert account.credentials.username not in serialized_receipt
    assert account.credentials.password not in serialized_receipt

    artifacts = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=tmp_path,
        browser_factory=_FakeBrowser,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
        provisioned_account=account,
        diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
    )

    assert len(registrations) == 1
    assert artifacts.result.target_version == "19.2.1-test"
    persisted = (artifacts.run_path / "provisioning-receipt.json").read_text(encoding="utf-8")
    assert account.credentials.username not in persisted
    assert account.credentials.password not in persisted


def test_cli_requires_explicit_local_lab_confirmation() -> None:
    result = CliRunner().invoke(
        app,
        ["web-assess-local", "--origin", "http://127.0.0.1:3000"],
    )
    assert result.exit_code == 2
    assert "Local Web assessment failed" in result.output
