from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock, call

import httpx
import pytest
from pydantic import ValidationError

from pajin.runtime.store import RunStore
from pajin.web_assessment.browser import (
    BrowserAssessmentError,
    BrowserCredentials,
    PlaywrightAssessmentBrowser,
)
from pajin.web_assessment.diagnostics import diagnose_object_access, diagnose_sql_login
from pajin.web_assessment.models import (
    BrowserPageEvidence,
    DOMXSSRecipe,
    LoginRecipe,
    ObjectAccessRecipe,
    RegistrationRecipe,
    SQLLoginRecipe,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentBoundaryError, AssessmentNetwork
from pajin.web_assessment.runner import assessment_policy

_ORIGIN = "http://127.0.0.1:43123"
_LOGIN_ROUTE = "/ui/sign-in"
_LOGIN_ENDPOINT = "/fixture/v2/session/open"
_REGISTRATION_ENDPOINT = "/fixture/v2/accounts"
_DIRECTORY_ENDPOINT = "/fixture/v2/directory"
_OBJECT_ENDPOINT_PREFIX = "/fixture/v2/carts/"
_USERNAME_SELECTOR = "[data-fixture='identity']"
_PASSWORD_SELECTOR = "[data-fixture='proof']"
_SUBMIT_SELECTOR = "[data-fixture='commit']"
_SUCCESS_ACTIVATION_SELECTOR = "[data-fixture='account-menu']"
_SUCCESS_SELECTOR = "[data-fixture='signed-in']"
_TOKEN = "fixture-session-token"
_ATTACK_OBJECT_ID = 17
_TARGET_OBJECT_ID = 29
_MISSING_OBJECT_ID = 2_147_483_647

_ROUTE_READY_SELECTORS = {
    "/ui/catalog": "[data-fixture='catalog-ready']",
    "/ui/profile": "[data-fixture='profile-ready']",
    "/ui/help": "[data-fixture='help-ready']",
}

ObservedRequest = tuple[str, str, dict[str, object] | None, str | None]


def _fixture_plan(
    *,
    submit_selector: str = _SUBMIT_SELECTOR,
    token_path: str = "session.access.value",
    object_id_path: str = "session.subject.cartId",
) -> WebAssessmentPlan:
    return WebAssessmentPlan(
        name="synthetic-shop-recipe",
        origin=_ORIGIN,
        fingerprint_endpoint="/fixture/v2/meta/version",
        login=LoginRecipe(
            route=_LOGIN_ROUTE,
            username_selector=_USERNAME_SELECTOR,
            password_selector=_PASSWORD_SELECTOR,
            submit_selector=submit_selector,
            activation_mode="submit-click",
            success_selector=_SUCCESS_SELECTOR,
            success_activation_selector=_SUCCESS_ACTIVATION_SELECTOR,
            success_activation_mode="click",
            endpoint=_LOGIN_ENDPOINT,
            username_field="identity",
            password_field="proof",
            token_path=token_path,
            object_id_path=object_id_path,
        ),
        registration=RegistrationRecipe(
            endpoint=_REGISTRATION_ENDPOINT,
            username_field="identity",
            password_field="proof",
            repeat_password_field=None,
            extra_fields={"fixturePurpose": "generic-recipe-test"},
        ),
        routes=tuple(_ROUTE_READY_SELECTORS),
        route_ready_selectors=_ROUTE_READY_SELECTORS,
        allowed_post_paths=(_LOGIN_ENDPOINT, _REGISTRATION_ENDPOINT),
        deny_paths=("/fixture/v2/session/revoke",),
        sql_login=SQLLoginRecipe(
            true_expression="fixture' OR 1=1--",
            false_expression="fixture' AND 1=2--",
            impact_endpoint=_DIRECTORY_ENDPOINT,
            records_path="payload.items",
        ),
        object_access=ObjectAccessRecipe(
            endpoint_template=_OBJECT_ENDPOINT_PREFIX + "{id}",
            object_path="payload.cart",
            id_field="cartId",
        ),
        dom_xss=DOMXSSRecipe(
            route_template="/ui/catalog?term={payload}",
            ready_selector=_ROUTE_READY_SELECTORS["/ui/catalog"],
        ),
    )


def _locator(*, wait_error: Exception | None = None) -> MagicMock:
    locator = MagicMock()
    locator.fill = AsyncMock()
    locator.wait_for = AsyncMock(side_effect=wait_error)
    locator.is_enabled = AsyncMock(return_value=True)
    locator.press = AsyncMock()
    locator.click = AsyncMock()
    return locator


def _browser_harness(
    plan: WebAssessmentPlan,
    *,
    submit_wait_error: Exception | None = None,
) -> tuple[PlaywrightAssessmentBrowser, MagicMock, dict[str, MagicMock]]:
    selectors = {
        plan.login.username_selector,
        plan.login.password_selector,
        plan.login.submit_selector,
        plan.login.success_selector,
        *plan.route_ready_selectors.values(),
    }
    if plan.login.success_activation_selector is not None:
        selectors.add(plan.login.success_activation_selector)
    locators = {selector: _locator() for selector in selectors}
    locators[plan.login.submit_selector].wait_for = AsyncMock(side_effect=submit_wait_error)

    page = MagicMock()
    page.url = plan.origin + "/ui/catalog"
    page.goto = AsyncMock()
    page.locator.side_effect = locators.__getitem__
    page.keyboard.press = AsyncMock()

    response = MagicMock()
    response.body = AsyncMock(
        return_value=json.dumps(
            {
                "session": {
                    "access": {"value": _TOKEN},
                    "subject": {"cartId": _ATTACK_OBJECT_ID},
                }
            }
        ).encode()
    )
    response_value: asyncio.Future[MagicMock] = asyncio.get_running_loop().create_future()
    response_value.set_result(response)
    response_context = MagicMock()
    response_context.__aenter__ = AsyncMock(return_value=SimpleNamespace(value=response_value))
    response_context.__aexit__ = AsyncMock(return_value=False)

    def expect_response(predicate: object, *, timeout: int) -> MagicMock:
        assert callable(predicate)
        wrong = SimpleNamespace(
            request=SimpleNamespace(method="POST"),
            url=plan.origin + "/fixture/v2/session/wrong",
        )
        expected = SimpleNamespace(
            request=SimpleNamespace(method="POST"),
            url=plan.origin + plan.login.endpoint,
        )
        assert predicate(wrong) is False
        assert predicate(expected) is True
        assert timeout == plan.request_timeout_seconds * 1_000
        return response_context

    page.expect_response.side_effect = expect_response
    browser = PlaywrightAssessmentBrowser(
        plan=plan,
        network=cast(AssessmentNetwork, object()),
        store=cast(RunStore, object()),
        navigation_policy=assessment_policy(plan, max_requests=20),
        xss_policy=assessment_policy(plan, max_requests=20),
    )
    browser._page = page
    return browser, page, locators


def _json_response(status: int, value: object) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/json"},
        content=json.dumps(value).encode(),
    )


def _diagnostic_transport(
    plan: WebAssessmentPlan,
    observed: list[ObservedRequest],
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        payload: dict[str, object] | None = None
        if request.content:
            decoded = json.loads(request.content)
            assert isinstance(decoded, dict)
            payload = decoded
        observed.append(
            (
                request.method,
                request.url.path,
                payload,
                request.headers.get("authorization"),
            )
        )
        if request.method == "POST" and request.url.path == _LOGIN_ENDPOINT:
            assert payload is not None
            assert plan.sql_login is not None
            if payload.get("identity") == plan.sql_login.true_expression:
                return _json_response(
                    200,
                    {
                        "session": {
                            "access": {"value": _TOKEN},
                            "subject": {"cartId": _ATTACK_OBJECT_ID},
                        }
                    },
                )
            if payload.get("identity") == plan.sql_login.false_expression:
                return _json_response(401, {"failure": {"reason": "invalid identity"}})
        if request.method == "GET" and request.url.path == _DIRECTORY_ENDPOINT:
            assert request.headers.get("authorization") == f"Bearer {_TOKEN}"
            return _json_response(
                200,
                {"payload": {"items": [{"subject": 1}, {"subject": 2}]}},
            )
        if request.method == "GET" and request.url.path.startswith(_OBJECT_ENDPOINT_PREFIX):
            assert request.headers.get("authorization") == f"Bearer {_TOKEN}"
            object_id = int(request.url.path.removeprefix(_OBJECT_ENDPOINT_PREFIX))
            if object_id == _MISSING_OBJECT_ID:
                return _json_response(200, {"payload": {"cart": None}})
            return _json_response(
                200,
                {
                    "payload": {
                        "cart": {
                            "cartId": object_id,
                            "Products": [],
                        }
                    }
                },
            )
        raise AssertionError(f"unexpected fixture request: {request.method} {request.url.path}")

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_generic_recipe_engine_consumes_custom_login_selectors_session_and_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _fixture_plan()
    browser, page, locators = _browser_harness(plan)
    captured_page = cast(BrowserPageEvidence, object())
    monkeypatch.setattr(browser, "_dismiss_login_obstructions", AsyncMock())
    monkeypatch.setattr(browser, "_settle", AsyncMock())
    capture_page = AsyncMock(return_value=captured_page)
    monkeypatch.setattr(browser, "_capture_page", capture_page)
    credentials = BrowserCredentials(username="fixture-user", password="fixture-proof")

    object_id, login_evidence = await browser._login(credentials)
    route_evidence = await browser._explore_routes()

    assert object_id == _ATTACK_OBJECT_ID
    assert login_evidence is captured_page
    assert route_evidence == [captured_page, captured_page, captured_page]
    locators[_USERNAME_SELECTOR].fill.assert_awaited_once_with(credentials.username)
    locators[_PASSWORD_SELECTOR].fill.assert_awaited_once_with(credentials.password)
    locators[_SUBMIT_SELECTOR].click.assert_awaited_once_with(
        timeout=plan.request_timeout_seconds * 1_000
    )
    locators[_PASSWORD_SELECTOR].press.assert_not_awaited()
    locators[_SUCCESS_ACTIVATION_SELECTOR].click.assert_awaited_once_with(
        timeout=plan.request_timeout_seconds * 1_000
    )
    locators[_SUCCESS_ACTIVATION_SELECTOR].press.assert_not_awaited()
    assert _TOKEN in browser._redactions
    assert _TOKEN in browser._visual_redactions
    assert page.goto.await_args_list == [
        call(
            plan.origin + _LOGIN_ROUTE,
            wait_until="domcontentloaded",
            timeout=plan.request_timeout_seconds * 1_000,
        ),
        *[
            call(
                plan.origin + route,
                wait_until="domcontentloaded",
                timeout=plan.request_timeout_seconds * 1_000,
            )
            for route in plan.routes[1:]
        ],
    ]
    for route, selector in _ROUTE_READY_SELECTORS.items():
        assert route in plan.routes
        locators[selector].wait_for.assert_awaited_once_with(
            state="attached",
            timeout=plan.request_timeout_seconds * 1_000,
        )
    assert capture_page.await_count == 1 + len(plan.routes)


@pytest.mark.parametrize("initial_suffix", ("", "?q=stale"))
@pytest.mark.asyncio
async def test_route_exploration_reuses_exact_authenticated_document_without_skipping_evidence(
    monkeypatch: pytest.MonkeyPatch,
    initial_suffix: str,
) -> None:
    plan = _fixture_plan()
    browser, page, locators = _browser_harness(plan)
    page.url = plan.origin + plan.routes[0] + initial_suffix

    async def navigate(url: str, *, wait_until: str, timeout: int) -> None:
        page.url = url

    page.goto = AsyncMock(side_effect=navigate)
    capture_page = AsyncMock(return_value=cast(BrowserPageEvidence, object()))
    monkeypatch.setattr(browser, "_capture_page", capture_page)
    monkeypatch.setattr(browser, "_settle", AsyncMock())

    captured = await browser._explore_routes()

    assert len(captured) == len(plan.routes)
    assert [item.kwargs["route"] for item in capture_page.await_args_list] == list(plan.routes)
    assert all(
        item.kwargs["phase"] == "authenticated-navigation" for item in capture_page.await_args_list
    )
    expected_navigation_routes = plan.routes[1:] if not initial_suffix else plan.routes
    assert [item.args[0] for item in page.goto.await_args_list] == [
        plan.origin + route for route in expected_navigation_routes
    ]
    for selector in plan.route_ready_selectors.values():
        locators[selector].wait_for.assert_awaited_once_with(
            state="attached",
            timeout=plan.request_timeout_seconds * 1_000,
        )


@pytest.mark.asyncio
async def test_generic_recipe_engine_consumes_declared_diagnostic_endpoints() -> None:
    plan = _fixture_plan()
    observed: list[ObservedRequest] = []
    network = AssessmentNetwork(plan, transport=_diagnostic_transport(plan, observed))
    policy = assessment_policy(plan, max_requests=20)
    try:
        sql = await diagnose_sql_login(network=network, plan=plan, policy=policy)
        assert sql.token == _TOKEN
        assert sql.object_id == _ATTACK_OBJECT_ID
        object_issue = await diagnose_object_access(
            network=network,
            plan=plan,
            policy=policy,
            attack_token=sql.token,
            attack_object_id=sql.object_id,
            target_object_id=_TARGET_OBJECT_ID,
        )
    finally:
        await network.close()

    assert sql.issue.status == "locally-reproduced"
    assert object_issue.status == "locally-reproduced"
    expected_paths = [
        _LOGIN_ENDPOINT,
        _LOGIN_ENDPOINT,
        _DIRECTORY_ENDPOINT,
        _LOGIN_ENDPOINT,
        _LOGIN_ENDPOINT,
        _DIRECTORY_ENDPOINT,
        _OBJECT_ENDPOINT_PREFIX + str(_ATTACK_OBJECT_ID),
        _OBJECT_ENDPOINT_PREFIX + str(_TARGET_OBJECT_ID),
        _OBJECT_ENDPOINT_PREFIX + str(_MISSING_OBJECT_ID),
        _OBJECT_ENDPOINT_PREFIX + str(_ATTACK_OBJECT_ID),
        _OBJECT_ENDPOINT_PREFIX + str(_TARGET_OBJECT_ID),
        _OBJECT_ENDPOINT_PREFIX + str(_MISSING_OBJECT_ID),
    ]
    assert [path for _, path, _, _ in observed] == expected_paths
    assert [evidence.path for evidence in network.evidence] == expected_paths
    login_payloads = [
        payload
        for method, path, payload, _ in observed
        if method == "POST" and path == _LOGIN_ENDPOINT
    ]
    assert len(login_payloads) == 4
    assert all(
        payload is not None and set(payload) == {"identity", "proof"} for payload in login_payloads
    )
    assert all(
        authorization == f"Bearer {_TOKEN}"
        for method, _, _, authorization in observed
        if method == "GET"
    )
    assert not any(
        path.startswith(("/rest/", "/api/")) or "/#/" in path for _, path, _, _ in observed
    )
    serialized_evidence = json.dumps(
        [item.model_dump(mode="json") for item in network.evidence],
        sort_keys=True,
    )
    assert _TOKEN not in serialized_evidence


@pytest.mark.asyncio
async def test_generic_recipe_engine_selector_mismatch_blocks_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_selector = "[data-fixture='missing-commit']"
    plan = _fixture_plan(submit_selector=missing_selector)
    browser, page, locators = _browser_harness(
        plan,
        submit_wait_error=TimeoutError("fixture selector was not found"),
    )
    monkeypatch.setattr(browser, "_dismiss_login_obstructions", AsyncMock())

    with pytest.raises(BrowserAssessmentError, match="login form did not become valid"):
        await browser._login(BrowserCredentials(username="fixture-user", password="fixture-proof"))

    locators[missing_selector].wait_for.assert_awaited_once()
    locators[missing_selector].click.assert_not_awaited()
    locators[_PASSWORD_SELECTOR].press.assert_not_awaited()
    page.expect_response.assert_not_called()


@pytest.mark.parametrize(
    ("token_path", "object_id_path"),
    [
        pytest.param("session.missing.value", "session.subject.cartId", id="token-path"),
        pytest.param("session.access.value", "session.subject.missing", id="object-id-path"),
    ],
)
@pytest.mark.asyncio
async def test_generic_recipe_engine_session_path_mismatch_does_not_promote(
    token_path: str,
    object_id_path: str,
) -> None:
    plan = _fixture_plan(token_path=token_path, object_id_path=object_id_path)
    observed: list[ObservedRequest] = []
    network = AssessmentNetwork(plan, transport=_diagnostic_transport(plan, observed))
    try:
        sql = await diagnose_sql_login(
            network=network,
            plan=plan,
            policy=assessment_policy(plan, max_requests=20),
        )
    finally:
        await network.close()

    assert sql.token is None
    assert sql.object_id is None
    assert sql.issue.status == "not-reproduced"
    assert [path for _, path, _, _ in observed] == [_LOGIN_ENDPOINT] * 4
    assert all(path != _DIRECTORY_ENDPOINT for _, path, _, _ in observed)


@pytest.mark.asyncio
async def test_generic_recipe_engine_blocks_undeclared_post_before_transport() -> None:
    plan = _fixture_plan()
    transport_called = False

    def unexpected_transport(_: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return _json_response(200, {})

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(unexpected_transport))
    network.begin_phase("path-mismatch", assessment_policy(plan, max_requests=1))
    try:
        with pytest.raises(AssessmentBoundaryError, match="unapproved-post-path"):
            await network.json_request(
                "POST",
                "/fixture/v2/session/not-declared",
                payload={"identity": "fixture-user", "proof": "fixture-proof"},
            )
    finally:
        await network.close()

    assert transport_called is False

    raw = plan.model_dump(mode="json")
    raw["route_ready_selectors"].pop("/ui/help")
    with pytest.raises(ValidationError, match="every navigation route"):
        WebAssessmentPlan.model_validate(raw)
