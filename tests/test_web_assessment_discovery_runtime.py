from __future__ import annotations

import asyncio
import gc
from collections.abc import Callable
from copy import deepcopy
from inspect import signature
from typing import Literal
from unittest.mock import AsyncMock, MagicMock

import pytest

from pajin.web_assessment.browser import BrowserCredentials
from pajin.web_assessment.discovery import (
    BrowserDiscoveryError,
    BrowserDiscoveryResult,
    DiscoveredBrowserRoute,
    browser_discovery_plan,
)
from pajin.web_assessment.discovery_runtime import (
    AuthenticatedBrowserDiscoverySession,
    BrowserDiscoveryRuntimeError,
    GovernedPlaywrightAuthenticatedDiscoverySession,
    PassiveDiscoveryRequestBoundaryError,
    PlaywrightAuthenticatedDiscoverySession,
    require_passive_discovery_request,
    run_authenticated_browser_discovery,
    run_governed_authenticated_browser_discovery,
    run_governed_authenticated_browser_discovery_with_evidence,
)
from pajin.web_assessment.models import WebAssessmentPlan
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import assessment_policy

_ORIGIN = "http://127.0.0.1:4317"


class _FakePage:
    def __init__(
        self,
        events: list[str],
        *,
        authenticated: Callable[[], bool],
        fail_on_evaluate: bool = False,
    ) -> None:
        self.events = events
        self.authenticated = authenticated
        self.fail_on_evaluate = fail_on_evaluate
        self._url = "about:blank"

    @property
    def url(self) -> str:
        return self._url

    async def goto(
        self,
        url: str,
        *,
        wait_until: Literal["domcontentloaded"],
        timeout: float,
    ) -> None:
        assert wait_until == "domcontentloaded"
        assert timeout > 0
        assert self.authenticated() is True
        self.events.append("discovery-goto")
        self._url = url

    async def wait_for_timeout(self, timeout: float) -> None:
        assert timeout >= 0
        self.events.append("discovery-wait")

    async def evaluate(self, expression: str, arg: object | None = None) -> object:
        assert expression
        assert arg is not None
        assert self.authenticated() is True
        self.events.append("discovery-evaluate")
        if self.fail_on_evaluate:
            raise RuntimeError("synthetic discovery failure")
        return deepcopy(
            {
                "links": [],
                "observed_link_count": 0,
                "forms": [],
                "observed_form_count": 0,
            }
        )


class _FakeSession:
    def __init__(
        self,
        events: list[str],
        *,
        expected_credentials: BrowserCredentials,
        fail_authentication: bool = False,
        fail_discovery: bool = False,
        authentication_requests: int = 0,
    ) -> None:
        self.events = events
        self.expected_credentials = expected_credentials
        self.fail_authentication = fail_authentication
        self.authentication_requests = authentication_requests
        self.authenticated = False
        self.network: AssessmentNetwork | None = None
        self.page = _FakePage(
            events,
            authenticated=lambda: self.authenticated,
            fail_on_evaluate=fail_discovery,
        )

    async def start(self) -> _FakePage:
        self.events.append("start")
        return self.page

    async def authenticate(self, credentials: BrowserCredentials) -> None:
        self.events.append("authenticate")
        assert credentials == self.expected_credentials
        if self.fail_authentication:
            raise RuntimeError("synthetic authentication failure")
        assert self.network is not None
        for _ in range(self.authentication_requests):
            reservation = await self.network.reserve("GET", _ORIGIN + "/authentication-resource")
            await self.network.complete(
                reservation,
                status=200,
                headers={"content-type": "application/json"},
                body=b"{}",
            )
        self.authenticated = True

    async def close(self) -> None:
        self.events.append("close")


class _FakeFactory:
    def __init__(self, session: AuthenticatedBrowserDiscoverySession) -> None:
        self.session = session
        self.calls = 0

    def __call__(
        self,
        *,
        plan: WebAssessmentPlan,
        network: AssessmentNetwork,
        headless: bool,
    ) -> AuthenticatedBrowserDiscoverySession:
        assert plan.origin == _ORIGIN
        assert network.plan.plan_digest == plan.plan_digest
        assert headless is True
        self.calls += 1
        if isinstance(self.session, _FakeSession):
            self.session.network = network
        return self.session


async def _run(
    session: _FakeSession,
    credentials: BrowserCredentials,
) -> BrowserDiscoveryResult:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    try:
        return await run_authenticated_browser_discovery(
            assessment_plan=plan,
            discovery_plan=browser_discovery_plan(
                _ORIGIN,
                limits={"max_routes": 1, "settle_milliseconds": 0},
            ),
            network=network,
            credentials=credentials,
            navigation_policy=assessment_policy(plan, max_requests=20),
            session_factory=_FakeFactory(session),
        )
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_runtime_authenticates_before_passive_discovery() -> None:
    events: list[str] = []
    credentials = BrowserCredentials(
        username="discovery-user@example.test",
        password="Discovery-Password!",
    )
    session = _FakeSession(events, expected_credentials=credentials)

    result = await _run(session, credentials)

    assert result.origin == _ORIGIN
    assert events.index("authenticate") < events.index("discovery-goto")
    assert events.index("authenticate") < events.index("discovery-evaluate")
    assert events[-1] == "close"
    assert session.network is not None
    assert session.network.phase == "browser-passive-discovery"
    assert session.network.policy is not None
    assert session.network.policy.allowed_methods == {"GET", "HEAD"}


def _discovery_login_harness(
    *,
    submit_actionable: bool,
    success_actionable: bool = True,
) -> tuple[
    PlaywrightAuthenticatedDiscoverySession,
    AssessmentNetwork,
    MagicMock,
    dict[str, MagicMock],
]:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = PlaywrightAuthenticatedDiscoverySession(plan=plan, network=network)
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

    locators[plan.login.submit_selector].is_enabled = AsyncMock(return_value=submit_actionable)
    success_activation_selector = plan.login.success_activation_selector
    assert success_activation_selector is not None
    locators[success_activation_selector].is_enabled = AsyncMock(return_value=success_actionable)
    page = MagicMock()
    page.goto = AsyncMock()
    page.locator.side_effect = locators.__getitem__
    page.keyboard.press = AsyncMock()
    response = MagicMock(status=200)
    response_value: asyncio.Future[MagicMock] = asyncio.get_running_loop().create_future()
    response_value.set_result(response)
    response_info = MagicMock(value=response_value)
    response_context = MagicMock()
    response_context.__aenter__ = AsyncMock(return_value=response_info)
    response_context.__aexit__ = AsyncMock(return_value=False)
    page.expect_response.return_value = response_context
    session._page = page
    return session, network, page, locators


@pytest.mark.asyncio
async def test_discovery_login_uses_shared_password_enter_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, network, page, locators = _discovery_login_harness(submit_actionable=True)
    dismiss = AsyncMock()
    prepare_passive = AsyncMock()
    monkeypatch.setattr(session, "_dismiss_login_obstructions", dismiss)
    monkeypatch.setattr(session, "_prepare_passive_discovery", prepare_passive)
    credentials = BrowserCredentials("discovery@example.test", "test-secret")
    try:
        await session.authenticate(credentials)
    finally:
        await network.close()

    submit = locators[session.plan.login.submit_selector]
    password = locators[session.plan.login.password_selector]
    submit.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=session.plan.request_timeout_seconds * 1_000,
    )
    submit.is_enabled.assert_awaited_once_with()
    submit.click.assert_not_awaited()
    password.press.assert_awaited_once_with(
        "Enter",
        timeout=session.plan.request_timeout_seconds * 1_000,
    )
    success_activation_selector = session.plan.login.success_activation_selector
    assert success_activation_selector is not None
    success_activation = locators[success_activation_selector]
    success_activation.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=session.plan.request_timeout_seconds * 1_000,
    )
    success_activation.is_enabled.assert_awaited_once_with()
    success_activation.press.assert_awaited_once_with(
        "Enter",
        timeout=session.plan.request_timeout_seconds * 1_000,
    )
    success_activation.click.assert_not_awaited()
    page.expect_response.assert_called_once()
    assert session._request_mode == "passive-discovery"
    prepare_passive.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_discovery_login_rejects_unactionable_submit_before_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, network, page, locators = _discovery_login_harness(submit_actionable=False)
    dismiss = AsyncMock()
    monkeypatch.setattr(session, "_dismiss_login_obstructions", dismiss)
    monotonic = MagicMock(side_effect=(0.0, 13.0))
    monkeypatch.setattr("pajin.web_assessment.login_activation.monotonic", monotonic)
    credentials = BrowserCredentials("discovery@example.test", "test-secret")
    try:
        with pytest.raises(BrowserDiscoveryRuntimeError, match="did not become valid"):
            await session.authenticate(credentials)
    finally:
        await network.close()

    submit = locators[session.plan.login.submit_selector]
    password = locators[session.plan.login.password_selector]
    submit.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=session.plan.request_timeout_seconds * 1_000,
    )
    submit.is_enabled.assert_awaited_once_with()
    submit.click.assert_not_awaited()
    password.press.assert_not_awaited()
    page.expect_response.assert_not_called()
    assert session._request_mode == "authentication"


@pytest.mark.asyncio
async def test_discovery_login_rejects_unactionable_success_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, network, page, locators = _discovery_login_harness(
        submit_actionable=True,
        success_actionable=False,
    )
    dismiss = AsyncMock()
    prepare_passive = AsyncMock()
    monkeypatch.setattr(session, "_dismiss_login_obstructions", dismiss)
    monkeypatch.setattr(session, "_prepare_passive_discovery", prepare_passive)
    monotonic = MagicMock(side_effect=(0.0, 0.0, 13.0))
    monkeypatch.setattr("pajin.web_assessment.login_activation.monotonic", monotonic)
    credentials = BrowserCredentials("discovery@example.test", "test-secret")
    try:
        with pytest.raises(
            BrowserDiscoveryRuntimeError,
            match="login success activation failed",
        ):
            await session.authenticate(credentials)
    finally:
        await network.close()

    password = locators[session.plan.login.password_selector]
    password.press.assert_awaited_once_with(
        "Enter",
        timeout=session.plan.request_timeout_seconds * 1_000,
    )
    success_activation_selector = session.plan.login.success_activation_selector
    assert success_activation_selector is not None
    success_activation = locators[success_activation_selector]
    success_activation.wait_for.assert_awaited_once_with(
        state="visible",
        timeout=session.plan.request_timeout_seconds * 1_000,
    )
    success_activation.is_enabled.assert_awaited_once_with()
    success_activation.press.assert_not_awaited()
    success_activation.click.assert_not_awaited()
    locators[session.plan.login.success_selector].wait_for.assert_not_awaited()
    page.keyboard.press.assert_not_awaited()
    prepare_passive.assert_not_awaited()
    assert session._request_mode == "passive-discovery"


@pytest.mark.asyncio
async def test_runtime_does_not_discover_after_authentication_failure() -> None:
    events: list[str] = []
    credentials = BrowserCredentials("failed@example.test", "Failed-Password!")
    session = _FakeSession(
        events,
        expected_credentials=credentials,
        fail_authentication=True,
    )

    with pytest.raises(RuntimeError, match="synthetic authentication failure"):
        await _run(session, credentials)

    assert events == ["start", "authenticate", "close"]


@pytest.mark.asyncio
async def test_runtime_closes_session_when_discovery_fails() -> None:
    events: list[str] = []
    credentials = BrowserCredentials("close@example.test", "Close-Password!")
    session = _FakeSession(
        events,
        expected_credentials=credentials,
        fail_discovery=True,
    )

    with pytest.raises(BrowserDiscoveryError, match="invalid structural snapshot"):
        await _run(session, credentials)

    assert events[-1] == "close"
    assert events.count("close") == 1


@pytest.mark.asyncio
async def test_runtime_result_retains_no_credentials_or_browser_capture() -> None:
    events: list[str] = []
    credentials = BrowserCredentials(
        "unique-retention-user@example.test",
        "Unique-Retention-Password!",
    )
    session = _FakeSession(events, expected_credentials=credentials)

    result = await _run(session, credentials)
    serialized = result.model_dump_json()

    assert credentials.username not in serialized
    assert credentials.password not in serialized
    assert result.raw_dom_retained is False
    assert result.screenshots_retained is False
    assert result.form_values_retained is False
    assert result.forms_submitted is False


@pytest.mark.asyncio
async def test_runtime_rejects_discovery_origin_drift_before_session_creation() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    credentials = BrowserCredentials("drift@example.test", "Drift-Password!")
    events: list[str] = []
    session = _FakeSession(events, expected_credentials=credentials)
    factory = _FakeFactory(session)
    try:
        with pytest.raises(BrowserDiscoveryRuntimeError, match="assessment origin"):
            await run_authenticated_browser_discovery(
                assessment_plan=plan,
                discovery_plan=browser_discovery_plan("http://127.0.0.1:4318"),
                network=network,
                credentials=credentials,
                navigation_policy=assessment_policy(plan, max_requests=20),
                session_factory=factory,
            )
    finally:
        await network.close()

    assert factory.calls == 0
    assert events == []


@pytest.mark.asyncio
async def test_runtime_preserves_total_request_budget_across_authentication_and_discovery() -> None:
    events: list[str] = []
    credentials = BrowserCredentials("budget@example.test", "Budget-Password!")
    session = _FakeSession(
        events,
        expected_credentials=credentials,
        authentication_requests=3,
    )

    await _run(session, credentials)

    assert session.network is not None
    assert session.network.policy is not None
    assert session.network.policy.allowed_methods == {"GET", "HEAD"}
    assert session.network.policy.max_requests == 17


@pytest.mark.asyncio
async def test_governed_runtime_uses_get_only_without_resetting_total_request_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    credentials = BrowserCredentials("governed@example.test", "Governed-Password!")
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    authenticated = False
    page = _FakePage(events, authenticated=lambda: authenticated)

    async def start(_session: GovernedPlaywrightAuthenticatedDiscoverySession) -> _FakePage:
        events.append("start")
        return page

    async def authenticate(
        session: GovernedPlaywrightAuthenticatedDiscoverySession,
        actual_credentials: BrowserCredentials,
    ) -> None:
        nonlocal authenticated
        events.append("authenticate")
        assert actual_credentials == credentials
        for _ in range(3):
            reservation = await session.network.reserve("GET", _ORIGIN + "/authentication-resource")
            await session.network.complete(
                reservation,
                status=200,
                headers={"content-type": "application/json"},
                body=b"{}",
            )
        authenticated = True

    async def close(_session: GovernedPlaywrightAuthenticatedDiscoverySession) -> None:
        events.append("close")

    monkeypatch.setattr(GovernedPlaywrightAuthenticatedDiscoverySession, "start", start)
    monkeypatch.setattr(
        GovernedPlaywrightAuthenticatedDiscoverySession, "authenticate", authenticate
    )
    monkeypatch.setattr(GovernedPlaywrightAuthenticatedDiscoverySession, "close", close)
    try:
        await run_governed_authenticated_browser_discovery(
            assessment_plan=plan,
            discovery_plan=browser_discovery_plan(
                _ORIGIN,
                limits={"max_routes": 1, "settle_milliseconds": 0},
            ),
            network=network,
            credentials=credentials,
            navigation_policy=assessment_policy(plan, max_requests=20),
        )
    finally:
        await network.close()

    assert network.policy is not None
    assert network.policy.allowed_methods == {"GET"}
    assert network.policy.max_requests == 17
    assert network.total_requests == 3
    assert events[-1] == "close"


def test_governed_runtime_does_not_expose_a_replaceable_session_factory() -> None:
    assert (
        "session_factory" not in signature(run_governed_authenticated_browser_discovery).parameters
    )


@pytest.mark.asyncio
async def test_governed_runtime_rejects_replaceable_network_implementation() -> None:
    class _DerivedAssessmentNetwork(AssessmentNetwork):
        pass

    plan = juice_shop_plan(_ORIGIN)
    network = _DerivedAssessmentNetwork(plan)
    try:
        with pytest.raises(BrowserDiscoveryRuntimeError, match="code-owned assessment network"):
            await run_governed_authenticated_browser_discovery(
                assessment_plan=plan,
                discovery_plan=browser_discovery_plan(_ORIGIN),
                network=network,
                credentials=BrowserCredentials("network@example.test", "Network-Password!"),
                navigation_policy=assessment_policy(plan, max_requests=20),
            )
    finally:
        await network.close()


class _SyntheticRequest:
    def __init__(
        self,
        method: str,
        url: str,
        *,
        content: bytes | None = None,
        redirected: bool = False,
        response_body_size: int = 2_048,
    ) -> None:
        self.method = method
        self.url = url
        self.redirected_from = object() if redirected else None
        self.post_data_buffer = b"{}" if method == "POST" and content is None else content
        self.response_body_size = response_body_size

    async def sizes(self) -> dict[str, int]:
        return {
            "requestBodySize": len(self.post_data_buffer or b""),
            "requestHeadersSize": 0,
            "responseBodySize": self.response_body_size,
            "responseHeadersSize": 0,
        }


class _SyntheticRoute:
    def __init__(self) -> None:
        self.aborted_with: str | None = None
        self.continued = False

    async def abort(self, error_code: str) -> None:
        self.aborted_with = error_code

    async def continue_(self) -> None:
        self.continued = True


class _SyntheticResponse:
    def __init__(
        self,
        request: _SyntheticRequest,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.request = request
        self.url = request.url
        self.status = status
        self._headers = headers or {"content-type": "application/octet-stream"}
        self.body_calls = 0
        self.finished_calls = 0

    async def finished(self) -> None:
        self.finished_calls += 1
        return None

    async def header_value(self, name: str) -> str | None:
        return self._headers.get(name.lower())

    async def body(self) -> bytes:
        self.body_calls += 1
        raise AssertionError("passive discovery must not collect response bodies")


@pytest.mark.parametrize("request_mode", ("authentication", "passive-discovery"))
@pytest.mark.asyncio
async def test_request_gate_rejects_synthetic_account_creation_post(
    request_mode: Literal["authentication", "passive-discovery"],
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = PlaywrightAuthenticatedDiscoverySession(
        plan=plan,
        network=network,
    )
    request = _SyntheticRequest("POST", _ORIGIN + "/api/Users/")
    route = _SyntheticRoute()
    try:
        network.begin_phase("browser-passive-discovery", assessment_policy(plan, max_requests=20))
        session._request_mode = request_mode

        await session._gate_route(route, request)  # type: ignore[arg-type]

        assert route.aborted_with == "blockedbyclient"
        assert route.continued is False
        assert network.phase_requests == 0
        assert network.blocked == {"unapproved-method": 1}

        get_request = _SyntheticRequest("GET", _ORIGIN + "/assets/about.js")
        get_route = _SyntheticRoute()
        await session._gate_route(get_route, get_request)  # type: ignore[arg-type]
        assert get_route.aborted_with is None
        assert get_route.continued is True
        assert network.phase_requests == 1
        reservation = session._reservations.pop(id(get_request))
        await network.fail(reservation, reason="synthetic-control-completed")
    finally:
        await network.close()


@pytest.mark.parametrize(
    ("method", "url", "content", "redirected", "reason"),
    (
        ("HEAD", _ORIGIN + "/assets/about.js", None, False, "unapproved-method"),
        ("POST", _ORIGIN + "/rest/user/login", b"{}", False, "unapproved-method"),
        ("GET", _ORIGIN + "/assets/about.js?v=1", None, False, "query-values"),
        ("GET", _ORIGIN + "/assets/about.js?", None, False, "query-values"),
        ("GET", _ORIGIN + "/assets/about.js", b"payload", False, "request-body-disabled"),
        (
            "GET",
            "http://127.0.0.1:4318/assets/about.js",
            None,
            False,
            "outside-approved-origin",
        ),
        ("GET", "http://[::1", None, False, "invalid-url"),
        ("GET", _ORIGIN + "/assets/about.js", None, True, "redirect-disabled"),
        (
            "GET",
            _ORIGIN + "/profiles/alice%40example.test",
            None,
            False,
            "value-bearing-path",
        ),
        (
            "GET",
            _ORIGIN + "/objects/550e8400-e29b-41d4-a716-446655440000",
            None,
            False,
            "value-bearing-path",
        ),
        ("GET", _ORIGIN + "/orders/history", None, False, "sensitive-path"),
    ),
)
def test_authoritative_passive_request_boundary_rejects_non_get_or_unsafe_requests(
    method: str,
    url: str,
    content: bytes | None,
    redirected: bool,
    reason: str,
) -> None:
    with pytest.raises(PassiveDiscoveryRequestBoundaryError, match=f"^{reason}$"):
        require_passive_discovery_request(
            origin=_ORIGIN,
            method=method,
            url=url,
            content=content,
            redirected=redirected,
        )


def test_authoritative_passive_request_boundary_accepts_exact_origin_bodyless_get() -> None:
    require_passive_discovery_request(
        origin=_ORIGIN,
        method="get",
        url=_ORIGIN + "/assets/about.js",
        content=b"",
        redirected=False,
    )


@pytest.mark.parametrize(
    ("browser_request", "reason"),
    (
        (_SyntheticRequest("HEAD", _ORIGIN + "/head"), "unapproved-method"),
        (_SyntheticRequest("POST", _ORIGIN + "/rest/user/login"), "unapproved-method"),
        (_SyntheticRequest("GET", _ORIGIN + "/asset.js?v=1"), "query-values"),
        (
            _SyntheticRequest("GET", _ORIGIN + "/asset.js", content=b"payload"),
            "request-body-disabled",
        ),
        (
            _SyntheticRequest("GET", "http://127.0.0.1:4318/asset.js"),
            "outside-approved-origin",
        ),
        (_SyntheticRequest("GET", "http://[::1"), "invalid-url"),
        (
            _SyntheticRequest("GET", _ORIGIN + "/asset.js", redirected=True),
            "redirect-disabled",
        ),
        (
            _SyntheticRequest(
                "GET",
                _ORIGIN + "/sessions/Az7kLm4Np9Qr2St5Uv8Wx1Yb3Cd6Ef0G",
            ),
            "value-bearing-path",
        ),
        (
            _SyntheticRequest("GET", _ORIGIN + "/orders/history"),
            "sensitive-path",
        ),
    ),
)
@pytest.mark.asyncio
async def test_passive_browser_gate_aborts_forbidden_request_before_reservation(
    browser_request: _SyntheticRequest,
    reason: str,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = GovernedPlaywrightAuthenticatedDiscoverySession(plan=plan, network=network)
    route = _SyntheticRoute()
    try:
        network.begin_phase("browser-passive-discovery", assessment_policy(plan, max_requests=20))
        session._request_mode = "passive-discovery"

        await session._gate_route(route, browser_request)  # type: ignore[arg-type]

        assert route.aborted_with == "blockedbyclient"
        assert route.continued is False
        assert network.phase_requests == 0
        assert network.total_requests == 0
        assert network.blocked == {reason: 1}
        assert session._reservations == {}
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_passive_browser_gate_reserves_exact_origin_bodyless_get() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = GovernedPlaywrightAuthenticatedDiscoverySession(plan=plan, network=network)
    request = _SyntheticRequest("GET", _ORIGIN + "/asset.js", content=b"")
    route = _SyntheticRoute()
    try:
        network.begin_phase("browser-passive-discovery", assessment_policy(plan, max_requests=20))
        session._request_mode = "passive-discovery"

        await session._gate_route(route, request)  # type: ignore[arg-type]

        assert route.aborted_with is None
        assert route.continued is True
        assert network.phase_requests == 1
        assert network.total_requests == 1
        reservation = session._reservations.pop(id(request))
        assert reservation.method == "GET"
        assert reservation.url == request.url
        await network.fail(reservation, reason="synthetic-control-completed")
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_passive_browser_gate_preserves_monotonic_total_request_ceiling() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, total_request_ceiling=1)
    session = GovernedPlaywrightAuthenticatedDiscoverySession(plan=plan, network=network)
    request = _SyntheticRequest("GET", _ORIGIN + "/asset.js", content=b"")
    route = _SyntheticRoute()
    try:
        policy = assessment_policy(plan, max_requests=20)
        network.begin_phase("browser-authentication", policy)
        authentication = await network.reserve("GET", _ORIGIN + "/authentication-resource")
        await network.complete(
            authentication,
            status=200,
            headers={"content-type": "application/json"},
            body=b"{}",
        )
        network.begin_phase("browser-passive-discovery", policy)
        session._request_mode = "passive-discovery"

        await session._gate_route(route, request)  # type: ignore[arg-type]

        assert route.aborted_with == "blockedbyclient"
        assert route.continued is False
        assert network.phase_requests == 0
        assert network.total_requests == 1
        assert network.blocked == {"total-request-budget": 1}
        assert session._reservations == {}
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_login_phase_settles_outstanding_response_before_passive_transition() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = PlaywrightAuthenticatedDiscoverySession(
        plan=plan,
        network=network,
    )
    events: list[str] = []
    session._page = _FakePage(events, authenticated=lambda: True)  # type: ignore[assignment]
    request = _SyntheticRequest("GET", _ORIGIN + "/authentication-resource")
    response = _SyntheticResponse(request)
    try:
        network.begin_phase("browser-authentication", assessment_policy(plan, max_requests=20))
        reservation = await network.reserve(request.method, request.url)
        session._reservations[id(request)] = reservation
        session._schedule(session._record_response(response))  # type: ignore[arg-type]

        await session._prepare_passive_discovery()

        assert session._request_mode == "passive-discovery"
        assert session._reservations == {}
        assert session._background_tasks == set()
        assert response.body_calls == 0
        assert response.finished_calls == 0
        assert len(network.evidence) == 1
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_response_metadata_is_recorded_without_collecting_compressed_body() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = PlaywrightAuthenticatedDiscoverySession(
        plan=plan,
        network=network,
    )
    request = _SyntheticRequest("GET", _ORIGIN + "/compressed.js")
    response = _SyntheticResponse(
        request,
        headers={
            "content-encoding": "gzip",
            "content-type": "application/javascript",
        },
    )
    try:
        network.begin_phase("browser-passive-discovery", assessment_policy(plan, max_requests=20))
        reservation = await network.reserve(request.method, request.url)
        session._reservations[id(request)] = reservation

        await session._record_response(response)  # type: ignore[arg-type]

        assert response.body_calls == 0
        assert response.finished_calls == 0
        assert session._background_failed is False
        assert len(network.evidence) == 1
        evidence = network.evidence[0]
        assert evidence.status == 200
        assert evidence.media_type == "application/javascript"
        assert evidence.response_bytes == 0
        assert session._observed_response_bytes == 2_048
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_governed_response_collector_is_ordered_and_available_only_after_close() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = GovernedPlaywrightAuthenticatedDiscoverySession(plan=plan, network=network)
    first_request = _SyntheticRequest(
        "GET",
        _ORIGIN + "/first.js",
        response_body_size=1_024,
    )
    second_request = _SyntheticRequest(
        "GET",
        _ORIGIN + "/second.js",
        response_body_size=2_048,
    )
    first_response = _SyntheticResponse(
        first_request,
        headers={"content-type": "application/javascript; charset=utf-8"},
    )
    second_response = _SyntheticResponse(
        second_request,
        headers={"content-type": "text/css; charset=utf-8"},
    )
    try:
        network.begin_phase("browser-passive-discovery", assessment_policy(plan, max_requests=20))
        first = await network.reserve(first_request.method, first_request.url)
        second = await network.reserve(second_request.method, second_request.url)
        session._reservations[id(first_request)] = first
        session._reservations[id(second_request)] = second

        await session._record_response(second_response)  # type: ignore[arg-type]
        await session._record_response(first_response)  # type: ignore[arg-type]

        with pytest.raises(BrowserDiscoveryRuntimeError, match="before browser closure"):
            session.passive_metadata_completions()
        await session.close()
        completions = session.passive_metadata_completions()

        assert tuple(item.evidence.evidence_id for item in completions) == (
            first.evidence_id,
            second.evidence_id,
        )
        assert tuple(item.boundary_receipt.evidence_id for item in completions) == (
            first.evidence_id,
            second.evidence_id,
        )
        assert tuple(item.evidence.media_type for item in completions) == (
            "application/javascript",
            "text/css",
        )
        assert tuple(
            item.boundary_receipt.observed_response_body_bytes for item in completions
        ) == (1_024, 2_048)
        assert all(item.evidence.response_bytes == 0 for item in completions)
        assert network.total_bytes == 3_072
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_governed_evidence_api_returns_after_close_with_exact_network_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    discovery_plan = browser_discovery_plan(
        _ORIGIN,
        limits={"max_routes": 1, "settle_milliseconds": 0},
    )
    network = AssessmentNetwork(plan)
    captured: list[GovernedPlaywrightAuthenticatedDiscoverySession] = []

    async def start(session: GovernedPlaywrightAuthenticatedDiscoverySession) -> _FakePage:
        captured.append(session)
        return _FakePage([], authenticated=lambda: True)

    async def authenticate(
        _session: GovernedPlaywrightAuthenticatedDiscoverySession,
        _credentials: BrowserCredentials,
    ) -> None:
        return None

    async def discover(
        _page: _FakePage,
        *,
        plan: object,
    ) -> BrowserDiscoveryResult:
        assert plan == discovery_plan
        session = captured[0]
        first_request = _SyntheticRequest("GET", _ORIGIN + "/first.js")
        second_request = _SyntheticRequest("GET", _ORIGIN + "/second.css")
        first = await network.reserve(first_request.method, first_request.url)
        second = await network.reserve(second_request.method, second_request.url)
        session._reservations[id(first_request)] = first
        session._reservations[id(second_request)] = second
        await session._record_response(_SyntheticResponse(second_request))  # type: ignore[arg-type]
        await session._record_response(_SyntheticResponse(first_request))  # type: ignore[arg-type]
        return BrowserDiscoveryResult(
            plan_digest=discovery_plan.plan_digest,
            origin=discovery_plan.origin,
            routes=(
                DiscoveredBrowserRoute(
                    route=discovery_plan.seed_routes[0],
                    depth=0,
                    source="seed",
                ),
            ),
            route_limit_reached=False,
            form_limit_reached=False,
            field_limit_reached=False,
        )

    monkeypatch.setattr(GovernedPlaywrightAuthenticatedDiscoverySession, "start", start)
    monkeypatch.setattr(
        GovernedPlaywrightAuthenticatedDiscoverySession,
        "authenticate",
        authenticate,
    )
    monkeypatch.setattr(
        "pajin.web_assessment.discovery_runtime.discover_browser_routes_and_forms",
        discover,
    )
    try:
        observation = await run_governed_authenticated_browser_discovery_with_evidence(
            assessment_plan=plan,
            discovery_plan=discovery_plan,
            network=network,
            credentials=BrowserCredentials("evidence@example.test", "Evidence-Password!"),
            navigation_policy=assessment_policy(plan, max_requests=20),
        )
    finally:
        await network.close()

    assert observation.browser_closed is True
    assert captured[0]._closed_cleanly is True
    assert tuple(item.path for item in observation.request_evidence) == (
        "/first.js",
        "/second.css",
    )
    assert tuple(item.evidence_id for item in observation.boundary_receipts) == tuple(
        item.evidence_id for item in observation.request_evidence
    )


@pytest.mark.asyncio
async def test_oversized_response_is_rejected_from_size_metadata_without_body_collection() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = PlaywrightAuthenticatedDiscoverySession(
        plan=plan,
        network=network,
    )
    request = _SyntheticRequest(
        "GET",
        _ORIGIN + "/oversized.bin",
        response_body_size=plan.max_response_bytes + 1,
    )
    response = _SyntheticResponse(request)
    try:
        network.begin_phase("browser-passive-discovery", assessment_policy(plan, max_requests=20))
        reservation = await network.reserve(request.method, request.url)
        session._reservations[id(request)] = reservation

        await session._record_response(response)  # type: ignore[arg-type]

        assert response.body_calls == 0
        assert response.finished_calls == 0
        assert session._background_failed is True
        assert network.evidence == []
        assert network.failures == {"response-byte-limit": 1}
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_background_task_exception_is_retrieved_before_task_is_discarded() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = PlaywrightAuthenticatedDiscoverySession(plan=plan, network=network)
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    reported: list[dict[str, object]] = []
    loop.set_exception_handler(lambda _loop, context: reported.append(context))

    async def fail_in_background() -> None:
        await asyncio.sleep(0)
        raise RuntimeError("synthetic unhandled task error")

    try:
        session._schedule(fail_in_background())
        while session._background_tasks:
            await asyncio.sleep(0)
        gc.collect()
        await asyncio.sleep(0)

        assert session._background_failed is True
        assert session._background_tasks == set()
        assert reported == []
    finally:
        loop.set_exception_handler(previous_handler)
        await network.close()


class _TargetClosedDuringSizesRequest(_SyntheticRequest):
    def __init__(self, method: str, url: str) -> None:
        super().__init__(method, url)
        self.sizes_started = asyncio.Event()

    async def sizes(self) -> dict[str, int]:
        self.sizes_started.set()
        try:
            await asyncio.Future[None]()
        except asyncio.CancelledError as exc:
            raise RuntimeError("Target closed") from exc
        raise AssertionError("synthetic transfer unexpectedly completed")


@pytest.mark.asyncio
async def test_browser_close_race_is_warning_free_and_fail_closed() -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan)
    session = PlaywrightAuthenticatedDiscoverySession(plan=plan, network=network)
    request = _TargetClosedDuringSizesRequest("GET", _ORIGIN + "/closing.js")
    response = _SyntheticResponse(request)
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    reported: list[dict[str, object]] = []
    loop.set_exception_handler(lambda _loop, context: reported.append(context))
    try:
        network.begin_phase("browser-passive-discovery", assessment_policy(plan, max_requests=20))
        reservation = await network.reserve(request.method, request.url)
        session._reservations[id(request)] = reservation
        session._schedule(session._record_response(response))  # type: ignore[arg-type]
        await request.sizes_started.wait()

        with pytest.raises(BrowserDiscoveryRuntimeError, match="did not close cleanly"):
            await session.close()

        gc.collect()
        await asyncio.sleep(0)
        assert response.finished_calls == 0
        assert session._background_tasks == set()
        assert network.failures == {"browser-response-capture-failure": 1}
        assert reported == []
    finally:
        loop.set_exception_handler(previous_handler)
        await network.close()
