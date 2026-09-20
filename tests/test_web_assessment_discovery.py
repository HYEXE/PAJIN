from __future__ import annotations

from copy import deepcopy
from typing import Literal

import pytest
from pydantic import ValidationError

from pajin.web_assessment.discovery import (
    BrowserDiscoveryBoundaryError,
    BrowserDiscoveryError,
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    browser_discovery_plan,
    discover_browser_routes_and_forms,
)

_ORIGIN = "http://127.0.0.1:4317"


def _control(
    ordinal: int,
    *,
    tag: str = "input",
    control_type: str = "text",
    name: str | None = None,
    autocomplete: str = "",
    required: bool = False,
) -> dict[str, object]:
    return {
        "ordinal": ordinal,
        "tag": tag,
        "control_type": control_type,
        "name": name,
        "name_truncated": False,
        "autocomplete": autocomplete,
        "required": required,
        "disabled": False,
        "read_only": False,
        "multiple": False,
    }


def _form(
    ordinal: int,
    *,
    action: str,
    method: str = "post",
    controls: list[dict[str, object]] | None = None,
    observed_control_count: int | None = None,
    action_truncated: bool = False,
) -> dict[str, object]:
    retained_controls = controls or []
    return {
        "document_ordinal": ordinal,
        "action": action,
        "action_truncated": action_truncated,
        "method": method,
        "encoding": "application/x-www-form-urlencoded",
        "controls": retained_controls,
        "observed_control_count": (
            len(retained_controls) if observed_control_count is None else observed_control_count
        ),
    }


def _snapshot(
    *,
    links: list[tuple[Literal["anchor", "area"], str]] | None = None,
    forms: list[dict[str, object]] | None = None,
    observed_link_count: int | None = None,
    observed_form_count: int | None = None,
) -> dict[str, object]:
    retained_links = links or []
    retained_forms = forms or []
    return {
        "links": [
            {"kind": kind, "href": href, "href_truncated": False} for kind, href in retained_links
        ],
        "observed_link_count": (
            len(retained_links) if observed_link_count is None else observed_link_count
        ),
        "forms": retained_forms,
        "observed_form_count": (
            len(retained_forms) if observed_form_count is None else observed_form_count
        ),
    }


class _FakePage:
    def __init__(
        self,
        snapshots: dict[str, object],
        *,
        redirects: dict[str, str] | None = None,
        sentinel_attached_by_url: dict[str, bool] | None = None,
    ) -> None:
        self._snapshots = snapshots
        self._redirects = redirects or {}
        self._sentinel_attached_by_url = sentinel_attached_by_url or {}
        self._url = "about:blank"
        self.goto_calls: list[str] = []
        self.wait_calls: list[float] = []
        self.evaluate_calls: list[tuple[str, object | None]] = []
        self.locator_calls: list[str] = []
        self.events: list[tuple[str, str]] = []
        self.keyboard = _FakeKeyboard(self)

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
        self.goto_calls.append(url)
        self._url = self._redirects.get(url, url)
        self.events.append(("goto", self._url))

    async def wait_for_timeout(self, timeout: float) -> None:
        self.wait_calls.append(timeout)

    async def evaluate(self, expression: str, arg: object | None = None) -> object:
        self.evaluate_calls.append((expression, deepcopy(arg)))
        self.events.append(("snapshot", self.url))
        return deepcopy(self._snapshots[self.url])

    def locator(self, selector: str) -> _FakeLocator:
        self.locator_calls.append(selector)
        return _FakeLocator(self, selector)


class _FakeLocator:
    def __init__(self, page: _FakePage, selector: str) -> None:
        self._page = page
        self._selector = selector

    async def wait_for(
        self,
        *,
        state: Literal["attached", "visible"],
        timeout: float,
    ) -> None:
        assert timeout > 0
        event = "sentinel" if state == "attached" else "activation-ready"
        self._page.events.append((event, self._page.url))
        if state == "attached" and not self._page._sentinel_attached_by_url.get(
            self._page.url, True
        ):
            raise RuntimeError("synthetic authentication loss")

    async def click(self, *, timeout: float) -> None:
        assert timeout > 0
        self._page.events.append(("activation-click", self._page.url))

    async def press(self, key: str, *, timeout: float) -> None:
        assert key == "Enter"
        assert timeout > 0
        self._page.events.append(("activation-enter", self._page.url))


class _FakeKeyboard:
    def __init__(self, page: _FakePage) -> None:
        self._page = page

    async def press(self, key: Literal["Escape"]) -> None:
        assert key == "Escape"
        self._page.events.append(("escape", self._page.url))


@pytest.mark.parametrize(
    "origin",
    (
        "http://localhost:4317",
        "http://127.0.0.2:4317",
        "http://user:redacted@127.0.0.1:4317",
        "http://127.0.0.1:4317/path",
        "http://127.0.0.1:4317/?key=redacted",
        "http://127.0.0.1:0",
    ),
)
def test_plan_requires_an_exact_numeric_loopback_origin(origin: str) -> None:
    with pytest.raises(ValidationError, match="exact numeric loopback"):
        browser_discovery_plan(origin)


@pytest.mark.parametrize(
    "seed_route",
    (
        "relative",
        "//127.0.0.1:4317/path",
        "http://127.0.0.1:4317/path",
        "/find?term=redacted",
        "/empty?",
        "/path;session=redacted",
        "/path%3Bsession%3Dredacted",
        "/admin",
        "/myAccount/profile",
        "/basket",
        "/orders/current",
        "/logout",
        "/password/reset",
        "/catalog/123",
        "/a/../b",
        "/%ZZ",
        "/café",
    ),
)
def test_plan_rejects_noncanonical_or_sensitive_seed_routes(seed_route: str) -> None:
    with pytest.raises(ValidationError, match="unsafe or noncanonical"):
        browser_discovery_plan(_ORIGIN, seed_routes=(seed_route,))


def test_plan_is_versioned_sorted_bounded_and_digest_bound() -> None:
    plan = browser_discovery_plan(
        _ORIGIN,
        seed_routes=("/", "/login"),
        limits={"max_routes": 7, "max_depth": 1},
    )

    assert plan.api_version == "pajin.dev/local-web-browser-discovery/v1alpha1"
    assert len(plan.plan_digest) == 64

    tampered = plan.model_dump(mode="json")
    tampered["max_routes"] = 8
    with pytest.raises(ValidationError, match="Plan Digest differs"):
        BrowserDiscoveryPlan.model_validate(tampered)

    with pytest.raises(ValidationError, match="unique and sorted"):
        browser_discovery_plan(_ORIGIN, seed_routes=("/login", "/"))
    with pytest.raises(ValidationError):
        browser_discovery_plan(_ORIGIN, limits={"max_routes": 31})
    with pytest.raises(ValueError, match="unknown browser discovery limit"):
        browser_discovery_plan(_ORIGIN, limits={"unexpected": 1})


def test_plan_binds_optional_authentication_sentinel_with_serialized_alias() -> None:
    plan = browser_discovery_plan(
        _ORIGIN,
        authentication_sentinel_selector="#authenticated-session",
    )

    assert plan.authentication_sentinel_selector == "#authenticated-session"
    assert plan.model_dump(mode="json", by_alias=True)["authenticationSentinelSelector"] == (
        "#authenticated-session"
    )

    tampered = plan.model_dump(mode="json", by_alias=True)
    tampered["authenticationSentinelSelector"] = "#different-session"
    with pytest.raises(ValidationError, match="Plan Digest differs"):
        BrowserDiscoveryPlan.model_validate(tampered)

    generic = browser_discovery_plan(_ORIGIN)
    assert generic.authentication_sentinel_selector is None


def test_plan_binds_optional_sentinel_activation_and_rejects_orphans() -> None:
    plan = browser_discovery_plan(
        _ORIGIN,
        authentication_sentinel_selector="#logout",
        authentication_sentinel_activation_selector="#account-menu",
        authentication_sentinel_activation_mode="enter",
    )

    serialized = plan.model_dump(mode="json", by_alias=True)
    assert serialized["authenticationSentinelActivationSelector"] == "#account-menu"
    assert serialized["authenticationSentinelActivationMode"] == "enter"

    with pytest.raises(ValidationError, match="activation requires a sentinel"):
        BrowserDiscoveryPlan(
            origin=_ORIGIN,
            authenticationSentinelActivationSelector="#account-menu",
        )
    with pytest.raises(ValidationError, match="activation mode requires a selector"):
        BrowserDiscoveryPlan(
            origin=_ORIGIN,
            authenticationSentinelSelector="#logout",
            authenticationSentinelActivationMode="enter",
        )


@pytest.mark.asyncio
async def test_discovery_is_deterministic_passive_same_origin_bfs() -> None:
    root_form = _form(
        0,
        action="/login",
        controls=[
            _control(
                0,
                control_type="email",
                name="username",
                autocomplete="username",
                required=True,
            ),
            _control(
                1,
                control_type="password",
                name="password",
                autocomplete="current-password",
                required=True,
            ),
            _control(2, tag="button", control_type="submit"),
        ],
    )
    root_snapshot = _snapshot(
        links=[
            ("anchor", "/public-b"),
            ("anchor", "/public-a"),
            ("area", "/map"),
            ("anchor", "/#/spa"),
            ("anchor", "https://example.test/out"),
            ("anchor", "javascript:alert(1)"),
            ("anchor", "/find?term=redacted"),
            ("anchor", "/empty?"),
            ("anchor", "/admin"),
            ("anchor", "/myAccount/profile"),
            ("anchor", "/basket"),
            ("anchor", "/orders/summary"),
            ("anchor", "/logout"),
            ("anchor", "/password/reset"),
            ("anchor", "/catalog/42"),
            ("anchor", "http://user:redacted@127.0.0.1:4317/private"),
            ("anchor", ""),
            ("anchor", "//127.0.0.1:4317/ambiguous"),
            ("anchor", "/a/../b"),
        ],
        forms=[root_form],
    )
    snapshots: dict[str, object] = {
        _ORIGIN + "/": root_snapshot,
        _ORIGIN + "/#/spa": _snapshot(),
        _ORIGIN + "/map": _snapshot(),
        _ORIGIN + "/public-a": _snapshot(links=[("anchor", "/deep")]),
        _ORIGIN + "/public-b": _snapshot(),
    }
    plan = browser_discovery_plan(_ORIGIN, limits={"max_depth": 1})

    first_page = _FakePage(snapshots)
    second_page = _FakePage(snapshots)
    first = await discover_browser_routes_and_forms(first_page, plan=plan)
    second = await discover_browser_routes_and_forms(second_page, plan=plan)

    expected_routes = ("/", "/#/spa", "/map", "/public-a", "/public-b")
    assert tuple(route.route for route in first.routes) == expected_routes
    assert first_page.goto_calls == [_ORIGIN + route for route in expected_routes]
    assert tuple(route.depth for route in first.routes) == (0, 1, 1, 1, 1)
    assert first.routes[2].source == "area"
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.result_digest == second.result_digest

    assert first.rejected_candidates == {
        "ambiguous-url": 2,
        "depth-limit": 1,
        "empty-target": 1,
        "external-origin": 1,
        "numeric-object-route": 1,
        "query-values": 2,
        "sensitive-path": 6,
        "unsafe-scheme": 1,
        "url-credentials": 1,
    }
    assert len(first.forms) == 1
    discovered_form = first.forms[0]
    assert discovered_form.method == "POST"
    assert discovered_form.action_route == "/login"
    assert discovered_form.submission_performed is False
    assert [control.control_type for control in discovered_form.controls] == [
        "email",
        "password",
        "submit",
    ]
    assert discovered_form.controls[2].name is None
    assert discovered_form.controls[2].name_omitted is True

    serialized = first.model_dump_json()
    assert "redacted" not in serialized
    assert first.raw_dom_retained is False
    assert first.screenshots_retained is False
    assert first.form_values_retained is False
    assert first.forms_submitted is False
    assert first.external_delivery_performed is False
    assert first.graph_admission_authority is False
    assert first.finding_authority is False
    assert first.execution_authority is False
    expected_argument_keys = {"maxLinks", "maxForms", "maxFieldsPerForm"}
    assert all(
        set(arg) == expected_argument_keys
        for _, arg in first_page.evaluate_calls
        if isinstance(arg, dict)
    )
    for script, _argument in first_page.evaluate_calls:
        lowered = script.lower()
        assert ".value" not in lowered
        assert ".click(" not in lowered
        assert ".submit(" not in lowered
        assert "screenshot" not in lowered
        assert "outerhtml" not in lowered
        assert "innerhtml" not in lowered
    assert first_page.locator_calls == []


@pytest.mark.parametrize(
    "value_bearing_route",
    (
        "/profiles/alice@example.test",
        "/profiles/alice%40example.test",
        "/objects/550e8400-e29b-41d4-a716-446655440000",
        "/sessions/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
        "/assets/4f8d3c2b1a00998877665544",
        "/share/Az7kLm4Np9Qr2St5Uv8Wx1Yb3Cd6Ef0G",
    ),
)
@pytest.mark.asyncio
async def test_value_bearing_path_candidates_are_rejected_without_serialization(
    value_bearing_route: str,
) -> None:
    page = _FakePage(
        {
            _ORIGIN + "/": _snapshot(
                links=[("anchor", value_bearing_route)],
                forms=[_form(0, action=value_bearing_route)],
            )
        }
    )

    result = await discover_browser_routes_and_forms(
        page,
        plan=browser_discovery_plan(_ORIGIN),
    )

    assert tuple(route.route for route in result.routes) == ("/",)
    assert result.rejected_candidates == {"value-bearing-path": 2}
    assert result.forms[0].action_disposition == "value-bearing-path"
    assert result.forms[0].action_route is None
    assert value_bearing_route not in result.model_dump_json()


@pytest.mark.parametrize(
    "seed_route",
    (
        "/profiles/alice@example.test",
        "/objects/550e8400-e29b-41d4-a716-446655440000",
        "/sessions/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
        "/assets/4f8d3c2b1a00998877665544",
        "/share/Az7kLm4Np9Qr2St5Uv8Wx1Yb3Cd6Ef0G",
    ),
)
def test_plan_rejects_value_bearing_seed_routes(seed_route: str) -> None:
    with pytest.raises(ValidationError, match="unsafe or noncanonical"):
        browser_discovery_plan(_ORIGIN, seed_routes=(seed_route,))


@pytest.mark.asyncio
async def test_authentication_sentinel_is_attached_before_every_route_snapshot() -> None:
    second_route = "/public"
    page = _FakePage(
        {
            _ORIGIN + "/": _snapshot(links=[("anchor", second_route)]),
            _ORIGIN + second_route: _snapshot(),
        }
    )
    plan = browser_discovery_plan(
        _ORIGIN,
        authentication_sentinel_selector="#authenticated-session",
    )

    result = await discover_browser_routes_and_forms(page, plan=plan)

    assert tuple(route.route for route in result.routes) == ("/", second_route)
    assert page.locator_calls == ["#authenticated-session", "#authenticated-session"]
    assert page.events == [
        ("goto", _ORIGIN + "/"),
        ("sentinel", _ORIGIN + "/"),
        ("snapshot", _ORIGIN + "/"),
        ("goto", _ORIGIN + second_route),
        ("sentinel", _ORIGIN + second_route),
        ("snapshot", _ORIGIN + second_route),
    ]


@pytest.mark.asyncio
async def test_authentication_sentinel_session_loss_fails_closed_before_snapshot() -> None:
    second_route = "/public"
    page = _FakePage(
        {
            _ORIGIN + "/": _snapshot(links=[("anchor", second_route)]),
            _ORIGIN + second_route: _snapshot(),
        },
        sentinel_attached_by_url={_ORIGIN + second_route: False},
    )
    plan = browser_discovery_plan(
        _ORIGIN,
        authentication_sentinel_selector="#authenticated-session",
    )

    with pytest.raises(BrowserDiscoveryBoundaryError, match="sentinel is not attached"):
        await discover_browser_routes_and_forms(page, plan=plan)

    assert page.events[-2:] == [
        ("goto", _ORIGIN + second_route),
        ("sentinel", _ORIGIN + second_route),
    ]
    assert len(page.evaluate_calls) == 1


@pytest.mark.asyncio
async def test_code_owned_activation_exposes_sentinel_before_each_snapshot() -> None:
    second_route = "/public"
    page = _FakePage(
        {
            _ORIGIN + "/": _snapshot(links=[("anchor", second_route)]),
            _ORIGIN + second_route: _snapshot(),
        }
    )
    plan = browser_discovery_plan(
        _ORIGIN,
        authentication_sentinel_selector="#logout",
        authentication_sentinel_activation_selector="#account-menu",
        authentication_sentinel_activation_mode="enter",
    )

    result = await discover_browser_routes_and_forms(page, plan=plan)

    assert tuple(route.route for route in result.routes) == ("/", second_route)
    for route in (_ORIGIN + "/", _ORIGIN + second_route):
        route_events = [event for event in page.events if event[1] == route]
        assert route_events == [
            ("goto", route),
            ("activation-ready", route),
            ("activation-enter", route),
            ("sentinel", route),
            ("escape", route),
            ("snapshot", route),
        ]


@pytest.mark.asyncio
async def test_forms_are_enumerated_structurally_without_visiting_actions() -> None:
    forms = [
        _form(0, action="/contact"),
        _form(1, action="https://example.test/submit"),
        _form(2, action="javascript:alert(1)"),
        _form(3, action="/submit?token=redacted"),
        _form(4, action="/admin/create"),
        _form(5, action="/objects/123"),
        _form(6, action="http://user:redacted@127.0.0.1:4317/private"),
        _form(7, action="/safe", method="dialog"),
        _form(8, action="x" * 2_001, action_truncated=True),
    ]
    page = _FakePage({_ORIGIN + "/": _snapshot(forms=forms)})

    result = await discover_browser_routes_and_forms(
        page,
        plan=browser_discovery_plan(_ORIGIN),
    )

    assert page.goto_calls == [_ORIGIN + "/"]
    assert len(result.forms) == len(forms)
    assert [form.action_disposition for form in result.forms] == [
        "same-origin",
        "external-origin",
        "unsafe-scheme",
        "query-values",
        "sensitive-path",
        "numeric-object-route",
        "url-credentials",
        "non-navigation-method",
        "candidate-too-long",
    ]
    assert result.forms[0].action_route == "/contact"
    assert all(form.action_route is None for form in result.forms[1:])
    assert all(form.submission_performed is False for form in result.forms)
    assert "redacted" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_discovery_enforces_route_link_form_and_field_budgets() -> None:
    controls = [_control(index, name=f"field_{index}") for index in range(3)]
    root = _snapshot(
        links=[
            ("anchor", "/a"),
            ("anchor", "/b"),
            ("anchor", "/c"),
            ("anchor", "/d"),
        ],
        forms=[
            _form(0, action="/submit-a", controls=controls, observed_control_count=3),
            _form(1, action="/submit-b", controls=controls, observed_control_count=3),
            _form(2, action="/submit-c", controls=controls, observed_control_count=3),
        ],
        observed_link_count=5,
        observed_form_count=3,
    )
    page = _FakePage({_ORIGIN + "/": root, _ORIGIN + "/a": _snapshot()})
    plan = browser_discovery_plan(
        _ORIGIN,
        limits={
            "max_routes": 2,
            "max_depth": 2,
            "max_links_per_page": 3,
            "max_forms": 2,
            "max_fields_per_form": 2,
            "max_total_fields": 3,
        },
    )

    result = await discover_browser_routes_and_forms(page, plan=plan)

    assert tuple(route.route for route in result.routes) == ("/", "/a")
    assert len(result.forms) == 2
    assert [len(form.controls) for form in result.forms] == [2, 1]
    assert sum(len(form.controls) for form in result.forms) == 3
    assert result.rejected_candidates == {
        "field-limit": 3,
        "form-limit": 1,
        "link-limit": 2,
        "route-limit": 2,
    }
    assert result.route_limit_reached is True
    assert result.form_limit_reached is True
    assert result.field_limit_reached is True


@pytest.mark.asyncio
async def test_navigation_route_drift_fails_closed_before_snapshot() -> None:
    page = _FakePage(
        {},
        redirects={_ORIGIN + "/": "https://example.test/out"},
    )

    with pytest.raises(BrowserDiscoveryBoundaryError, match="route drifted"):
        await discover_browser_routes_and_forms(
            page,
            plan=browser_discovery_plan(_ORIGIN),
        )

    assert page.goto_calls == [_ORIGIN + "/"]
    assert page.evaluate_calls == []


@pytest.mark.asyncio
async def test_snapshot_rejects_unexpected_value_data_with_a_fixed_error() -> None:
    leaked_control = _control(0, name="username")
    leaked_control["value"] = "not-retained-secret"
    page = _FakePage(
        {_ORIGIN + "/": _snapshot(forms=[_form(0, action="/login", controls=[leaked_control])])}
    )

    with pytest.raises(
        BrowserDiscoveryError,
        match="invalid structural snapshot",
    ) as caught:
        await discover_browser_routes_and_forms(
            page,
            plan=browser_discovery_plan(_ORIGIN),
        )

    assert "not-retained-secret" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.asyncio
async def test_result_digest_rejects_tampering() -> None:
    result = await discover_browser_routes_and_forms(
        _FakePage({_ORIGIN + "/": _snapshot()}),
        plan=browser_discovery_plan(_ORIGIN),
    )
    assert result.api_version == "pajin.dev/local-web-browser-discovery-result/v1alpha1"
    assert len(result.result_digest) == 64

    tampered = result.model_dump(mode="json")
    tampered["origin"] = "http://127.0.0.1:4318"
    with pytest.raises(ValidationError, match="Result Digest differs"):
        BrowserDiscoveryResult.model_validate(tampered)
