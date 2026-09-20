from __future__ import annotations

import hashlib
import json
import pickle
from copy import copy, deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

import httpx
import pytest

from pajin.agentic.execution_profiles import ResolvedSpecialistExecutionProfile
from pajin.runtime.store import RunStore
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment import diagnostics
from pajin.web_assessment.browser import (
    BrowserAssessmentError,
    BrowserCredentials,
    PlaywrightAssessmentBrowser,
    PlaywrightSpecialistAssessmentBrowser,
    SpecialistBrowserObservation,
    _testing_specialist_browser_invocation,
    specialist_browser_navigation_policy,
    specialist_browser_xss_policy,
)
from pajin.web_assessment.models import (
    BrowserPageEvidence,
    IssueCheck,
    ProbeTrial,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentBoundaryError, AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import assessment_policy
from pajin.web_assessment.specialist_executors import (
    SpecialistDiagnosticPolicies,
    WebSpecialistDependencyError,
    WebSpecialistExecutorCatalog,
    WebSpecialistExecutorError,
    _testing_web_specialist_executor_catalog,
    production_web_specialist_executor_catalog,
    specialist_object_access_policy,
    specialist_sql_login_policy,
)
from pajin.web_assessment.specialist_profiles import (
    WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID,
    WEB_SQLI_SPECIALIST_PROFILE_ID,
    WEB_XSS_SPECIALIST_PROFILE_ID,
    production_web_specialist_execution_profile_catalog,
)

_ORIGIN = "http://127.0.0.1:3000"


def _profiles() -> dict[str, ResolvedSpecialistExecutionProfile]:
    catalog = production_web_specialist_execution_profile_catalog()
    return {reference.profile_id: catalog.resolve(reference) for reference in catalog.references()}


def _page(
    store: RunStore,
    plan: WebAssessmentPlan,
    *,
    index: int,
    phase: Literal[
        "authenticated-navigation",
        "dom-xss-control",
        "dom-xss-source",
        "dom-xss-replay",
    ],
    marker_executed: bool | None,
) -> BrowserPageEvidence:
    body = f"specialist-dom-{index}".encode()
    screenshot = f"specialist-png-{index}".encode()
    reference = store.write_bytes(f"evidence/specialist-{index}.png", screenshot)
    if phase == "authenticated-navigation":
        route = "/#/search"
        ready_selector = plan.login.success_activation_selector or plan.login.success_selector
    else:
        assert plan.dom_xss is not None
        prefix = plan.dom_xss.route_template.partition("{payload}")[0]
        route = prefix + (
            "<control-redacted>" if phase == "dom-xss-control" else "<probe-redacted>"
        )
        ready_selector = plan.dom_xss.ready_selector
    return BrowserPageEvidence(
        phase=phase,
        route=route,
        title="Juice Shop",
        ready_selector=ready_selector,
        dom_sha256=hashlib.sha256(body).hexdigest(),
        dom_bytes=len(body),
        screenshot_reference=reference,
        screenshot_sha256=hashlib.sha256(screenshot).hexdigest(),
        screenshot_bytes=len(screenshot),
        marker_executed=marker_executed,
        captured_at=datetime(2026, 9, 18, 1, index, tzinfo=UTC),
    )


def _browser_observation(
    store: RunStore,
    plan: WebAssessmentPlan,
    *,
    steps: tuple[IssueCheck, ...],
    xss_reproduced: bool = True,
) -> SpecialistBrowserObservation:
    login = _page(
        store,
        plan,
        index=1,
        phase="authenticated-navigation",
        marker_executed=None,
    )
    if steps == ("sql-login", "object-access"):
        return SpecialistBrowserObservation(
            diagnostic_steps=steps,
            object_id=7,
            pages=(login,),
            dom_xss_trials=None,
            requests_completed=1,
            blocked_requests=(),
            request_failures=(),
            unexpected_console_error_fingerprints=(),
        )
    assert steps == ("dom-xss",)
    source_control = _page(
        store,
        plan,
        index=2,
        phase="dom-xss-control",
        marker_executed=False,
    )
    source_probe = _page(
        store,
        plan,
        index=3,
        phase="dom-xss-source",
        marker_executed=xss_reproduced,
    )
    replay_control = _page(
        store,
        plan,
        index=4,
        phase="dom-xss-control",
        marker_executed=False,
    )
    replay_probe = _page(
        store,
        plan,
        index=5,
        phase="dom-xss-replay",
        marker_executed=xss_reproduced,
    )
    source = ProbeTrial(
        check="dom-xss",
        repetition="source",
        reproduced=xss_reproduced,
        controls_passed=True,
        evidence_ids=(source_control.evidence_id, source_probe.evidence_id),
        facts={
            "controlMarkerExecuted": False,
            "probeMarkerExecuted": xss_reproduced,
            "externalTransmission": False,
        },
    )
    replay = ProbeTrial(
        check="dom-xss",
        repetition="replay",
        reproduced=xss_reproduced,
        controls_passed=True,
        evidence_ids=(replay_control.evidence_id, replay_probe.evidence_id),
        facts={
            "controlMarkerExecuted": False,
            "probeMarkerExecuted": xss_reproduced,
            "externalTransmission": False,
        },
    )
    return SpecialistBrowserObservation(
        diagnostic_steps=steps,
        object_id=7,
        pages=(login, source_control, source_probe, replay_control, replay_probe),
        dom_xss_trials=(source, replay),
        requests_completed=5,
        blocked_requests=(),
        request_failures=(),
        unexpected_console_error_fingerprints=(),
    )


def _json_response(status: int, value: object) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/json"},
        content=json.dumps(value).encode(),
    )


def _transport(
    requests: list[tuple[str, str, str]],
    *,
    sql_succeeds: bool = True,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        phase = request.headers.get("x-test-phase", "")
        requests.append((request.method, request.url.path, phase))
        if request.method == "POST" and request.url.path == "/rest/user/login":
            payload = json.loads(request.content)
            if sql_succeeds and payload["email"] == "' OR 1=1--":
                return _json_response(
                    200,
                    {"authentication": {"token": "process-local-token", "bid": 1}},
                )
            return _json_response(401, {"error": "invalid credentials"})
        if request.method == "GET" and request.url.path == "/api/Users/":
            return _json_response(200, {"data": [{"id": 1}, {"id": 2}]})
        if request.method == "GET" and request.url.path.startswith("/rest/basket/"):
            object_id = int(request.url.path.rsplit("/", 1)[1])
            return _json_response(
                200,
                {
                    "data": (
                        None
                        if object_id == 2_147_483_647
                        else {"id": object_id, "UserId": object_id, "Products": []}
                    )
                },
            )
        if request.method == "GET" and request.url.path == "/":
            return httpx.Response(200, content=b"<html>Juice Shop</html>")
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    return httpx.MockTransport(handler)


def _policy(plan: WebAssessmentPlan) -> EgressPolicy:
    return assessment_policy(plan, max_requests=20)


def _specialist_policies(
    plan: WebAssessmentPlan,
    *,
    steps: tuple[IssueCheck, ...],
) -> SpecialistDiagnosticPolicies:
    return SpecialistDiagnosticPolicies(
        sql_login=(specialist_sql_login_policy(plan) if "sql-login" in steps else None),
        object_access=(specialist_object_access_policy(plan) if "object-access" in steps else None),
    )


async def _record_phase(
    network: AssessmentNetwork,
    plan: WebAssessmentPlan,
    phase: str,
) -> None:
    policy = (
        specialist_browser_navigation_policy(plan)
        if phase == "browser-authenticated-navigation"
        else specialist_browser_xss_policy(plan)
    )
    network.begin_phase(phase, policy)
    response = await network.json_request("GET", "/")
    assert response.status == 200


def test_executor_catalog_binds_three_distinct_non_authoritative_closures() -> None:
    catalog = production_web_specialist_executor_catalog()
    second = production_web_specialist_executor_catalog()
    profiles = _profiles()

    assert catalog.catalog_digest == second.catalog_digest
    descriptors = {item.profile_ref.profile_id: item for item in catalog.descriptors()}
    assert set(descriptors) == {
        WEB_XSS_SPECIALIST_PROFILE_ID,
        WEB_SQLI_SPECIALIST_PROFILE_ID,
        WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID,
    }
    assert len({item.executor_digest for item in descriptors.values()}) == 3
    assert {item.executor_version for item in descriptors.values()} == {"1.1.0"}
    assert descriptors[WEB_XSS_SPECIALIST_PROFILE_ID].diagnostic_steps == ("dom-xss",)
    assert descriptors[WEB_XSS_SPECIALIST_PROFILE_ID].browser_implementation_version == "1.1.0"
    assert descriptors[WEB_SQLI_SPECIALIST_PROFILE_ID].diagnostic_steps == ("sql-login",)
    authorization = descriptors[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID]
    assert authorization.diagnostic_steps == ("sql-login", "object-access")
    assert authorization.promotable_steps == ("object-access",)
    for profile_id, descriptor in descriptors.items():
        assert catalog.resolve(profiles[profile_id]) == descriptor
        assert descriptor.scope_authority is False
        assert descriptor.capability_authority is False
        assert descriptor.permit_authority is False
        assert descriptor.gateway_authority is False
        assert descriptor.worker_authority is False
        assert descriptor.finding_authority is False
        assert descriptor.graph_authority is False
    assert not hasattr(catalog, "register")
    assert not hasattr(catalog, "resolve_latest")


def test_catalog_cannot_be_constructed_by_a_caller() -> None:
    with pytest.raises(TypeError, match="code-owned factory"):
        WebSpecialistExecutorCatalog(
            _runtime_profile="testing-injected-transport",
        )


def test_production_catalog_identity_cannot_be_mutated_copied_or_serialized() -> None:
    catalog = production_web_specialist_executor_catalog()
    for attribute, value in (
        ("_WebSpecialistExecutorCatalog__runtime_profile", "testing-injected-transport"),
        ("_WebSpecialistExecutorCatalog__catalog_digest", "0" * 64),
    ):
        with pytest.raises(AttributeError, match="immutable"):
            setattr(catalog, attribute, value)
        with pytest.raises(AttributeError, match="immutable"):
            delattr(catalog, attribute)
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(catalog)


def test_specialist_browser_observation_uses_provisioned_account_semantics(
    tmp_path: Path,
) -> None:
    observation = _browser_observation(
        RunStore.create(tmp_path, "specialist-account-semantics"),
        juice_shop_plan(_ORIGIN),
        steps=("dom-xss",),
    )

    assert observation.account_creation_performed is False
    assert observation.provisioned_account_used is True
    assert not hasattr(observation, "ephemeral_account_created")


def test_specialist_diagnostic_policies_are_exact_step_scoped() -> None:
    plan = juice_shop_plan(_ORIGIN)
    assert plan.sql_login is not None
    assert plan.object_access is not None

    sql = specialist_sql_login_policy(plan)
    object_access = specialist_object_access_policy(plan)

    assert sql.allow == [
        plan.origin + plan.login.endpoint,
        plan.origin + plan.sql_login.impact_endpoint,
    ]
    assert sql.allowed_methods == {"GET", "POST"}
    assert sql.max_requests == 3
    assert object_access.allow == [
        plan.origin + plan.object_access.endpoint_template.replace("{id}", "*")
    ]
    assert object_access.allowed_methods == {"GET"}
    assert object_access.max_requests == 3
    assert (
        sql.deny
        == object_access.deny
        == [plan.origin + path.rstrip("/") + "*" for path in plan.deny_paths]
    )
    assert sql != assessment_policy(plan, max_requests=20)
    assert object_access != assessment_policy(plan, max_requests=20)


@pytest.mark.asyncio
async def test_specialist_observation_rejects_account_claim_substitution_before_io(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    store = RunStore.create(tmp_path, "specialist-account-substitution")
    await _record_phase(network, plan, "browser-authenticated-navigation")
    observation = _browser_observation(
        store,
        plan,
        steps=("sql-login", "object-access"),
    )
    invalid = (
        replace(
            observation,
            account_creation_performed=cast(Literal[False], True),
        ),
        replace(
            observation,
            provisioned_account_used=cast(Literal[True], False),
        ),
    )
    catalog = _testing_web_specialist_executor_catalog()
    before = tuple(requests)
    try:
        for substituted in invalid:
            with pytest.raises(WebSpecialistExecutorError, match="not canonical"):
                catalog._bind_runner_execution(
                    profile=_profiles()[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID],
                    plan=plan,
                    browser_observation=substituted,
                    network=network,
                    policies=_specialist_policies(
                        plan,
                        steps=("sql-login", "object-access"),
                    ),
                    store=store,
                    browser_factory=object(),
                    network_factory=object(),
                )
    finally:
        await network.close()
    assert tuple(requests) == before


@pytest.mark.asyncio
async def test_sql_specialist_rejects_aggregate_policy_before_io(tmp_path: Path) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    catalog = _testing_web_specialist_executor_catalog()
    try:
        with pytest.raises(WebSpecialistExecutorError, match="exact code-owned boundary"):
            catalog._bind_runner_execution(
                profile=_profiles()[WEB_SQLI_SPECIALIST_PROFILE_ID],
                plan=plan,
                browser_observation=None,
                network=network,
                policies=SpecialistDiagnosticPolicies(sql_login=_policy(plan)),
                store=RunStore.create(tmp_path, "specialist-sql-broad-policy"),
                browser_factory=None,
                network_factory=object(),
            )
    finally:
        await network.close()
    assert requests == []


@pytest.mark.asyncio
async def test_authorization_specialist_rejects_smuggled_object_policy_before_io(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    store = RunStore.create(tmp_path, "specialist-object-broad-policy")
    await _record_phase(network, plan, "browser-authenticated-navigation")
    exact_object = specialist_object_access_policy(plan)
    smuggled_object = EgressPolicy.model_validate(
        {
            **exact_object.model_dump(mode="json"),
            "allow": [plan.origin + "/*"],
            "allowed_methods": ["GET", "HEAD"],
        }
    )
    before = tuple(requests)
    try:
        with pytest.raises(WebSpecialistExecutorError, match="exact code-owned boundary"):
            _testing_web_specialist_executor_catalog()._bind_runner_execution(
                profile=_profiles()[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID],
                plan=plan,
                browser_observation=_browser_observation(
                    store,
                    plan,
                    steps=("sql-login", "object-access"),
                ),
                network=network,
                policies=SpecialistDiagnosticPolicies(
                    sql_login=specialist_sql_login_policy(plan),
                    object_access=smuggled_object,
                ),
                store=store,
                browser_factory=object(),
                network_factory=object(),
            )
    finally:
        await network.close()
    assert tuple(requests) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile_id", "expected_checks", "expected_promotable", "expected_requests"),
    (
        (
            WEB_XSS_SPECIALIST_PROFILE_ID,
            ("dom-xss",),
            ("dom-xss",),
            (("GET", "/"), ("GET", "/"), ("GET", "/")),
        ),
        (
            WEB_SQLI_SPECIALIST_PROFILE_ID,
            ("sql-login",),
            ("sql-login",),
            (
                ("POST", "/rest/user/login"),
                ("POST", "/rest/user/login"),
                ("GET", "/api/Users/"),
                ("POST", "/rest/user/login"),
                ("POST", "/rest/user/login"),
                ("GET", "/api/Users/"),
            ),
        ),
        (
            WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID,
            ("sql-login", "object-access"),
            ("object-access",),
            (
                ("GET", "/"),
                ("POST", "/rest/user/login"),
                ("POST", "/rest/user/login"),
                ("GET", "/api/Users/"),
                ("POST", "/rest/user/login"),
                ("POST", "/rest/user/login"),
                ("GET", "/api/Users/"),
                ("GET", "/rest/basket/1"),
                ("GET", "/rest/basket/7"),
                ("GET", "/rest/basket/2147483647"),
                ("GET", "/rest/basket/1"),
                ("GET", "/rest/basket/7"),
                ("GET", "/rest/basket/2147483647"),
            ),
        ),
    ),
)
async def test_each_profile_executes_only_its_exact_closure(
    tmp_path: Path,
    profile_id: str,
    expected_checks: tuple[IssueCheck, ...],
    expected_promotable: tuple[IssueCheck, ...],
    expected_requests: tuple[tuple[str, str], ...],
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    store = RunStore.create(tmp_path, profile_id.rsplit(".", 1)[-1])
    catalog = _testing_web_specialist_executor_catalog()
    profile = _profiles()[profile_id]
    observation = (
        None
        if profile_id == WEB_SQLI_SPECIALIST_PROFILE_ID
        else _browser_observation(store, plan, steps=expected_checks)
    )
    if observation is not None:
        await _record_phase(network, plan, "browser-authenticated-navigation")
    if profile_id == WEB_XSS_SPECIALIST_PROFILE_ID:
        await _record_phase(network, plan, "dom-xss-source")
        await _record_phase(network, plan, "dom-xss-replay")
    policies = _specialist_policies(plan, steps=expected_checks)
    try:
        authority = catalog._bind_runner_execution(
            profile=profile,
            plan=plan,
            browser_observation=observation,
            network=network,
            policies=policies,
            store=store,
            browser_factory=(object() if observation is not None else None),
            network_factory=object(),
        )
        result = await catalog.execute(authority=authority)
        with pytest.raises(WebSpecialistExecutorError, match="consumed"):
            await catalog.execute(authority=authority)
    finally:
        await network.close()

    assert tuple(issue.check for issue in result.issues) == expected_checks
    assert tuple(issue.check for issue in result.promotable_issues) == expected_promotable
    assert result.descriptor.diagnostic_steps == expected_checks
    assert result.independent_validation_performed is False
    assert result.finding_authority is False
    assert result.graph_authority is False
    assert tuple((method, path) for method, path, _phase in requests) == expected_requests


@pytest.mark.asyncio
async def test_out_of_closure_phase_is_rejected_before_specialist_execution(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    await _record_phase(network, plan, "object-access-source")
    store = RunStore.create(tmp_path, "specialist-out-of-closure")
    catalog = _testing_web_specialist_executor_catalog()
    profile = _profiles()[WEB_SQLI_SPECIALIST_PROFILE_ID]
    try:
        with pytest.raises(WebSpecialistExecutorError, match="exact profile closure"):
            catalog._bind_runner_execution(
                profile=profile,
                plan=plan,
                browser_observation=None,
                network=network,
                policies=_specialist_policies(plan, steps=("sql-login",)),
                store=store,
                browser_factory=None,
                network_factory=object(),
            )
    finally:
        await network.close()
    assert tuple((method, path) for method, path, _phase in requests) == (("GET", "/"),)


@pytest.mark.asyncio
async def test_trace_cannot_skip_an_earlier_dependency_before_execution(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    await _record_phase(network, plan, "object-access-source")
    store = RunStore.create(tmp_path, "specialist-missing-dependency")
    profile = _profiles()[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID]
    observation = _browser_observation(
        store,
        plan,
        steps=("sql-login", "object-access"),
    )
    catalog = _testing_web_specialist_executor_catalog()
    try:
        with pytest.raises(WebSpecialistExecutorError, match="exact profile closure"):
            catalog._bind_runner_execution(
                profile=profile,
                plan=plan,
                browser_observation=observation,
                network=network,
                policies=_specialist_policies(
                    plan,
                    steps=("sql-login", "object-access"),
                ),
                store=store,
                browser_factory=object(),
                network_factory=object(),
            )
    finally:
        await network.close()
    assert tuple((method, path) for method, path, _phase in requests) == (("GET", "/"),)


@pytest.mark.asyncio
async def test_sql_profile_rejects_browser_evidence_and_extra_policy_before_io(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    store = RunStore.create(tmp_path, "specialist-sql-browser")
    observation = _browser_observation(
        store,
        plan,
        steps=("sql-login", "object-access"),
    )
    catalog = _testing_web_specialist_executor_catalog()
    profile = _profiles()[WEB_SQLI_SPECIALIST_PROFILE_ID]
    try:
        with pytest.raises(WebSpecialistExecutorError, match="must not receive"):
            catalog._bind_runner_execution(
                profile=profile,
                plan=plan,
                browser_observation=observation,
                network=network,
                policies=_specialist_policies(
                    plan,
                    steps=("sql-login", "object-access"),
                ),
                store=store,
                browser_factory=object(),
                network_factory=object(),
            )
    finally:
        await network.close()
    assert requests == []


@pytest.mark.asyncio
async def test_specialist_execution_does_not_call_aggregate_browser_or_path_builder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def forbidden_aggregate(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("aggregate browser must not run")

    def forbidden_paths(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("aggregate attack path builder must not run")

    monkeypatch.setattr(PlaywrightAssessmentBrowser, "run", forbidden_aggregate)
    monkeypatch.setattr(diagnostics, "build_attack_paths", forbidden_paths)
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, transport=_transport([]))
    store = RunStore.create(tmp_path, "specialist-no-aggregate")
    catalog = _testing_web_specialist_executor_catalog()
    profile = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID]
    observation = _browser_observation(store, plan, steps=("dom-xss",))
    await _record_phase(network, plan, "browser-authenticated-navigation")
    await _record_phase(network, plan, "dom-xss-source")
    await _record_phase(network, plan, "dom-xss-replay")
    try:
        authority = catalog._bind_runner_execution(
            profile=profile,
            plan=plan,
            browser_observation=observation,
            network=network,
            policies=SpecialistDiagnosticPolicies(),
            store=store,
            browser_factory=object(),
            network_factory=object(),
        )
        result = await catalog.execute(authority=authority)
    finally:
        await network.close()
    assert tuple(issue.check for issue in result.issues) == ("dom-xss",)


def test_specialist_browser_policies_exclude_registration_and_xss_posts() -> None:
    plan = juice_shop_plan(_ORIGIN)
    assert plan.registration is not None
    navigation = specialist_browser_navigation_policy(plan)
    xss = specialist_browser_xss_policy(plan)
    denied_registration = plan.origin + plan.registration.endpoint.rstrip("/") + "*"
    assert plan.sql_login is not None
    assert plan.object_access is not None
    denied_sql_impact = plan.origin + plan.sql_login.impact_endpoint.rstrip("/") + "*"
    denied_object_access = (
        plan.origin + plan.object_access.endpoint_template.partition("{id}")[0].rstrip("/") + "*"
    )
    assert denied_registration in navigation.deny
    assert denied_registration in xss.deny
    assert denied_sql_impact in navigation.deny
    assert denied_sql_impact in xss.deny
    assert denied_object_access in navigation.deny
    assert denied_object_access in xss.deny
    assert navigation.allowed_methods == {"GET", "HEAD", "POST"}
    assert xss.allowed_methods == {"GET", "HEAD"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("steps", "expected_events"),
    (
        (("sql-login", "object-access"), ("start", "login", "close")),
        (
            ("dom-xss",),
            ("start", "login", "probe-source", "probe-replay", "close"),
        ),
    ),
)
async def test_specialist_browser_runs_only_the_selected_browser_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    steps: tuple[IssueCheck, ...],
    expected_events: tuple[str, ...],
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    store = RunStore.create(tmp_path, "specialist-browser-phases")
    complete = _browser_observation(store, plan, steps=steps)
    network = AssessmentNetwork(plan, transport=_transport([]))
    browser = PlaywrightSpecialistAssessmentBrowser(
        plan=plan,
        network=network,
        store=store,
        navigation_policy=specialist_browser_navigation_policy(plan),
        xss_policy=specialist_browser_xss_policy(plan),
    )
    events: list[str] = []

    async def start() -> None:
        events.append("start")

    async def login(_credentials: BrowserCredentials) -> tuple[int, BrowserPageEvidence]:
        events.append("login")
        return complete.object_id, complete.pages[0]

    async def probe(
        repetition: Literal["source", "replay"],
    ) -> tuple[ProbeTrial, tuple[BrowserPageEvidence, BrowserPageEvidence]]:
        events.append(f"probe-{repetition}")
        assert complete.dom_xss_trials is not None
        if repetition == "source":
            return complete.dom_xss_trials[0], (complete.pages[1], complete.pages[2])
        return complete.dom_xss_trials[1], (complete.pages[3], complete.pages[4])

    async def close() -> None:
        events.append("close")

    monkeypatch.setattr(browser, "_start", start)
    monkeypatch.setattr(browser, "_login", login)
    monkeypatch.setattr(browser, "_probe_dom_xss", probe)
    monkeypatch.setattr(browser, "_close", close)
    try:
        invocation = _testing_specialist_browser_invocation(
            browser,
            diagnostic_steps=steps,
        )
        result = await browser.run_specialist(
            BrowserCredentials(username="local@example.test", password="not-persisted"),
            diagnostic_steps=steps,
            invocation=invocation,
        )
    finally:
        await network.close()
    assert tuple(events) == expected_events
    assert result.diagnostic_steps == steps
    assert (result.dom_xss_trials is not None) is (steps == ("dom-xss",))
    assert result.account_creation_performed is False
    assert result.provisioned_account_used is True
    before_retry = tuple(events)
    with pytest.raises(BrowserAssessmentError, match="absent, foreign, or consumed"):
        await browser.run_specialist(
            BrowserCredentials(username="local@example.test", password="not-persisted"),
            diagnostic_steps=steps,
            invocation=invocation,
        )
    assert tuple(events) == before_retry


@pytest.mark.asyncio
async def test_specialist_browser_rejects_aggregate_policy_before_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    browser = PlaywrightSpecialistAssessmentBrowser(
        plan=plan,
        network=AssessmentNetwork(plan, transport=_transport([])),
        store=cast(RunStore, object()),
        navigation_policy=assessment_policy(plan, max_requests=100),
        xss_policy=assessment_policy(plan, max_requests=40),
    )
    started = False

    async def forbidden_start() -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(browser, "_start", forbidden_start)
    try:
        invocation = _testing_specialist_browser_invocation(
            browser,
            diagnostic_steps=("dom-xss",),
        )
        with pytest.raises(BrowserAssessmentError, match="navigation policy differs"):
            await browser.run_specialist(
                BrowserCredentials(username="local@example.test", password="not-persisted"),
                diagnostic_steps=("dom-xss",),
                invocation=invocation,
            )
    finally:
        await browser.network.close()
    assert started is False


@pytest.mark.asyncio
async def test_specialist_browser_blocks_inherited_aggregate_run_before_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, transport=_transport([]))
    browser = PlaywrightSpecialistAssessmentBrowser(
        plan=plan,
        network=network,
        store=RunStore.create(tmp_path, "specialist-no-aggregate-run"),
        navigation_policy=specialist_browser_navigation_policy(plan),
        xss_policy=specialist_browser_xss_policy(plan),
    )
    started = False

    async def forbidden_start() -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(browser, "_start", forbidden_start)
    try:
        with pytest.raises(BrowserAssessmentError, match="cannot invoke the aggregate"):
            await browser.run(
                BrowserCredentials(
                    username="local@example.test",
                    password="not-persisted",
                )
            )
        with pytest.raises(BrowserAssessmentError, match="exact implementation"):
            await PlaywrightAssessmentBrowser.run(
                browser,
                BrowserCredentials(
                    username="local@example.test",
                    password="not-persisted",
                ),
            )
    finally:
        await network.close()
    assert started is False


@pytest.mark.asyncio
async def test_specialist_browser_requires_one_use_task_local_invocation_before_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, transport=_transport([]))
    browser = PlaywrightSpecialistAssessmentBrowser(
        plan=plan,
        network=network,
        store=RunStore.create(tmp_path, "specialist-invocation-required"),
        navigation_policy=specialist_browser_navigation_policy(plan),
        xss_policy=specialist_browser_xss_policy(plan),
    )
    started = False

    async def forbidden_start() -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(browser, "_start", forbidden_start)
    try:
        with pytest.raises(BrowserAssessmentError, match="invocation is invalid"):
            await browser.run_specialist(
                BrowserCredentials(
                    username="local@example.test",
                    password="not-persisted",
                ),
                diagnostic_steps=("dom-xss",),
                invocation=cast(object, object()),
            )
    finally:
        await network.close()
    assert started is False


@pytest.mark.asyncio
async def test_specialist_browser_invocation_cannot_be_copied_or_serialized(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, transport=_transport([]))
    browser = PlaywrightSpecialistAssessmentBrowser(
        plan=plan,
        network=network,
        store=RunStore.create(tmp_path, "specialist-invocation-immutable"),
        navigation_policy=specialist_browser_navigation_policy(plan),
        xss_policy=specialist_browser_xss_policy(plan),
    )
    invocation = _testing_specialist_browser_invocation(
        browser,
        diagnostic_steps=("dom-xss",),
    )
    try:
        for operation in (
            lambda: copy(invocation),
            lambda: deepcopy(invocation),
            lambda: pickle.dumps(invocation),
        ):
            with pytest.raises(TypeError):
                operation()
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_production_catalog_has_no_execution_binding_before_agentic_003c(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    store = RunStore.create(tmp_path, "specialist-production-inert")
    profile = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID]
    observation = _browser_observation(store, plan, steps=("dom-xss",))
    catalog = production_web_specialist_executor_catalog()
    try:
        with pytest.raises(WebSpecialistExecutorError, match="AGENTIC-003C"):
            catalog._bind_runner_execution(
                profile=profile,
                plan=plan,
                browser_observation=observation,
                network=network,
                policies=SpecialistDiagnosticPolicies(),
                store=store,
                browser_factory=PlaywrightSpecialistAssessmentBrowser,
                network_factory=AssessmentNetwork,
            )
    finally:
        await network.close()
    assert requests == []


@pytest.mark.parametrize(
    "path",
    (
        "/api/Users",
        "/api/users/",
        "/API/USERS/",
        "/rest/basket/7",
        "/rest/Basket/7",
        "/REST/BASKET/7",
        "/REST/%42ASKET/7",
        "/%41PI/%55SERS/",
        "/%41PI/USERS/",
    ),
)
@pytest.mark.asyncio
async def test_specialist_browser_policy_denies_sensitive_path_aliases(path: str) -> None:
    plan = juice_shop_plan(_ORIGIN)
    for policy in (
        specialist_browser_navigation_policy(plan),
        specialist_browser_xss_policy(plan),
    ):
        network = AssessmentNetwork(plan, transport=_transport([]))
        try:
            network.begin_phase("specialist-policy-check", policy)
            with pytest.raises(AssessmentBoundaryError, match="outside-campaign-scope"):
                network.require_url(plan.origin + path, "GET")
        finally:
            await network.close()


@pytest.mark.asyncio
async def test_authorization_requires_distinct_account_objects_as_typed_dependency(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(plan, transport=_transport(requests))
    store = RunStore.create(tmp_path, "specialist-auth-distinct-object")
    await _record_phase(network, plan, "browser-authenticated-navigation")
    observation = _browser_observation(
        store,
        plan,
        steps=("sql-login", "object-access"),
    )
    observation = SpecialistBrowserObservation(
        diagnostic_steps=observation.diagnostic_steps,
        object_id=1,
        pages=observation.pages,
        dom_xss_trials=observation.dom_xss_trials,
        requests_completed=observation.requests_completed,
        blocked_requests=observation.blocked_requests,
        request_failures=observation.request_failures,
        unexpected_console_error_fingerprints=(observation.unexpected_console_error_fingerprints),
    )
    catalog = _testing_web_specialist_executor_catalog()
    authority = catalog._bind_runner_execution(
        profile=_profiles()[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID],
        plan=plan,
        browser_observation=observation,
        network=network,
        policies=_specialist_policies(
            plan,
            steps=("sql-login", "object-access"),
        ),
        store=store,
        browser_factory=object(),
        network_factory=object(),
    )
    try:
        with pytest.raises(WebSpecialistDependencyError, match="distinct account"):
            await catalog.execute(authority=authority)
    finally:
        await network.close()
    assert all(not path.startswith("/rest/basket/") for _method, path, _phase in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "phases",
    (
        ("browser-authenticated-navigation", "dom-xss-source"),
        ("browser-authenticated-navigation", "dom-xss-replay", "dom-xss-source"),
        (
            "browser-authenticated-navigation",
            "dom-xss-source",
            "dom-xss-replay",
            "dom-xss-source",
        ),
        ("browser-authenticated-navigation", "unowned-specialist-phase"),
    ),
)
async def test_xss_trace_requires_exact_contiguous_source_replay_groups(
    tmp_path: Path,
    phases: tuple[str, ...],
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, transport=_transport([]))
    store = RunStore.create(tmp_path, "specialist-bad-xss-trace")
    for phase in phases:
        await _record_phase(network, plan, phase)
    catalog = _testing_web_specialist_executor_catalog()
    try:
        with pytest.raises(WebSpecialistExecutorError, match="exact profile closure"):
            catalog._bind_runner_execution(
                profile=_profiles()[WEB_XSS_SPECIALIST_PROFILE_ID],
                plan=plan,
                browser_observation=_browser_observation(
                    store,
                    plan,
                    steps=("dom-xss",),
                ),
                network=network,
                policies=SpecialistDiagnosticPolicies(),
                store=store,
                browser_factory=object(),
                network_factory=object(),
            )
    finally:
        await network.close()


@pytest.mark.asyncio
async def test_authorization_dependency_failure_returns_no_result_or_promotion(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str, str]] = []
    network = AssessmentNetwork(
        plan,
        transport=_transport(requests, sql_succeeds=False),
    )
    store = RunStore.create(tmp_path, "specialist-auth-dependency-failed")
    await _record_phase(network, plan, "browser-authenticated-navigation")
    catalog = _testing_web_specialist_executor_catalog()
    authority = catalog._bind_runner_execution(
        profile=_profiles()[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID],
        plan=plan,
        browser_observation=_browser_observation(
            store,
            plan,
            steps=("sql-login", "object-access"),
        ),
        network=network,
        policies=_specialist_policies(
            plan,
            steps=("sql-login", "object-access"),
        ),
        store=store,
        browser_factory=object(),
        network_factory=object(),
    )
    try:
        with pytest.raises(WebSpecialistDependencyError, match="was not reproduced"):
            await catalog.execute(authority=authority)
    finally:
        await network.close()
    assert all(not path.startswith("/rest/basket/") for _method, path, _phase in requests)


@pytest.mark.asyncio
async def test_non_reproduced_sql_and_xss_are_not_promotion_candidates(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    catalog = _testing_web_specialist_executor_catalog()

    sql_network = AssessmentNetwork(plan, transport=_transport([], sql_succeeds=False))
    sql_store = RunStore.create(tmp_path, "specialist-sql-not-reproduced")
    sql_authority = catalog._bind_runner_execution(
        profile=_profiles()[WEB_SQLI_SPECIALIST_PROFILE_ID],
        plan=plan,
        browser_observation=None,
        network=sql_network,
        policies=_specialist_policies(plan, steps=("sql-login",)),
        store=sql_store,
        browser_factory=None,
        network_factory=object(),
    )
    try:
        sql_result = await catalog.execute(authority=sql_authority)
    finally:
        await sql_network.close()
    assert sql_result.issues[0].status == "not-reproduced"
    assert sql_result.promotable_issues == ()

    xss_network = AssessmentNetwork(plan, transport=_transport([]))
    xss_store = RunStore.create(tmp_path, "specialist-xss-not-reproduced")
    for phase in (
        "browser-authenticated-navigation",
        "dom-xss-source",
        "dom-xss-replay",
    ):
        await _record_phase(xss_network, plan, phase)
    xss_authority = catalog._bind_runner_execution(
        profile=_profiles()[WEB_XSS_SPECIALIST_PROFILE_ID],
        plan=plan,
        browser_observation=_browser_observation(
            xss_store,
            plan,
            steps=("dom-xss",),
            xss_reproduced=False,
        ),
        network=xss_network,
        policies=SpecialistDiagnosticPolicies(),
        store=xss_store,
        browser_factory=object(),
        network_factory=object(),
    )
    try:
        xss_result = await catalog.execute(authority=xss_authority)
    finally:
        await xss_network.close()
    assert xss_result.issues[0].status == "not-reproduced"
    assert xss_result.promotable_issues == ()
