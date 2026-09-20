from __future__ import annotations

import inspect
import json
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

import httpx
import pytest
from pydantic import ValidationError

from pajin.capabilities.models import capability_definition_digest
from pajin.runtime.store import RunStore
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment import diagnostic_catalog as catalog_module
from pajin.web_assessment.adapter_catalog import (
    _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
    _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    production_adapter_implementation_catalog,
)
from pajin.web_assessment.browser import BrowserAssessmentObservation, BrowserCredentials
from pajin.web_assessment.diagnostic_catalog import (
    EXECUTOR_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_DIAGNOSTIC_BUNDLE_ID,
    PATH_BUILDER_IMPLEMENTATION_DIGEST,
    DiagnosticBundleCatalog,
    DiagnosticBundleCatalogError,
    DiagnosticBundleDescriptor,
    DiagnosticExecutionPolicies,
    _testing_diagnostic_bundle_catalog,
    production_diagnostic_bundle_catalog,
)
from pajin.web_assessment.models import (
    BrowserPageEvidence,
    BrowserSessionSummary,
    ProbeTrial,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    LocalWebAssessmentError,
    issue_local_web_assessment_authorization,
    run_local_web_assessment,
)

_ORIGIN = "http://127.0.0.1:3000"


def _bundle_material(descriptor: DiagnosticBundleDescriptor) -> dict[str, object]:
    return {
        "bundleId": descriptor.bundle_id,
        "adapterImplementationId": descriptor.adapter_implementation_id,
        "adapterImplementationDigest": descriptor.adapter_implementation_digest,
        "executorId": descriptor.executor_id,
        "executorImplementationDigest": descriptor.executor_implementation_digest,
        "pathBuilderId": descriptor.path_builder_id,
        "pathBuilderImplementationDigest": descriptor.path_builder_implementation_digest,
        "diagnosticOrder": list(descriptor.diagnostic_order),
        "attackPathIssueSequences": [
            list(sequence) for sequence in descriptor.attack_path_issue_sequences
        ],
        "findingAuthority": False,
        "graphAuthority": False,
    }


def _page(
    *,
    store: RunStore,
    index: int,
    phase: Literal[
        "authenticated-navigation",
        "dom-xss-control",
        "dom-xss-source",
        "dom-xss-replay",
    ],
    marker_executed: bool,
) -> BrowserPageEvidence:
    body = f"diagnostic-page-{index}".encode()
    screenshot = f"diagnostic-screenshot-{index}".encode()
    reference = store.write_bytes(f"evidence/diagnostic-{index}.png", screenshot)
    return BrowserPageEvidence(
        phase=phase,
        route=(
            "/#/search?q=<control-redacted>"
            if phase == "dom-xss-control"
            else "/#/search?q=<probe-redacted>"
        ),
        title="Local assessment target",
        ready_selector="app-search-result",
        dom_sha256=sha256(body).hexdigest(),
        dom_bytes=len(body),
        screenshot_reference=reference,
        screenshot_sha256=sha256(screenshot).hexdigest(),
        screenshot_bytes=len(screenshot),
        marker_executed=marker_executed,
        captured_at=datetime(2026, 9, 15, index, tzinfo=UTC),
    )


def _observation(store: RunStore) -> BrowserAssessmentObservation:
    source_control = _page(
        store=store,
        index=1,
        phase="dom-xss-control",
        marker_executed=False,
    )
    source_probe = _page(
        store=store,
        index=2,
        phase="dom-xss-source",
        marker_executed=True,
    )
    replay_control = _page(
        store=store,
        index=3,
        phase="dom-xss-control",
        marker_executed=False,
    )
    replay_probe = _page(
        store=store,
        index=4,
        phase="dom-xss-replay",
        marker_executed=True,
    )
    source = ProbeTrial(
        check="dom-xss",
        repetition="source",
        reproduced=True,
        controls_passed=True,
        evidence_ids=(source_control.evidence_id, source_probe.evidence_id),
        facts={
            "controlMarkerExecuted": False,
            "probeMarkerExecuted": True,
            "externalTransmission": False,
        },
    )
    replay = ProbeTrial(
        check="dom-xss",
        repetition="replay",
        reproduced=True,
        controls_passed=True,
        evidence_ids=(replay_control.evidence_id, replay_probe.evidence_id),
        facts={
            "controlMarkerExecuted": False,
            "probeMarkerExecuted": True,
            "externalTransmission": False,
        },
    )
    return BrowserAssessmentObservation(
        object_id=7,
        summary=BrowserSessionSummary(
            authenticated=True,
            ephemeral_account_created=True,
            pages=(source_control, source_probe, replay_control, replay_probe),
            requests_completed=1,
            browser_closed=True,
        ),
        dom_xss_trials=(source, replay),
    )


def _policy(plan: WebAssessmentPlan) -> EgressPolicy:
    return EgressPolicy(
        allow=[plan.origin + "/*"],
        deny=[plan.origin + path + "*" for path in plan.deny_paths],
        allowed_methods={"GET", "HEAD", "POST"},
        allow_private_networks=True,
        max_response_bytes=plan.max_response_bytes,
        max_requests=20,
        max_request_bytes=64_000,
    )


def _json_response(status: int, value: object) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/json"},
        content=json.dumps(value).encode(),
    )


def _diagnostic_response(
    request: httpx.Request,
    requests: list[tuple[str, str]],
) -> httpx.Response:
    path = request.url.path
    requests.append((request.method, path))
    if request.method == "POST" and path == "/rest/user/login":
        payload = json.loads(request.content)
        if payload["email"] == "' OR 1=1--":
            return _json_response(
                200,
                {"authentication": {"token": "process-local-token", "bid": 1}},
            )
        return _json_response(401, {"error": "invalid credentials"})
    if request.method == "GET" and path == "/api/Users/":
        assert request.headers["authorization"] == "Bearer process-local-token"
        return _json_response(200, {"data": [{"id": 1}, {"id": 2}]})
    if request.method == "GET" and path.startswith("/rest/basket/"):
        object_id = int(path.rsplit("/", 1)[1])
        if object_id == 2_147_483_647:
            return _json_response(200, {"data": None})
        return _json_response(
            200,
            {"data": {"id": object_id, "UserId": object_id, "Products": []}},
        )
    raise AssertionError(f"unexpected diagnostic request: {request.method} {path}")


def _diagnostic_transport(requests: list[tuple[str, str]]) -> httpx.MockTransport:
    def respond(request: httpx.Request) -> httpx.Response:
        return _diagnostic_response(request, requests)

    return httpx.MockTransport(respond)


def _runner_transport(
    plan: WebAssessmentPlan,
    requests: list[tuple[str, str]],
) -> httpx.MockTransport:
    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == plan.fingerprint_endpoint:
            requests.append((request.method, path))
            return _json_response(200, {"version": "19.2.1-catalog-integration"})
        if plan.registration is not None and (
            request.method == "POST" and path == plan.registration.endpoint
        ):
            requests.append((request.method, path))
            return _json_response(201, {"status": "success"})
        if request.method == "GET" and path == "/":
            requests.append((request.method, path))
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b"<html><title>Juice Shop</title></html>",
            )
        return _diagnostic_response(request, requests)

    return httpx.MockTransport(respond)


class _RunnerBrowser:
    def __init__(
        self,
        *,
        plan: WebAssessmentPlan,
        network: AssessmentNetwork,
        store: RunStore,
        navigation_policy: EgressPolicy,
        xss_policy: EgressPolicy,
        headless: bool,
    ) -> None:
        del plan, xss_policy, headless
        self._network = network
        self._store = store
        self._navigation_policy = navigation_policy

    async def run(
        self,
        credentials: BrowserCredentials,
    ) -> BrowserAssessmentObservation:
        del credentials
        self._network.begin_phase("diagnostic-catalog-browser", self._navigation_policy)
        response = await self._network.json_request("GET", "/")
        assert response.status == 200
        return _observation(self._store)


def test_production_bundle_identity_and_catalog_digests_are_deterministic() -> None:
    catalog = production_diagnostic_bundle_catalog()
    descriptor = catalog.resolve(
        adapter_implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    expected_bundle_digest = capability_definition_digest(
        "pajin.web-assessment.diagnostic-bundle/v1",
        _bundle_material(descriptor),
    )
    expected_catalog_digest = capability_definition_digest(
        "pajin.web-assessment.diagnostic-catalog/v1",
        {
            "adapterCatalogDigest": (production_adapter_implementation_catalog().catalog_digest),
            "runtimeProfile": "production-default-httpx",
            "bundles": [
                {
                    **_bundle_material(descriptor),
                    "bundleDigest": expected_bundle_digest,
                }
            ],
        },
    )

    assert catalog.references() == (
        (JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID, JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST),
    )
    assert descriptor.bundle_id == JUICE_SHOP_DIAGNOSTIC_BUNDLE_ID
    assert descriptor.bundle_digest == expected_bundle_digest
    assert descriptor.catalog_digest == expected_catalog_digest == catalog.catalog_digest
    assert descriptor.diagnostic_order == ("sql-login", "object-access", "dom-xss")
    assert descriptor.attack_path_issue_sequences == (
        ("sql-login", "object-access"),
        ("dom-xss",),
    )
    assert descriptor.finding_authority is False
    assert descriptor.graph_authority is False
    assert EXECUTOR_IMPLEMENTATION_DIGEST == (
        "a47af4d3054a673a51fa4b4f6fd4fd8552c8bcaab0032eba09bc46c51fb45d06"
    )
    assert PATH_BUILDER_IMPLEMENTATION_DIGEST == (
        "0506e64331b4c5e441da4113fdb65cfa2d3f9648357b6996e0663919e0f2747b"
    )
    assert descriptor.bundle_digest == (
        "c2f342968a520ca3112956b795eb5a383a6739f267532fcd34016b82d77e62c3"
    )
    assert descriptor.catalog_digest == (
        "759e49fe21d3cbeb289967bcaa45af7967ca8f040bcf91bf765d4a237ecada1d"
    )
    assert descriptor.executor_implementation_digest == EXECUTOR_IMPLEMENTATION_DIGEST
    assert descriptor.path_builder_implementation_digest == (PATH_BUILDER_IMPLEMENTATION_DIGEST)


def test_nonproduction_bundle_requires_the_internal_adapter_fixture_catalog() -> None:
    production = production_diagnostic_bundle_catalog()
    with pytest.raises(DiagnosticBundleCatalogError, match="not installed"):
        production.resolve(
            adapter_implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
            adapter_implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        )

    first = _testing_diagnostic_bundle_catalog()
    second = _testing_diagnostic_bundle_catalog()
    fixture = first.resolve(
        adapter_implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    assert fixture.bundle_id == "pajin.web-diagnostics.local-fixture.v1"
    assert first.catalog_digest == second.catalog_digest
    assert set(first.references()) == {
        (JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID, JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST),
        (
            _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
            _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        ),
    }


@pytest.mark.parametrize(
    ("implementation_id", "implementation_digest"),
    (
        (JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID, "9" * 64),
        ("pajin.web-assessment.unknown.v1", JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST),
        (
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        ),
        (
            _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        ),
    ),
)
def test_catalog_requires_an_exact_adapter_identity_without_fallback(
    implementation_id: str,
    implementation_digest: str,
) -> None:
    with pytest.raises(DiagnosticBundleCatalogError, match="not installed"):
        _testing_diagnostic_bundle_catalog().resolve(
            adapter_implementation_id=implementation_id,
            adapter_implementation_digest=implementation_digest,
        )


def test_catalog_construction_and_runtime_mutation_fail_closed() -> None:
    with pytest.raises(TypeError, match="code-owned factory"):
        DiagnosticBundleCatalog(
            _bundles=(),
            _adapter_catalog=production_adapter_implementation_catalog(),
            _runtime_profile="production-default-httpx",
            _factory_token=object(),
        )
    with pytest.raises(DiagnosticBundleCatalogError, match="empty"):
        catalog_module._new_diagnostic_bundle_catalog(
            bundles=(),
            implementation_catalog=production_adapter_implementation_catalog(),
        )
    with pytest.raises(DiagnosticBundleCatalogError, match="duplicate identity"):
        catalog_module._new_diagnostic_bundle_catalog(
            bundles=(catalog_module._JUICE_SHOP_BUNDLE, catalog_module._JUICE_SHOP_BUNDLE),
            implementation_catalog=production_adapter_implementation_catalog(),
        )
    with pytest.raises(DiagnosticBundleCatalogError, match="not code-owned"):
        catalog_module._new_diagnostic_bundle_catalog(
            bundles=(catalog_module._LOCAL_FIXTURE_BUNDLE,),
            implementation_catalog=(
                catalog_module.adapter_catalog._testing_adapter_implementation_catalog()
            ),
            runtime_profile="production-default-httpx",
        )

    catalog = _testing_diagnostic_bundle_catalog()
    object.__setattr__(
        catalog,
        "_DiagnosticBundleCatalog__catalog_digest",
        "0" * 64,
    )
    with pytest.raises(DiagnosticBundleCatalogError, match="identity changed"):
        catalog.references()

    catalog = _testing_diagnostic_bundle_catalog()
    entries = object.__getattribute__(catalog, "_DiagnosticBundleCatalog__entries")
    object.__setattr__(catalog, "_DiagnosticBundleCatalog__entries", dict(entries))
    with pytest.raises(DiagnosticBundleCatalogError, match="identity changed"):
        catalog.references()

    catalog = _testing_diagnostic_bundle_catalog()
    bundles = object.__getattribute__(catalog, "_DiagnosticBundleCatalog__bundles")
    object.__setattr__(catalog, "_DiagnosticBundleCatalog__bundles", list(bundles))
    with pytest.raises(DiagnosticBundleCatalogError, match="identity changed"):
        catalog.references()
    assert not hasattr(production_diagnostic_bundle_catalog(), "register")


def test_forged_descriptor_fails_before_any_runtime_input_is_used() -> None:
    catalog = production_diagnostic_bundle_catalog()
    descriptor = catalog.resolve(
        adapter_implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    forged = replace(descriptor, bundle_digest="0" * 64)

    with pytest.raises(DiagnosticBundleCatalogError, match="identity changed"):
        catalog._bind_runner_execution(
            descriptor=forged,
            plan=juice_shop_plan(_ORIGIN),
            observation=cast(BrowserAssessmentObservation, object()),
            network=cast(AssessmentNetwork, object()),
            policies=cast(DiagnosticExecutionPolicies, object()),
            store=cast(RunStore, object()),
            browser_factory=object(),
            network_factory=object(),
        )


def test_caller_authored_payload_plan_is_rejected_before_execution() -> None:
    catalog = production_diagnostic_bundle_catalog()
    descriptor = catalog.resolve(
        adapter_implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    material = juice_shop_plan(_ORIGIN).model_dump(mode="json")
    sql_login = material["sql_login"]
    assert isinstance(sql_login, dict)
    sql_login["true_expression"] = "caller-supplied-payload"
    caller_plan = WebAssessmentPlan.model_validate(material)

    with pytest.raises(DiagnosticBundleCatalogError, match="not the code-owned"):
        catalog._bind_runner_execution(
            descriptor=descriptor,
            plan=caller_plan,
            observation=cast(BrowserAssessmentObservation, object()),
            network=cast(AssessmentNetwork, object()),
            policies=cast(DiagnosticExecutionPolicies, object()),
            store=cast(RunStore, object()),
            browser_factory=object(),
            network_factory=object(),
        )


@pytest.mark.asyncio
async def test_execute_runs_existing_diagnostics_in_code_owned_order(tmp_path: Path) -> None:
    plan = juice_shop_plan(_ORIGIN)
    requests: list[tuple[str, str]] = []
    network = AssessmentNetwork(plan, transport=_diagnostic_transport(requests))
    policy = _policy(plan)
    catalog = _testing_diagnostic_bundle_catalog()
    descriptor = catalog.resolve(
        adapter_implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    try:
        store = RunStore.create(tmp_path, "diagnostic-catalog-execution")
        authority = catalog._bind_runner_execution(
            descriptor=descriptor,
            plan=plan,
            observation=_observation(store),
            network=network,
            policies=DiagnosticExecutionPolicies(
                sql_login=policy,
                object_access=policy.model_copy(deep=True),
            ),
            store=store,
            browser_factory=object(),
            network_factory=object(),
        )
        result = await catalog.execute(authority=authority)
    finally:
        await network.close()

    assert requests == [
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
    ]
    assert tuple(issue.check for issue in result.issues) == descriptor.diagnostic_order
    assert tuple(path.status for path in result.attack_paths) == (
        "locally-validated",
        "locally-validated",
    )
    assert result.finding_authority is False
    assert result.graph_authority is False
    assert result.descriptor == descriptor
    assert result.run_id == store.run_id

    with pytest.raises(DiagnosticBundleCatalogError, match="consumed"):
        await catalog.execute(authority=authority)


@pytest.mark.asyncio
async def test_policy_expansion_is_rejected_before_network_use(tmp_path: Path) -> None:
    plan = juice_shop_plan(_ORIGIN)
    policy = _policy(plan)
    policy.allow.append("http://127.0.0.1:3999/*")
    network = AssessmentNetwork(plan, transport=_diagnostic_transport([]))
    catalog = _testing_diagnostic_bundle_catalog()
    descriptor = catalog.resolve(
        adapter_implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    try:
        with pytest.raises(DiagnosticBundleCatalogError, match="exact plan boundary"):
            store = RunStore.create(tmp_path, "diagnostic-policy-expansion")
            catalog._bind_runner_execution(
                descriptor=descriptor,
                plan=plan,
                observation=_observation(store),
                network=network,
                policies=DiagnosticExecutionPolicies(
                    sql_login=policy,
                    object_access=_policy(plan),
                ),
                store=store,
                browser_factory=object(),
                network_factory=object(),
            )
    finally:
        await network.close()
    assert network.evidence == []


@pytest.mark.asyncio
async def test_production_catalog_rejects_a_caller_transport(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, transport=_diagnostic_transport([]))
    policy = _policy(plan)
    store = RunStore.create(tmp_path, "diagnostic-production-provenance")
    catalog = production_diagnostic_bundle_catalog()
    descriptor = catalog.resolve(
        adapter_implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    try:
        with pytest.raises(DiagnosticBundleCatalogError, match="code-owned browser and network"):
            catalog._bind_runner_execution(
                descriptor=descriptor,
                plan=plan,
                observation=_observation(store),
                network=network,
                policies=DiagnosticExecutionPolicies(
                    sql_login=policy,
                    object_access=policy.model_copy(deep=True),
                ),
                store=store,
                browser_factory=object(),
                network_factory=object(),
            )
    finally:
        await network.close()
    assert network.evidence == []


@pytest.mark.asyncio
async def test_dom_trial_must_reference_its_run_control_and_probe_pages(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    network = AssessmentNetwork(plan, transport=_diagnostic_transport([]))
    policy = _policy(plan)
    store = RunStore.create(tmp_path, "diagnostic-dom-lineage")
    catalog = _testing_diagnostic_bundle_catalog()
    descriptor = catalog.resolve(
        adapter_implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    observation = _observation(store)
    source, replay = observation.dom_xss_trials
    foreign_source = source.model_copy(
        update={"evidence_ids": ("browser-page:" + "0" * 64, source.evidence_ids[1])}
    )
    forged = replace(observation, dom_xss_trials=(foreign_source, replay))
    try:
        with pytest.raises(DiagnosticBundleCatalogError, match="unknown page Evidence"):
            catalog._bind_runner_execution(
                descriptor=descriptor,
                plan=plan,
                observation=forged,
                network=network,
                policies=DiagnosticExecutionPolicies(
                    sql_login=policy,
                    object_access=policy.model_copy(deep=True),
                ),
                store=store,
                browser_factory=object(),
                network_factory=object(),
            )
    finally:
        await network.close()
    assert network.evidence == []


def test_execute_surface_exposes_no_callable_payload_narrative_or_graph_input() -> None:
    parameters = set(inspect.signature(DiagnosticBundleCatalog.execute).parameters)
    assert parameters == {"self", "authority"}
    descriptor_fields = set(DiagnosticBundleDescriptor.__dataclass_fields__)
    assert descriptor_fields.isdisjoint(
        {"callable", "function", "payload", "success_narrative", "graph_authority_input"}
    )


@pytest.mark.asyncio
async def test_runner_dispatches_through_the_exact_testing_bundle_without_digest_drift(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    requests: list[tuple[str, str]] = []
    transport = _runner_transport(plan, requests)

    artifacts = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=tmp_path,
        browser_factory=_RunnerBrowser,
        network_factory=lambda selected: AssessmentNetwork(
            selected,
            transport=transport,
        ),
        adapter_implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
    )

    assert requests == [
        ("GET", "/rest/admin/application-version"),
        ("POST", "/api/Users/"),
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
    ]
    assert tuple(issue.check for issue in artifacts.result.issues) == (
        "sql-login",
        "object-access",
        "dom-xss",
    )
    assert tuple(path.status for path in artifacts.result.attack_paths) == (
        "locally-validated",
        "locally-validated",
    )
    round_trip = type(artifacts.result).model_validate(
        artifacts.result.model_dump(mode="json", by_alias=True)
    )
    assert round_trip == artifacts.result
    assert round_trip.result_digest == artifacts.result.result_digest

    tampered = artifacts.result.model_dump(mode="json", by_alias=True)
    tampered["target_version"] = "changed-after-seal"
    with pytest.raises(ValidationError, match="Result Digest differs"):
        type(artifacts.result).model_validate(tampered)


@pytest.mark.asyncio
async def test_runner_rejects_an_adapter_digest_mismatch_before_runtime_or_output(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    factory_called = False

    def forbidden_network(_plan: WebAssessmentPlan) -> AssessmentNetwork:
        nonlocal factory_called
        factory_called = True
        raise AssertionError("network must not be constructed for an unknown digest")

    output_root = tmp_path / "not-created"
    with pytest.raises(LocalWebAssessmentError, match="bundle resolution failed"):
        await run_local_web_assessment(
            plan=plan,
            authorization=authorization,
            output_root=output_root,
            network_factory=forbidden_network,
            adapter_implementation_digest="0" * 64,
            diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
        )

    assert factory_called is False
    assert not output_root.exists()


@pytest.mark.asyncio
async def test_runner_rejects_production_factory_injection_before_runtime_or_output(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan(_ORIGIN)
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    factory_calls: list[str] = []

    def forbidden_network(_plan: WebAssessmentPlan) -> AssessmentNetwork:
        factory_calls.append("network")
        raise AssertionError("injected network factory must not be called")

    def forbidden_browser(**_kwargs: object) -> object:
        factory_calls.append("browser")
        raise AssertionError("injected browser factory must not be called")

    output_root = tmp_path / "not-created"
    with pytest.raises(LocalWebAssessmentError, match="runtime provenance failed"):
        await run_local_web_assessment(
            plan=plan,
            authorization=authorization,
            output_root=output_root,
            browser_factory=forbidden_browser,
            network_factory=forbidden_network,
        )

    assert factory_calls == []
    assert not output_root.exists()
