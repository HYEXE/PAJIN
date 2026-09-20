from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import httpx
import pytest
import pytest_asyncio

from pajin.runtime.pinned_workspace import PinnedOutputRoot
from pajin.runtime.store import RunStore
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.browser import (
    BrowserAssessmentObservation,
    BrowserCredentials,
)
from pajin.web_assessment.diagnostic_catalog import _testing_diagnostic_bundle_catalog
from pajin.web_assessment.discovery import (
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    DiscoveredBrowserRoute,
)
from pajin.web_assessment.discovery_evidence import (
    AuthenticatedDiscoveryEvidence,
    authenticated_discovery_evidence,
)
from pajin.web_assessment.models import (
    BrowserPageEvidence,
    BrowserSessionSummary,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentResult,
    ProbeTrial,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.report import render_local_web_assessment_report
from pajin.web_assessment.runner import (
    LocalWebAssessmentArtifacts,
    issue_local_web_assessment_authorization,
    provision_local_web_assessment_account,
    run_local_web_assessment,
)
from pajin.web_assessment.verification import (
    LocalWebAssessmentSourceIntegrityError,
    load_verified_local_web_assessment_source_integrity,
)


def _json_response(status: int, value: object) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/json"},
        content=json.dumps(value).encode(),
    )


def _fingerprint_payload(plan: WebAssessmentPlan, version: str) -> dict[str, object]:
    value: object = version
    for key in reversed(plan.fingerprint_version_path.split(".")):
        value = {key: value}
    assert isinstance(value, dict)
    return value


def _transport(plan: WebAssessmentPlan) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == plan.fingerprint_endpoint:
            return _json_response(
                200,
                _fingerprint_payload(plan, "19.2.1-source-integrity-test"),
            )
        assert plan.registration is not None
        if request.method == "POST" and path == plan.registration.endpoint:
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
            return _json_response(200, {"data": [{"id": 1}, {"id": 2}]})
        if request.method == "GET" and path.startswith("/rest/basket/"):
            object_id = int(path.rsplit("/", 1)[1])
            if object_id == 2_147_483_647:
                return _json_response(200, {"data": None})
            return _json_response(
                200,
                {"data": {"id": object_id, "UserId": object_id, "Products": []}},
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
    screenshots: ClassVar[dict[str, bytes]] = {}

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
        del xss_policy, headless
        self.plan = plan
        self.network = network
        self.store = store
        self.navigation_policy = navigation_policy

    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        del credentials
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
        reference = f"evidence/fake-{index}.png"
        self.screenshots[reference] = screenshot
        self.store.write_bytes(reference, screenshot)
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


class _DiscoveryFakeBrowser(_FakeBrowser):
    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        observation = await super().run(credentials)
        self.network.begin_phase("browser-passive-discovery", self.navigation_policy)
        first_reservation = await self.network.reserve("GET", self.plan.origin + "/")
        second_reservation = await self.network.reserve("GET", self.plan.origin + "/asset.js")
        second_completion = await self.network.complete_passive_metadata(
            second_reservation,
            status=200,
            headers={"content-type": "application/javascript"},
            observed_response_bytes=512,
            return_boundary_receipt=True,
        )
        first_completion = await self.network.complete_passive_metadata(
            first_reservation,
            status=200,
            headers={"content-type": "text/html; charset=utf-8"},
            observed_response_bytes=1_024,
            return_boundary_receipt=True,
        )
        discovery_plan = BrowserDiscoveryPlan(
            origin=self.plan.origin,
            seed_routes=("/",),
            max_routes=4,
            max_depth=1,
            max_links_per_page=40,
            max_forms=20,
            max_fields_per_form=16,
            max_total_fields=64,
            navigation_timeout_milliseconds=self.plan.request_timeout_seconds * 1_000,
            settle_milliseconds=250,
        )
        discovery_result = BrowserDiscoveryResult(
            plan_digest=discovery_plan.plan_digest,
            origin=self.plan.origin,
            routes=(DiscoveredBrowserRoute(route="/", depth=0, source="seed"),),
            route_limit_reached=False,
            form_limit_reached=False,
            field_limit_reached=False,
        )
        summary = BrowserSessionSummary.model_validate(
            {
                **observation.summary.model_dump(mode="json"),
                "requests_completed": observation.summary.requests_completed + 2,
            }
        )
        return BrowserAssessmentObservation(
            object_id=observation.object_id,
            summary=summary,
            dom_xss_trials=observation.dom_xss_trials,
            discovery_evidence=authenticated_discovery_evidence(
                discovery_plan=discovery_plan,
                discovery_result=discovery_result,
                request_evidence=(second_completion.evidence, first_completion.evidence),
                boundary_receipts=(
                    second_completion.boundary_receipt,
                    first_completion.boundary_receipt,
                ),
            ),
        )


@pytest_asyncio.fixture
async def source_run(
    tmp_path: Path,
) -> tuple[
    WebAssessmentPlan,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentArtifacts,
]:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    transport = _transport(plan)
    account = await provision_local_web_assessment_account(
        plan=plan,
        authorization=authorization,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
    )
    _FakeBrowser.screenshots = {}
    artifacts = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=tmp_path,
        browser_factory=_FakeBrowser,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
        provisioned_account=account,
        diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
    )
    return plan, authorization, artifacts


def _clone_source_run(
    root: Path,
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    source: LocalWebAssessmentArtifacts,
    wrong_report: bool = False,
    wrong_screenshot: bool = False,
    unexpected_artifact: bool = False,
    wrong_result_plan_digest: bool = False,
    wrong_target_product: bool = False,
    wrong_started_event: bool = False,
    duplicate_plan_key: bool = False,
    legacy_plan_identity_fields: bool = False,
    result_target_version: str | None = None,
    include_provisioning_receipt: bool = True,
    wrong_discovery_evidence: bool = False,
) -> tuple[Path, str, str]:
    store = RunStore.create(root, "web-assessment-verification-clone")
    raw_result = source.result.model_dump(mode="json")
    raw_result.update(
        {
            "run_id": store.run_id,
            "plan_name": plan.name,
            "plan_digest": plan.plan_digest,
            "authorization_id": authorization.authorization_id,
            "origin": plan.origin,
            "target_product": plan.target_product,
            "result_digest": "",
        }
    )
    if result_target_version is not None:
        raw_result["target_version"] = result_target_version
    if wrong_result_plan_digest:
        raw_result["plan_digest"] = "0" * 64
    if wrong_target_product:
        raw_result["target_product"] = "Substituted Product"
    result = LocalWebAssessmentResult.model_validate(raw_result)

    if duplicate_plan_key:
        raw_plan = json.dumps(plan.model_dump(mode="json"), separators=(",", ":"))
        store.write_text_create_only(
            "plan.json",
            raw_plan[:-1] + ',"name":"duplicate-web-assessment"}',
        )
    else:
        raw_plan = plan.model_dump(mode="json")
        if legacy_plan_identity_fields:
            raw_plan.pop("target_product")
            raw_plan.pop("fingerprint_version_path")
            raw_plan.pop("adapter_implementation_id")
        store.write_json_create_only("plan.json", raw_plan)
    store.write_json_create_only(
        "authorization.json",
        authorization.model_dump(mode="json"),
    )
    receipt_path = source.run_path / "provisioning-receipt.json"
    if include_provisioning_receipt and receipt_path.is_file():
        store.write_bytes("provisioning-receipt.json", receipt_path.read_bytes())
    discovery_path = source.run_path / "discovery-evidence.json"
    discovery_evidence = None
    if discovery_path.is_file():
        discovery_evidence = AuthenticatedDiscoveryEvidence.model_validate_json(
            discovery_path.read_bytes()
        )
        discovery_bytes = discovery_path.read_bytes()
        if wrong_discovery_evidence:
            discovery_raw = json.loads(discovery_bytes)
            assert isinstance(discovery_raw, dict)
            receipts = discovery_raw["boundaryReceipts"]
            assert isinstance(receipts, list) and isinstance(receipts[0], dict)
            receipts[0]["observedResponseBodyBytes"] += 1
            receipts[0]["receiptDigest"] = ""
            discovery_raw["boundaryReceiptsDigest"] = ""
            discovery_raw["evidenceDigest"] = ""
            changed = AuthenticatedDiscoveryEvidence.model_validate(discovery_raw)
            discovery_bytes = json.dumps(
                changed.model_dump(mode="json", by_alias=True),
                separators=(",", ":"),
            ).encode()
        store.write_bytes("discovery-evidence.json", discovery_bytes)
    for index, page in enumerate(result.browser.pages):
        screenshot = (source.run_path / page.screenshot_reference).read_bytes()
        if wrong_screenshot and index == 0:
            screenshot += b"-changed-with-valid-seal"
        store.write_bytes(page.screenshot_reference, screenshot)
    store.write_json_create_only("result.json", result.model_dump(mode="json"))
    report = render_local_web_assessment_report(
        result,
        discovery_evidence=discovery_evidence,
    )
    if wrong_report:
        report += "\nUnbound report statement.\n"
    store.write_text_create_only("report.md", report)
    if unexpected_artifact:
        store.write_json_create_only("unexpected.json", {"authority": "none"})

    started_payload = {
        "authorizationId": authorization.authorization_id,
        "origin": plan.origin,
        "planDigest": plan.plan_digest,
    }
    if wrong_started_event:
        started_payload["origin"] = "http://127.0.0.1:3001"
    store.append_event(
        "web-assessment.started",
        started_payload,
        occurred_at=result.started_at,
    )
    store.append_event(
        "web-assessment.completed",
        {
            "attackPathCount": len(result.attack_paths),
            "issueCount": len(result.issues),
            "resultDigest": result.result_digest,
        },
        occurred_at=result.finished_at,
    )
    seal = store.seal()
    return store.path, store.run_id, seal.root_digest


@pytest.mark.asyncio
async def test_loader_proves_source_integrity_only(
    source_run: tuple[
        WebAssessmentPlan,
        LocalWebAssessmentAuthorization,
        LocalWebAssessmentArtifacts,
    ],
) -> None:
    plan, _, artifacts = source_run
    verified = load_verified_local_web_assessment_source_integrity(
        artifacts.run_path,
        expected_run_id=artifacts.result.run_id,
        expected_root_digest=artifacts.root_digest,
    )

    assert verified.semantics == "source-integrity-only"
    assert verified.independent_replay_verified is False
    assert verified.finding_authority is False
    assert verified.plan == plan
    assert verified.result == artifacts.result
    assert verified.report_markdown == render_local_web_assessment_report(artifacts.result)
    assert "empty-retention sentinels" not in verified.report_markdown
    assert verified.screenshot_references == tuple(
        page.screenshot_reference for page in artifacts.result.browser.pages
    )


@pytest.mark.asyncio
async def test_runner_and_loader_bind_authenticated_discovery_sidecar(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    transport = _transport(plan)
    account = await provision_local_web_assessment_account(
        plan=plan,
        authorization=authorization,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
    )
    artifacts = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=tmp_path,
        browser_factory=_DiscoveryFakeBrowser,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
        provisioned_account=account,
        diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
    )

    assert artifacts.discovery_evidence_path == artifacts.run_path / "discovery-evidence.json"
    assert artifacts.discovery_evidence_path.is_file()
    assert artifacts.result.discovery_evidence_reference == "discovery-evidence.json"
    verified = load_verified_local_web_assessment_source_integrity(
        artifacts.run_path,
        expected_run_id=artifacts.result.run_id,
        expected_root_digest=artifacts.root_digest,
    )
    assert verified.discovery_evidence is not None
    assert verified.result.discovery_evidence_digest == verified.discovery_evidence.evidence_digest
    assert "Passive routes discovered: `1`" in verified.report_markdown
    assert "Passive discovery requests: `2`" in verified.report_markdown
    assert "These values are empty-retention sentinels" in verified.report_markdown
    assert "`observedResponseBodyBytes` in `discovery-evidence.json`" in (verified.report_markdown)
    assert "Non-passive RequestEvidence records retain their normal" in verified.report_markdown


@pytest.mark.asyncio
async def test_loader_rejects_validly_sealed_discovery_sidecar_substitution(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    transport = _transport(plan)
    account = await provision_local_web_assessment_account(
        plan=plan,
        authorization=authorization,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
    )
    source = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=tmp_path / "source",
        browser_factory=_DiscoveryFakeBrowser,
        network_factory=lambda selected: AssessmentNetwork(selected, transport=transport),
        provisioned_account=account,
        diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
    )
    run_path, run_id, root_digest = _clone_source_run(
        tmp_path / "clone",
        plan=plan,
        authorization=authorization,
        source=source,
        wrong_discovery_evidence=True,
    )

    with pytest.raises(
        LocalWebAssessmentSourceIntegrityError,
        match="discovery Evidence differs",
    ):
        load_verified_local_web_assessment_source_integrity(
            run_path,
            expected_run_id=run_id,
            expected_root_digest=root_digest,
        )


@pytest.mark.asyncio
async def test_loader_accepts_legacy_plan_without_product_identity_fields(
    tmp_path: Path,
    source_run: tuple[
        WebAssessmentPlan,
        LocalWebAssessmentAuthorization,
        LocalWebAssessmentArtifacts,
    ],
) -> None:
    plan, authorization, source = source_run
    run_path, run_id, root_digest = _clone_source_run(
        tmp_path,
        plan=plan,
        authorization=authorization,
        source=source,
        legacy_plan_identity_fields=True,
    )

    verified = load_verified_local_web_assessment_source_integrity(
        run_path,
        expected_run_id=run_id,
        expected_root_digest=root_digest,
    )

    assert verified.plan.plan_digest == plan.plan_digest
    assert verified.plan.target_product == plan.target_product
    assert verified.plan.fingerprint_version_path == plan.fingerprint_version_path
    assert verified.plan.adapter_implementation_id == plan.adapter_implementation_id


@pytest.mark.asyncio
async def test_loader_binds_alternate_product_and_fingerprint_json_path(
    tmp_path: Path,
    source_run: tuple[
        WebAssessmentPlan,
        LocalWebAssessmentAuthorization,
        LocalWebAssessmentArtifacts,
    ],
) -> None:
    raw = juice_shop_plan("http://127.0.0.1:3000").model_dump(mode="json")
    raw.update(
        {
            "name": "synthetic-shop-source-integrity",
            "target_product": "Synthetic Shop",
            "fingerprint_version_path": "metadata.release.version",
            "adapter_implementation_id": "pajin.web-assessment.synthetic-shop.v1",
        }
    )
    plan = WebAssessmentPlan.model_validate(raw)
    _, _, source = source_run
    authorization = LocalWebAssessmentAuthorization(
        plan_digest=plan.plan_digest,
        origin=plan.origin,
        approved_at=source.result.started_at - timedelta(seconds=1),
        expires_at=source.result.finished_at + timedelta(minutes=1),
        operator_attested_authorized=True,
        ephemeral_account_creation_allowed=True,
    )
    run_path, run_id, root_digest = _clone_source_run(
        tmp_path,
        plan=plan,
        authorization=authorization,
        source=source,
        result_target_version="synthetic-2026.09",
        include_provisioning_receipt=False,
    )

    verified = load_verified_local_web_assessment_source_integrity(
        run_path,
        expected_run_id=run_id,
        expected_root_digest=root_digest,
    )

    assert verified.plan == plan
    assert verified.result.target_product == "Synthetic Shop"
    assert verified.result.target_version == "synthetic-2026.09"


@pytest.mark.skipif(os.name != "posix", reason="POSIX pinned CWD capability")
@pytest.mark.asyncio
async def test_loader_stays_on_pinned_cwd_after_original_root_replacement(
    source_run: tuple[
        WebAssessmentPlan,
        LocalWebAssessmentAuthorization,
        LocalWebAssessmentArtifacts,
    ],
    tmp_path: Path,
) -> None:
    plan, authorization, source = source_run
    output = tmp_path / "pinned-output"
    parked = tmp_path / "parked-output"
    victim = tmp_path / "victim-output"
    victim.mkdir()

    with PinnedOutputRoot.create(output) as pinned, pinned.activate():
        output.rename(parked)
        output.symlink_to(victim, target_is_directory=True)
        run_path, run_id, root_digest = _clone_source_run(
            Path("verification-runs"),
            plan=plan,
            authorization=authorization,
            source=source,
        )

        verified = load_verified_local_web_assessment_source_integrity(
            run_path,
            expected_run_id=run_id,
            expected_root_digest=root_digest,
        )

        assert verified.result.run_id == run_id
        assert not run_path.is_absolute()
        assert tuple(victim.iterdir()) == ()
        assert (parked / run_path).is_dir()


@pytest.mark.asyncio
async def test_loader_rejects_wrong_pinned_root_and_sealed_byte_tampering(
    source_run: tuple[
        WebAssessmentPlan,
        LocalWebAssessmentAuthorization,
        LocalWebAssessmentArtifacts,
    ],
) -> None:
    _, _, artifacts = source_run
    with pytest.raises(LocalWebAssessmentSourceIntegrityError, match="root digest differs"):
        load_verified_local_web_assessment_source_integrity(
            artifacts.run_path,
            expected_run_id=artifacts.result.run_id,
            expected_root_digest="0" * 64,
        )

    first = artifacts.result.browser.pages[0]
    (artifacts.run_path / first.screenshot_reference).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="sealed Run artifact changed"):
        load_verified_local_web_assessment_source_integrity(
            artifacts.run_path,
            expected_run_id=artifacts.result.run_id,
            expected_root_digest=artifacts.root_digest,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"wrong_report": True}, "report differs"),
        ({"wrong_screenshot": True}, "screenshot bytes differ"),
        ({"unexpected_artifact": True}, "unsupported sealed artifact"),
        ({"wrong_result_plan_digest": True}, "binding differs"),
        ({"wrong_target_product": True}, "binding differs"),
        ({"wrong_started_event": True}, "audit events differ"),
        ({"duplicate_plan_key": True}, "plan failed strict validation"),
    ],
)
async def test_loader_rejects_validly_sealed_but_semantically_forged_runs(
    tmp_path: Path,
    source_run: tuple[
        WebAssessmentPlan,
        LocalWebAssessmentAuthorization,
        LocalWebAssessmentArtifacts,
    ],
    mutation: dict[str, bool],
    message: str,
) -> None:
    plan, authorization, artifacts = source_run
    path, run_id, root_digest = _clone_source_run(
        tmp_path,
        plan=plan,
        authorization=authorization,
        source=artifacts,
        **mutation,
    )

    with pytest.raises(LocalWebAssessmentSourceIntegrityError, match=message):
        load_verified_local_web_assessment_source_integrity(
            path,
            expected_run_id=run_id,
            expected_root_digest=root_digest,
        )
