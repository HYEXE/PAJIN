from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import httpx
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from pajin.cli import app
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.web_assessment.browser import BrowserAssessmentObservation, BrowserCredentials
from pajin.web_assessment.campaign_observation import (
    LocalWebCampaignObservationArtifacts,
    LocalWebCampaignObservationIntegrityError,
    LocalWebCampaignObservationResult,
    load_verified_local_web_campaign_observation,
    render_local_web_campaign_observation_report,
    run_local_web_campaign_observation,
)
from pajin.web_assessment.diagnostic_catalog import _testing_diagnostic_bundle_catalog
from pajin.web_assessment.models import WebAssessmentPlan
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import issue_local_web_assessment_authorization
from tests.test_web_assessment import _FakeBrowser, _json_response

_ORIGIN = "http://127.0.0.1:3000"
_ROOT_BODY_SENTINEL = "private-root-response-sentinel"
_FTP_FILE_SENTINEL = "private-customer-export.csv"


class _SemanticFakeBrowser(_FakeBrowser):
    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        observed = await super().run(credentials)
        trials = tuple(
            trial.model_copy(
                update={
                    "facts": {
                        "controlMarkerExecuted": False,
                        "probeMarkerExecuted": True,
                        "externalTransmission": False,
                    }
                }
            )
            for trial in observed.dom_xss_trials
        )
        return replace(observed, dom_xss_trials=(trials[0], trials[1]))


class _DiscoveryPage:
    def __init__(self, session: _DiscoverySession) -> None:
        self.session = session
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
        assert self.session.authenticated is True
        assert wait_until == "domcontentloaded"
        assert timeout > 0
        self.session.events.append("discover")
        self._url = _ORIGIN + "/#/" if url == _ORIGIN + "/" else url

    async def wait_for_timeout(self, timeout: float) -> None:
        assert timeout >= 0

    async def evaluate(self, expression: str, arg: object | None = None) -> object:
        assert self.session.authenticated is True
        assert expression
        assert arg is not None
        return deepcopy(
            {
                "links": [],
                "observed_link_count": 0,
                "forms": [],
                "observed_form_count": 0,
            }
        )


class _DiscoverySession:
    def __init__(self) -> None:
        self.authenticated = False
        self.credentials: BrowserCredentials | None = None
        self.events: list[str] = []
        self.page = _DiscoveryPage(self)

    async def start(self) -> _DiscoveryPage:
        self.events.append("start")
        return self.page

    async def authenticate(self, credentials: BrowserCredentials) -> None:
        self.credentials = credentials
        self.authenticated = True
        self.events.append("authenticate")

    async def close(self) -> None:
        self.events.append("close")


class _DiscoverySessionFactory:
    def __init__(self) -> None:
        self.session = _DiscoverySession()
        self.calls = 0

    def __call__(
        self,
        *,
        plan: WebAssessmentPlan,
        network: AssessmentNetwork,
        headless: bool,
    ) -> _DiscoverySession:
        assert plan == juice_shop_plan(_ORIGIN)
        assert network.plan == plan
        assert headless is True
        self.calls += 1
        return self.session


def _transport(
    plan: WebAssessmentPlan,
    registrations: list[dict[str, object]],
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == plan.fingerprint_endpoint:
            return _json_response(200, {"version": "19.2.1-observation-test"})
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
                headers={"content-type": "text/html; charset=utf-8"},
                content=f"<!doctype html><html>{_ROOT_BODY_SENTINEL}</html>".encode(),
            )
        if request.method == "GET" and path == "/ftp/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=(
                    "<!doctype html><html><title>listing directory /ftp/</title>"
                    f'<a href="/ftp/{_FTP_FILE_SENTINEL}">{_FTP_FILE_SENTINEL}</a>'
                    "</html>"
                ).encode(),
            )
        if request.method == "GET" and path == "/ftp/pajin-web004-control-missing-v1.md":
            return httpx.Response(
                404,
                headers={"content-type": "text/html"},
                content=b"<html>missing</html>",
            )
        raise AssertionError(f"unexpected request: {request.method} {path}")

    return httpx.MockTransport(handler)


async def _run_observation(
    tmp_path: Path,
) -> tuple[
    LocalWebCampaignObservationArtifacts,
    list[dict[str, object]],
    _DiscoverySessionFactory,
]:
    plan = juice_shop_plan(_ORIGIN)
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    registrations: list[dict[str, object]] = []
    discovery_factory = _DiscoverySessionFactory()
    _SemanticFakeBrowser.captured_credentials = []
    with patch(
        "pajin.web_assessment.runner.production_diagnostic_bundle_catalog",
        _testing_diagnostic_bundle_catalog,
    ):
        artifacts = await run_local_web_campaign_observation(
            plan=plan,
            authorization=authorization,
            output_root=tmp_path,
            browser_factory=_SemanticFakeBrowser,
            network_factory=lambda selected: AssessmentNetwork(
                selected,
                transport=_transport(selected, registrations),
            ),
            discovery_session_factory=discovery_factory,
        )
    return artifacts, registrations, discovery_factory


@pytest.mark.asyncio
async def test_local_observation_runs_one_account_and_seals_non_authoritative_output(
    tmp_path: Path,
) -> None:
    artifacts, registrations, discovery_factory = await _run_observation(tmp_path)
    result = artifacts.result

    assert len(registrations) == 1
    assert len(_SemanticFakeBrowser.captured_credentials) == 1
    assert discovery_factory.calls == 1
    assert discovery_factory.session.credentials == _SemanticFakeBrowser.captured_credentials[0]
    assert discovery_factory.session.events == [
        "start",
        "authenticate",
        "discover",
        "close",
    ]
    assert result.semantics == "local-observation-only"
    assert result.account_provisioned_outside_capability is True
    assert result.source_integrity_verified is True
    assert result.semantic_validation_applied is True
    assert result.neutral_graph_proposals_built is True
    assert result.source_identity_pin_independently_supplied is False
    assert result.discovery_plan.seed_routes == ("/#/",)
    assert [claim.status for claim in result.source.semantic_claims.claims] == [
        "locally-reproduced",
        "locally-reproduced",
        "locally-reproduced",
    ]
    assert [diagnostic.status for diagnostic in result.extra_diagnostics] == [
        "locally-observed",
        "locally-observed",
    ]
    for marker in (
        result.action_permit_issued,
        result.lifecycle_activated,
        result.gateway_dispatched,
        result.independent_execution_attested,
        result.graph_admission,
        result.finding_authority,
        result.sarif_export,
        result.external_delivery,
    ):
        assert marker is False
    assert result.campaign_draft.campaign_manifest_compiled is False
    assert result.campaign_preparation.campaign_manifest_compiled is False
    assert result.neutral_graph_projection.graph_admission_performed is False
    assert (
        result.neutral_graph_projection.source_authority.source_identity_pin_independently_supplied
        is False
    )
    assert result.capability_profile.state == "registered-not-activated"
    assert result.capability_plan.state == "planned-not-authorized"
    assert result.capability_profile.side_effect_class == "irreversible-write"
    assert result.capability_profile.cleanup_required is True
    assert result.account_receipt.issuer_authenticated is False
    assert verify_run_integrity(artifacts.run_path).root_digest == artifacts.root_digest

    verified = load_verified_local_web_campaign_observation(
        artifacts.run_path,
        expected_run_id=result.run_id,
        expected_root_digest=artifacts.root_digest,
    )
    assert verified.result == result
    assert verified.report_markdown == render_local_web_campaign_observation_report(result)


@pytest.mark.asyncio
async def test_outer_run_persists_no_credentials_bodies_queries_paths_or_permit_identity(
    tmp_path: Path,
) -> None:
    artifacts, registrations, _ = await _run_observation(tmp_path)
    credentials = _SemanticFakeBrowser.captured_credentials[0]
    outer_bytes = b"".join(
        path.read_bytes() for path in artifacts.run_path.rglob("*") if path.is_file()
    )
    serialized = outer_bytes.decode("utf-8")

    assert registrations[0]["email"] == credentials.username
    assert credentials.username not in serialized
    assert credentials.password not in serialized
    assert _ROOT_BODY_SENTINEL not in serialized
    assert _FTP_FILE_SENTINEL not in serialized
    assert str(tmp_path) not in serialized
    assert "actionPermitId" not in serialized
    assert "actionPermitDigest" not in serialized
    assert "approvalReceipt" not in serialized
    assert '"kind": "CampaignManifest"' not in serialized
    assert "capabilityGrantId" not in serialized
    assert "?" not in "".join(
        request.path
        for request in (
            *artifacts.result.discovery_requests,
            *artifacts.result.extra_diagnostic_requests,
        )
    )
    assert artifacts.result.credentials_persisted is False
    assert artifacts.result.query_values_persisted is False
    assert artifacts.result.raw_dom_persisted is False
    assert artifacts.result.extra_response_bodies_persisted is False
    assert artifacts.result.absolute_paths_persisted is False


@pytest.mark.parametrize(
    "field",
    (
        "actionPermitIssued",
        "sourceIdentityPinIndependentlySupplied",
        "lifecycleActivated",
        "gatewayDispatched",
        "independentExecutionAttested",
        "graphAdmission",
        "findingAuthority",
        "sarifExport",
        "externalDelivery",
    ),
)
@pytest.mark.asyncio
async def test_result_rejects_forged_authority_markers(
    tmp_path: Path,
    field: str,
) -> None:
    artifacts, _, _ = await _run_observation(tmp_path)
    raw = artifacts.result.model_dump(mode="json", by_alias=True)
    raw.pop("resultDigest")
    raw[field] = True

    with pytest.raises(ValidationError, match="authority and sensitive-retention"):
        LocalWebCampaignObservationResult.model_validate(raw)


def _write_clone(
    store: RunStore,
    result: LocalWebCampaignObservationResult,
    *,
    report: str,
) -> None:
    artifacts = {
        "campaign-draft.json": result.campaign_draft,
        "campaign-preparation.json": result.campaign_preparation,
        "capability-account-receipt.json": result.account_receipt,
        "capability-plan.json": result.capability_plan,
        "capability-profile.json": result.capability_profile,
        "discovery-plan.json": result.discovery_plan,
        "discovery-result.json": result.discovery,
        "extra-ftp-directory-listing.json": result.extra_diagnostics[1],
        "extra-security-header-posture.json": result.extra_diagnostics[0],
        "graph-projection.json": result.neutral_graph_projection,
        "semantic-claims.json": result.source.semantic_claims,
        "source-reference.json": result.source,
    }
    for path, artifact in artifacts.items():
        store.write_json_create_only(
            path,
            artifact.model_dump(mode="json", by_alias=True, exclude_none=True),
        )
    store.write_json_create_only(
        "result.json",
        result.model_dump(mode="json", by_alias=True, exclude_none=True),
    )
    store.write_text_create_only("report.md", report)
    store.append_event(
        "local-web-campaign-observation.started",
        {
            "origin": result.assessment_plan.origin,
            "planDigest": result.assessment_plan.plan_digest,
            "semantics": result.semantics,
        },
        occurred_at=result.started_at,
    )
    store.append_event(
        "local-web-campaign-observation.completed",
        {
            "resultDigest": result.result_digest,
            "sourceRunId": result.source.run_id,
            "semantics": result.semantics,
        },
        occurred_at=result.finished_at,
    )


@pytest.mark.asyncio
async def test_verified_loader_rejects_tampering_and_resealed_unbound_report(
    tmp_path: Path,
) -> None:
    artifacts, _, _ = await _run_observation(tmp_path)
    report_path = artifacts.report_path
    report_path.write_text(report_path.read_text() + "unsealed tampering\n")
    with pytest.raises(LocalWebCampaignObservationIntegrityError):
        load_verified_local_web_campaign_observation(
            artifacts.run_path,
            expected_run_id=artifacts.result.run_id,
            expected_root_digest=artifacts.root_digest,
        )

    clone = RunStore.create(tmp_path, "local-observation-report-clone")
    raw = artifacts.result.model_dump(mode="json", by_alias=True)
    raw.pop("resultDigest")
    raw["runId"] = clone.run_id
    clone_result = LocalWebCampaignObservationResult.model_validate(raw)
    _write_clone(
        clone,
        clone_result,
        report=render_local_web_campaign_observation_report(clone_result)
        + "Unbound report assertion.\n",
    )
    seal = clone.seal()

    with pytest.raises(
        LocalWebCampaignObservationIntegrityError,
        match="report differs from deterministic",
    ):
        load_verified_local_web_campaign_observation(
            clone.path,
            expected_run_id=clone.run_id,
            expected_root_digest=seal.root_digest,
        )


def test_observation_cli_requires_explicit_local_lab_confirmation() -> None:
    result = CliRunner().invoke(
        app,
        [
            "web-campaign-observe-local",
            "--origin",
            "http://127.0.0.1:3000",
        ],
    )

    assert result.exit_code == 2
    assert "Local Web campaign observation failed" in result.output
