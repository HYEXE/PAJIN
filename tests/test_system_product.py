"""Transport and custody tests use real seals over explicit synthetic failure."""

from __future__ import annotations

from dataclasses import replace

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from pydantic import ValidationError

import pajin.control_plane.system_product as products
import pajin.system_read.report as reporting
from pajin.control_plane.api import create_app
from pajin.control_plane.measured_product_deployment import (
    MeasuredProductDeployment,
    MeasuredProductDeploymentError,
    load_measured_product_readers,
    write_measured_product_deployment,
)
from pajin.control_plane.system_product import (
    SystemProductIntegrityError,
    SystemProductReader,
    SystemProductRecipe,
)
from pajin.system_read.report import SystemReportTrust, read_system_run
from pajin.system_read.runtime import SystemGateway, dispatch_system_action
from pajin.system_read.tool import SystemReadTool
from tests.sys_002_support import fixture_action
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)
from tests.test_system_read import deployment
from tests.test_system_read_report import FailedBackend

ENDPOINT = "/v1/campaigns/sys-002-run/products/system-os-release"


@pytest_asyncio.fixture
async def retained(tmp_path, monkeypatch):
    tool = SystemReadTool(deployment())
    action, authority, graph, store = fixture_action(tmp_path, tool, tool.deployment.value)
    gateway = SystemGateway(tool, store, "{}")
    gateway._worker = FailedBackend()
    monkeypatch.setattr(reporting, "observe_worker_absence", lambda _result: "unknown")
    outcome = await dispatch_system_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    policy, keys, releases = authority.activation.lifecycle.verification_material()
    trust = SystemReportTrust(
        deployment=tool.deployment,
        operator_public_key=authority.public_key.hex(),
        operator_id=authority.operator_id,
        policy=policy,
        keys=keys,
        releases=releases,
        release=authority.activation.release,
    )
    reference = reporting.seal_system_execution(store, outcome, trust)
    return SystemProductRecipe(
        campaignId="sys-002-run",
        operatorSubjects=("web-operator",),
        root=store.path.parent.parent,
        trust=trust,
        source=reference,
    ), store


def test_authentication_precedes_configuration_and_query_checks(tmp_path):
    with TestClient(create_app(_settings(tmp_path / "cp.db"))) as client:
        assert client.get(ENDPOINT).status_code == 401
        for token in (APPROVER_TOKEN, AUDITOR_TOKEN, WORKER_TOKEN):
            assert client.get(ENDPOINT, headers=_auth(token)).status_code == 403
        result = client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN))
        assert result.status_code == 503 and "not configured" in result.text
        assert (
            client.get(ENDPOINT + "?root=private", headers=_auth(OPERATOR_TOKEN)).status_code == 400
        )


@pytest.mark.asyncio
async def test_failed_execution_is_integrity_verified_but_never_complete(retained, tmp_path):
    recipe, store = retained
    reader = SystemProductReader(recipe)
    raw = read_system_run(recipe.root, recipe.source, recipe.trust)
    before = {p: p.read_bytes() for p in store.path.rglob("*") if p.is_file()}
    with TestClient(
        create_app(_settings(tmp_path / "cp.db"), system_product_reader=reader)
    ) as client:
        response = client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 200, response.text
        value = response.json()
        assert value["state"] == "incomplete" and value["evidenceVerified"] is True
        assert value["source"] == {
            key: raw[key]
            for key in ("run", "workerExecuted", "distribution", "cleanup", "complete")
        }
        assert value["source"]["complete"] is False and value["source"]["cleanup"] == "unknown"
        assert value["replay"] is None and value["distributionMatch"] is None
        assert (
            value["findingAuthority"]
            is value["generalSystemSupport"]
            is value["executionAuthorized"]
            is False
        )
        for private in (
            str(tmp_path),
            recipe.trust.operator_public_key,
            recipe.trust.deployment.value.target,
            "stderr",
            "fileBase64",
            "operatorSubjects",
            "secretLeases",
        ):
            assert private not in response.text
        assert (
            client.request(
                "GET", ENDPOINT, headers=_auth(OPERATOR_TOKEN), json={"scope": "*"}
            ).status_code
            == 400
        )
        assert client.post(ENDPOINT, headers=_auth(OPERATOR_TOKEN)).status_code == 405
    assert {p: p.read_bytes() for p in before} == before


@pytest.mark.asyncio
async def test_campaign_and_subject_denials_happen_without_evidence_access(
    retained, tmp_path, monkeypatch
):
    recipe, _ = retained
    reader = SystemProductReader(recipe)

    def forbidden(*_args, **_kwargs):
        pytest.fail("unauthorized request opened System evidence")

    monkeypatch.setattr(products, "read_system_run", forbidden)
    with TestClient(
        create_app(_settings(tmp_path / "cp.db"), system_product_reader=reader)
    ) as client:
        for campaign in ("other-campaign", "SYS-002-run", "sys-002-run-private"):
            assert (
                client.get(
                    ENDPOINT.replace("sys-002-run", campaign), headers=_auth(OPERATOR_TOKEN)
                ).status_code
                == 404
            )
        reader._recipe = recipe.model_copy(update={"operator_subjects": ("other-operator",)})
        assert client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN)).status_code == 404


@pytest.mark.asyncio
async def test_pinned_campaign_must_match_sealed_authorization(retained):
    recipe, _ = retained
    with pytest.raises(SystemProductIntegrityError):
        SystemProductReader(recipe.model_copy(update={"campaign_id": "other-campaign"})).preflight()
    with pytest.raises(ValueError, match="Campaign"):
        read_system_run(
            recipe.root, recipe.source, recipe.trust, expected_campaign="other-campaign"
        )


@pytest.mark.asyncio
async def test_empty_result_is_not_an_execution_failure(retained, tmp_path):
    recipe, _ = retained
    reader = SystemProductReader(recipe.model_copy(update={"source": None}))
    with TestClient(
        create_app(_settings(tmp_path / "empty.db"), system_product_reader=reader)
    ) as client:
        response = client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 200
        value = response.json()
        assert value["state"] == "empty" and value["evidenceVerified"] is False
        assert value["source"] is value["replay"] is value["distributionMatch"] is None


@pytest.mark.asyncio
async def test_deployment_roundtrip_pins_trust_and_revalidates_each_request(retained, tmp_path):
    recipe, store = retained
    bundle = MeasuredProductDeployment(
        deploymentId="system-test", evidenceRoot=tmp_path.resolve(), system=recipe
    )
    path = tmp_path / "private-inventory.json"
    digest = write_measured_product_deployment(path, bundle)
    assert load_measured_product_readers(path, digest).diagnostic()["system"] == "verified"
    settings = replace(
        _settings(tmp_path / "cp.db"),
        measured_product_deployment_path=path,
        measured_product_deployment_sha256=digest,
    )
    with pytest.raises(ValueError, match="both injected"):
        create_app(settings, system_product_reader=SystemProductReader(recipe))
    with TestClient(create_app(settings)) as client:
        assert client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN)).status_code == 200
        execution = store.path / "execution.json"
        original = execution.read_bytes()
        execution.write_bytes(original + b" ")
        failed = client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN))
        assert failed.status_code == 409 and str(tmp_path) not in failed.text
        execution.write_bytes(original)
        assert client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN)).status_code == 200
    bad = recipe.model_copy(
        update={"trust": recipe.trust.model_copy(update={"operator_public_key": "a" * 64})}
    )
    bad_bundle = bundle.model_copy(update={"system": bad})
    bad_digest = write_measured_product_deployment(path, bad_bundle)
    with pytest.raises(MeasuredProductDeploymentError, match="system-verification"):
        load_measured_product_readers(path, bad_digest)


@pytest.mark.asyncio
async def test_safe_read_failure_and_copied_deployment_authority(retained, tmp_path, monkeypatch):
    recipe, _ = retained
    reader = SystemProductReader(recipe)
    recipe.trust.operator_id = "changed"
    assert reader.preflight().state == "incomplete"

    def unavailable(*_args, **_kwargs):
        raise OSError("private credential and path")

    monkeypatch.setattr(products, "read_system_run", unavailable)
    with TestClient(
        create_app(_settings(tmp_path / "cp.db"), system_product_reader=reader)
    ) as client:
        result = client.get(ENDPOINT, headers=_auth(OPERATOR_TOKEN))
        assert result.status_code == 503
        assert "private" not in result.text and "could not be read" in result.text


@pytest.mark.asyncio
async def test_recipe_rejects_replay_only_and_duplicate_subjects(retained):
    recipe, _ = retained
    raw = recipe.model_dump(mode="json")
    with pytest.raises(ValidationError):
        SystemProductRecipe.model_validate({**raw, "source": None, "replay": raw["source"]})
    with pytest.raises(ValidationError, match="distinct sealed"):
        SystemProductRecipe.model_validate({**raw, "replay": raw["source"]})
    with pytest.raises(ValidationError):
        SystemProductRecipe.model_validate(
            {**raw, "operator_subjects": ["web-operator", "web-operator"]}
        )
