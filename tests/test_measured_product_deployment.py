from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from pajin.control_plane.api import create_app
from pajin.control_plane.measured_product_deployment import (
    MeasuredProductDeployment,
    MeasuredProductDeploymentError,
    load_measured_product_readers,
    write_measured_product_deployment,
)
from pajin.control_plane.measured_product_settings import (
    validate_measured_product_deployment_settings,
)
from pajin.control_plane.measured_product_sources import (
    AIProductRecipe,
    GraphStoreReadCoordinate,
    NetworkProductRecipe,
)
from pajin.workflow.ai_fixture_runtime import SubprocessAIDockerCommandRunner
from pajin.workflow.network_fixture_runtime import SubprocessNetworkDockerCommandRunner
from tests.ai_measured_product_fresh_process import _FakeAIDockerRunner
from tests.measured_product_deployment_probe import probe_fresh_deployment
from tests.test_control_plane_web import OPERATOR_TOKEN, _auth, _settings
from tests.test_network_fixture_runtime import _FakeDocker

pytest_plugins = ("tests.test_ai_measured_product", "tests.test_network_measured_product")


def _browser_accepts(payload: dict[str, Any], domain: str, path: Path) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
    protocol = (
        Path(__file__).resolve().parents[1] / "src/pajin/control_plane/web/protocol.js"
    ).as_uri()
    result = subprocess.run(
        [
            "node",
            "--input-type=module",
            "--eval",
            'import fs from "node:fs"; const p = await import(process.argv[1]); '
            'p.validateMeasuredBenchmarkProduct(p.parseJsonPayload('
            'fs.readFileSync(process.argv[2], "utf8"), 4000000), process.argv[3]);',
            protocol,
            str(path),
            domain,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("path", "digest"),
    [
        (Path("/unavailable"), None),
        (None, "a" * 64),
        (Path("relative"), "a" * 64),
        (Path("/unavailable"), ""),
        (Path("/unavailable"), "G" * 64),
    ],
)
def test_deployment_configuration_requires_exact_pair(
    path: Path | None, digest: str | None
) -> None:
    with pytest.raises(ValueError):
        validate_measured_product_deployment_settings(path, digest)


def test_unconfigured_deployment_preserves_optional_products() -> None:
    assert load_measured_product_readers(None, None).diagnostic() == {
        "web": "not-configured",
        "network": "not-configured",
        "ai": "not-configured",
    }


def test_browser_contract_matches_authoritative_models() -> None:
    from pajin.control_plane.measured_product_web_contract import measured_product_browser_contract

    path = (
        Path(__file__).resolve().parents[1]
        / "src/pajin/control_plane/web/measured-product-contracts.js"
    )
    assert path.read_text(encoding="utf-8") == measured_product_browser_contract()


@pytest.mark.parametrize(
    "raw", [b"{}", b'{"web":null,"web":null}', b'{"factory":"untrusted.call"}']
)
def test_bad_deployment_fails_before_control_plane_database_creation(
    tmp_path: Path, raw: bytes
) -> None:
    path = tmp_path / "private-config.json"
    path.write_bytes(raw)
    database = tmp_path / "cp.sqlite3"
    settings = replace(
        _settings(database),
        measured_product_deployment_path=path,
        measured_product_deployment_sha256=sha256(raw).hexdigest(),
    )
    with pytest.raises(MeasuredProductDeploymentError, match="bundle-schema") as caught:
        create_app(settings)
    assert str(tmp_path) not in str(caught.value)
    assert raw.decode() not in str(caught.value)
    assert not database.exists()


def test_digest_and_aliases_fail_before_deserialization(tmp_path: Path) -> None:
    path = tmp_path / "private.json"
    path.write_bytes(b"{}")
    with pytest.raises(MeasuredProductDeploymentError, match="bundle-digest"):
        load_measured_product_readers(path, "0" * 64)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(MeasuredProductDeploymentError, match="bundle-read"):
        load_measured_product_readers(alias, sha256(b"{}").hexdigest())


def test_graph_reopen_does_not_create_a_missing_database(tmp_path: Path) -> None:
    path = tmp_path / "absent.sqlite3"
    with pytest.raises(ValueError, match="unavailable"):
        GraphStoreReadCoordinate(path=path, campaignId="test-campaign").reopen()
    assert not path.exists()


def test_ai_deployment_roundtrip_reconstructs_and_reopens_every_request(
    ai_product_context: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ai_product_context
    recipe = AIProductRecipe.from_outcome(context.outcome)
    deployment = MeasuredProductDeployment(
        deploymentId="measured-test",
        evidenceRoot=context.root.resolve(),
        ai=recipe,
    )
    parsed = MeasuredProductDeployment.model_validate_json(
        deployment.model_dump_json(by_alias=True)
    )
    assert parsed == deployment
    material = json.loads(deployment.model_dump_json(by_alias=True))
    material["ai"]["source"]["source"]["execution"]["source_inputs"]["factory"] = "untrusted.call"
    with pytest.raises(ValidationError):
        MeasuredProductDeployment.model_validate_json(json.dumps(material))

    delegate = _FakeAIDockerRunner()
    calls = []

    def run(_self: SubprocessAIDockerCommandRunner, arguments: Any) -> Any:
        calls.append(tuple(arguments))
        return delegate.run(arguments)

    monkeypatch.setattr(SubprocessAIDockerCommandRunner, "run", run)
    config = tmp_path / "private-deployment.json"
    digest = write_measured_product_deployment(config, deployment)
    before = {path: path.read_bytes() for path in context.root.rglob("*") if path.is_file()}
    settings = replace(
        _settings(tmp_path / "cp.sqlite3"),
        measured_product_deployment_path=config,
        measured_product_deployment_sha256=digest,
    )
    with TestClient(create_app(settings)) as client:
        startup_calls = len(calls)
        response = client.get(
            "/v1/products/ai-measured-system-prompt-disclosure", headers=_auth(OPERATOR_TOKEN)
        )
        assert response.status_code == 200, response.text
        assert response.json() == context.outcome.product.model_dump(mode="json", by_alias=True)
        _browser_accepts(response.json(), "ai", tmp_path / "ai-response.json")
        assert len(calls) > startup_calls > 0
    assert {path: path.read_bytes() for path in before} == before
    probe_fresh_deployment(
        config,
        digest,
        "ai",
        context.outcome.product.product_digest,
        tmp_path / "fresh-ai",
        simulate_docker=True,
    )

    bad = deployment.model_copy(update={"evidence_root": tmp_path})
    with pytest.raises(ValueError, match="coordinate"):
        write_measured_product_deployment(tmp_path / "bad.json", bad)


def test_network_deployment_restores_public_lifecycle_and_verifies_source(
    network_product_context: Any,
    network_replay_context: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = NetworkProductRecipe.from_outcome(network_product_context.outcome)
    deployment = MeasuredProductDeployment(
        deploymentId="measured-test",
        evidenceRoot=network_replay_context.root.resolve(),
        network=recipe,
    )
    assert MeasuredProductDeployment.model_validate_json(deployment.model_dump_json()) == deployment
    assert set(deployment.model_dump(mode="json", by_alias=True)) == {
        "apiVersion", "kind", "deploymentId", "evidenceRoot", "web", "network", "ai",
    }
    delegate = _FakeDocker()

    def run(_self: SubprocessNetworkDockerCommandRunner, arguments: Any) -> Any:
        assert tuple(arguments[:2]) in {
            ("image", "inspect"),
            ("container", "ls"),
            ("network", "ls"),
        }
        return delegate.run(arguments)

    monkeypatch.setattr(SubprocessNetworkDockerCommandRunner, "run", run)
    path = tmp_path / "private-network.json"
    digest = write_measured_product_deployment(path, deployment)
    readers = load_measured_product_readers(path, digest)
    assert readers.network is not None
    assert readers.diagnostic() == {
        "web": "not-configured",
        "ai": "not-configured",
        "network": "verified",
    }
    assert readers.network.read() == network_product_context.outcome.product
    _browser_accepts(
        network_product_context.outcome.product.model_dump(mode="json", by_alias=True),
        "network",
        tmp_path / "network-response.json",
    )
    probe_fresh_deployment(
        path,
        digest,
        "network",
        network_product_context.outcome.product.product_digest,
        tmp_path / "fresh-network",
        simulate_docker=True,
    )


@pytest.mark.parametrize("entrypoint", ["module", "console"])
def test_configuration_cli_checks_environment_without_creating_database(
    tmp_path: Path, entrypoint: str
) -> None:
    database = tmp_path / "uncreated.sqlite3"
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("PAJIN_CP_")
    }
    environment.update(
        PAJIN_CP_DATABASE_URL=f"sqlite:///{database}",
        PAJIN_CP_OPERATOR_TOKEN="test-operator-for-measured-config-check",
        PAJIN_CP_APPROVER_TOKEN="test-approver-for-measured-config-check",
        PAJIN_CP_WORKER_TOKEN="test-worker-for-measured-config-check",
        PAJIN_CP_CHECKPOINT_KEY="test-checkpoint-for-measured-config-check",
    )
    invocation = (
        ["-m", "pajin.control_plane"]
        if entrypoint == "module"
        else ["-c", "from pajin.entrypoints import control_plane_main; control_plane_main()"]
    )
    command = [sys.executable, *invocation, "--check-config"]
    result = subprocess.run(
        command, env=environment, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "status": "valid",
        "measuredProducts": {
            "web": "not-configured",
            "network": "not-configured",
            "ai": "not-configured",
        },
    }
    assert not database.exists()
    path = tmp_path / "private-config.json"
    path.write_bytes(b"{}")
    environment.update(
        PAJIN_CP_MEASURED_PRODUCT_DEPLOYMENT_PATH=str(path),
        PAJIN_CP_MEASURED_PRODUCT_DEPLOYMENT_SHA256=sha256(b"{}").hexdigest(),
    )
    failed = subprocess.run(
        command, env=environment, capture_output=True, text=True, timeout=30, check=False
    )
    assert failed.returncode == 1
    assert "bundle-schema" in failed.stderr
    assert str(path) not in failed.stderr
    assert not database.exists()
