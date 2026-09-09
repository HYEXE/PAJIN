from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from pajin.control_plane import api, replay_worker_main, worker_main
from pajin.control_plane.api import ControlPlaneSettings
from pajin.control_plane.client import ControlPlaneClient
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.runtime import inventory_fingerprint
from pajin.runtime.host_gate import HostActivityError, enroll_host_gate, host_quiescence
from pajin.runtime.inventory import (
    COMPONENT_ID_ENV,
    INVENTORY_PATH_ENV,
    INVENTORY_SHA256_ENV,
    RuntimeInventory,
    RuntimeInventoryError,
    fingerprint_component,
    host_root_digest,
    load_runtime_inventory,
    verify_runtime_inventory,
)


@pytest.fixture(autouse=True)
def _without_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (INVENTORY_PATH_ENV, INVENTORY_SHA256_ENV, COMPONENT_ID_ENV):
        monkeypatch.delenv(name, raising=False)


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            "isolated-inventory-operator-token": Principal(
                subject="operator", roles=frozenset({PrincipalRole.OPERATOR}),
            ),
        },
        checkpoint_keys={"v1": b"isolated-inventory-checkpoint-key-32-bytes"},
    )


def _pin(
    path: Path, monkeypatch: pytest.MonkeyPatch, *, role: str = "control-plane",
    configuration: object | None = None,
    recovery: bool = False,
) -> RuntimeInventory:
    host_root = os.environ.get("PAJIN_HOST_RUNTIME_ROOT")
    inventory = RuntimeInventory(
        api_version=(
            "pajin.dev/runtime-inventory/v3" if recovery else
            "pajin.dev/runtime-inventory/v2" if host_root is not None
            else "pajin.dev/runtime-inventory/v1"
        ),
        inventory_id="isolated-host",
        recoveryPolicy="closed-local-sqlite-v1" if recovery else None,
        hostRootSha256=host_root_digest(Path(host_root)) if host_root is not None else None,
        components=(fingerprint_component(role, configuration=configuration),),
    )
    path.write_text(inventory.model_dump_json(by_alias=True))
    monkeypatch.setenv(INVENTORY_PATH_ENV, str(path))
    monkeypatch.setenv(INVENTORY_SHA256_ENV, hashlib.sha256(path.read_bytes()).hexdigest())
    return inventory


def test_default_cp_same_inventory_restarts_without_configuration_secrets_in_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path / "cp.db")
    path = tmp_path / "inventory.json"
    expected = _pin(path, monkeypatch, configuration=settings)
    for _ in range(2):
        with TestClient(api.create_app(settings)) as client:
            assert client.get("/healthz").status_code == 200
    observed = verify_runtime_inventory("control-plane", configuration=settings)
    assert observed == expected.components[0]
    payload = path.read_text()
    for secret in ("isolated-inventory-operator-token", "checkpoint-key-32-bytes", str(tmp_path)):
        assert secret not in payload


@pytest.mark.parametrize("change", ["key", "credential", "database", "schema", "request-timeout"])
def test_default_cp_rejects_effective_settings_drift_before_readers_or_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    from pajin.control_plane import measured_product_deployment

    settings = _settings(tmp_path / "source.db")
    _pin(tmp_path / "inventory.json", monkeypatch, configuration=settings)
    changes = {
        "key": {"checkpoint_keys": {"v1": b"substituted-inventory-checkpoint-key-bytes"}},
        "credential": {"credentials": {"replacement-inventory-operator-token": next(
            iter(settings.credentials.values()),
        )}},
        "database": {"database_url": f"sqlite:///{tmp_path / 'other.db'}"},
        "schema": {"initialize_schema": False},
        "request-timeout": {"request_body_timeout_seconds": 1.0},
    }
    changed = replace(settings, **changes[change])

    def unexpected(*_args: object, **_kwargs: object) -> None:
        pytest.fail("startup must reject drift before constructing a reader/repository")

    monkeypatch.setattr(measured_product_deployment, "load_measured_product_readers", unexpected)
    monkeypatch.setattr(api, "_build_application_context", unexpected)
    with pytest.raises(RuntimeInventoryError, match="differs"):
        api.create_app(changed)
    assert not (tmp_path / "source.db").exists()
    assert not (tmp_path / "other.db").exists()


@pytest.mark.parametrize("attribute", [
    "pentest_recon_runtime", "pentest_replay_runtime", "pentest_workflow_runtime",
    "pentest_workflow_coordination_runtime", "ai_measured_product_reader",
    "network_measured_product_reader", "web_measured_product_reader",
])
def test_pinned_default_cp_refuses_unfingerprintable_injected_collaborators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attribute: str,
) -> None:
    settings = _settings(tmp_path / "cp.db")
    _pin(tmp_path / "inventory.json", monkeypatch, configuration=settings)
    with pytest.raises(RuntimeInventoryError, match="code-owned"):
        api.create_app(settings, **{attribute: object()})
    assert not (tmp_path / "cp.db").exists()


@pytest.mark.parametrize(("module", "role"), [
    (worker_main, "worker"), (replay_worker_main, "replay-worker"),
])
def test_default_daemons_reject_drift_before_loader_backend_client_or_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: object, role: str,
) -> None:
    _pin(tmp_path / "inventory.json", monkeypatch, role=role)
    monkeypatch.setenv("PAJIN_CP_URL", "https://changed.invalid")

    def unexpected(*_args: object, **_kwargs: object) -> None:
        pytest.fail("startup must reject before opening a deployment/backend/client")

    monkeypatch.setattr(module, "ControlPlaneClient", unexpected)
    if role == "worker":
        monkeypatch.setattr(module, "_capability_graph_deployment_from_env", unexpected)
    else:
        monkeypatch.setattr(module, "DockerWorkerBackend", unexpected)
    with pytest.raises(RuntimeInventoryError, match="differs"):
        asyncio.run(module.run_from_env())


@pytest.mark.asyncio
@pytest.mark.parametrize(("host_enrolled", "recovery"), [
    (False, False),
    pytest.param(True, False, marks=pytest.mark.skipif(os.name != "posix", reason="POSIX gate")),
    pytest.param(True, True, marks=pytest.mark.skipif(os.name != "posix", reason="POSIX gate")),
])
@pytest.mark.parametrize(("module", "role", "route"), [
    (worker_main, "worker", "/v1/worker/jobs/claim"),
    (replay_worker_main, "replay-worker", "/v1/worker/replay/jobs/claim"),
])
async def test_same_inventory_reaches_normal_daemon_claim_and_stops_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: object, role: str, route: str,
    host_enrolled: bool, recovery: bool,
) -> None:
    stop = asyncio.Event()
    outputs = tmp_path / "host/state" if recovery else tmp_path
    if recovery:
        (tmp_path / "host").mkdir(mode=0o700)
        outputs.mkdir(mode=0o700)
    (outputs / "staging").mkdir(mode=0o700, parents=True)
    for name, value in {
        "PAJIN_CP_URL": "http://127.0.0.1:8090",
        "PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB": "true",
        "PAJIN_CP_WORKER_TOKEN": "isolated-inventory-worker-token-32-bytes",
        "PAJIN_CP_REPLAY_WORKER_TOKEN": "isolated-inventory-replay-token-32-bytes",
        "PAJIN_WORKER_ID": "inventory-worker",
        "PAJIN_REPLAY_WORKER_ID": "inventory-replay-worker",
        "PAJIN_REPLAY_STAGING_ROOT": str(outputs / "staging"),
        "PAJIN_DAEMON_OUTPUT_ROOT": str(outputs / "runs"),
        "PAJIN_DAEMON_STATUS_PATH": str(tmp_path / "worker-status.json"),
        "PAJIN_REPLAY_STATUS_PATH": str(tmp_path / "replay-status.json"),
    }.items():
        monkeypatch.setenv(name, value)
    root = tmp_path / "host"
    path = tmp_path / "inventory.json"
    if host_enrolled:
        monkeypatch.setenv("PAJIN_HOST_RUNTIME_ROOT", str(root))
    _pin(path, monkeypatch, role=role, recovery=recovery)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if host_enrolled:
        enroll_host_gate(root, inventory_path=path, inventory_sha256=digest)
    requests: list[httpx.Request] = []

    async def claim(request: httpx.Request) -> httpx.Response:
        if host_enrolled:
            with pytest.raises(HostActivityError), host_quiescence(
                root, inventory_path=path, inventory_sha256=digest,
            ):
                pytest.fail("claim occurred without host activity")
        requests.append(request)
        stop.set()
        return httpx.Response(204)

    def client(**kwargs: object) -> ControlPlaneClient:
        return ControlPlaneClient(**kwargs, transport=httpx.MockTransport(claim))

    monkeypatch.setattr(module, "ControlPlaneClient", client)
    monkeypatch.setattr(module, "install_stop_event", lambda: stop)
    await asyncio.wait_for(module.run_from_env(), timeout=5)
    assert len(requests) == 1
    assert requests[0].url.path == route
    assert requests[0].method == "POST"
    status = tmp_path / ("worker-status.json" if role == "worker" else "replay-status.json")
    assert status.is_file()
    assert not (outputs / "runs").exists()
    if host_enrolled:
        with host_quiescence(root, inventory_path=path, inventory_sha256=digest):
            pass


@pytest.mark.parametrize("name", [
    "PAJIN_CP_TLS_KEY_FILE", "PAJIN_CP_TLS_CA_FILE",
    "PAJIN_CAPABILITY_GRAPH_DEPLOYMENT_PATH", "PAJIN_CP_MEASURED_PRODUCT_DEPLOYMENT_PATH",
])
def test_configured_file_bytes_are_bound_not_only_their_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str,
) -> None:
    file = tmp_path / "config"
    file.write_text("isolated-configuration-before")
    monkeypatch.setenv(name, str(file))
    _pin(tmp_path / "inventory.json", monkeypatch, role="worker")
    file.write_text("isolated-configuration-after")
    with pytest.raises(RuntimeInventoryError, match="differs"):
        verify_runtime_inventory("worker")


def test_injected_cp_settings_deployment_file_is_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    file = tmp_path / "config"
    file.write_text("not-loaded-by-inventory")
    settings = replace(
        _settings(tmp_path / "cp.db"), measured_product_deployment_path=file,
        measured_product_deployment_sha256="a" * 64,
    )
    _pin(tmp_path / "inventory.json", monkeypatch, configuration=settings)
    file.write_text("changed")
    with pytest.raises(RuntimeInventoryError, match="differs"):
        api.create_app(settings)
    assert not (tmp_path / "cp.db").exists()


@pytest.mark.parametrize("entry", ["verifier.py", "web/console.js", "new-verifier.py"])
def test_source_bytes_and_file_inventory_are_pinned_without_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str,
) -> None:
    package = tmp_path / "pajin"
    (package / "runtime").mkdir(parents=True)
    (package / "web").mkdir()
    (package / "verifier.py").write_text("IMPLEMENTATION = 1\n")
    (package / "web/console.js").write_text("const value = 1;\n")
    monkeypatch.setattr(inventory_fingerprint, "__file__", str(package / "runtime/fingerprint.py"))
    _pin(tmp_path / "inventory.json", monkeypatch, role="worker")
    (package / entry).write_text("changed\n")
    with pytest.raises(RuntimeInventoryError, match="differs"):
        verify_runtime_inventory("worker")


@pytest.mark.parametrize("link", ["symlink", "hardlink", "parent-symlink"])
def test_inventory_refuses_linked_files(tmp_path: Path, link: str) -> None:
    source = tmp_path / "source"
    source.mkdir()
    file = source / "inventory.json"
    file.write_text("{}")
    other = tmp_path / "other"
    if link == "symlink":
        other.symlink_to(file)
    elif link == "hardlink":
        os.link(file, other)
    else:
        other.symlink_to(source, target_is_directory=True)
        other /= "inventory.json"
    with pytest.raises(RuntimeInventoryError, match="invalid"):
        load_runtime_inventory(other, hashlib.sha256(file.read_bytes()).hexdigest())


@pytest.mark.parametrize("content", [
    b'{}', b'{"inventoryId":"first","inventoryId":"second"}',
    b'{"extra":"secret-in-malformed-input"}', b'x' * (64 * 1024 + 1),
], ids=["missing-fields", "duplicate-field", "unknown-secret-field", "oversized"])
def test_malformed_inventory_has_secret_safe_errors(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "secret-in-filename.json"
    path.write_bytes(content)
    with pytest.raises(RuntimeInventoryError) as error:
        load_runtime_inventory(path, hashlib.sha256(content).hexdigest())
    assert "secret" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("setting", [INVENTORY_PATH_ENV, INVENTORY_SHA256_ENV, COMPONENT_ID_ENV])
def test_partial_inventory_never_becomes_legacy_startup(
    monkeypatch: pytest.MonkeyPatch, setting: str,
) -> None:
    assert verify_runtime_inventory("worker") is None
    monkeypatch.setenv(setting, "")
    with pytest.raises(RuntimeInventoryError):
        verify_runtime_inventory("worker")


def test_component_identity_and_role_are_not_interchangeable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(tmp_path / "inventory.json", monkeypatch, role="worker")
    with pytest.raises(RuntimeInventoryError, match="differs"):
        verify_runtime_inventory("replay-worker")
    monkeypatch.setenv(COMPONENT_ID_ENV, "missing-worker")
    with pytest.raises(RuntimeInventoryError, match="differs"):
        verify_runtime_inventory("worker")


def test_inventory_requires_independent_pin_and_unique_component_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "inventory.json"
    expected = _pin(path, monkeypatch, role="worker")
    with pytest.raises(RuntimeInventoryError):
        load_runtime_inventory(path, "a" * 64)
    content = expected.model_dump(mode="json", by_alias=True)
    content["components"] *= 2
    path.write_text(json.dumps(content))
    with pytest.raises(RuntimeInventoryError):
        load_runtime_inventory(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_fingerprint_refuses_callable_or_identity_only_configuration() -> None:
    with pytest.raises(RuntimeInventoryError, match="could not be verified"):
        fingerprint_component("worker", configuration={"verifier": lambda: True})


def _command(arguments: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *arguments], env=environment, text=True, capture_output=True,
        check=False, timeout=45,
    )


@pytest.mark.parametrize(("host_enrolled", "recovery"), [
    (False, False),
    pytest.param(True, False, marks=pytest.mark.skipif(os.name != "posix", reason="POSIX gate")),
    pytest.param(True, True, marks=pytest.mark.skipif(os.name != "posix", reason="POSIX gate")),
])
def test_real_cli_default_cp_and_new_process_restart_use_same_pinned_inventory(
    tmp_path: Path, host_enrolled: bool, recovery: bool,
) -> None:
    database = tmp_path / "host/state/cp.db" if recovery else tmp_path / "cp.db"
    environment = {
        **os.environ,
        "PAJIN_CP_DATABASE_URL": f"sqlite:///{database}",
        "PAJIN_CP_OPERATOR_TOKEN": "isolated-inventory-operator-token",
        "PAJIN_CP_APPROVER_TOKEN": "isolated-inventory-approver-token",
        "PAJIN_CP_WORKER_TOKEN": "isolated-inventory-worker-token-32-bytes",
        "PAJIN_CP_CHECKPOINT_KEY": "isolated-inventory-checkpoint-key-32-bytes",
    }
    if host_enrolled:
        environment["PAJIN_HOST_RUNTIME_ROOT"] = str(tmp_path / "host")
    fingerprint = _command(
        ["-m", "pajin.runtime.inventory", "fingerprint", "--role", "control-plane"], environment,
    )
    assert fingerprint.returncode == 0, fingerprint.stderr
    component_file = tmp_path / "component.json"
    component_file.write_text(fingerprint.stdout)
    composed = _command([
        "-m", "pajin.runtime.inventory", "compose", "--inventory-id", "isolated-host",
        str(component_file),
        *(["--host-root", str(tmp_path / "host")] if host_enrolled else []),
        *(["--enroll-recovery"] if recovery else []),
    ], environment)
    assert composed.returncode == 0, composed.stderr
    inventory_file = tmp_path / "inventory.json"
    inventory_file.write_text(composed.stdout)
    environment.update({
        INVENTORY_PATH_ENV: str(inventory_file),
        INVENTORY_SHA256_ENV: hashlib.sha256(inventory_file.read_bytes()).hexdigest(),
    })
    if host_enrolled:
        enrolled = _command([
            "-m", "pajin.runtime.host_gate", "enroll", "--root", str(tmp_path / "host"),
            "--inventory", str(inventory_file), "--sha256", environment[INVENTORY_SHA256_ENV],
        ], environment)
        assert enrolled.returncode == 0, enrolled.stderr
    verified = _command(
        ["-m", "pajin.runtime.inventory", "verify", "--role", "control-plane"], environment,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout) == json.loads(fingerprint.stdout)
    checked = _command(["-m", "pajin.control_plane", "--check-config"], environment)
    assert checked.returncode == 0, checked.stderr
    assert not database.exists()
    script = (
        "from fastapi.testclient import TestClient\n"
        "from pajin.control_plane.api import create_app\n"
        "with TestClient(create_app()) as client:\n"
        "    assert client.get('/healthz').status_code == 200\n"
    )
    for _ in range(2):
        started = _command(["-c", script], environment)
        assert started.returncode == 0, started.stderr
    if host_enrolled:
        idle = _command([
            "-m", "pajin.runtime.host_gate", "check-idle", "--root", str(tmp_path / "host"),
            "--inventory", str(inventory_file), "--sha256", environment[INVENTORY_SHA256_ENV],
        ], environment)
        assert idle.returncode == 0, idle.stderr
    environment["PAJIN_CP_CHECKPOINT_KEY"] = "substituted-inventory-checkpoint-key-bytes"
    rejected = _command(["-m", "pajin.control_plane", "--check-config"], environment)
    assert rejected.returncode != 0
    assert "differs from the pinned startup inventory" in rejected.stderr
    assert "substituted-inventory-checkpoint-key-bytes" not in rejected.stderr
