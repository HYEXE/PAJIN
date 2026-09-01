from __future__ import annotations

import importlib.util
import json
from base64 import b64decode
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import ValidationError

from pajin.runtime.worker import DockerWorkerBackend, NetworkMode, WorkerJob
from pajin.workflow.network_fixture_runtime import (
    NETWORK_BANNER_EMITTER_IMAGE,
    NETWORK_EGRESS_PROXY_IMAGE,
    NETWORK_WORKER_IMAGE,
    NetworkDockerCommandResult,
    NetworkFixtureDockerProvider,
    NetworkFixtureOperationJournal,
    NetworkFixtureProxyTopologyObservation,
    NetworkFixtureRuntimeError,
    NetworkFixtureTargetLifecycleRunner,
    NetworkMeasurementImageRole,
    NetworkSourceImageBinding,
    load_network_source_image_binding,
    registered_network_source_image_binding,
)
from pajin.workflow.network_measured_case_authority import (
    registered_network_measured_case_mapping,
)

TARGET_IMAGE_ID = "sha256:" + ("a" * 64)
WORKER_IMAGE_ID = "sha256:" + ("b" * 64)
PROXY_IMAGE_ID = "sha256:" + ("c" * 64)
TARGET_CONTAINER_ID = "1" * 64
TARGET_NETWORK_ID = "2" * 64
WORKER_CONTAINER_ID = "3" * 64
PROXY_CONTAINER_ID = "4" * 64
INTERNAL_NETWORK_ID = "5" * 64


def _emitter_module() -> ModuleType:
    path = Path("containers/network-banner-emitter/banner_emitter.py")
    spec = importlib.util.spec_from_file_location("network_banner_emitter", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _StopEmitter(RuntimeError):
    pass


class _FakeConnection:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)


class _FakeListener:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.accepted = False
        self.bound: tuple[str, int] | None = None
        self.backlog: int | None = None

    def __enter__(self) -> _FakeListener:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def setsockopt(self, *_args: object) -> None:
        return None

    def bind(self, address: tuple[str, int]) -> None:
        self.bound = address

    def listen(self, backlog: int) -> None:
        self.backlog = backlog

    def accept(self) -> tuple[_FakeConnection, tuple[str, int]]:
        if self.accepted:
            raise _StopEmitter
        self.accepted = True
        return self.connection, ("127.0.0.1", 40_000)


class _FakeDocker:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.target_exists = False
        self.network_exists = False
        self.target_name = ""
        self.network_name = ""
        self.case_id = ""
        self.labels: dict[str, str] = {}
        self.network_labels: dict[str, str] = {}
        self.banner_emitted = False
        self.attempt_sequence = 0
        self.target_container_id = TARGET_CONTAINER_ID
        self.target_network_id = TARGET_NETWORK_ID
        self.image_ids = {
            NETWORK_BANNER_EMITTER_IMAGE: TARGET_IMAGE_ID,
            NETWORK_WORKER_IMAGE: WORKER_IMAGE_ID,
            NETWORK_EGRESS_PROXY_IMAGE: PROXY_IMAGE_ID,
        }

    def run(self, arguments: Any) -> NetworkDockerCommandResult:
        command = tuple(arguments)
        self.commands.append(command)
        if command[:2] == ("image", "inspect"):
            return self._ok(self.image_ids[command[2]])
        if command[:2] == ("container", "ls"):
            return self._ok(self.target_container_id if self.target_exists else "")
        if command[:2] == ("network", "ls"):
            return self._ok(self.target_network_id if self.network_exists else "")
        if command[:2] == ("network", "create"):
            self.attempt_sequence += 1
            self.target_container_id = sha256(
                f"target-container:{self.attempt_sequence}".encode()
            ).hexdigest()
            self.target_network_id = sha256(
                f"target-network:{self.attempt_sequence}".encode()
            ).hexdigest()
            self.network_exists = True
            self.network_name = command[-1]
            self.network_labels = self._labels(command)
            return self._ok(self.target_network_id)
        if command[0] == "run":
            self.target_exists = True
            self.banner_emitted = False
            self.target_name = command[command.index("--name") + 1]
            self.labels = self._labels(command)
            self.case_id = command[-1]
            return self._ok(self.target_container_id)
        if command[0] == "logs":
            events = [
                {
                    "event": "ready",
                    "caseId": self.case_id,
                    "port": 18080,
                }
            ]
            if self.banner_emitted:
                events.append(
                    {
                        "event": "banner-emitted",
                        "caseId": self.case_id,
                        "port": 18080,
                        "sequence": 1,
                    }
                )
            return self._ok("\n".join(json.dumps(event, separators=(",", ":")) for event in events))
        if command[:2] == ("container", "inspect"):
            return self._ok(json.dumps([self._target_inspect()]))
        if command[:2] == ("network", "inspect"):
            return self._ok(json.dumps([self._network_inspect()]))
        if command[:3] == ("container", "rm", "--force"):
            self.target_exists = False
            return self._ok(self.target_container_id)
        if command[:2] == ("network", "rm"):
            self.network_exists = False
            return self._ok(self.target_network_id)
        raise AssertionError(f"unexpected fake Docker command: {command}")

    @staticmethod
    def _ok(output: str) -> NetworkDockerCommandResult:
        return NetworkDockerCommandResult(
            returncode=0,
            stdout=output.encode(),
            stderr=b"",
        )

    @staticmethod
    def _labels(command: tuple[str, ...]) -> dict[str, str]:
        labels: dict[str, str] = {}
        for index, value in enumerate(command):
            if value == "--label":
                key, item = command[index + 1].split("=", maxsplit=1)
                labels[key] = item
        return labels

    def _target_inspect(self) -> dict[str, object]:
        return {
            "Id": self.target_container_id,
            "Image": TARGET_IMAGE_ID,
            "Config": {
                "User": "65532:65532",
                "Entrypoint": ["python", "/opt/pajin/banner_emitter.py"],
                "Cmd": [self.case_id],
                "Labels": self.labels,
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PortBindings": {},
            },
            "State": {"Running": True},
            "NetworkSettings": {
                "Ports": {"18080/tcp": None},
                "Networks": {
                    self.network_name: {
                        "NetworkID": self.target_network_id,
                        "IPAddress": "172.30.0.2",
                    }
                },
            },
        }

    def _network_inspect(self) -> dict[str, object]:
        return {
            "Id": self.target_network_id,
            "Internal": True,
            "Labels": self.network_labels,
            "Containers": (
                {self.target_container_id: {"Name": self.target_name}} if self.target_exists else {}
            ),
        }


def _runtime() -> tuple[
    _FakeDocker,
    NetworkFixtureDockerProvider,
    NetworkSourceImageBinding,
]:
    docker = _FakeDocker()
    provider = NetworkFixtureDockerProvider(command_runner=docker)
    images = registered_network_source_image_binding(provider)
    return docker, provider, images


def _topology(
    *,
    execution_id: str,
    target_container_id: str,
    target_image_id: str,
    target_network_name: str,
    target_network_id: str,
    worker_container_id: str = WORKER_CONTAINER_ID,
    proxy_container_id: str = PROXY_CONTAINER_ID,
    internal_network_id: str = INTERNAL_NETWORK_ID,
    worker_container_name: str = "pajin-worker-source",
    proxy_container_name: str = "pajin-proxy-source",
    internal_network_name: str = "pajin-egress-source",
) -> NetworkFixtureProxyTopologyObservation:
    now = datetime.now(UTC)
    return NetworkFixtureProxyTopologyObservation(
        executionId=execution_id,
        workerContainerName=worker_container_name,
        workerContainerId=worker_container_id,
        workerImageId=WORKER_IMAGE_ID,
        proxyContainerName=proxy_container_name,
        proxyContainerId=proxy_container_id,
        proxyImageId=PROXY_IMAGE_ID,
        internalNetworkName=internal_network_name,
        internalNetworkId=internal_network_id,
        targetNetworkName=target_network_name,
        targetNetworkId=target_network_id,
        targetContainerId=target_container_id,
        targetImageId=target_image_id,
        workerNetworkIds=(internal_network_id,),
        proxyNetworkIds=tuple(sorted((internal_network_id, target_network_id))),
        targetNetworkIds=(target_network_id,),
        publishedPortCount=0,
        attachedAt=now,
        ephemeralResourcesAbsentAt=now,
    )


def test_banner_emitter_is_exact_case_id_only_and_never_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _emitter_module()
    private = registered_network_measured_case_mapping().private_binding
    expected = {item.case_id: b64decode(item.fixture.banner_base64) for item in private.cases}

    assert tuple(module.CASE_BANNERS) == tuple(expected)
    assert dict(module.CASE_BANNERS) == expected
    assert module.LISTEN_PORT == 18080
    with pytest.raises(ValueError):
        module.selected_case(["emitter"])
    with pytest.raises(ValueError):
        module.selected_case(["emitter", next(iter(expected)), "extra"])
    with pytest.raises(ValueError):
        module.selected_case(["emitter", "network-fixture:foreign"])

    connection = _FakeConnection()
    listener = _FakeListener(connection)
    monkeypatch.setattr(module.socket, "socket", lambda *_args: listener)
    case_id, banner = module.selected_case(["emitter", next(iter(expected))])
    with pytest.raises(_StopEmitter):
        module.serve(case_id, banner)
    assert listener.bound == ("0.0.0.0", 18080)
    assert connection.sent == [banner]
    assert not hasattr(connection, "recv")


def test_banner_emitter_dockerfile_has_no_health_probe_or_host_port_authority() -> None:
    dockerfile = Path("containers/network-banner-emitter/Dockerfile").read_text(encoding="utf-8")
    assert "python:3.12-slim@sha256:" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "EXPOSE 18080/tcp" in dockerfile
    assert 'ENTRYPOINT ["python", "/opt/pajin/banner_emitter.py"]' in dockerfile
    assert "HEALTHCHECK" not in dockerfile
    assert "CMD [" not in dockerfile


def test_runtime_image_binding_is_canonical_and_reinspected() -> None:
    docker, provider, images = _runtime()

    assert tuple(item.role for item in images.roles) == tuple(NetworkMeasurementImageRole)
    assert load_network_source_image_binding(images, inspector=provider) == images
    docker.image_ids[NETWORK_WORKER_IMAGE] = "sha256:" + ("d" * 64)
    with pytest.raises(NetworkFixtureRuntimeError, match="identity differs"):
        load_network_source_image_binding(images, inspector=provider)

    payload = images.model_dump(mode="json", by_alias=True)
    payload["roles"].reverse()
    payload["bindingId"] = ""
    payload["bindingDigest"] = ""
    with pytest.raises(ValidationError):
        NetworkSourceImageBinding.model_validate_json(json.dumps(payload))


def test_docker_worker_runtime_image_binding_preserves_logical_job_metadata() -> None:
    backend = DockerWorkerBackend(
        allowed_images={NETWORK_WORKER_IMAGE},
        runtime_image_bindings={NETWORK_WORKER_IMAGE: WORKER_IMAGE_ID},
    )
    job = WorkerJob(
        execution_id="exec_network_runtime_binding",
        image=NETWORK_WORKER_IMAGE,
        command=["network-service-identify"],
        network=NetworkMode.NONE,
    )

    arguments = backend._docker_args(job, "pajin-worker-runtime-binding")
    assert job.image == NETWORK_WORKER_IMAGE
    assert WORKER_IMAGE_ID in arguments
    assert NETWORK_WORKER_IMAGE not in arguments
    assert backend.stable_execution_context()["runtimeImageBindings"] == {
        NETWORK_WORKER_IMAGE: WORKER_IMAGE_ID
    }
    with pytest.raises(ValueError, match="OCI image IDs"):
        DockerWorkerBackend(
            allowed_images={NETWORK_WORKER_IMAGE},
            runtime_image_bindings={NETWORK_WORKER_IMAGE: "pajin-worker:mutable"},
        )


def test_network_fixture_lifecycle_is_fenced_internal_and_recoverable(
    tmp_path: Path,
) -> None:
    docker, provider, images = _runtime()
    journal = NetworkFixtureOperationJournal(tmp_path / "network-target.sqlite3")
    runner = NetworkFixtureTargetLifecycleRunner(provider=provider, journal=journal)
    case = (
        registered_network_measured_case_mapping()
        .public_authority.public_registry.cases[0]
        .reference()
    )

    live = runner.start(case=case, images=images)
    target_command = next(command for command in docker.commands if command[0] == "run")
    network_command = next(
        command for command in docker.commands if command[:2] == ("network", "create")
    )
    assert "--internal" in network_command
    assert "--publish" not in target_command
    assert "-p" not in target_command
    assert target_command[-2:] == (TARGET_IMAGE_ID, case.case_id)
    assert live.coordinate.host == "172.30.0.2"
    assert live.coordinate.port == 18080
    assert live.coordinate.published_port_count == 0

    recovery = runner.reconcile_abandoned()
    assert len(recovery) == 1
    assert recovery[0].recovery_fence > recovery[0].abandoned_fence
    assert recovery[0].measurement_eligible is False
    assert provider.managed_resources_absent()

    second = runner.start(case=case, images=images)
    docker.banner_emitted = True
    assert second.attempt.fence > recovery[0].recovery_fence
    topology = _topology(
        execution_id="exec_network_fixture_source",
        target_container_id=second.coordinate.target_container_id,
        target_image_id=second.coordinate.target_image_id,
        target_network_name=second.coordinate.target_network_name,
        target_network_id=second.coordinate.target_network_id,
    )
    evidence = runner.finish(second, topology=topology)
    assert tuple(item.record_type for item in evidence.journal_records) == (
        "intent",
        "receipt",
        "intent",
        "receipt",
        "intent",
        "receipt",
    )
    assert evidence.cleanup.resources_absent is True
    assert evidence.target_banner_emission_count == 1
    assert evidence.target_application_read_bytes == 0
    assert provider.managed_resources_absent()


def test_topology_model_rejects_direct_worker_attachment_and_published_ports() -> None:
    valid = _topology(
        execution_id="exec_network_topology",
        target_container_id=TARGET_CONTAINER_ID,
        target_image_id=TARGET_IMAGE_ID,
        target_network_name="pajin-net-target-net-test",
        target_network_id=TARGET_NETWORK_ID,
    )
    payload = valid.model_dump(mode="json", by_alias=True)
    payload["observationDigest"] = ""
    payload["workerNetworkIds"] = [INTERNAL_NETWORK_ID, TARGET_NETWORK_ID]
    with pytest.raises(ValidationError):
        NetworkFixtureProxyTopologyObservation.model_validate(payload)

    payload = valid.model_dump(mode="json", by_alias=True)
    payload["observationDigest"] = ""
    payload["publishedPortCount"] = 1
    with pytest.raises(ValidationError):
        NetworkFixtureProxyTopologyObservation.model_validate(payload)
