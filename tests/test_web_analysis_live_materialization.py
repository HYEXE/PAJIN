from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest

import pajin.web_assessment.analysis_capacity_v2 as live_module
from pajin.runtime.worker import DockerPreCleanupBarrierDeadlineExceeded
from pajin.web_assessment.analysis_capacity import (
    ModelDescriptorCopyObservation,
    ModelDescriptorIdentity,
    SubprocessLlamaCppTokenizerBackend,
    WebAnalysisCapacityError,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    SubprocessLlamaCppLiveMaterialization,
    VerifiedWebAnalysisCapacityV2Run,
    WebAnalysisLiveModelCleanupOnlyResult,
    WebAnalysisLiveModelProviderRouteAttestation,
    WebAnalysisLiveModelResourceAbsenceProof,
    WebAnalysisModelMaterializationAttestation,
    _create_web_analysis_capacity_v2_run_with_backend,
)
from tests.test_web_analysis_capacity_v2 import _FakeV2Tokenizer, _inputs_v2

_SEED_ID = "a" * 64
_LIVE_ID = "b" * 64
_NETWORK_ID = "c" * 64
_CLAIM_DIGEST = "d" * 64
_PROVIDER_REGISTRATION_DIGEST = "e" * 64
_PROVIDER_ENDPOINT = "http://host.docker.internal:8080/v1/chat/completions"


def _verified_capacity(tmp_path: Path) -> VerifiedWebAnalysisCapacityV2Run:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    return _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )


class _FakeDocker:
    def __init__(
        self,
        runtime: SubprocessLlamaCppLiveMaterialization,
        capacity: VerifiedWebAnalysisCapacityV2Run,
        *,
        tampered_mount: str | None = None,
        retained_resource: str | None = None,
        malformed_network_id: bool = False,
        uncertain_create: str | None = None,
        tampered_alias: str | None = None,
        foreign_network_member: bool = False,
        foreign_owner_resource: str | None = None,
    ) -> None:
        self.runtime = runtime
        self.pin = capacity.pin
        self.tampered_mount = tampered_mount
        self.retained_resource = retained_resource
        self.malformed_network_id = malformed_network_id
        self.uncertain_create = uncertain_create
        self.tampered_alias = tampered_alias
        self.foreign_network_member = foreign_network_member
        self.foreign_owner_resource = foreign_owner_resource
        self.network_exists = False
        self.volume_exists = False
        self.seed_exists = False
        self.seed_running = False
        self.live_exists = False
        self.live_running = False
        self.live_command: list[str] = []
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(arguments)
        for handler in (self._run_resource, self._run_container, self._run_exec):
            result = handler(arguments)
            if result is not None:
                return result
        raise AssertionError(arguments)

    def _run_resource(
        self,
        arguments: tuple[str, ...],
    ) -> subprocess.CompletedProcess[bytes] | None:
        if arguments[1:3] == ("image", "inspect"):
            repository_with_tag, image_digest = self.pin.tokenizer_image.rsplit("@", 1)
            expected_reference = repository_with_tag.rsplit(":", 1)[0] + "@" + image_digest
            return self._success(
                arguments,
                [
                    {
                        "Id": self.pin.tokenizer_image_id,
                        "RepoDigests": [expected_reference],
                        "Os": self.pin.model_platform.split("/", 1)[0],
                        "Architecture": self.pin.model_platform.split("/", 1)[1],
                        "Config": {"Entrypoint": ["/app/llama-server"]},
                    }
                ],
            )
        if arguments[1:3] == ("network", "create"):
            self.network_exists = True
            if self.uncertain_create == "network":
                raise WebAnalysisCapacityError("simulated uncertain network create")
            network_id = "malformed" if self.malformed_network_id else _NETWORK_ID
            return self._success(arguments, network_id + "\n", encode_json=False)
        if arguments[1:3] == ("network", "inspect"):
            return self._success(arguments, [self._network_inspection()])
        if arguments[1:3] == ("volume", "create"):
            self.volume_exists = True
            if self.uncertain_create == "volume":
                raise WebAnalysisCapacityError("simulated uncertain volume create")
            return self._success(arguments, self.runtime._volume_name + "\n", encode_json=False)
        if arguments[1:3] == ("volume", "inspect"):
            return self._success(arguments, [self._volume_inspection()])
        return None

    def _run_container(
        self,
        arguments: tuple[str, ...],
    ) -> subprocess.CompletedProcess[bytes] | None:
        if arguments[1] == "create":
            name = arguments[arguments.index("--name") + 1]
            if name == self.runtime._seed_container_name:
                self.seed_exists = True
                if self.uncertain_create == "seed":
                    raise WebAnalysisCapacityError("simulated uncertain seed create")
                return self._success(arguments, _SEED_ID + "\n", encode_json=False)
            if name == self.runtime._container_name:
                self.live_exists = True
                if self.uncertain_create == "container":
                    raise WebAnalysisCapacityError("simulated uncertain container create")
                image_index = arguments.index(self.pin.tokenizer_image)
                self.live_command = list(arguments[image_index + 1 :])
                return self._success(arguments, _LIVE_ID + "\n", encode_json=False)
        if arguments[1] == "start":
            if arguments[-1] == _SEED_ID:
                self.seed_running = True
            elif arguments[-1] == _LIVE_ID:
                self.live_running = True
            else:  # pragma: no cover - unexpected fake command
                raise AssertionError(arguments)
            return self._success(arguments, "", encode_json=False)
        if arguments[1:3] == ("container", "inspect"):
            if arguments[-1] in {_SEED_ID, self.runtime._seed_container_name}:
                return self._success(arguments, [self._seed_inspection()])
            if arguments[-1] in {_LIVE_ID, self.runtime._container_name}:
                return self._success(arguments, [self._live_inspection()])
        return None

    def _run_exec(
        self,
        arguments: tuple[str, ...],
    ) -> subprocess.CompletedProcess[bytes] | None:
        if arguments[1] == "exec":
            if arguments[-2] == "%u:%g:%a:%s":
                value = f"10001:10001:400:{self.pin.model_size_bytes}\n"
                return self._success(arguments, value, encode_json=False)
            if "/usr/bin/sha256sum" in arguments:
                value = f"{self.pin.model_sha256}  /models/model.gguf\n"
                return self._success(arguments, value, encode_json=False)
            if "/usr/bin/chown" in arguments or "/usr/bin/chmod" in arguments:
                return self._success(arguments, "", encode_json=False)
        return None

    def run_unchecked(
        self,
        arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(arguments)
        for handler in (self._run_removal, self._run_absence_query):
            result = handler(arguments)
            if result is not None:
                return result
        raise AssertionError(arguments)

    def _run_removal(
        self,
        arguments: tuple[str, ...],
    ) -> subprocess.CompletedProcess[bytes] | None:
        if arguments[1:3] == ("rm", "--force"):
            if arguments[-1] in {_SEED_ID, self.runtime._seed_container_name}:
                if self.retained_resource != "seed":
                    self.seed_exists = False
                    self.seed_running = False
            elif (
                arguments[-1] in {_LIVE_ID, self.runtime._container_name}
                and self.retained_resource != "container"
            ):
                self.live_exists = False
                self.live_running = False
            return self._success(arguments, "", encode_json=False)
        if arguments[1:3] == ("volume", "rm"):
            if self.retained_resource != "volume":
                self.volume_exists = False
            return self._success(arguments, "", encode_json=False)
        if arguments[1:3] == ("network", "rm"):
            if self.retained_resource != "network":
                self.network_exists = False
            return self._success(arguments, "", encode_json=False)
        return None

    def _run_absence_query(
        self,
        arguments: tuple[str, ...],
    ) -> subprocess.CompletedProcess[bytes] | None:
        if arguments[1:3] == ("container", "inspect"):
            name = arguments[-1]
            if name in {_SEED_ID, self.runtime._seed_container_name} and self.seed_exists:
                return self._success(arguments, [self._seed_inspection()])
            if name in {_LIVE_ID, self.runtime._container_name} and self.live_exists:
                return self._success(arguments, [self._live_inspection()])
            return self._presence(arguments, False, b"No such container")
        if arguments[1:3] == ("container", "ls"):
            owned = _LIVE_ID if self.live_exists else _SEED_ID if self.seed_exists else ""
            if self.retained_resource == "owner-label":
                owned = "d" * 64
            return self._success(arguments, owned, encode_json=False)
        if arguments[1:3] == ("volume", "inspect"):
            if self.volume_exists:
                return self._success(arguments, [self._volume_inspection()])
            return self._presence(arguments, False, b"No such volume")
        if arguments[1:3] == ("volume", "ls"):
            owned = self.runtime._volume_name if self.volume_exists else ""
            return self._success(arguments, owned, encode_json=False)
        if arguments[1:3] == ("network", "inspect"):
            if self.network_exists:
                return self._success(arguments, [self._network_inspection()])
            return self._presence(arguments, False, b"No such network")
        if arguments[1:3] == ("network", "ls"):
            owned = _NETWORK_ID if self.network_exists else ""
            return self._success(arguments, owned, encode_json=False)
        return None

    def _seed_inspection(self) -> dict[str, object]:
        return {
            "Id": _SEED_ID,
            "Name": f"/{self.runtime._seed_container_name}",
            "Image": self.pin.tokenizer_image_id,
            "Path": "/usr/bin/sleep",
            "Args": [str(self.runtime._seed_lifetime_seconds)],
            "Config": {
                "Image": self.pin.tokenizer_image,
                "User": "0:0",
                "Entrypoint": ["/usr/bin/sleep"],
                "Cmd": [str(self.runtime._seed_lifetime_seconds)],
                "Labels": {
                    "pajin.capacity-purpose": "web-analysis-live-model-seed",
                    "pajin.capacity-owner": (
                        "foreign"
                        if self.foreign_owner_resource == "seed-container"
                        else self.runtime._owner
                    ),
                },
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "CapAdd": ["CAP_CHOWN"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Privileged": False,
                "Devices": [],
                "PidMode": "",
                "UTSMode": "",
                "IpcMode": "private",
                "NanoCpus": 4_000_000_000,
                "Memory": 6144 * 1024 * 1024,
                "PidsLimit": 128,
                "PortBindings": {},
            },
            "NetworkSettings": {"Ports": {}},
            "State": {"Running": self.seed_running},
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": self.runtime._volume_name,
                    "Destination": "/models",
                    "RW": True,
                }
            ],
        }

    def _live_inspection(self) -> dict[str, object]:
        mounts: list[dict[str, object]] = [
            {
                "Type": "bind" if self.tampered_mount == "bind" else "volume",
                "Name": self.runtime._volume_name,
                "Destination": "/models",
                "RW": self.tampered_mount == "writable",
            }
        ]
        if self.tampered_mount == "extra":
            mounts.append(
                {"Type": "volume", "Name": "foreign", "Destination": "/extra", "RW": False}
            )
        aliases: list[str] = []
        if self.runtime._provider_network_alias is not None:
            aliases.extend(
                [
                    self.runtime._container_name,
                    _LIVE_ID,
                    _LIVE_ID[:12],
                    self.runtime._provider_network_alias,
                ]
            )
        if self.tampered_alias == "missing":
            aliases = []
        elif self.tampered_alias == "wrong":
            aliases = ["model.internal"]
        elif self.tampered_alias == "extra":
            aliases.append("foreign.invalid")
        return {
            "Id": _LIVE_ID,
            "Name": f"/{self.runtime._container_name}",
            "Image": self.pin.tokenizer_image_id,
            "Path": "/app/llama-server",
            "Args": self.live_command,
            "Config": {
                "Image": self.pin.tokenizer_image,
                "User": "10001:10001",
                "Cmd": self.live_command,
                "Labels": {
                    "pajin.capacity-purpose": "web-analysis-live-runtime",
                    "pajin.capacity-owner": (
                        "foreign"
                        if self.foreign_owner_resource == "runtime-container"
                        else self.runtime._owner
                    ),
                    "pajin.network-topology": "owned-internal-no-published-ports",
                    "pajin.image-id": self.pin.tokenizer_image_id,
                    "pajin.platform-manifest": self.pin.model_platform_manifest,
                },
            },
            "HostConfig": {
                "NetworkMode": self.runtime._network_name,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Privileged": False,
                "Binds": None,
                "Devices": [],
                "PidMode": "",
                "UTSMode": "",
                "IpcMode": "private",
                "NanoCpus": 4_000_000_000,
                "Memory": 6144 * 1024 * 1024,
                "PidsLimit": 128,
                "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=10001,gid=10001"},
                "PortBindings": {},
            },
            "NetworkSettings": {
                "Ports": {},
                "Networks": {
                    self.runtime._network_name: {
                        "NetworkID": _NETWORK_ID,
                        "IPAddress": "172.30.0.2",
                        "Aliases": aliases,
                    }
                },
            },
            "State": {"Running": self.live_running},
            "Mounts": mounts,
        }

    def _volume_inspection(self) -> dict[str, object]:
        return {
            "Name": self.runtime._volume_name,
            "Driver": "local",
            "Scope": "local",
            "Labels": {
                "pajin.capacity-purpose": "web-analysis-live-model",
                "pajin.capacity-owner": (
                    "foreign"
                    if self.foreign_owner_resource == "model-volume"
                    else self.runtime._owner
                ),
            },
            "Options": None,
        }

    def _network_inspection(self) -> dict[str, object]:
        containers: dict[str, object] = {}
        if self.live_exists:
            containers[_LIVE_ID] = {"Name": self.runtime._container_name}
        if self.foreign_network_member:
            containers["d" * 64] = {"Name": "foreign"}
        return {
            "Name": self.runtime._network_name,
            "Id": _NETWORK_ID,
            "Driver": "bridge",
            "Internal": True,
            "Attachable": False,
            "Ingress": False,
            "Labels": {
                "pajin.capacity-purpose": "web-analysis-live-network",
                "pajin.capacity-owner": (
                    "foreign" if self.foreign_owner_resource == "network" else self.runtime._owner
                ),
            },
            "Containers": containers,
        }

    @staticmethod
    def _success(
        arguments: tuple[str, ...],
        value: object,
        *,
        encode_json: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        stdout = json.dumps(value).encode() if encode_json else cast(str, value).encode()
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    @staticmethod
    def _presence(
        arguments: tuple[str, ...],
        exists: bool,
        missing: bytes,
    ) -> subprocess.CompletedProcess[bytes]:
        if exists:
            return subprocess.CompletedProcess(arguments, 0, b"[]", b"")
        return subprocess.CompletedProcess(arguments, 1, b"", missing)


def _descriptor_observation(
    capacity: VerifiedWebAnalysisCapacityV2Run,
    *,
    changed_inode: bool = False,
) -> ModelDescriptorCopyObservation:
    before = ModelDescriptorIdentity(
        device=1,
        inode=2,
        size_bytes=capacity.pin.model_size_bytes,
        modified_time_ns=3,
        changed_time_ns=4,
    )
    after = ModelDescriptorIdentity(
        device=before.device,
        inode=before.inode + int(changed_inode),
        size_bytes=before.size_bytes,
        modified_time_ns=before.modified_time_ns,
        changed_time_ns=before.changed_time_ns,
    )
    return ModelDescriptorCopyObservation(before=before, after=after)


def _runtime_with_fake_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    tampered_mount: str | None = None,
    retained_resource: str | None = None,
    changed_inode: bool = False,
    malformed_network_id: bool = False,
    uncertain_create: str | None = None,
    provider_network_alias: Literal["host.docker.internal"] | None = None,
    tampered_alias: str | None = None,
    foreign_network_member: bool = False,
    foreign_owner_resource: str | None = None,
) -> tuple[
    SubprocessLlamaCppLiveMaterialization,
    VerifiedWebAnalysisCapacityV2Run,
    _FakeDocker,
]:
    capacity = _verified_capacity(tmp_path)
    runtime = SubprocessLlamaCppLiveMaterialization(
        model_path=tmp_path / "model.gguf",
        provider_network_alias=provider_network_alias,
    )
    docker = _FakeDocker(
        runtime,
        capacity,
        tampered_mount=tampered_mount,
        retained_resource=retained_resource,
        malformed_network_id=malformed_network_id,
        uncertain_create=uncertain_create,
        tampered_alias=tampered_alias,
        foreign_network_member=foreign_network_member,
        foreign_owner_resource=foreign_owner_resource,
    )
    monkeypatch.setattr(runtime, "_run", docker.run)
    monkeypatch.setattr(runtime, "_run_unchecked", docker.run_unchecked)
    monkeypatch.setattr(
        runtime,
        "_copy_verified_model_descriptor",
        lambda _pin: _descriptor_observation(capacity, changed_inode=changed_inode),
    )
    return runtime, capacity, docker


def test_live_materialization_binds_capacity_and_cleans_owned_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(tmp_path, monkeypatch)

    runtime.materialize(capacity)
    attestation = runtime.live_attestation()
    assert runtime.reattest_final_view() == attestation
    assert attestation.capacity_root_digest == capacity.root_digest
    assert (
        attestation.capacity_materialization_attestation_digest
        == capacity.model_materialization_attestation_digest
    )
    assert attestation.model_dispatch_performed is False
    assert attestation.provider_dispatch_count == 0
    assert attestation.target_request_count == 0
    assert attestation.mount_type == "volume"
    assert attestation.mount_read_only is True
    assert attestation.runtime_user_read_verified is True
    with pytest.raises(WebAnalysisCapacityError, match="exposes no model endpoints"):
        runtime.get_props()

    create = next(
        command
        for command in docker.commands
        if command[1] == "create" and runtime._container_name in command
    )
    mount = create[create.index("--mount") + 1]
    assert mount == f"type=volume,src={runtime._volume_name},dst=/models,readonly"
    assert create.count("--mount") == 1
    assert "--network-alias" not in create
    assert all(not value.startswith("type=bind") for value in create)
    assert str(tmp_path / "model.gguf") not in create
    assert all(
        "/v1/chat/completions" not in part for command in docker.commands for part in command
    )

    cleanup = runtime.cleanup_and_verify_absent()
    assert cleanup.live_attestation_digest == attestation.attestation_digest
    assert cleanup.cleanup_attempted is True
    assert cleanup.owned_resources_removed is True
    assert cleanup.absence_verified is True


def test_live_materialization_adds_and_reattests_exact_provider_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        provider_network_alias="host.docker.internal",
    )

    runtime.materialize(capacity)
    route = runtime.reattest_provider_route(
        claim_digest=_CLAIM_DIGEST,
        resource_owner=runtime._owner,
        provider_registration_digest=_PROVIDER_REGISTRATION_DIGEST,
        provider_endpoint=_PROVIDER_ENDPOINT,
    )
    assert type(route) is WebAnalysisLiveModelProviderRouteAttestation
    assert route.claim_digest == _CLAIM_DIGEST
    assert route.resource_owner == runtime._owner
    assert (
        route.live_materialization_attestation_digest
        == runtime.live_attestation().attestation_digest
    )
    assert route.runtime_container_id == _LIVE_ID
    assert route.network_id == _NETWORK_ID
    assert route.provider_registration_digest == _PROVIDER_REGISTRATION_DIGEST
    assert route.provider_endpoint == _PROVIDER_ENDPOINT
    assert route.provider_endpoint_scheme == "http"
    assert route.provider_endpoint_host == "host.docker.internal"
    assert route.provider_endpoint_port == 8080
    assert route.provider_endpoint_path == "/v1/chat/completions"
    assert route.provider_network_alias == "host.docker.internal"
    assert route.provider_dispatch_authority is False
    assert route.target_request_authority is False
    assert route.execution_authority is False
    assert route.model_dispatch_performed is False
    assert route.provider_dispatch_count == 0
    assert route.target_request_count == 0
    create = next(
        command
        for command in docker.commands
        if command[1] == "create" and runtime._container_name in command
    )
    assert create[create.index("--network-alias") + 1] == "host.docker.internal"
    assert create.count("--network-alias") == 1

    runtime.cleanup_and_verify_absent()


def test_provider_route_attestation_requires_exact_alias_but_preserves_no_alias_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    runtime.materialize(capacity)

    assert runtime.reattest_final_view() == runtime.live_attestation()
    with pytest.raises(WebAnalysisCapacityError, match="requires the exact Provider network alias"):
        runtime.reattest_provider_route(
            claim_digest=_CLAIM_DIGEST,
            resource_owner=runtime._owner,
            provider_registration_digest=_PROVIDER_REGISTRATION_DIGEST,
            provider_endpoint=_PROVIDER_ENDPOINT,
        )

    runtime.cleanup_and_verify_absent()


@pytest.mark.parametrize(
    "provider_endpoint",
    (
        "https://host.docker.internal:8080/v1/chat/completions",
        "http://host.docker.internal:8080/v1/completions",
        "http://127.0.0.1:8080/v1/chat/completions",
        "http://host.docker.internal:8080/v1/chat/completions?retry=1",
    ),
)
def test_provider_route_attestation_rejects_endpoint_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_endpoint: str,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        provider_network_alias="host.docker.internal",
    )
    runtime.materialize(capacity)

    with pytest.raises(WebAnalysisCapacityError, match="endpoint differs"):
        runtime.reattest_provider_route(
            claim_digest=_CLAIM_DIGEST,
            resource_owner=runtime._owner,
            provider_registration_digest=_PROVIDER_REGISTRATION_DIGEST,
            provider_endpoint=provider_endpoint,
        )

    runtime.cleanup_and_verify_absent()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("claim_digest", "not-a-digest", "claim digest is invalid"),
        ("resource_owner", "f" * 32, "claim owner differs"),
        ("provider_registration_digest", "not-a-digest", "registration digest is invalid"),
    ),
)
def test_provider_route_attestation_rejects_foreign_claim_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    message: str,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        provider_network_alias="host.docker.internal",
    )
    runtime.materialize(capacity)
    arguments = {
        "claim_digest": _CLAIM_DIGEST,
        "resource_owner": runtime._owner,
        "provider_registration_digest": _PROVIDER_REGISTRATION_DIGEST,
        "provider_endpoint": _PROVIDER_ENDPOINT,
    }
    arguments[field] = value

    with pytest.raises(WebAnalysisCapacityError, match=message):
        runtime.reattest_provider_route(**arguments)

    runtime.cleanup_and_verify_absent()


def test_live_materialization_rejects_foreign_provider_alias(tmp_path: Path) -> None:
    with pytest.raises(WebAnalysisCapacityError, match="Provider network alias is invalid"):
        SubprocessLlamaCppLiveMaterialization(
            model_path=tmp_path / "model.gguf",
            provider_network_alias=cast(Any, "model.internal"),
        )


@pytest.mark.parametrize(
    "tamper",
    ("missing-alias", "wrong-alias", "extra-alias", "extra-member"),
)
def test_live_materialization_revalidation_rejects_provider_route_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        provider_network_alias="host.docker.internal",
    )
    runtime.materialize(capacity)
    if tamper == "missing-alias":
        docker.tampered_alias = "missing"
    elif tamper == "wrong-alias":
        docker.tampered_alias = "wrong"
    elif tamper == "extra-alias":
        docker.tampered_alias = "extra"
    else:
        docker.foreign_network_member = True

    with pytest.raises(WebAnalysisCapacityError, match=r"topology differs|member set differs"):
        runtime.reattest_provider_route(
            claim_digest=_CLAIM_DIGEST,
            resource_owner=runtime._owner,
            provider_registration_digest=_PROVIDER_REGISTRATION_DIGEST,
            provider_endpoint=_PROVIDER_ENDPOINT,
        )

    docker.foreign_network_member = False
    runtime.cleanup()
    runtime.verify_absent()


def test_live_materialization_module_has_no_legacy_runtime_dependency() -> None:
    source = Path(cast(str, live_module.__file__)).read_text(encoding="utf-8")
    assert "LocalModelRuntime" not in source
    assert "pajin.benchmark.effectiveness.docker" not in source


def test_live_materialization_rejects_unpinned_resource_profile(tmp_path: Path) -> None:
    with pytest.raises(WebAnalysisCapacityError, match="resource profile differs"):
        SubprocessLlamaCppLiveMaterialization(
            model_path=tmp_path / "model.gguf",
            cpus=2,
        )


def test_live_materialization_cleans_network_after_malformed_create_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        malformed_network_id=True,
    )

    with pytest.raises(WebAnalysisCapacityError, match="network ID is invalid"):
        runtime.materialize(capacity)

    assert docker.network_exists is True
    runtime.cleanup()
    runtime.verify_absent()
    assert docker.network_exists is False


@pytest.mark.parametrize("resource", ("network", "volume", "seed", "container"))
def test_live_materialization_recovers_resource_after_uncertain_create(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resource: str,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        uncertain_create=resource,
    )

    with pytest.raises(WebAnalysisCapacityError, match="simulated uncertain"):
        runtime.materialize(capacity)

    cleanup, proof = runtime.cleanup_owned_resources_and_verify_absent()
    assert cleanup.absence_proof_digest == proof.proof_digest
    assert cleanup.cleanup_digest != proof.proof_digest
    assert docker.network_exists is False
    assert docker.volume_exists is False
    assert docker.seed_exists is False
    assert docker.live_exists is False


def test_live_materialization_rejects_descriptor_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        changed_inode=True,
    )

    with pytest.raises(WebAnalysisCapacityError, match="descriptor identity changed"):
        runtime.materialize(capacity)

    assert docker.live_exists is False
    runtime.cleanup()
    runtime.verify_absent()


def test_live_materialization_rejects_capacity_attestation_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    payload = capacity.evidence.model_materialization_attestation.model_dump(
        mode="json",
        by_alias=True,
    )
    payload["attestationDigest"] = ""
    payload["modelPinDigest"] = "0" * 64
    foreign = WebAnalysisModelMaterializationAttestation.model_validate(payload)

    def foreign_attestation(
        _observation: object,
        *,
        pin: object,
    ) -> WebAnalysisModelMaterializationAttestation:
        del pin
        return foreign

    monkeypatch.setattr(
        live_module,
        "_attestation_from_observation",
        foreign_attestation,
    )

    with pytest.raises(WebAnalysisCapacityError, match="admitted Capacity v2 anchor"):
        runtime.materialize(capacity)

    runtime.cleanup()
    runtime.verify_absent()


@pytest.mark.parametrize("tampered_mount", ("bind", "writable", "extra"))
def test_live_materialization_rejects_mount_topology_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tampered_mount: str,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        tampered_mount=tampered_mount,
    )

    with pytest.raises(WebAnalysisCapacityError, match="topology differs"):
        runtime.materialize(capacity)

    runtime.cleanup()
    runtime.verify_absent()


def test_live_materialization_rejects_cleanup_omission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    runtime.materialize(capacity)

    with pytest.raises(WebAnalysisCapacityError, match="cleanup result is absent"):
        runtime.cleanup_result()
    with pytest.raises(WebAnalysisCapacityError, match="cleanup was not attempted"):
        runtime.verify_absent()


@pytest.mark.parametrize(
    ("retained_resource", "message"),
    (
        ("container", "container remains"),
        ("seed", "container remains"),
        ("volume", "volume remains"),
        ("network", "network remains"),
        ("owner-label", "Owned offline tokenizer resources remain"),
    ),
)
def test_live_materialization_rejects_residual_owned_resource(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retained_resource: str,
    message: str,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        retained_resource=retained_resource,
    )
    runtime.materialize(capacity)
    runtime.cleanup()

    with pytest.raises(WebAnalysisCapacityError, match=message):
        runtime.verify_absent()


@pytest.mark.parametrize("tampered_mount", ("bind", "writable", "extra"))
def test_live_materialization_revalidation_rejects_mount_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tampered_mount: str,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    runtime.materialize(capacity)
    docker.tampered_mount = tampered_mount

    with pytest.raises(WebAnalysisCapacityError, match="topology differs"):
        runtime.reattest_final_view()

    runtime.cleanup()
    runtime.verify_absent()


def test_live_cleanup_rejects_foreign_volume_owner_before_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    runtime.materialize(capacity)
    original = docker._volume_inspection

    def foreign_volume() -> dict[str, object]:
        inspection = original()
        labels = cast(dict[str, str], inspection["Labels"])
        labels["pajin.capacity-owner"] = "foreign"
        return inspection

    monkeypatch.setattr(docker, "_volume_inspection", foreign_volume)
    removal_commands = {
        ("rm", "--force"),
        ("volume", "rm"),
        ("network", "rm"),
    }
    removal_count = sum(command[1:3] in removal_commands for command in docker.commands)

    with pytest.raises(WebAnalysisCapacityError, match="resource cleanup failed") as raised:
        runtime.cleanup()

    assert "volume ownership differs" in str(raised.value.__cause__)
    assert sum(command[1:3] in removal_commands for command in docker.commands) > removal_count
    assert docker.volume_exists is True
    assert docker.live_exists is False
    assert docker.network_exists is False


def test_live_cleanup_tolerates_already_absent_owned_resource(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    runtime.materialize(capacity)
    docker.live_exists = False
    docker.live_running = False

    cleanup = runtime.cleanup_and_verify_absent()

    assert cleanup.absence_verified is True
    assert docker.volume_exists is False
    assert docker.network_exists is False


def test_cleanup_only_api_handles_normal_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    runtime.materialize(capacity)

    result, proof = runtime.cleanup_owned_resources_and_verify_absent()

    assert type(result) is WebAnalysisLiveModelCleanupOnlyResult
    assert type(proof) is WebAnalysisLiveModelResourceAbsenceProof
    assert result.removed_resources == (
        "runtime-container",
        "model-volume",
        "network",
    )
    assert result.already_absent_resources == ("seed-container",)
    assert result.absence_proof_digest == proof.proof_digest
    assert result.cleanup_digest != proof.proof_digest
    assert (
        runtime.cleanup_result().live_attestation_digest
        == runtime.live_attestation().attestation_digest
    )
    assert docker.live_exists is False
    assert docker.volume_exists is False
    assert docker.network_exists is False


@pytest.mark.parametrize(
    "process_control",
    (
        DockerPreCleanupBarrierDeadlineExceeded("injected cleanup deadline"),
        asyncio.CancelledError("injected cleanup cancellation"),
        SystemExit("injected cleanup exit"),
        KeyboardInterrupt("injected cleanup interrupt"),
    ),
    ids=("deadline", "cancelled", "system-exit", "keyboard-interrupt"),
)
def test_cleanup_only_preserves_process_control_after_all_owned_cleanup_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_control: BaseException,
) -> None:
    runtime = SubprocessLlamaCppLiveMaterialization(
        model_path=tmp_path / "model.gguf",
        resource_owner="f" * 32,
    )
    ownership_checks: list[tuple[str, str]] = []
    removal_attempts: list[tuple[str, str]] = []

    def verify_container(
        identity: str,
        *,
        expected_name: str,
        expected_purpose: str,
        allow_absent: bool,
    ) -> bool:
        assert identity == expected_name
        assert allow_absent is True
        ownership_checks.append((expected_purpose, expected_name))
        return True

    def remove_container(identity: str, *, label: str) -> None:
        removal_attempts.append((label, identity))
        if identity == runtime._container_name:
            raise process_control
        raise RuntimeError("secondary-sensitive-cleanup-detail")

    def verify_volume(*, allow_absent: bool) -> bool:
        assert allow_absent is True
        ownership_checks.append(("web-analysis-live-model", runtime._volume_name))
        return True

    def remove_volume() -> None:
        removal_attempts.append(("model volume", runtime._volume_name))

    def verify_network(*, allow_absent: bool, expected_live_member: bool) -> bool:
        assert allow_absent is True
        assert expected_live_member is False
        ownership_checks.append(("web-analysis-live-network", runtime._network_name))
        return True

    def remove_network() -> None:
        removal_attempts.append(("network", runtime._network_name))

    monkeypatch.setattr(runtime, "_verify_container_cleanup_owner", verify_container)
    monkeypatch.setattr(runtime, "_remove_container", remove_container)
    monkeypatch.setattr(runtime, "_verify_model_volume_ownership", verify_volume)
    monkeypatch.setattr(runtime, "_remove_volume", remove_volume)
    monkeypatch.setattr(runtime, "_verify_network_ownership", verify_network)
    monkeypatch.setattr(runtime, "_remove_network", remove_network)

    with pytest.raises(type(process_control)) as raised:
        runtime.cleanup_owned_resources_and_verify_absent()

    assert raised.value is process_control
    assert ownership_checks == [
        ("web-analysis-live-runtime", runtime._container_name),
        ("web-analysis-live-model-seed", runtime._seed_container_name),
        ("web-analysis-live-model", runtime._volume_name),
        ("web-analysis-live-network", runtime._network_name),
    ]
    assert removal_attempts == [
        ("live model", runtime._container_name),
        ("live model seed", runtime._seed_container_name),
        ("model volume", runtime._volume_name),
        ("network", runtime._network_name),
    ]
    notes = getattr(process_control, "__notes__", ())
    assert notes == [
        "Live model cleanup-only recovery also failed while preserving process control: "
        "exception_type=RuntimeError; stage=docker-cleanup; detail=omitted"
    ]
    assert "secondary-sensitive-cleanup-detail" not in "\n".join(notes)
    assert all(len(note) <= 256 for note in notes)


@pytest.mark.parametrize(
    ("resource", "expected_kind"),
    (
        ("container", "runtime-container"),
        ("seed", "seed-container"),
        ("volume", "model-volume"),
        ("network", "network"),
    ),
)
def test_cleanup_only_api_recovers_each_partial_resource_in_fresh_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resource: str,
    expected_kind: str,
) -> None:
    owner = "e" * 32
    capacity = _verified_capacity(tmp_path)
    original = SubprocessLlamaCppLiveMaterialization(
        model_path=tmp_path / "model.gguf",
        resource_owner=owner,
    )
    docker = _FakeDocker(original, capacity)
    setattr(docker, f"{resource}_exists" if resource != "container" else "live_exists", True)
    fresh = SubprocessLlamaCppLiveMaterialization(
        model_path=tmp_path / "model.gguf",
        resource_owner=owner,
    )
    docker.runtime = fresh
    monkeypatch.setattr(fresh, "_run_unchecked", docker.run_unchecked)

    result, proof = fresh.cleanup_owned_resources_and_verify_absent()

    assert result.removed_resources == (expected_kind,)
    assert len(result.already_absent_resources) == 3
    assert result.absence_proof_digest == proof.proof_digest
    assert result.resource_owner == owner
    assert all(command[1] not in {"create", "start"} for command in docker.commands)
    assert all(
        "/v1/chat/completions" not in part for command in docker.commands for part in command
    )


@pytest.mark.parametrize(
    ("resource", "exists_attribute"),
    (
        ("runtime-container", "live_exists"),
        ("seed-container", "seed_exists"),
        ("model-volume", "volume_exists"),
        ("network", "network_exists"),
    ),
)
def test_cleanup_only_api_refuses_foreign_owner_without_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resource: str,
    exists_attribute: str,
) -> None:
    owner = "f" * 32
    capacity = _verified_capacity(tmp_path)
    runtime = SubprocessLlamaCppLiveMaterialization(
        model_path=tmp_path / "model.gguf",
        resource_owner=owner,
    )
    docker = _FakeDocker(runtime, capacity, foreign_owner_resource=resource)
    setattr(docker, exists_attribute, True)
    monkeypatch.setattr(runtime, "_run_unchecked", docker.run_unchecked)

    with pytest.raises(WebAnalysisCapacityError, match="cleanup-only recovery failed") as raised:
        runtime.cleanup_owned_resources_and_verify_absent()

    assert "ownership differs" in str(raised.value.__cause__)
    assert getattr(docker, exists_attribute) is True


def test_cleanup_only_api_is_idempotent_for_already_absent_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    del capacity

    first, first_proof = runtime.cleanup_owned_resources_and_verify_absent()
    second, second_proof = runtime.cleanup_owned_resources_and_verify_absent()

    assert first.removed_resources == ()
    assert first.already_absent_resources == (
        "runtime-container",
        "seed-container",
        "model-volume",
        "network",
    )
    assert first == second
    assert first_proof == second_proof
    assert first.cleanup_digest != first_proof.proof_digest
    assert all(command[1] not in {"create", "start"} for command in docker.commands)


def test_absence_proof_is_independent_and_never_removes_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    del capacity

    proof = runtime.verify_owned_resources_absent()

    assert type(proof) is WebAnalysisLiveModelResourceAbsenceProof
    assert proof.resource_owner == runtime._owner
    assert all(command[1] not in {"create", "start", "rm"} for command in docker.commands)

    docker.volume_exists = True
    with pytest.raises(WebAnalysisCapacityError, match="model volume remains"):
        runtime.verify_owned_resources_absent()

    assert docker.volume_exists is True
    assert all(command[1] not in {"create", "start", "rm"} for command in docker.commands)


def test_cleanup_only_api_rejects_residual_owner_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, docker = _runtime_with_fake_docker(
        tmp_path,
        monkeypatch,
        retained_resource="owner-label",
    )
    del capacity

    with pytest.raises(WebAnalysisCapacityError, match="Owned offline tokenizer resources remain"):
        runtime.cleanup_owned_resources_and_verify_absent()

    assert all(command[1] not in {"create", "start"} for command in docker.commands)


def test_cleanup_only_and_absence_proof_digests_are_independent_and_tamper_evident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, capacity, _docker = _runtime_with_fake_docker(tmp_path, monkeypatch)
    del capacity
    cleanup, proof = runtime.cleanup_owned_resources_and_verify_absent()

    assert cleanup.cleanup_digest != proof.proof_digest
    assert cleanup.absence_proof_digest == proof.proof_digest
    cleanup_wire = cleanup.model_dump(mode="python", by_alias=True)
    cleanup_wire["cleanupDigest"] = "0" * 64
    with pytest.raises(ValueError, match="cleanup-only result digest differs"):
        WebAnalysisLiveModelCleanupOnlyResult.model_validate(cleanup_wire)
    proof_wire = proof.model_dump(mode="python", by_alias=True)
    proof_wire["proofDigest"] = "0" * 64
    with pytest.raises(ValueError, match="absence proof digest differs"):
        WebAnalysisLiveModelResourceAbsenceProof.model_validate(proof_wire)


def test_descriptor_copy_rejects_post_copy_inode_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "model.gguf"
    model_path.write_bytes(b"GGUF-pinned-model")
    runtime = SubprocessLlamaCppTokenizerBackend(model_path=model_path)
    runtime._seed_container_id = _SEED_ID
    actual_fstat = os.fstat
    calls = 0

    def changed_fstat(descriptor: int) -> Any:
        nonlocal calls
        calls += 1
        observed = actual_fstat(descriptor)
        if calls == 1:
            return observed
        return SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=observed.st_dev,
            st_ino=observed.st_ino + 1,
            st_size=observed.st_size,
            st_mtime_ns=observed.st_mtime_ns,
            st_ctime_ns=observed.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", changed_fstat)
    monkeypatch.setattr(
        runtime,
        "_run_descriptor_copy",
        lambda _descriptor: subprocess.CompletedProcess([], 0, b"", b""),
    )

    with pytest.raises(WebAnalysisCapacityError, match="identity changed during staging"):
        runtime._copy_verified_model_descriptor(
            cast(Any, SimpleNamespace(model_size_bytes=model_path.stat().st_size))
        )


@pytest.mark.skipif(
    os.environ.get("PAJIN_RUN_LIVE_MATERIALIZATION_TESTS") != "1",
    reason="requires the pinned local GGUF and a running Docker engine",
)
def test_operational_live_materialization_attests_without_dispatch(tmp_path: Path) -> None:
    model_path = Path(
        ".pajin/models/qwen3-4b-instruct-2507/qwen3-4b-instruct-2507-q8_0.gguf"
    ).resolve()
    if not model_path.is_file():
        pytest.fail("pinned local Qwen GGUF is unavailable")
    capacity = _verified_capacity(tmp_path)
    runtime = SubprocessLlamaCppLiveMaterialization(
        model_path=model_path,
        timeout_seconds=120,
    )
    try:
        runtime.materialize(capacity)
        attestation = runtime.reattest_final_view()
        assert attestation.model_dispatch_performed is False
        assert attestation.provider_dispatch_count == 0
        assert attestation.target_request_count == 0
    finally:
        runtime.cleanup()
        runtime.verify_absent()
    assert runtime.cleanup_result().live_attestation_digest == attestation.attestation_digest
