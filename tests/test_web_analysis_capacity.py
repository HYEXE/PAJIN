from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError

import pajin.web_assessment.analysis_capacity as capacity_module
from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin, model_pins
from pajin.runtime.store import RunIntegrityError, RunStore
from pajin.web_assessment.analysis_capacity import (
    WEB_ANALYSIS_COMPLETION_TOKENS,
    ModelDescriptorCopyObservation,
    ModelDescriptorIdentity,
    SubprocessLlamaCppTokenizerBackend,
    WebAnalysisCapacityError,
    WebAnalysisCapacityIndex,
    WebAnalysisCapacityPin,
    _conservative_campaign_prompt_bound,
    _create_web_analysis_capacity_run_with_backend,
    build_web_analysis_capacity_pin,
    create_web_analysis_capacity_run,
    load_verified_web_analysis_capacity_run,
)
from pajin.web_assessment.analysis_skill_compact import (
    COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    COMPACT_SKILL_BOUND_USER_SENTINEL,
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_projection import (
    _create_web_analysis_skill_projection_run_with_loader,
)
from tests.test_web_analysis_proposal import _synthetic_loader, _verified_source


class _FakeTokenizer:
    def __init__(
        self,
        *,
        prompt_tokens: int = 1_505,
        omit_system: bool = False,
        omit_user: bool = False,
        cleanup_failure: bool = False,
        absence_failure: bool = False,
    ) -> None:
        self.prompt_tokens = prompt_tokens
        self.omit_system = omit_system
        self.omit_user = omit_user
        self.cleanup_failure = cleanup_failure
        self.absence_failure = absence_failure
        self.calls: list[object] = []
        self.started = False

    def start(self, pin: WebAnalysisCapacityPin) -> None:
        self.calls.append(("start", pin.pin_digest))
        self.started = True

    def get_props(self) -> object:
        self.calls.append(("GET", "/props"))
        return {
            "chat_template": "{{ system }}{{ user }}",
            "default_generation_settings": {"n_ctx": 4096},
        }

    def apply_template(self, messages: object) -> object:
        self.calls.append(("POST", "/apply-template"))
        values = cast(list[dict[str, object]], messages)
        system = cast(str, values[0]["content"])
        user = cast(str, values[1]["content"])
        if self.omit_system:
            system = system.replace(COMPACT_SKILL_BOUND_SYSTEM_SENTINEL, "omitted-system")
        if self.omit_user:
            user = user.replace(COMPACT_SKILL_BOUND_USER_SENTINEL, "omitted-user")
        return {"prompt": f"<system>{system}</system><user>{user}</user>"}

    def tokenize(self, formatted_prompt: str) -> object:
        self.calls.append(
            (
                "POST",
                "/tokenize",
                {
                    "add_special": True,
                    "parse_special": True,
                    "with_pieces": False,
                },
            )
        )
        assert formatted_prompt.startswith("<system>")
        return {"tokens": list(range(self.prompt_tokens))}

    def cleanup(self) -> None:
        self.calls.append("cleanup")
        self.started = False
        if self.cleanup_failure:
            raise RuntimeError("injected cleanup failure")

    def verify_absent(self) -> None:
        self.calls.append("verify-absent")
        if self.absence_failure:
            raise RuntimeError("injected absence failure")


def _record_staging_exec(
    arguments: tuple[str, ...],
    *,
    events: list[str],
    seed_id: str,
    pin: WebAnalysisCapacityPin,
) -> bytes:
    if "/usr/bin/chown" in arguments:
        events.append("seed-chown")
        return b""
    if "/usr/bin/chmod" in arguments:
        events.append("seed-chmod")
        return b""
    if arguments[-2] == "%u:%g:%a:%s":
        events.append("staged-stat" if seed_id in arguments else "mounted-stat")
        return f"10001:10001:400:{pin.model_size_bytes}\n".encode()
    if "/usr/bin/sha256sum" in arguments:
        events.append("seed-hash" if seed_id in arguments else "mounted-hash")
        return f"{pin.model_sha256}  /models/model.gguf\n".encode()
    raise AssertionError(arguments)


def _inputs(tmp_path: Path):
    source = _verified_source()
    skill_run = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path / "skill",
        source_loader=_synthetic_loader(source),
    )
    projection = build_compact_skill_bound_web_analysis_projection(skill_run.snapshot)
    request = build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
    runtime = RuntimePin(
        platform="linux/arm64",
        platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
        worker_image="sha256:" + "1" * 64,
        proxy_image="sha256:" + "2" * 64,
    )
    pin = build_web_analysis_capacity_pin(
        skill_run,
        projection,
        request,
        runtime=runtime,
        model_pin=model_pins()[0],
        transport_pin_digest="3" * 64,
        conservative_campaign_prompt_tokens=_conservative_campaign_prompt_bound(
            request,
            model_id=model_pins()[0].name,
        ),
    )
    return skill_run, projection, request, pin


def test_capacity_public_producer_rejects_injected_backend(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    output_root = tmp_path / "capacity"

    with pytest.raises(WebAnalysisCapacityError, match=r"exact pinned llama\.cpp backend"):
        create_web_analysis_capacity_run(
            output_root,
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=cast(Any, _FakeTokenizer()),
        )

    assert not output_root.exists()


def test_tokenizer_absence_rejects_unknown_docker_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = SubprocessLlamaCppTokenizerBackend(model_path=tmp_path / "model.gguf")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=125, stdout=b"", stderr=b"daemon unavailable"
        ),
    )

    with pytest.raises(WebAnalysisCapacityError, match="absence could not be verified"):
        backend.verify_absent()


@pytest.mark.parametrize(
    ("field", "value", "rejected"),
    (
        ("control", None, False),
        ("image", "sha256:" + "9" * 64, True),
        ("mount_rw", True, True),
        ("privileged", True, True),
        ("security", ["no-new-privileges:false"], True),
        ("mount_type", "bind", True),
        ("volume_name", "foreign-volume", True),
    ),
)
def test_tokenizer_topology_rejects_runtime_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    rejected: bool,
) -> None:
    _skill_run, _projection, _request, pin = _inputs(tmp_path)
    model_path = tmp_path / "model.gguf"
    backend = SubprocessLlamaCppTokenizerBackend(model_path=model_path)
    container_id = "a" * 64
    backend._container_id = container_id
    backend._image_entrypoint = "/app/llama-server"
    command = [
        "--model",
        "/models/model.gguf",
        "--host",
        "127.0.0.1",
        "--port",
        "8080",
        "--ctx-size",
        "4096",
        "--parallel",
        "1",
        "--no-warmup",
        "--offline",
        "--no-ui",
    ]
    inspection: dict[str, object] = {
        "Id": container_id,
        "Image": pin.tokenizer_image_id,
        "Path": "/app/llama-server",
        "Args": command,
        "Config": {
            "Image": pin.tokenizer_image,
            "User": "10001:10001",
            "Cmd": command,
            "Labels": {
                "pajin.capacity-purpose": "offline-tokenizer-only",
                "pajin.capacity-owner": backend._owner,
                "pajin.network-topology": "none-loopback-only-no-published-ports",
                "pajin.image-id": pin.tokenizer_image_id,
                "pajin.platform-manifest": pin.model_platform_manifest,
            },
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "CapAdd": None,
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
        "NetworkSettings": {"Ports": {}},
        "Mounts": [
            {
                "Type": "volume",
                "Name": backend._volume_name,
                "Destination": "/models",
                "RW": False,
            }
        ],
    }
    if field == "image":
        inspection["Image"] = value
    elif field == "mount_rw":
        cast(list[dict[str, object]], inspection["Mounts"])[0]["RW"] = value
    elif field == "privileged":
        cast(dict[str, object], inspection["HostConfig"])["Privileged"] = value
    elif field == "security":
        cast(dict[str, object], inspection["HostConfig"])["SecurityOpt"] = value
    elif field == "mount_type":
        cast(list[dict[str, object]], inspection["Mounts"])[0]["Type"] = value
    elif field == "volume_name":
        cast(list[dict[str, object]], inspection["Mounts"])[0]["Name"] = value
    encoded = (json.dumps([inspection]) + "\n").encode()
    monkeypatch.setattr(
        backend,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=encoded, stderr=b""
        ),
    )

    if not rejected:
        backend._verify_topology(pin)
    else:
        with pytest.raises(WebAnalysisCapacityError, match="topology differs"):
            backend._verify_topology(pin)


@pytest.mark.parametrize(
    ("field", "value", "rejected"),
    (
        ("control", None, False),
        ("network", "bridge", True),
        ("cap_add", [], True),
        ("mount_rw", False, True),
        ("running", False, True),
    ),
)
def test_tokenizer_seed_topology_rejects_normalization_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    rejected: bool,
) -> None:
    _skill_run, _projection, _request, pin = _inputs(tmp_path)
    backend = SubprocessLlamaCppTokenizerBackend(model_path=tmp_path / "model.gguf")
    seed_id = "a" * 64
    backend._seed_container_id = seed_id
    inspection: dict[str, object] = {
        "Id": seed_id,
        "Image": pin.tokenizer_image_id,
        "Path": "/usr/bin/sleep",
        "Args": [str(backend._seed_lifetime_seconds)],
        "Config": {
            "Image": pin.tokenizer_image,
            "User": "0:0",
            "Entrypoint": ["/usr/bin/sleep"],
            "Cmd": [str(backend._seed_lifetime_seconds)],
            "Labels": {
                "pajin.capacity-purpose": "offline-tokenizer-model-seed",
                "pajin.capacity-owner": backend._owner,
            },
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "CapAdd": ["CAP_CHOWN"],
            "SecurityOpt": ["no-new-privileges"],
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
        "State": {"Running": True},
        "Mounts": [
            {
                "Type": "volume",
                "Name": backend._volume_name,
                "Destination": "/models",
                "RW": True,
            }
        ],
    }
    if field == "network":
        cast(dict[str, object], inspection["HostConfig"])["NetworkMode"] = value
    elif field == "cap_add":
        cast(dict[str, object], inspection["HostConfig"])["CapAdd"] = value
    elif field == "mount_rw":
        cast(list[dict[str, object]], inspection["Mounts"])[0]["RW"] = value
    elif field == "running":
        cast(dict[str, object], inspection["State"])["Running"] = value

    monkeypatch.setattr(
        backend,
        "_run",
        lambda arguments: subprocess.CompletedProcess(
            arguments,
            0,
            json.dumps([inspection]).encode(),
            b"",
        ),
    )

    if rejected:
        with pytest.raises(WebAnalysisCapacityError, match="seed topology differs"):
            backend._verify_seed_topology(pin)
    else:
        backend._verify_seed_topology(pin)


def test_model_staging_copies_from_held_descriptor_after_path_rebind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "model.gguf"
    original = b"GGUF-original-pinned-model-bytes"
    replacement = b"GGUF-replacement-untrusted-bytes"
    model_path.write_bytes(original)
    backend = SubprocessLlamaCppTokenizerBackend(model_path=model_path)
    backend._seed_container_id = "a" * 64
    copied: list[bytes] = []
    commands: list[tuple[str, ...]] = []

    def fake_run(arguments: tuple[str, ...], **kwargs: object):
        commands.append(arguments)
        descriptor = cast(tuple[int, ...], kwargs["pass_fds"])[0]
        model_path.rename(tmp_path / "original.gguf")
        model_path.write_bytes(replacement)
        copied.append(os.pread(descriptor, len(original), 0))
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(WebAnalysisCapacityError, match="identity changed"):
        backend._copy_verified_model_descriptor(
            cast(Any, SimpleNamespace(model_size_bytes=len(original)))
        )

    assert copied == [original]
    assert len(commands) == 1
    assert commands[0][1:3] == ("cp", "-L")
    assert commands[0][3].startswith("/dev/fd/")
    assert str(model_path) not in commands[0]


def test_staged_model_digest_mismatch_prevents_tokenizer_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _skill_run, _projection, _request, pin = _inputs(tmp_path)
    backend = SubprocessLlamaCppTokenizerBackend(model_path=tmp_path / "model.gguf")
    calls: list[tuple[str, ...]] = []
    repository_with_tag, image_digest = pin.tokenizer_image.rsplit("@", 1)
    expected_reference = repository_with_tag.rsplit(":", 1)[0] + "@" + image_digest
    image_record = [
        {
            "Id": pin.tokenizer_image_id,
            "RepoDigests": [expected_reference],
            "Os": pin.model_platform.split("/", 1)[0],
            "Architecture": pin.model_platform.split("/", 1)[1],
            "Config": {"Entrypoint": ["/app/llama-server"]},
        }
    ]

    def fake_run(arguments: tuple[str, ...], **_kwargs: object):
        calls.append(arguments)
        if arguments[1:3] == ("image", "inspect"):
            stdout = json.dumps(image_record).encode()
        elif arguments[1:3] == ("volume", "create"):
            stdout = (backend._volume_name + "\n").encode()
        elif arguments[1] == "create":
            stdout = b"a" * 64 + b"\n"
        elif arguments[1] == "start":
            stdout = b""
        elif arguments[1] == "exec" and arguments[-2] == "%u:%g:%a:%s":
            stdout = f"10001:10001:400:{pin.model_size_bytes}\n".encode()
        elif arguments[1] == "exec" and "/usr/bin/sha256sum" in arguments:
            stdout = b"0" * 64 + b"  /models/model.gguf\n"
        elif arguments[1] == "exec":
            stdout = b""
        else:  # pragma: no cover - proves no later command is admitted
            raise AssertionError(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr(backend, "_verify_seed_topology", lambda _pin: None)
    monkeypatch.setattr(backend, "_copy_verified_model_descriptor", lambda _pin: None)

    with pytest.raises(WebAnalysisCapacityError, match="Staged tokenizer model SHA-256"):
        backend.start(pin)

    assert sum(arguments[1] == "create" for arguments in calls) == 1
    assert all(backend._container_name not in arguments for arguments in calls)


def test_tokenizer_stages_and_attests_model_before_first_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _skill_run, _projection, _request, pin = _inputs(tmp_path)
    model_path = tmp_path / "model.gguf"
    backend = SubprocessLlamaCppTokenizerBackend(model_path=model_path)
    events: list[str] = []
    commands: list[tuple[str, ...]] = []
    seed_id = "a" * 64
    tokenizer_id = "b" * 64
    repository_with_tag, image_digest = pin.tokenizer_image.rsplit("@", 1)
    expected_reference = repository_with_tag.rsplit(":", 1)[0] + "@" + image_digest
    image_record = [
        {
            "Id": pin.tokenizer_image_id,
            "RepoDigests": [expected_reference],
            "Os": pin.model_platform.split("/", 1)[0],
            "Architecture": pin.model_platform.split("/", 1)[1],
            "Config": {"Entrypoint": ["/app/llama-server"]},
        }
    ]

    def fake_run(arguments: tuple[str, ...], **_kwargs: object):
        commands.append(arguments)
        if arguments[1:3] == ("image", "inspect"):
            events.append("image-inspect")
            stdout = json.dumps(image_record).encode()
        elif arguments[1:3] == ("volume", "create"):
            events.append("volume-create")
            stdout = (backend._volume_name + "\n").encode()
        elif arguments[1] == "create" and backend._seed_container_name in arguments:
            events.append("seed-create")
            stdout = (seed_id + "\n").encode()
        elif arguments[1] == "create" and backend._container_name in arguments:
            events.append("tokenizer-create")
            stdout = (tokenizer_id + "\n").encode()
        elif arguments[1] == "start" and arguments[-1] == seed_id:
            events.append("seed-start")
            stdout = (seed_id + "\n").encode()
        elif arguments[1] == "start" and arguments[-1] == tokenizer_id:
            events.append("tokenizer-start")
            stdout = (tokenizer_id + "\n").encode()
        elif arguments[1] == "exec":
            stdout = _record_staging_exec(
                arguments,
                events=events,
                seed_id=seed_id,
                pin=pin,
            )
        else:  # pragma: no cover - exact Docker sequence is part of the contract
            raise AssertionError(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    def fake_unchecked(arguments: tuple[str, ...], **_kwargs: object):
        assert arguments[:3] == ("docker", "rm", "--force")
        events.append("seed-remove")
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    def fake_request(method: str, endpoint: str, _payload: object):
        events.append(f"endpoint:{method}:{endpoint}")
        return {
            "chat_template": "{{ system }}{{ user }}",
            "default_generation_settings": {"n_ctx": 4096},
        }

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr(backend, "_run_unchecked", fake_unchecked)

    def fake_descriptor_copy(_pin: WebAnalysisCapacityPin) -> ModelDescriptorCopyObservation:
        events.append("descriptor-copy")
        identity = ModelDescriptorIdentity(
            device=1,
            inode=2,
            size_bytes=pin.model_size_bytes,
            modified_time_ns=3,
            changed_time_ns=4,
        )
        return ModelDescriptorCopyObservation(before=identity, after=identity)

    monkeypatch.setattr(backend, "_copy_verified_model_descriptor", fake_descriptor_copy)
    monkeypatch.setattr(
        backend,
        "_verify_seed_topology",
        lambda _pin: events.append("seed-topology-verified"),
    )
    monkeypatch.setattr(
        backend,
        "_verify_topology",
        lambda _pin: events.append("topology-verified"),
    )
    monkeypatch.setattr(backend, "_request", fake_request)

    backend.start(pin)

    assert events == [
        "image-inspect",
        "volume-create",
        "seed-create",
        "seed-start",
        "seed-topology-verified",
        "descriptor-copy",
        "seed-chown",
        "seed-chmod",
        "staged-stat",
        "seed-hash",
        "seed-remove",
        "tokenizer-create",
        "topology-verified",
        "tokenizer-start",
        "mounted-hash",
        "mounted-stat",
        "endpoint:GET:/props",
    ]
    assert backend._staged_model_sha256 == pin.model_sha256
    assert backend._mounted_model_sha256 == pin.model_sha256
    observation = backend.model_mount_observation()
    assert observation.model_pin_digest == pin.model_pin_digest
    assert observation.expected_model_sha256 == pin.model_sha256
    assert observation.staged_model_sha256 == pin.model_sha256
    assert observation.staged_model_uid == 10001
    assert observation.staged_model_gid == 10001
    assert observation.staged_model_mode == "0400"
    assert observation.mounted_model_sha256 == pin.model_sha256
    assert observation.mounted_model_uid == 10001
    assert observation.mounted_model_gid == 10001
    assert observation.mounted_model_mode == "0400"
    assert observation.mount_type == "volume"
    assert observation.mount_destination == "/models"
    assert observation.mount_read_only is True
    assert observation.attested_before_tokenizer_requests is True
    assert observation.runtime_user_read_verified is True
    assert all(str(model_path) not in arguments for arguments in commands)
    tokenizer_create = next(
        arguments
        for arguments in commands
        if arguments[1] == "create" and backend._container_name in arguments
    )
    mount = tokenizer_create[tokenizer_create.index("--mount") + 1]
    assert mount == f"type=volume,src={backend._volume_name},dst=/models,readonly"


def test_tokenizer_absence_rejects_residual_model_volume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = SubprocessLlamaCppTokenizerBackend(model_path=tmp_path / "model.gguf")

    def fake_run(arguments: tuple[str, ...], **_kwargs: object):
        if arguments[1:3] == ("container", "inspect"):
            return subprocess.CompletedProcess(arguments, 1, b"", b"No such container")
        if arguments[1:3] == ("container", "ls"):
            return subprocess.CompletedProcess(arguments, 0, b"", b"")
        if arguments[1:3] == ("volume", "inspect"):
            return subprocess.CompletedProcess(arguments, 0, b"[]\n", b"")
        raise AssertionError(arguments)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(WebAnalysisCapacityError, match="volume remains"):
        backend.verify_absent()


def test_tokenizer_cleanup_attempts_all_owned_resources_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = SubprocessLlamaCppTokenizerBackend(model_path=tmp_path / "model.gguf")
    backend._container_id = "a" * 64
    backend._seed_container_id = "b" * 64
    backend._container_created = True
    backend._seed_container_created = True
    backend._volume_created = True
    calls: list[tuple[str, ...]] = []
    failed_once = False

    def fake_run(arguments: tuple[str, ...], **_kwargs: object):
        nonlocal failed_once
        calls.append(arguments)
        if arguments[-1] == "a" * 64 and not failed_once:
            failed_once = True
            return subprocess.CompletedProcess(arguments, 1, b"", b"daemon failure")
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(WebAnalysisCapacityError, match="resource cleanup failed"):
        backend.cleanup()

    assert calls == [
        ("docker", "rm", "--force", "a" * 64),
        ("docker", "rm", "--force", "b" * 64),
        ("docker", "volume", "rm", backend._volume_name),
    ]
    assert backend._container_created is True
    assert backend._seed_container_created is False
    assert backend._volume_created is False

    backend.cleanup()
    assert calls[-1] == ("docker", "rm", "--force", "a" * 64)


def test_capacity_success_seals_five_artifacts_and_strictly_reloads(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    backend = _FakeTokenizer()

    verified = _create_web_analysis_capacity_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=backend,
    )

    assert verified.proof.prompt_tokens == 1_505
    assert len(verified.evidence.token_ids) == verified.proof.prompt_tokens
    assert verified.proof.evidence_digest == verified.evidence.evidence_digest
    assert verified.proof.completion_tokens == WEB_ANALYSIS_COMPLETION_TOKENS
    assert verified.proof.total_tokens == 2_529
    assert verified.proof.remaining_tokens == 1_567
    assert verified.proof.fits is True
    assert verified.proof.conservative_campaign_total_tokens == (
        pin.conservative_campaign_total_tokens
    )
    assert verified.proof.model_inference_performed is False
    assert verified.proof.provider_dispatch is False
    assert verified.proof.target_requests == 0
    assert backend.calls[1:] == [
        ("GET", "/props"),
        ("POST", "/apply-template"),
        (
            "POST",
            "/tokenize",
            {"add_special": True, "parse_special": True, "with_pieces": False},
        ),
        "cleanup",
        "verify-absent",
    ]
    assert {item.name for item in verified.run_path.iterdir() if item.name.endswith(".json")} == {
        "compact-projection.json",
        "capacity-pin.json",
        "capacity-evidence.json",
        "capacity-proof.json",
        "capacity-index.json",
    }

    reloaded = load_verified_web_analysis_capacity_run(
        verified.run_path,
        skill_run=skill_run,
        expected_run_id=verified.run_id,
        expected_root_digest=verified.root_digest,
        expected_pin_digest=pin.pin_digest,
        expected_transport_pin_digest=pin.transport_pin_digest,
    )
    assert reloaded == verified


@pytest.mark.parametrize(
    ("prompt_tokens", "accepted"),
    ((3_072, True), (3_073, False)),
)
def test_capacity_exact_context_boundary(
    tmp_path: Path,
    prompt_tokens: int,
    accepted: bool,
) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    backend = _FakeTokenizer(prompt_tokens=prompt_tokens)

    def call():
        return _create_web_analysis_capacity_run_with_backend(
            tmp_path / "capacity",
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=backend,
        )

    if accepted:
        assert call().proof.remaining_tokens == 0
    else:
        with pytest.raises(WebAnalysisCapacityError, match="measurement failed"):
            call()
    assert backend.calls[-2:] == ["cleanup", "verify-absent"]


@pytest.mark.parametrize("omission", ("system", "user"))
def test_capacity_rejects_missing_semantic_sentinel(
    tmp_path: Path,
    omission: str,
) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    backend = _FakeTokenizer(
        omit_system=omission == "system",
        omit_user=omission == "user",
    )
    with pytest.raises(WebAnalysisCapacityError, match="measurement failed"):
        _create_web_analysis_capacity_run_with_backend(
            tmp_path / "capacity",
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=backend,
        )
    assert backend.calls[-2:] == ["cleanup", "verify-absent"]


def test_capacity_rejects_wrong_pin_and_compact_lineage(tmp_path: Path) -> None:
    _skill_run, projection, request, pin = _inputs(tmp_path)
    raw = pin.model_dump(mode="json", by_alias=True)
    raw["transportPinDigest"] = "9" * 64
    with pytest.raises(ValidationError, match="Pin digest differs"):
        WebAnalysisCapacityPin.model_validate(raw)

    foreign_source = _verified_source(run_suffix="deadbeef")
    foreign_run = _create_web_analysis_skill_projection_run_with_loader(
        source=foreign_source,
        expected_source_run_id=foreign_source.verification.run_id,
        expected_source_root_digest=foreign_source.verification.root_digest,
        output_root=tmp_path / "foreign-skill",
        source_loader=_synthetic_loader(foreign_source),
    )
    with pytest.raises(WebAnalysisCapacityError, match="verified Skill snapshot"):
        _create_web_analysis_capacity_run_with_backend(
            tmp_path / "capacity",
            skill_run=foreign_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=_FakeTokenizer(),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("modelPlatformManifest", "sha256:" + "9" * 64, "RuntimePin"),
        ("tokenizerImageId", "sha256:" + "9" * 64, "RuntimePin"),
        ("tokenizerRuntimeDigest", "9" * 64, "runtime profile"),
        ("modelRevision", "unregistered-revision", "registered ModelPin"),
    ),
)
def test_capacity_pin_rejects_image_runtime_and_model_identity_drift(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    _skill_run, _projection, _request, pin = _inputs(tmp_path)
    raw = pin.model_dump(mode="json", by_alias=True)
    raw["pinDigest"] = ""
    raw[field] = value

    with pytest.raises(ValidationError, match=message):
        WebAnalysisCapacityPin.model_validate(raw)


def test_capacity_strict_reload_rejects_tamper_and_wrong_anchor(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    verified = _create_web_analysis_capacity_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeTokenizer(),
    )
    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        load_verified_web_analysis_capacity_run(
            verified.run_path,
            skill_run=skill_run,
            expected_run_id=verified.run_id,
            expected_root_digest="0" * 64,
            expected_pin_digest=pin.pin_digest,
            expected_transport_pin_digest=pin.transport_pin_digest,
        )
    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        load_verified_web_analysis_capacity_run(
            verified.run_path,
            skill_run=skill_run,
            expected_run_id=verified.run_id,
            expected_root_digest=verified.root_digest,
            expected_pin_digest=pin.pin_digest,
            expected_transport_pin_digest="4" * 64,
        )

    proof_path = verified.run_path / "capacity-proof.json"
    raw = json.loads(proof_path.read_text(encoding="utf-8"))
    raw["promptTokens"] += 1
    proof_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises((WebAnalysisCapacityError, RunIntegrityError)):
        load_verified_web_analysis_capacity_run(
            verified.run_path,
            skill_run=skill_run,
            expected_run_id=verified.run_id,
            expected_root_digest=verified.root_digest,
            expected_pin_digest=pin.pin_digest,
            expected_transport_pin_digest=pin.transport_pin_digest,
        )


def test_capacity_strict_reload_recomputes_campaign_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    verified = _create_web_analysis_capacity_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeTokenizer(),
    )
    monkeypatch.setattr(
        capacity_module,
        "_conservative_campaign_prompt_bound",
        lambda _request, *, model_id: pin.conservative_campaign_prompt_tokens + 1,
    )

    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        load_verified_web_analysis_capacity_run(
            verified.run_path,
            skill_run=skill_run,
            expected_run_id=verified.run_id,
            expected_root_digest=verified.root_digest,
            expected_pin_digest=pin.pin_digest,
            expected_transport_pin_digest=pin.transport_pin_digest,
        )


def test_capacity_strict_reload_rejects_a_second_seal(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    verified = _create_web_analysis_capacity_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeTokenizer(),
    )
    extension = RunStore(verified.run_id, verified.run_path)
    extension.append_event("web-analysis.capacity-proof.unexpected-extension", {})
    second_seal = extension.seal()

    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        load_verified_web_analysis_capacity_run(
            verified.run_path,
            skill_run=skill_run,
            expected_run_id=verified.run_id,
            expected_root_digest=second_seal.root_digest,
            expected_pin_digest=pin.pin_digest,
            expected_transport_pin_digest=pin.transport_pin_digest,
        )


def test_capacity_strict_reload_rejects_defaulted_wire_fields(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    verified = _create_web_analysis_capacity_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeTokenizer(),
    )
    projection_raw = json.loads(
        (verified.run_path / "compact-projection.json").read_text(encoding="utf-8")
    )
    pin_raw = json.loads((verified.run_path / "capacity-pin.json").read_text(encoding="utf-8"))
    evidence_raw = json.loads(
        (verified.run_path / "capacity-evidence.json").read_text(encoding="utf-8")
    )
    proof_raw = json.loads((verified.run_path / "capacity-proof.json").read_text(encoding="utf-8"))
    pin_raw.pop("offline")
    forged = RunStore.create(tmp_path / "forged", "web-analysis-capacity-proof")
    index = WebAnalysisCapacityIndex(
        runId=forged.run_id,
        projectionDigest=verified.projection_digest,
        pinDigest=pin.pin_digest,
        evidenceDigest=verified.evidence.evidence_digest,
        proofDigest=verified.proof.proof_digest,
    )
    forged.append_event(
        "web-analysis.capacity-proof.started",
        {
            "pinDigest": pin.pin_digest,
            "projectionDigest": verified.projection_digest,
            "requestDigest": pin.chat_request_digest,
            "modelInferencePerformed": False,
            "providerDispatch": False,
            "targetRequests": 0,
        },
    )
    forged.write_json_create_only("compact-projection.json", projection_raw)
    forged.write_json_create_only("capacity-pin.json", pin_raw)
    forged.write_json_create_only("capacity-evidence.json", evidence_raw)
    forged.write_json_create_only("capacity-proof.json", proof_raw)
    forged.write_json_create_only(
        "capacity-index.json", index.model_dump(mode="json", by_alias=True)
    )
    forged.append_event(
        "web-analysis.capacity-proof.completed",
        {
            "indexDigest": index.index_digest,
            "evidenceDigest": verified.evidence.evidence_digest,
            "proofDigest": verified.proof.proof_digest,
            "promptTokens": verified.proof.prompt_tokens,
            "totalTokens": verified.proof.total_tokens,
            "remainingTokens": verified.proof.remaining_tokens,
            "modelInferencePerformed": False,
            "providerDispatch": False,
            "targetRequests": 0,
        },
    )
    seal = forged.seal()

    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        load_verified_web_analysis_capacity_run(
            forged.path,
            skill_run=skill_run,
            expected_run_id=forged.run_id,
            expected_root_digest=seal.root_digest,
            expected_pin_digest=pin.pin_digest,
            expected_transport_pin_digest=pin.transport_pin_digest,
        )


@pytest.mark.parametrize(("cleanup_failure", "absence_failure"), ((True, False), (False, True)))
def test_capacity_cleanup_failure_is_never_reported_as_success(
    tmp_path: Path,
    cleanup_failure: bool,
    absence_failure: bool,
) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    backend = _FakeTokenizer(
        cleanup_failure=cleanup_failure,
        absence_failure=absence_failure,
    )
    with pytest.raises(WebAnalysisCapacityError, match="cleanup"):
        _create_web_analysis_capacity_run_with_backend(
            tmp_path / "capacity",
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=backend,
        )
    assert backend.calls[-2:] == ["cleanup", "verify-absent"]


@pytest.mark.parametrize(("cleanup_failure", "absence_failure"), ((True, False), (False, True)))
def test_capacity_cleanup_failure_takes_priority_over_measurement_failure(
    tmp_path: Path,
    cleanup_failure: bool,
    absence_failure: bool,
) -> None:
    skill_run, projection, request, pin = _inputs(tmp_path)
    backend = _FakeTokenizer(
        prompt_tokens=4_096,
        cleanup_failure=cleanup_failure,
        absence_failure=absence_failure,
    )

    with pytest.raises(
        WebAnalysisCapacityError,
        match="cleanup did not prove container absence",
    ):
        _create_web_analysis_capacity_run_with_backend(
            tmp_path / "capacity",
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=backend,
        )

    assert backend.calls[-2:] == ["cleanup", "verify-absent"]
