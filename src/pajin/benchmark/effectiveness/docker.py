"""Owned, bounded, port-free local llama.cpp runtime for EFFECT-001."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from time import monotonic, sleep
from typing import cast
from uuid import uuid4

from pajin.benchmark.effectiveness.evidence import Lifecycle
from pajin.benchmark.effectiveness.suite import ModelPin, RuntimePin


def docker(*args: str) -> str:
    completed = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)
    if completed.returncode:
        # CLI stderr can contain host paths and arguments. Retain a classified error only.
        raise RuntimeError(f"Docker {args[0]} failed with exit code {completed.returncode}")
    return completed.stdout.strip()


def inspect_one(kind: str, identity: str) -> dict[str, object]:
    value = json.loads(docker(kind, "inspect", identity))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError("Docker inspect must return one object")
    return cast(dict[str, object], value[0])


def object_field(value: dict[str, object], key: str) -> dict[str, object]:
    field = value[key]
    if not isinstance(field, dict):
        raise ValueError("Docker observation contains an invalid object field")
    return cast(dict[str, object], field)


def verify_model(path: Path, model: ModelPin) -> Path:
    original = path.absolute()
    if any(parent.is_symlink() for parent in (original, *original.parents)):
        raise ValueError("model path must not traverse symbolic links")
    with original.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != model.size_bytes:
            raise ValueError("model is not the registered regular GGUF file")
        if source.read(4) != b"GGUF":
            raise ValueError("model GGUF header differs")
        source.seek(0)
        measured = hashlib.file_digest(source, "sha256").hexdigest()
        after = os.fstat(source.fileno())
    identities = {
        (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        for s in (before, after, original.stat())
    }
    if measured != model.sha256 or len(identities) != 1:
        raise ValueError("model SHA-256 or file identity differs")
    return original


def verify_images(runtime: RuntimePin) -> None:
    for expected in (runtime.model_image, runtime.worker_image, runtime.proxy_image):
        observed = inspect_one("image", expected)
        if f"{observed['Os']}/{observed['Architecture']}" != runtime.platform:
            raise ValueError("Docker image platform differs from frozen runtime")
        if expected.startswith("sha256:") and observed["Id"] != expected:
            raise ValueError("Docker image identity differs from frozen runtime")
        if "@" in expected:
            digests = observed.get("RepoDigests")
            repository, pinned_digest = expected.split("@", 1)
            normalized = repository.rsplit(":", 1)[0] + "@" + pinned_digest
            if not isinstance(digests, list) or normalized not in digests:
                raise ValueError("model image registry digest differs")


class LocalModelRuntime:
    def __init__(
        self, *, runtime: RuntimePin, model: ModelPin, model_path: Path, key_file: Path
    ) -> None:
        self.runtime = runtime
        self.model = model
        self.model_path = model_path
        self.key_file = key_file
        self.owner = uuid4().hex
        self.label = f"pajin.effect-001-owner={self.owner}"
        self.network_name = f"pajin-effect-{self.owner}"
        self.container_name = f"pajin-effect-model-{self.owner}"
        self.lifecycle = Lifecycle(owner=self.owner)

    def start(self) -> None:
        started = monotonic()
        network_id = docker(
            "network", "create", "--internal", "--label", self.label, self.network_name
        )
        self._set(network_id=network_id)
        if os.getuid() == 0:
            raise ValueError("local model runtime requires an unprivileged operator")
        uid, gid = str(os.getuid()), str(os.getgid())
        container_id = docker(
            "run",
            "--detach",
            "--pull",
            "never",
            "--name",
            self.container_name,
            "--label",
            self.label,
            "--network",
            network_id,
            "--network-alias",
            "host.docker.internal",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "6144m",
            "--cpus",
            "4",
            "--platform",
            self.runtime.platform,
            "--user",
            f"{uid}:{gid}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,mode=0700,uid={uid},gid={gid},size=32m",
            "--health-interval",
            "2s",
            "--health-timeout",
            "2s",
            "--health-retries",
            "60",
            "--health-start-period",
            "10s",
            "--mount",
            f"type=bind,src={self.model_path},dst=/models/model.gguf,readonly",
            "--mount",
            f"type=bind,src={self.key_file},dst=/run/model-api-key,readonly",
            self.runtime.model_image,
            "--model",
            "/models/model.gguf",
            "--ctx-size",
            "4096",
            "--parallel",
            "1",
            "--cache-ram",
            "0",
            "--threads",
            "4",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
            "--alias",
            self.model.name,
            "--api-key-file",
            "/run/model-api-key",
        )
        self._set(container_id=container_id)
        self._verify_topology()
        while monotonic() - started < 180:
            state = object_field(inspect_one("container", container_id), "State")
            if state["Status"] != "running":
                raise RuntimeError("local model stopped before becoming healthy")
            if object_field(state, "Health")["Status"] == "healthy":
                self._set(healthy=True, startup_seconds=monotonic() - started)
                return
            sleep(1)
        raise TimeoutError("local model startup exceeded 180 seconds")

    def _verify_topology(self) -> None:
        target = inspect_one("container", self.container_name)
        host = object_field(target, "HostConfig")
        network = inspect_one("network", self.network_name)
        if (
            network.get("Internal") is not True
            or host.get("PortBindings")
            or host.get("ReadonlyRootfs") is not True
            or host.get("Memory") != 6144 * 1024 * 1024
            or host.get("NanoCpus") != 4_000_000_000
            or host.get("PidsLimit") != 128
            or host.get("CapDrop") != ["ALL"]
        ):
            raise ValueError("model resource or network isolation differs")
        self._require_owner("container", target, self.label)
        self._require_owner("network", network, self.label)
        self._set(
            model_image_id=target["Image"],
            internal_network=network["Internal"],
            published_ports=bool(host.get("PortBindings")),
            read_only=host["ReadonlyRootfs"],
            memory_bytes=host["Memory"],
            nano_cpus=host["NanoCpus"],
            pids_limit=host["PidsLimit"],
        )

    def cleanup(self, execution_ids: list[str]) -> None:
        labels = [self.label, *(f"pajin.execution-id={i}" for i in execution_ids)]
        for kind in ("container", "network"):
            for label in labels:
                for identity in docker(
                    kind,
                    "ls",
                    *(["--all"] if kind == "container" else []),
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    f"label={label}",
                ).split():
                    observed = inspect_one(kind, identity)
                    self._require_owner(kind, observed, label)
                    docker(kind, "rm", *(["--force"] if kind == "container" else []), identity)
        containers, networks = [], []
        for label in labels:
            containers.extend(
                docker("container", "ls", "--all", "--quiet", "--filter", f"label={label}").split()
            )
            networks.extend(
                docker("network", "ls", "--quiet", "--filter", f"label={label}").split()
            )
        self._set(
            execution_ids=tuple(execution_ids),
            remaining_containers=tuple(containers),
            remaining_networks=tuple(networks),
            cleanup_observed=True,
        )
        if not self.lifecycle.clean:
            raise RuntimeError("owned local evaluation resources remain after cleanup")

    @staticmethod
    def _require_owner(kind: str, observed: dict[str, object], label: str) -> None:
        key, value = label.split("=", 1)
        source = object_field(observed, "Config") if kind == "container" else observed
        if object_field(source, "Labels").get(key) != value:
            raise ValueError("Docker resource ownership differs")
        if re.fullmatch(r"[a-f0-9]{64}", str(observed["Id"])) is None:
            raise ValueError("Docker resource must use a complete immutable identity")

    def _set(self, **values: object) -> None:
        self.lifecycle = Lifecycle.model_validate({**self.lifecycle.model_dump(), **values})
