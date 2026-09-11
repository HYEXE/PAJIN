"""Rehearse the selected Linux/PostgreSQL/local-SQLite host in owned disposable resources.

No external URL, existing volume or host path is accepted as application state.
The controller requires Docker access. Only its newly created resources are stopped.
Restoration is passive; no restored Worker is launched.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import shutil
import time
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import TypedDict, cast
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.engine import make_url

from scripts.operational_postgres import OwnedPostgres, command, source_inventory, tls_files
from scripts.operations_cold_checkpoint import (
    ColdCheckpoint,
    ColdFile,
    ColdFiles,
    authenticate,
    encode,
    seal,
)

LABEL = "pajin.ops002-linux-owner"
PROBE = "/app/tests/operational_linux_probe.py"


class ContainerState(TypedDict):
    Running: bool
    Pid: int


class ContainerConfig(TypedDict):
    Labels: dict[str, str]


class DockerResource(TypedDict):
    Id: str
    Image: str
    Config: ContainerConfig
    Labels: dict[str, str]
    State: ContainerState


def worker_certificate(directory: Path) -> None:
    ca = x509.load_pem_x509_certificate((directory / "server.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((directory / "server.key").read_bytes(), None)
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise ValueError("owned TLS fixture requires its generated RSA CA")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned-linux-worker")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "worker.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (directory / "worker.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def image_id(value: str) -> str:
    import re

    if re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None:
        raise ValueError("an explicit locally built image ID is required")
    return value


class LinuxLab:
    def __init__(self, output: Path, runtime: str, worker: str) -> None:
        self.output = output
        self.runtime = image_id(runtime)
        self.worker = image_id(worker)
        self.owner = uuid4().hex
        self.volumes: dict[str, str] = {}
        self.containers: dict[str, str] = {}
        self.envs: dict[str, Path] = {}

    def inspect(self, kind: str, identity: str) -> DockerResource:
        item = cast(DockerResource, json.loads(command(["docker", kind, "inspect", identity]))[0])
        labels = item["Config"]["Labels"] if kind == "container" else item["Labels"]
        if labels.get(LABEL) != self.owner or (kind == "container" and item["Id"] != identity):
            raise ValueError("Linux resource ownership or identity differs")
        return item

    def volume(self, role: str) -> str:
        name = f"pajin-ops002-linux-{self.owner}-{role}"
        command(["docker", "volume", "create", "--label", f"{LABEL}={self.owner}", name])
        self.volumes[role] = name
        self.inspect("volume", name)
        return name

    def socket_group(self) -> str:
        """Observe the daemon-side socket GID only for this trusted fixture controller."""
        value = command(
            [
                "docker", "run", "--rm", "--pull", "never", "--network", "none",
                "--label", f"{LABEL}={self.owner}", "--read-only", "--user", "0:0",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "16", "--memory", "64m",
                "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
                self.runtime, "python", "-c",
                "import os,stat; s=os.stat('/var/run/docker.sock'); "
                "assert stat.S_ISSOCK(s.st_mode); print(s.st_gid)",
            ]
        ).decode().strip()
        if not value.isascii() or not value.isdecimal() or not 0 <= int(value) < 2**32 - 1:
            raise ValueError("fixture Docker socket group is not a numeric GID")
        return str(int(value))

    def configure(self, pg: OwnedPostgres, url: str, *, role: str) -> None:
        directory = self.output / ("configuration-" + role)
        directory.mkdir(mode=0o700)
        (directory / "pg").mkdir(mode=0o700)
        shutil.copyfile(pg.output / "server.crt", directory / "pg/server.crt")
        if role == "source":
            (directory / "api").mkdir(mode=0o700)
            tls_files(directory / "api")
            worker_certificate(directory / "api")
            (directory / "keys.json").write_text(
                json.dumps(
                    {"v1": secrets.token_hex(32), "v2": secrets.token_hex(32)},
                )
            )
        else:
            original = self.output / "configuration-source"
            shutil.copytree(original / "api", directory / "api")
            shutil.copyfile(original / "keys.json", directory / "keys.json")
        database = make_url(url).set(
            port=5432,
            query={
                "sslmode": "verify-full",
                "sslrootcert": "/control/pg/server.crt",
            },
        )
        env = self.output / f"{role}.env"
        env.write_text(
            f"PAJIN_TEST_POSTGRES_URL={database.render_as_string(hide_password=False)}\n"
            f"PAJIN_OPS002_OWNED=1\nPAJIN_OPS002_WORKER_IMAGE={self.worker}\n"
        )
        env.chmod(0o600)
        self.envs[role] = env
        control = self.volume("control-" + role)
        if "evidence" not in self.volumes:
            self.volume("evidence")
        state = self.volume("state-" + role)
        roots = ["/control", "/state"] + (["/evidence"] if role == "source" else [])
        args = [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--label",
            f"{LABEL}={self.owner}",
            "--read-only",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "DAC_OVERRIDE",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "32",
            "--memory",
            "128m",
            "-v",
            f"{directory}:/input:ro",
            "-v",
            f"{control}:/control",
            "-v",
            f"{state}:/state",
            "-v",
            f"{self.volumes['evidence']}:/evidence",
            self.runtime,
            "python",
            "-c",
            "import os, pathlib, shutil; "
            "shutil.copytree('/input', '/control', dirs_exist_ok=True); "
            f"roots=[pathlib.Path(p) for p in {roots!r}]; "
            "paths=[p for r in roots for p in [r,*r.rglob('*')]]; "
            "[(p.chmod(0o700 if p.is_dir() else 0o600),os.chown(p,10001,10001)) for p in paths]",
        ]
        command(args, output=self.output / f"initialize-{role}.log")

    def start(
        self, pg: OwnedPostgres, *, role: str, name: str, readonly: bool = False,
        init_process: bool = False,
    ) -> str:
        assert pg.container_id is not None
        identity = (
            command(
                [
                    "docker",
                    "run",
                    "-d",
                    *(["--init"] if init_process else []),
                    "--pull",
                    "never",
                    "--name",
                    f"pajin-ops002-linux-{self.owner}-{name}",
                    "--label",
                    f"{LABEL}={self.owner}",
                    "--network",
                    "none" if readonly else f"container:{pg.container_id}",
                    "--read-only",
                    "--user",
                    "10001:10001",
                    *([] if readonly else ["--group-add", self.socket_group()]),
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "256",
                    "--memory",
                    "1536m",
                    "--cpus",
                    "2",
                    "--restart",
                    "no",
                    "--env-file",
                    str(self.envs[role]),
                    "-v",
                    f"{self.volumes['state-' + role]}:/state" + (":ro" if readonly else ""),
                    "-v",
                    f"{self.volumes['control-' + role]}:/control:ro",
                    "-v",
                    f"{self.volumes['evidence']}:/evidence",
                    *([] if readonly else ["-v", "/var/run/docker.sock:/var/run/docker.sock"]),
                    "--tmpfs",
                    "/tmp:uid=10001,gid=10001,mode=0700,size=256m,nosuid,nodev",
                    self.runtime,
                ]
            )
            .decode()
            .strip()
        )
        self.containers[name] = identity
        item = self.inspect("container", identity)
        if not item["State"]["Running"] or item["Image"] != self.runtime:
            raise ValueError("Linux controller did not start with its pinned image")
        return identity

    def execute(
        self,
        identity: str,
        args: list[str],
        *,
        log: str,
        env: dict[str, str] | None = None,
        timeout: int = 1800,
        stdin: bytes | None = None,
    ) -> bytes:
        self.inspect("container", identity)
        env_args = [part for k, v in (env or {}).items() for part in ("-e", f"{k}={v}")]
        return command(
            ["docker", "exec", "-i", *env_args, identity, *args],
            output=self.output / (log + ".log"),
            timeout=timeout,
            stdin=stdin,
        )

    def read(self, identity: str, path: str) -> bytes:
        return self.execute(identity, ["cat", path], log="read-private-state")

    def stop(self, identity: str, *, crash: bool = False) -> None:
        item = self.inspect("container", identity)
        if item["State"]["Running"]:
            if crash:
                command(["docker", "kill", "--signal", "KILL", identity])
            else:
                command(["docker", "stop", "--time", "3", identity])
        stopped = self.inspect("container", identity)
        if stopped["State"]["Running"] or stopped["State"]["Pid"] != 0:
            raise ValueError("Linux writers are not fenced")

    def require_stopped(self) -> None:
        for identity in self.containers.values():
            if self.inspect("container", identity)["State"]["Running"]:
                raise ValueError("cold checkpoint requires all owned Linux writers stopped")

    def close(self) -> bool:
        for identity in self.containers.values():
            self.inspect("container", identity)
            command(["docker", "rm", "-f", identity])
        for volume in self.volumes.values():
            self.inspect("volume", volume)
            command(["docker", "volume", "rm", volume])
        return all(
            not command(
                [
                    "docker",
                    kind,
                    "ls",
                    "-q",
                    "--filter",
                    f"label={LABEL}={self.owner}",
                ]
            ).strip()
            for kind in ("container", "volume")
        )

    def retain_evidence(self) -> bool:
        if "evidence" not in self.volumes:
            return True
        volume = self.volumes["evidence"]
        self.inspect("volume", volume)
        content = command(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--label",
                f"{LABEL}={self.owner}",
                "--read-only",
                "--user",
                "10001:10001",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "-v",
                f"{volume}:/evidence:ro",
                self.runtime,
                "python",
                "-c",
                "import sys; from pathlib import Path; "
                "from scripts.operations_cold_checkpoint import collect,encode; "
                "p=Path('/evidence'); "
                "sys.stdout.buffer.write(encode(collect(p)) if any(p.iterdir()) else b'')",
            ]
        )
        (self.output / "private-linux-evidence.json").write_bytes(content)
        return True


def archive(
    lab: LinuxLab, pg: OwnedPostgres, expected_state: bytes, source_digest: str
) -> tuple[ColdCheckpoint, str]:
    lab.require_stopped()
    sessions = pg.pg(
        "psql",
        "-U",
        "pajin",
        "-d",
        "pajin_ops002",
        "-Atc",
        "SELECT count(*) FROM pg_stat_activity WHERE datname='pajin_ops002' "
        "AND backend_type='client backend' AND pid<>pg_backend_pid()",
    )
    if sessions.strip() != b"0":
        raise ValueError("PostgreSQL still has application connections")
    dump = pg.pg("pg_dump", "-U", "pajin", "-Fc", "pajin_ops002")
    reader = lab.start(pg, role="source", name="collector", readonly=True)
    lab.execute(reader, ["python", PROBE, "collect"], log="collect")
    local = lab.read(reader, "/evidence/local.json")
    lab.stop(reader)
    lab.require_stopped()
    checkpoint = ColdCheckpoint(
        source_sha256=source_digest,
        runtime_image=lab.runtime,
        expected_state_sha256=sha256(expected_state).hexdigest(),
        postgres=ColdFile(
            path="postgres.dump",
            sha256=sha256(dump).hexdigest(),
            content=base64.b64encode(dump).decode(),
        ),
        local=ColdFiles.model_validate_json(local),
    )
    key = secrets.token_bytes(32)
    sealed = seal(checkpoint, key)
    pin = sha256(sealed).hexdigest()
    (lab.output / "cold.checkpoint").write_bytes(sealed)
    (lab.output / "cold.key").write_bytes(key)
    (lab.output / "independent-pin.json").write_text(
        json.dumps(
            {
                "checkpoint_sha256": pin,
                "expected_state_sha256": checkpoint.expected_state_sha256,
                "source_sha256": source_digest,
                "runtime_image": lab.runtime,
            },
            indent=2,
        )
        + "\n"
    )
    verified = authenticate(
        (lab.output / "cold.checkpoint").read_bytes(), expected_sha256=pin, key=key
    )
    if verified != checkpoint:
        raise ValueError("encrypted checkpoint did not preserve the whole recovery set")
    return verified, pin


def rehearse(
    lab: LinuxLab, source: OwnedPostgres, restored: OwnedPostgres, report: dict[str, object]
) -> None:
    sources = source_inventory()
    source_bytes = (json.dumps(sources, sort_keys=True, indent=2) + "\n").encode()
    source_digest = sha256(source_bytes).hexdigest()
    (lab.output / "source-manifest.json").write_bytes(source_bytes)
    url = source.start()
    lab.configure(source, url, role="source")
    host = lab.start(source, role="source", name="host")
    # Check that the built controller actually contains the bytes under review.
    copied_sources = {p: h for p, h in sources.items() if not p.startswith("containers/")}
    actual = lab.execute(
        host,
        [
            "python",
            "-c",
            "import pathlib,hashlib,json,sys; paths=json.load(sys.stdin); "
            "hashes={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths}; "
            "print(json.dumps(hashes))",
        ],
        log="image-sources",
        stdin=json.dumps(copied_sources).encode(),
    )
    if json.loads(actual) != copied_sources:
        raise ValueError("built Linux image differs from current source")
    lab.execute(
        host,
        [
            "python",
            "-m",
            "pytest",
            "-q",
            "-o",
            "cache_dir=/tmp/pytest-cache",
            "tests/test_control_plane_postgres.py",
            "tests/test_control_plane_replay_postgres.py",
            "tests/operational_postgres_probe.py",
            "tests/test_supervisor_invocation_journal.py",
        ],
        log="linux-regression",
    )
    lab.execute(host, ["python", PROBE, "seed"], log="seed")
    expected = lab.read(host, "/evidence/state.json")
    (lab.output / "expected-state.json").write_bytes(expected)
    state = json.loads(expected)
    report["linux_runtime"] = {name: state[name] for name in ("system", "machine", "python")}
    report["worker_observation"] = state["stop"]
    report["postgres_version"] = (
        source.pg(
            "psql",
            "-U",
            "pajin",
            "-d",
            "pajin_ops002",
            "-Atc",
            "SELECT version()",
        )
        .decode()
        .strip()
    )
    env = {"PAJIN_OPS002_EXPECTED_STATE_SHA256": sha256(expected).hexdigest()}
    # Kill a serving API process, not just an already-exited Python invocation.
    command(["docker", "exec", "-d", host, "python", PROBE, "hold"])
    for attempt in range(60):
        ready = lab.execute(
            host,
            [
                "python",
                "-c",
                "from pathlib import Path; print(Path('/evidence/ready-for-loss').exists())",
            ],
            log="loss-ready",
        )
        if ready.strip() == b"True":
            break
        if attempt == 59:
            raise TimeoutError("serving Linux API was not observed before loss")
        time.sleep(0.2)
    lab.stop(host, crash=True)
    source.crash_restart(url)
    restarted = lab.start(source, role="source", name="restart")
    lab.execute(restarted, ["python", PROBE, "verify"], log="restart", env=env)
    lab.stop(restarted)
    checkpoint, pin = archive(lab, source, expected, source_digest)
    # The old complete deployment remains physically stopped during restore verification.
    assert source.container_id is not None
    source.require_owner("container", source.container_id)
    command(["docker", "stop", source.container_id])
    old_state = json.loads(command(["docker", "inspect", source.container_id]))[0]["State"]
    if old_state["Running"] or old_state["Pid"] != 0:
        raise ValueError("original PostgreSQL is not stopped before passive restore")
    destination_url = restored.start()
    lab.configure(restored, destination_url, role="restored")
    restored.pg(
        "pg_restore",
        "-U",
        "pajin",
        "--exit-on-error",
        "--single-transaction",
        "-d",
        "pajin_ops002",
        stdin=checkpoint.postgres.read(),
    )
    destination = lab.start(restored, role="restored", name="restored")
    lab.execute(
        destination,
        ["python", PROBE, "restore"],
        log="restore-local",
        env={
            "PAJIN_OPS002_LOCAL_SHA256": sha256(encode(checkpoint.local)).hexdigest(),
        },
    )
    lab.execute(destination, ["python", PROBE, "verify"], log="restore-verify", env=env)
    lab.stop(destination)
    lab.require_stopped()
    if source_inventory() != sources:
        raise ValueError("source changed during the Linux operational rehearsal")
    report.update(
        checks_passed=True,
        independent_checkpoint_sha256=pin,
        source_manifest_sha256=source_digest,
        restart="serving-Linux-container-and-PostgreSQL-loss-verified",
        restore="separate-database-and-local-volume-passively-verified",
        worker_auto_restart=False,
        external_rollback="unknown",
    )


def run(output: Path, *, runtime_image: str, worker_image: str) -> None:
    output.mkdir(mode=0o700, exist_ok=False)
    lab = LinuxLab(output, runtime_image, worker_image)
    for name in ("source-postgres", "restored-postgres"):
        (output / name).mkdir(mode=0o700)
    source = OwnedPostgres(output / "source-postgres")
    restored = OwnedPostgres(output / "restored-postgres")
    report: dict[str, object] = {
        "version": "ops002-linux-v1",
        "complete": False,
        "runtime_image": lab.runtime,
        "worker_image": lab.worker,
        "started_at": datetime.now(UTC).isoformat(),
        "cleanup": "unknown",
    }
    try:
        rehearse(lab, source, restored, report)
    finally:
        cleanup = []
        try:
            try:
                report["private_logs_retained"] = lab.retain_evidence()
            except (RuntimeError, ValueError):
                report["private_logs_retained"] = False
            finally:
                cleanup.append(lab.close())
        finally:
            try:
                cleanup.append(source.close())
            finally:
                try:
                    cleanup.append(restored.close())
                finally:
                    report["cleanup"] = "observed-absent" if cleanup == [True] * 3 else "unknown"
                    report["complete"] = (
                        report.get("checks_passed") is True
                        and cleanup == [True] * 3
                        and report.get("private_logs_retained") is True
                    )
                    report["finished_at"] = datetime.now(UTC).isoformat()
                    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                    for path in output.rglob("*"):
                        if path.is_file():
                            path.chmod(0o600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--worker-image", required=True)
    options = parser.parse_args()
    run(
        options.output.resolve(),
        runtime_image=options.runtime_image,
        worker_image=options.worker_image,
    )
