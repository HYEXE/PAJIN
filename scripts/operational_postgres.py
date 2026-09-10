"""Create an owned PostgreSQL lab, run real-server probes, crash, restore, and clean up.

This command never accepts a database URL or reuses an existing container/volume.
Private credentials, dump and logs stay in a new output directory. It does not
admit a production deployment or claim atomic recovery of SQLite/Run stores.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import OperationalError

IMAGE = (
    "postgres:17.11-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73"
)
LABEL = "pajin.ops-002-owner"
ROOT = Path(__file__).resolve().parents[1]


def command(
    args: list[str], *, output: Path | None = None, timeout: int = 120, stdin: bytes | None = None
) -> bytes:
    result = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout, check=False)
    if output is not None:
        output.write_bytes(result.stdout + result.stderr)
        output.chmod(0o600)
    if result.returncode:
        # Database diagnostics may contain credential-bearing URLs. Keep them private.
        raise RuntimeError(f"{args[0]} failed with exit {result.returncode}; inspect private log")
    return result.stdout


def tls_files(directory: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pajin-owned-postgres-lab")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (directory / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (directory / "pg_hba.conf").write_text(
        "local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\n"
        "hostssl all all ::/0 scram-sha-256\n"
    )
    for file in directory.iterdir():
        file.chmod(0o600)


class OwnedPostgres:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.owner = uuid4().hex
        self.name = "pajin-ops002-" + self.owner
        self.volume = self.name + "-data"
        self.container_id: str | None = None
        self.volume_created = False
        self.password = secrets.token_hex(24)

    def start(self) -> str:
        tls_files(self.output)
        env_file = self.output / "postgres.env"
        env_file.write_text(
            f"POSTGRES_USER=pajin\nPOSTGRES_PASSWORD={self.password}\n"
            "POSTGRES_DB=pajin_ops002\nPGDATA=/state/data\nPOSTGRES_INITDB_ARGS=--auth-host=scram-sha-256\n"
        )
        env_file.chmod(0o600)
        command(["docker", "volume", "create", "--label", f"{LABEL}={self.owner}", self.volume])
        self.volume_created = True
        command(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--label",
                f"{LABEL}={self.owner}",
                "--user",
                "0:0",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                "64m",
                "--cpus",
                "0.5",
                "-v",
                f"{self.volume}:/state",
                "-v",
                f"{self.output}:/input:ro",
                "--entrypoint",
                "sh",
                IMAGE,
                "-ec",
                "mkdir /state/data /state/tls; cp /input/server.crt /input/server.key "
                "/input/pg_hba.conf /state/tls/; chmod 700 /state/data; chown -R 70:70 /state",
            ],
            output=self.output / "init.log",
        )
        self.container_id = (
            command(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    self.name,
                    "--pull",
                    "never",
                    "--read-only",
                    "--label",
                    f"{LABEL}={self.owner}",
                    "--user",
                    "70:70",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "128",
                    "--memory",
                    "512m",
                    "--cpus",
                    "2",
                    "--restart",
                    "no",
                    "--env-file",
                    str(env_file),
                    "-p",
                    "127.0.0.1::5432",
                    "-v",
                    f"{self.volume}:/state",
                    "--tmpfs",
                    "/run/postgresql:uid=70,gid=70,mode=0700",
                    "--tmpfs",
                    "/tmp:mode=1777,size=32m,noexec,nosuid,nodev",
                    IMAGE,
                    "postgres",
                    "-c",
                    "ssl=on",
                    "-c",
                    "ssl_cert_file=/state/tls/server.crt",
                    "-c",
                    "ssl_key_file=/state/tls/server.key",
                    "-c",
                    "hba_file=/state/tls/pg_hba.conf",
                ],
                output=self.output / "start.log",
            )
            .decode()
            .strip()
        )
        port = command(["docker", "port", self.container_id, "5432/tcp"]).decode().strip()
        if not port.startswith("127.0.0.1:") or "\n" in port:
            raise ValueError("database port is not exclusively loopback")
        url = URL.create(
            "postgresql+psycopg",
            username="pajin",
            password=self.password,
            host="127.0.0.1",
            port=int(port.rsplit(":", 1)[1]),
            database="pajin_ops002",
            query={"sslmode": "verify-full", "sslrootcert": str(self.output / "server.crt")},
        )
        value = url.render_as_string(hide_password=False)
        self.wait_ready(value)
        return value

    @staticmethod
    def wait_ready(url: str) -> None:
        engine = create_engine(url, connect_args={"connect_timeout": 2})
        try:
            for attempt in range(40):
                try:
                    with engine.connect() as connection:
                        if (
                            connection.scalar(
                                text("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
                            )
                            is not True
                        ):
                            raise ValueError("PostgreSQL connection is not TLS")
                    return
                except OperationalError:
                    if attempt == 39:
                        raise
                    time.sleep(0.5)
        finally:
            engine.dispose()

    def require_owner(self, kind: str, name: str) -> None:
        data = json.loads(command(["docker", kind, "inspect", name]))[0]
        labels = data["Config"]["Labels"] if kind == "container" else data["Labels"]
        if labels.get(LABEL) != self.owner:
            raise ValueError("refusing mutation of a resource with different ownership")
        if kind == "container" and data["Id"] != self.container_id:
            raise ValueError("owned container identity changed")

    def crash_restart(self, url: str) -> str:
        assert self.container_id is not None
        self.require_owner("container", self.container_id)
        command(["docker", "kill", "--signal", "KILL", self.container_id])
        command(["docker", "start", self.container_id])
        port = command(["docker", "port", self.container_id, "5432/tcp"]).decode().strip()
        if not port.startswith("127.0.0.1:") or "\n" in port:
            raise ValueError("restarted database port is not exclusively loopback")
        # Docker can assign another host port when restarting an ephemeral published port.
        restarted = make_url(url).set(port=int(port.rsplit(":", 1)[1]))
        value = restarted.render_as_string(hide_password=False)
        self.wait_ready(value)
        return value

    def pg(self, *args: str, stdin: bytes | None = None) -> bytes:
        assert self.container_id is not None
        self.require_owner("container", self.container_id)
        return command(
            ["docker", "exec", "-i", self.container_id, *args],
            stdin=stdin,
            output=self.output / "database-command.log" if stdin is not None else None,
        )

    def close(self) -> bool:
        if self.container_id is not None:
            self.require_owner("container", self.container_id)
            command(["docker", "logs", self.container_id], output=self.output / "postgres.log")
            command(["docker", "rm", "-f", self.container_id])
        if self.volume_created:
            self.require_owner("volume", self.volume)
            command(["docker", "volume", "rm", self.volume])
        for kind in ("container", "volume"):
            if command(
                ["docker", kind, "ls", "-q", "--filter", f"label={LABEL}={self.owner}"]
            ).strip():
                return False
        return True


def child(output: Path, name: str, args: list[str], url: str, worker_image: str) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PAJIN_")}
    env.update(
        PAJIN_TEST_POSTGRES_URL=url, PAJIN_OPS002_OWNED="1", PAJIN_OPS002_WORKER_IMAGE=worker_image
    )
    with (output / (name + ".log")).open("wb") as log:
        result = subprocess.run(
            [sys.executable, *args],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=1800,
            check=False,
        )
    if result.returncode:
        raise RuntimeError(f"{name} failed; inspect the private log")


def require_checkpoint(output: Path, pin: dict[str, str]) -> None:
    for filename, key in (("db.dump", "archive_sha256"), ("state.json", "state_sha256")):
        if sha256((output / filename).read_bytes()).hexdigest() != pin[key]:
            raise ValueError("independent checkpoint pin differs")


def source_inventory() -> dict[str, str]:
    paths = [ROOT / "pyproject.toml", ROOT / "uv.lock"]
    for directory in ("src", "scripts", "tests", "containers", "examples"):
        paths.extend(
            path
            for path in (ROOT / directory).rglob("*")
            if path.is_file()
            and (path.suffix in {".py", ".yaml", ".lock", ".toml"} or path.name == "Dockerfile")
        )
    return {
        str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
        for path in sorted(set(paths))
    }


def run(output: Path, *, worker_image: str = "") -> None:
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    if re.fullmatch(r"sha256:[a-f0-9]{64}", worker_image) is None:
        raise ValueError("an explicit built Worker image ID is required")
    lab = OwnedPostgres(output)
    sources = source_inventory()
    (output / "source-manifest.json").write_text(
        json.dumps(sources, sort_keys=True, indent=2) + "\n"
    )
    report: dict[str, object] = {
        "version": "ops-002-v1",
        "image": IMAGE,
        "complete": False,
        "host_recovery_admitted": False,
        "cleanup": "unknown",
        "worker_image": worker_image,
        "python_host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "source_manifest_sha256": sha256(
            (output / "source-manifest.json").read_bytes()
        ).hexdigest(),
        "started_at": datetime.now(UTC).isoformat(),
    }
    try:
        url = lab.start()
        report["server"] = (
            lab.pg("psql", "-U", "pajin", "-d", "pajin_ops002", "-Atc", "SELECT version()")
            .decode()
            .strip()
        )
        child(
            output,
            "postgres-tests",
            [
                "-m",
                "pytest",
                "-q",
                "tests/test_control_plane_postgres.py",
                "tests/test_control_plane_replay_postgres.py",
                "tests/operational_postgres_probe.py",
            ],
            url,
            worker_image,
        )
        state = output / "state.json"
        probe = ["tests/operational_postgres_probe.py"]
        child(output, "seed", [*probe, "seed", str(state)], url, worker_image)
        url = lab.crash_restart(url)
        child(output, "restart", [*probe, "verify", str(state)], url, worker_image)
        # The expected pin is held outside both databases and checked before pg_restore.
        archive = lab.pg("pg_dump", "-U", "pajin", "-Fc", "pajin_ops002")
        assert lab.container_id is not None
        (output / "db.dump").write_bytes(archive)
        pin = {
            "archive_sha256": sha256(archive).hexdigest(),
            "state_sha256": sha256(state.read_bytes()).hexdigest(),
        }
        (output / "independent-checkpoint.json").write_text(json.dumps(pin, indent=2) + "\n")
        lab.pg("createdb", "-U", "pajin", "pajin_ops002_restored")
        require_checkpoint(output, pin)
        restore_input = (output / "db.dump").read_bytes()
        if sha256(restore_input).hexdigest() != pin["archive_sha256"]:
            raise ValueError("restore input differs from the independent archive pin")
        lab.pg(
            "pg_restore",
            "-U",
            "pajin",
            "--exit-on-error",
            "--single-transaction",
            "-d",
            "pajin_ops002_restored",
            stdin=restore_input,
        )
        require_checkpoint(output, pin)
        restored_url = make_url(url).set(database="pajin_ops002_restored")
        child(
            output,
            "restore",
            [*probe, "verify", str(state)],
            restored_url.render_as_string(hide_password=False),
            worker_image,
        )
        if source_inventory() != sources:
            raise ValueError("source changed during operational verification")
        report.update(
            checks_passed=True,
            independent_checkpoint=pin,
            restart="crash-recovery-verified",
            restore="separate-empty-database-verified",
        )
    finally:
        try:
            report["cleanup"] = "observed-absent" if lab.close() else "unknown"
        finally:
            report["complete"] = (
                report.get("checks_passed") is True and report["cleanup"] == "observed-absent"
            )
            report["finished_at"] = datetime.now(UTC).isoformat()
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            for file in output.iterdir():
                if file.is_file():
                    file.chmod(0o600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--worker-image", required=True)
    options = parser.parse_args()
    run(options.output.resolve(), worker_image=options.worker_image)
