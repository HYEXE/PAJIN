"""Exact pinned Docker resources only; labels locate participants but do not grant authority."""

from __future__ import annotations

import json
import subprocess

from pajin.operations.hybrid_models import MAX_BYTES, Deployment, Writer, digest


def command(arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        arguments,
        input=input_bytes,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode or len(result.stdout) > MAX_BYTES:
        raise RuntimeError("bounded recovery command failed; target remains unverified")
    return result.stdout


def inspect_writer(writer: Writer, label: str, owner: str) -> dict[str, object]:
    data = json.loads(command(["docker", "container", "inspect", writer.container_id]))
    if len(data) != 1:
        raise ValueError("pinned recovery container is absent")
    item = data[0]
    if (
        item["Id"] != writer.container_id
        or item["Image"] != writer.image_id
        or item["Config"]["Labels"].get(label) != owner
        or item["HostConfig"]["RestartPolicy"]["Name"] not in ("", "no")
    ):
        raise ValueError("container identity, ownership, image or restart policy differs")
    return dict(item["State"])


class WriterFence:
    def __init__(self, deployment: Deployment) -> None:
        self.deployment = deployment

    def inspect(self, *, stopped: bool) -> None:
        plan = self.deployment
        observed = (
            command(
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    f"label={plan.writer_label}={plan.writer_owner}",
                ]
            )
            .decode()
            .split()
        )
        if set(observed) != {w.container_id for w in plan.writers}:
            raise ValueError("participating writer inventory changed")
        for writer in plan.writers:
            state = inspect_writer(writer, plan.writer_label, plan.writer_owner)
            if stopped and (state.get("Running") or state.get("Pid") != 0):
                raise ValueError("participating writer is not physically stopped")

    def stop(self) -> None:
        self.inspect(stopped=False)
        for writer in self.deployment.writers:
            state = inspect_writer(
                writer,
                self.deployment.writer_label,
                self.deployment.writer_owner,
            )
            if state.get("Running"):
                command(["docker", "stop", "--time", "30", writer.container_id])
        self.inspect(stopped=True)


class Postgres:
    def __init__(self, deployment: Deployment) -> None:
        self.deployment = deployment

    def inspect(self) -> None:
        plan = self.deployment
        state = inspect_writer(plan.postgres, plan.postgres_label, plan.postgres_owner)
        if not state.get("Running"):
            raise ValueError("pinned PostgreSQL is not running")

    def execute(self, executable: str, *arguments: str, data: bytes | None = None) -> bytes:
        self.inspect()
        return command(
            [
                "docker",
                "exec",
                "-i",
                self.deployment.postgres.container_id,
                executable,
                "-U",
                self.deployment.database_user,
                *arguments,
            ],
            input_bytes=data,
        )

    def query(self, sql: str) -> str:
        return (
            self.execute(
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-d",
                self.deployment.database,
                "-Atc",
                sql,
            )
            .decode()
            .strip()
        )

    def identity(self) -> str:
        version = int(self.query("SHOW server_version_num"))
        if not 170000 <= version < 180000:
            raise ValueError("recovery requires PostgreSQL 17")
        return digest(
            json.loads(
                self.query(
                    "SELECT json_build_array(system_identifier::text, current_database(), "
                    "(SELECT oid::text FROM pg_database WHERE datname=current_database())) "
                    "FROM pg_control_system()",
                )
            )
        )

    def require_no_clients(self) -> None:
        if (
            self.query(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                "AND backend_type='client backend' AND pid<>pg_backend_pid()",
            )
            != "0"
        ):
            raise ValueError("PostgreSQL has other client connections; checkpoint denied")

    def dump(self) -> bytes:
        self.require_no_clients()
        return self.execute("pg_dump", "-Fc", "--no-owner", "--no-acl", self.deployment.database)

    def require_empty(self) -> None:
        self.require_no_clients()
        if (
            self.query(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
                "AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f')",
            )
            != "0"
        ):
            raise ValueError("restore target database is not empty")

    def restore(self, content: bytes) -> None:
        self.require_empty()
        self.execute(
            "pg_restore",
            "--exit-on-error",
            "--single-transaction",
            "--no-owner",
            "--no-acl",
            "-d",
            self.deployment.database,
            data=content,
        )
