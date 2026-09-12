"""Exercise OPS-003 only in newly owned Linux containers, databases and volumes.

Provisioning helpers remain test-only. Product commands import no test helpers.
No external database URL, existing state volume or production service is accepted.
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.operations.hybrid import implementation_digest
from pajin.operations.hybrid_models import ResumeAuthorization, digest
from scripts.operational_linux import LABEL as WRITER_LABEL
from scripts.operational_linux import LinuxLab
from scripts.operational_postgres import LABEL as PG_LABEL
from scripts.operational_postgres import OwnedPostgres, command

LABEL = "pajin.ops003-controller-owner"
PROBE = "/app/tests/hybrid_operations_probe.py"
PHASES = frozenset({
    "source-postgres", "source-configuration", "source-start", "source-seed",
    "source-preflight", "source-checkpoint", "target-postgres", "target-configuration",
    "target-start", "target-restore", "target-resume", "target-resume-ready",
    "target-resume-expired-denial", "target-resume-unapproved-denial",
    "target-resume-approval", "target-resume-approved", "target-continuation",
    "witness-process-crash", "complete",
})


class Rehearsal:
    def __init__(self, output: Path, runtime: str, worker: str) -> None:
        self.output = output
        self.owner = uuid4().hex
        self.controllers: list[str] = []
        self.labs: list[LinuxLab] = []
        self.databases: list[OwnedPostgres] = []
        self.runtime = runtime
        self.worker = worker
        self.sequence = 0
        self.signer = Ed25519PrivateKey.generate()
        self.checks: list[str] = []
        self.phase = "source-postgres"

    def pair(self, role: str) -> tuple[LinuxLab, OwnedPostgres, str]:
        output = self.output / role
        output.mkdir(mode=0o700)
        lab = LinuxLab(output, self.runtime, self.worker)
        self.labs.append(lab)
        pg_output = output / "postgres"
        pg_output.mkdir(mode=0o700)
        pg = OwnedPostgres(pg_output)
        self.databases.append(pg)
        self.phase = f"{role}-postgres"
        url = pg.start()
        if role == "target":
            shutil.copytree(
                self.labs[0].output / "configuration-source", output / "configuration-source"
            )
        self.phase = f"{role}-configuration"
        lab.configure(pg, url, role="source" if role == "source" else "restored")
        self.phase = f"{role}-start"
        host = lab.start(
            pg, role="source" if role == "source" else "restored", name=role, init_process=True
        )
        return lab, pg, host

    def controller(self, lab: LinuxLab, pg: OwnedPostgres, role: str) -> str:
        config = "source" if role == "source" else "restored"
        shared = self.labs[0].volumes["evidence"]
        identity = (
            command(
                [
                    "docker",
                    "run",
                    "-d",
                    "--pull",
                    "never",
                    "--label",
                    f"{LABEL}={self.owner}",
                    "--network",
                    f"container:{pg.container_id}",
                    "--read-only",
                    "--user",
                    "10001:10001",
                    "--group-add",
                    lab.socket_group(),
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
                    str(lab.envs[config]),
                    "-v",
                    f"{lab.volumes['state-' + config]}:/{role}",
                    "-v",
                    f"{lab.volumes['control-' + config]}:/control:ro",
                    "-v",
                    f"{shared}:/evidence",
                    *self.controller_mounts(role),
                    "-v",
                    "/var/run/docker.sock:/var/run/docker.sock",
                    "--tmpfs",
                    "/tmp:uid=10001,gid=10001,mode=0700,size=128m,nosuid,nodev",
                    lab.runtime,
                ]
            )
            .decode()
            .strip()
        )
        self.controllers.append(identity)
        return identity

    def controller_mounts(self, role: str) -> list[str]:
        return []

    def execute(self, identity: str, args: list[str], *, stdin: bytes | None = None) -> bytes:
        self.sequence += 1
        return command(
            ["docker", "exec", "-i", identity, *args],
            stdin=stdin,
            output=self.output / f"command-{self.sequence:03d}.log",
            timeout=180,
        )

    def write(self, identity: str, path: str, content: bytes) -> None:
        self.execute(
            identity,
            [
                "python",
                "-c",
                "import sys; from pathlib import Path; p=Path(sys.argv[1]); "
                "p.write_bytes(sys.stdin.buffer.read()); p.chmod(0o600)",
                path,
            ],
            stdin=content,
        )

    def read_json(self, identity: str, path: str) -> dict[str, Any]:
        value = json.loads(self.execute(identity, ["cat", path]))
        if not isinstance(value, dict):
            raise ValueError("probe report is not an object")
        return value

    def cli(
        self, identity: str, args: list[str], *, succeeds: bool = True, error: str | None = None
    ) -> None:
        self.sequence += 1
        content = self.execute(
            identity,
            [
                "python",
                "-c",
                "import os, subprocess, sys; "
                "env=dict(os.environ,PAJIN_RECOVERY_DATABASE_URL=os.environ['PAJIN_TEST_POSTGRES_URL'],"
                "PAJIN_RECOVERY_OPERATOR_TOKEN='isolated-checkpoint-operator-token-32-bytes'); "
                "r=subprocess.run([sys.executable,'-m','pajin.operations',*sys.argv[2:]],env=env,"
                "capture_output=True); sys.stdout.buffer.write(r.stdout+r.stderr); "
                "assert (r.returncode==0)==(sys.argv[1]=='success'), r.returncode",
                "success" if succeeds else "denied",
                *args,
            ],
        )
        (self.output / f"cli-{self.sequence:03d}.log").write_bytes(content)
        if error is not None and error.encode() not in content:
            raise ValueError("negative operation failed for an unexpected reason")

    def plan(
        self, lab: LinuxLab, pg: OwnedPostgres, host: str, role: str, seed: dict[str, Any]
    ) -> dict[str, Any]:
        pg_info = json.loads(command(["docker", "inspect", str(pg.container_id)]))[0]
        keys = json.loads((lab.output / "configuration-source/keys.json").read_text())
        from pajin.control_plane.security import CheckpointSigner

        return dict(
            version="pajin-hybrid-deployment-v1",
            deployment_id=role,
            writer_label=WRITER_LABEL,
            writer_owner=lab.owner,
            writers=[
                dict(container_id=host, image_id=lab.runtime, role="control-plane"),
                dict(container_id=lab.containers["worker"], image_id=lab.runtime, role="worker"),
            ],
            postgres=dict(container_id=pg.container_id, image_id=pg_info["Image"], role="postgres"),
            postgres_label=PG_LABEL,
            postgres_owner=pg.owner,
            database="pajin_ops002",
            database_user="pajin",
            graphs=seed["graphs"],
            journals=seed["journals"],
            runs=seed["runs"],
            checkpoint_key_commitments=CheckpointSigner(
                active_key_id="v2",
                keys={k: bytes.fromhex(v) for k, v in keys.items()},
            ).key_commitments(),
            code_sha256=implementation_digest(),
            state_root_sha256=digest(f"/{role}/host"),
            resume_signers={
                "recovery": dict(
                    subject="operator",
                    public_key_hex=self.signer.public_key().public_bytes_raw().hex(),
                )
            },
            operator_api_origin="https://127.0.0.1:8443",
            operator_ca_sha256=sha256(
                (lab.output / "configuration-source/api/server.crt").read_bytes()
            ).hexdigest(),
        )

    def grant(
        self,
        controller: str,
        report: dict[str, Any],
        seed: dict[str, Any],
        *,
        expired: bool = False,
    ) -> None:
        grant = ResumeAuthorization(
            checkpoint_sha256=report["checkpoint_sha256"],
            verification_sha256=digest(report),
            target_database_identity=report["target_database_identity"],
            target_state_sha256=report["target_state_sha256"],
            checkpoint_id=seed["checkpoint_id"],
            approval_id=seed["approval_id"],
            operator_subject="operator",
            key_id="recovery",
            expires_at=datetime.now(UTC) + timedelta(minutes=-1 if expired else 5),
            signature_hex="0" * 128,
        )
        signed = grant.model_copy(
            update={
                "signature_hex": self.signer.sign(grant.signed_bytes()).hex(),
            }
        )
        self.write(controller, "/evidence/grant.json", signed.model_dump_json().encode())

    def run(self) -> None:
        source, pg, host = self.pair("source")
        source_worker = source.start(pg, role="source", name="worker", init_process=True)
        self.phase = "source-seed"
        source.execute(
            host,
            ["python", PROBE, "seed"],
            log="seed",
            env={"PAJIN_OPS003_WORKER_CONTAINER": source_worker},
        )
        seed = json.loads(source.read(host, "/evidence/seed.json"))
        controller = self.controller(source, pg, "source")
        actual_digest = self.execute(
            controller, ["python", "-m", "pajin.operations", "code-digest"]
        )
        if actual_digest.decode().strip() != implementation_digest():
            raise ValueError("runtime does not contain the implementation under review")
        plan = self.plan(source, pg, host, "source", seed)
        content = json.dumps(plan).encode()
        self.write(controller, "/evidence/source.json", content)
        common = [
            "--deployment",
            "/evidence/source.json",
            "--deployment-pin",
            sha256(content).hexdigest(),
            "--state-root",
            "/source/host",
        ]
        self.phase = "source-preflight"
        self.cli(controller, ["preflight", *common, "--output", "/evidence/preflight.json"])
        keyring = dict(
            active_key_id="v2",
            keys=json.loads((source.output / "configuration-source/keys.json").read_text()),
        )
        self.write(controller, "/evidence/keys.json", json.dumps(keyring).encode())
        self.write(controller, "/evidence/encryption.key", secrets.token_bytes(32))
        state_args = [
            "--cp-keyring",
            "/evidence/keys.json",
            "--encryption-key",
            "/evidence/encryption.key",
            "--checkpoint",
            "/evidence/cold.bin",
        ]
        self.phase = "source-checkpoint"
        self.cli(
            controller,
            ["checkpoint", *common, *state_args, "--output", "/evidence/running-denial.json"],
            succeeds=False,
        )
        self.checks.append("running-source-denied")
        self.cli(controller, ["stop", *common, "--output", "/evidence/stopped.json"])
        self.checkpoint_source(controller, common, state_args)
        cp = self.read_json(controller, "/evidence/checkpoint.json")
        self.checks.append("full-cold-checkpoint-source-stopped")
        target, restored, target_host = self.pair("target")
        target_worker = target.start(restored, role="restored", name="worker", init_process=True)
        target.stop(target_host)
        target.stop(target_worker)
        recovery = self.controller(target, restored, "target")
        self.phase = "target-restore"
        target_plan = self.plan(target, restored, target_host, "target", seed)
        content = json.dumps(target_plan).encode()
        self.write(recovery, "/evidence/target.json", content)
        target_common = [
            "--deployment",
            "/evidence/target.json",
            "--deployment-pin",
            sha256(content).hexdigest(),
            "--state-root",
            "/target/host",
        ]
        restore_args = [*state_args, "--checkpoint-pin", cp["checkpoint_sha256"]]
        self.before_restore(recovery, target_common, state_args)
        self.cli(
            recovery,
            ["restore", *target_common, *restore_args, "--output", "/evidence/restored.json"],
        )
        self.cli(
            recovery,
            ["verify", *target_common, *restore_args, "--output", "/evidence/verified.json"],
        )
        self.checks.extend(self.restoration_checks())
        report = self.read_json(recovery, "/evidence/verified.json")
        self.check_restored(recovery, report)
        self.phase = "target-resume"
        command(["docker", "start", target_host])
        command(
            [
                "docker", "exec", "-d", target_host, "python",
                "/app/tests/operational_linux_probe.py", "server", "v2",
            ]
        )
        self.phase = "target-resume-ready"
        target.execute(target_host, ["python", PROBE, "ready"], log="api-ready")
        self.resume_target(recovery, target_common, restore_args, report, seed, target_host)
        self.phase = "target-continuation"
        command(["docker", "start", target_worker])
        result = target.execute(
            target_host,
            ["python", PROBE, "finish"],
            log="continuation",
            stdin=json.dumps(seed).encode(),
            env={"PAJIN_OPS003_WORKER_CONTAINER": target_worker},
        )
        (self.output / "continuation.json").write_bytes(result)
        self.checks.extend(
            [
                "expired-recovery-authorization-denied",
                "unapproved-cp-resume-denied",
                "approver-role-rechecked",
                "approved-continuation-completed",
                "one-use-resume",
                "unacknowledged-call-charge-preserved",
            ]
        )
        self.phase = "complete"

    def checkpoint_source(
        self, controller: str, common: list[str], state_args: list[str]
    ) -> None:
        self.cli(
            controller,
            ["checkpoint", *common, *state_args, "--output", "/evidence/checkpoint.json"],
        )

    def before_restore(
        self, recovery: str, target_common: list[str], state_args: list[str]
    ) -> None:
        # A valid encrypted object with an invalid pg_dump exercises interruption after
        # local materialization. The original archive remains intact for the exact retry.
        malformed = (
            self.execute(
                recovery,
                [
                    "python",
                    "-c",
                    "from pathlib import Path; from hashlib import sha256; "
                    "from pajin.operations.hybrid_files import authenticate,seal,file_object; "
                    "p=Path('/evidence'); b=(p/'cold.bin').read_bytes(); "
                    "k=(p/'encryption.key').read_bytes(); "
                    "c=authenticate(b,pin=sha256(b).hexdigest(),key=k); "
                    "bad=c.model_copy(update={'postgres_dump':"
                    "file_object('postgres.dump',b'invalid')}); "
                    "data=seal(bad,k); (p/'interrupted.bin').write_bytes(data); "
                    "print(sha256(data).hexdigest())",
                ],
            )
            .decode()
            .strip()
        )
        interrupted = [
            *state_args[:-2],
            "--checkpoint",
            "/evidence/interrupted.bin",
            "--checkpoint-pin",
            malformed,
        ]
        self.cli(
            recovery,
            ["restore", *target_common, *interrupted, "--output", "/evidence/interrupted.json"],
            succeeds=False,
        )

    def restoration_checks(self) -> list[str]:
        return [
            "failed-pg-restore-kept-target-inactive",
            "exact-retry-restored",
            "fresh-process-domain-verification",
        ]

    def check_restored(self, recovery: str, report: dict[str, Any]) -> None:
        return None

    def resume_target(
        self, recovery: str, target_common: list[str], restore_args: list[str],
        report: dict[str, Any], seed: dict[str, Any], target_host: str,
    ) -> None:
        resume_args = [
            "resume",
            *target_common,
            *restore_args,
            "--verification",
            "/evidence/verified.json",
            "--resume-authorization",
            "/evidence/grant.json",
            "--operator-ca",
            "/control/api/server.crt",
        ]
        self.phase = "target-resume-expired-denial"
        self.grant(recovery, report, seed, expired=True)
        self.cli(
            recovery,
            [
                *resume_args,
                "--attempt",
                "/evidence/expired-attempt.json",
                "--output",
                "/evidence/expired-resume.json",
            ],
            succeeds=False,
            error="recovery resume authorization is expired",
        )
        self.phase = "target-resume-unapproved-denial"
        self.grant(recovery, report, seed)
        self.cli(
            recovery,
            [
                *resume_args,
                "--attempt",
                "/evidence/unapproved-attempt.json",
                "--output",
                "/evidence/unapproved-resume.json",
            ],
            succeeds=False,
            error="current Control Plane authentication, approval or resume policy denied",
        )
        self.phase = "target-resume-approval"
        self.labs[1].execute(
            target_host,
            ["python", PROBE, "approve"],
            log="approval",
            stdin=json.dumps(seed).encode(),
        )
        self.phase = "target-resume-approved"
        self.cli(
            recovery,
            [
                *resume_args,
                "--attempt",
                "/evidence/approved-attempt.json",
                "--output",
                "/evidence/approved-resume.json",
            ],
        )

    def _close_controller(self, identity: str) -> bool:
        item = json.loads(command(["docker", "inspect", identity]))[0]
        if item["Id"] != identity or item["Config"]["Labels"].get(LABEL) != self.owner:
            raise ValueError("controller cleanup ownership differs")
        command(["docker", "rm", "-f", identity])
        return True

    @staticmethod
    def _close_lab(lab: LinuxLab) -> bool:
        try:
            lab.retain_evidence()
        finally:
            result = lab.close()
        return result

    def close(self) -> bool:
        from functools import partial

        ok = True
        failures = []
        operations = [partial(self._close_controller, c) for c in self.controllers]
        operations += [partial(self._close_lab, lab) for lab in self.labs]
        operations += [partial(pg.close) for pg in self.databases]
        for operation in operations:
            try:
                ok = operation() and ok
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise ExceptionGroup("owned cleanup incomplete", failures)
        return (
            not command(
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    f"label={LABEL}={self.owner}",
                ]
            ).strip()
            and ok
        )


def run(output: Path, runtime: str, worker: str) -> None:
    output.mkdir(mode=0o700, exist_ok=False)
    exercise = Rehearsal(output, runtime, worker)
    report: dict[str, object] = dict(
        version="ops003-linux-rehearsal-v1",
        complete=False,
        cleanup="unknown",
        started_at=datetime.now(UTC).isoformat(),
    )
    try:
        exercise.run()
        report["checks_passed"] = True
    finally:
        try:
            report["cleanup"] = "observed-absent" if exercise.close() else "unknown"
        finally:
            report.update(
                checks=exercise.checks,
                phase=exercise.phase if exercise.phase in PHASES else "unknown",
                finished_at=datetime.now(UTC).isoformat(),
                code_sha256=implementation_digest(),
            )
            report["complete"] = report.get("checks_passed") is True and (
                report.get("cleanup") == "observed-absent"
            )
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            for path in output.rglob("*"):
                if path.is_file():
                    path.chmod(0o600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--worker-image", required=True)
    args = parser.parse_args()
    run(args.output.resolve(), args.runtime_image, args.worker_image)
