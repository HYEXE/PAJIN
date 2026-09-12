"""Exercise OPS-004 with an owned anchor volume, read-only recovery and fresh CLI processes."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.operations.hybrid import implementation_digest
from scripts.hybrid_operations_rehearsal import PHASES, Rehearsal
from scripts.operational_linux import LABEL, LinuxLab
from scripts.operational_postgres import OwnedPostgres, command


class AnchoredRehearsal(Rehearsal):
    def __init__(self, output: Path, runtime: str, worker: str) -> None:
        super().__init__(output, runtime, worker)
        self.anchor_volume: str | None = None
        self.anchor_binding: dict[str, object] | None = None
        self.publisher = Ed25519PrivateKey.generate()
        self.anchor_sequence = 0

    def controller_mounts(self, role: str) -> list[str]:
        if self.anchor_volume is None:
            raise ValueError("owned anchor must be provisioned before a recovery controller")
        mode = "rw" if role == "source" else "ro"
        return ["-v", f"{self.anchor_volume}:/anchor:{mode}"]

    def controller(self, lab: LinuxLab, pg: OwnedPostgres, role: str) -> str:
        if self.anchor_volume is None:
            if role != "source":
                raise ValueError("source must initialize its independent anchor first")
            self.anchor_volume = lab.volume("independent-anchor")
            command([
                "docker", "run", "--rm", "--pull", "never", "--network", "none",
                "--label", f"{LABEL}={lab.owner}", "--read-only", "--user", "0:0",
                "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
                "--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m",
                "-v", f"{self.anchor_volume}:/anchor", self.runtime, "python", "-c",
                "import os; os.chmod('/anchor',0o700); os.chown('/anchor',10001,10001)",
            ], output=self.output / "anchor-volume-init.log")
        identity = super().controller(lab, pg, role)
        if role == "source":
            self.write(identity, "/tmp/anchor.key", self.publisher.private_bytes_raw())
            if self.anchor_binding is None:
                output = self.execute(identity, [
                    "python", "-m", "pajin.operations.checkpoint_anchor", "init",
                    "--directory", "/anchor/head", "--binding", "/evidence/anchor-binding.json",
                    "--authority-id", "owned-recovery",
                    "--public-key", self.publisher.public_key().public_bytes_raw().hex(),
                ])
                self.anchor_binding = json.loads(output)
        return identity

    def plan(
        self, lab: LinuxLab, pg: OwnedPostgres, host: str, role: str, seed: dict[str, Any]
    ) -> dict[str, Any]:
        if self.anchor_binding is None:
            raise ValueError("independent enrollment must precede deployment pinning")
        return {**super().plan(lab, pg, host, role, seed), "recovery_anchor": self.anchor_binding}

    def cli(
        self, identity: str, args: list[str], *, succeeds: bool = True, error: str | None = None
    ) -> None:
        if args[0] in ("checkpoint", "restore", "verify", "resume"):
            args = [*args, "--anchor-directory", "/anchor/head"]
        if args[0] == "checkpoint":
            args += [
                "--anchor-key", "/tmp/anchor.key",
                "--expected-anchor-sequence", str(self.anchor_sequence),
            ]
        super().cli(identity, args, succeeds=succeeds, error=error)
        if args[0] == "checkpoint" and succeeds:
            self.anchor_sequence += 1

    def checkpoint_source(
        self, controller: str, common: list[str], state_args: list[str]
    ) -> None:
        old_args = [
            "/evidence/old.bin" if arg == "/evidence/cold.bin" else arg for arg in state_args
        ]
        self.cli(controller, [
            "checkpoint", *common, *old_args, "--output", "/evidence/old-checkpoint.json",
        ])
        # Only this owned PostgreSQL process restarts. Application writers stay stopped.
        pg = self.databases[0]
        assert pg.container_id is not None
        pg.require_owner("container", pg.container_id)
        command(["docker", "start", pg.container_id])
        fresh = self.controller(self.labs[0], pg, "source")
        self.execute(fresh, [
            "python", "-c",
            "import os; from scripts.operational_postgres import OwnedPostgres; "
            "OwnedPostgres.wait_ready(os.environ['PAJIN_TEST_POSTGRES_URL'])",
        ])
        super().checkpoint_source(fresh, common, state_args)
        self.checks.append("two-durable-independent-checkpoints")

    def before_restore(
        self, recovery: str, target_common: list[str], state_args: list[str]
    ) -> None:
        old = self.read_json(recovery, "/evidence/old-checkpoint.json")
        stale_args = [
            "/evidence/old.bin" if arg == "/evidence/cold.bin" else arg for arg in state_args
        ]
        stale_args += ["--checkpoint-pin", old["checkpoint_sha256"]]
        for operation in ("restore", "verify"):
            self.cli(recovery, [
                operation, *target_common, *stale_args,
                "--output", f"/evidence/stale-{operation}.json",
            ], succeeds=False, error="not the independent latest recovery head")
        self.execute(recovery, [
            "python", "-c",
            "from pathlib import Path; from pajin.operations.hybrid_models import Deployment; "
            "from pajin.operations.hybrid_docker import Postgres; "
            "p=Deployment.model_validate_json(Path('/evidence/target.json').read_bytes()); "
            "Postgres(p).require_empty(); assert not Path('/target/host').exists(); "
            "assert not Path('/tmp/anchor.key').exists()",
        ])
        self.checks.append("stale-archive-and-old-pin-denied-before-materialization")

    def restoration_checks(self) -> list[str]:
        return ["latest-enrolled-checkpoint-restored", "fresh-process-domain-verification"]

    def check_restored(self, recovery: str, report: dict[str, Any]) -> None:
        head = json.loads(self.execute(recovery, [
            "python", "-m", "pajin.operations.checkpoint_anchor", "inspect",
            "--directory", "/anchor/head", "--binding", "/evidence/anchor-binding.json",
        ]))
        if (
            head["sequence"] != 2 or report.get("independent_checkpoint") != head
            or head["checkpoint_sha256"] != report["checkpoint_sha256"]
        ):
            raise ValueError("fresh reader and restoration head differ")
        observed = json.loads(command(["docker", "inspect", recovery]))[0]
        mounts = [m for m in observed["Mounts"] if m.get("Name") == self.anchor_volume]
        if len(mounts) != 1 or mounts[0]["RW"] or mounts[0]["Destination"] != "/anchor":
            raise ValueError("recovery anchor is not independently mounted read-only")
        for lab in self.labs:
            for identity in lab.containers.values():
                info = json.loads(command(["docker", "inspect", identity]))[0]
                if any(m.get("Name") == self.anchor_volume for m in info["Mounts"]):
                    raise ValueError("an application writer can reach the anchor volume")
        self.execute(recovery, [
            "python", "-c",
            "import errno; from pathlib import Path\n"
            "try: Path('/anchor/head/entries.jsonl').open('ab')\n"
            "except OSError as exc: assert exc.errno == errno.EROFS\n"
            "else: raise AssertionError('recovery anchor is writable')\n",
        ])
        (self.output / "independent-head.json").write_text(json.dumps(head, indent=2) + "\n")
        self.checks.extend([
            "fresh-process-latest-head-agrees", "recovery-anchor-read-only",
            "application-writers-have-no-anchor-mount",
        ])

    def close(self) -> bool:
        try:
            if self.controllers and self.anchor_binding is not None:
                retained = self.output / "retained-anchor"
                retained.mkdir(mode=0o700)
                for filename in ("genesis.json", "entries.jsonl"):
                    content = self.execute(self.controllers[0], ["cat", "/anchor/head/" + filename])
                    (retained / filename).write_bytes(content)
        finally:
            clean = super().close()
        return clean


def run(output: Path, runtime: str, worker: str) -> None:
    output.mkdir(mode=0o700, exist_ok=False)
    exercise = AnchoredRehearsal(output, runtime, worker)
    report: dict[str, object] = dict(
        version="ops004-linux-rehearsal-v1", complete=False, cleanup="unknown",
        started_at=datetime.now(UTC).isoformat(),
        physical_separate_host_verified=False, anchor_volume_rollback_detected=False,
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
                finished_at=datetime.now(UTC).isoformat(), code_sha256=implementation_digest(),
            )
            report["complete"] = report.get("checks_passed") is True and (
                report["cleanup"] == "observed-absent"
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
