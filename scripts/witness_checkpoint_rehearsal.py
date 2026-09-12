"""OPS-005: separate owned witness volume, rollback refusal and explicit fresh restoration."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.operations.hybrid import implementation_digest
from scripts.hybrid_operations_rehearsal import PHASES
from scripts.independent_checkpoint_rehearsal import AnchoredRehearsal
from scripts.operational_linux import LABEL, LinuxLab
from scripts.operational_postgres import OwnedPostgres, command


class WitnessedRehearsal(AnchoredRehearsal):
    def __init__(self, output: Path, runtime: str, worker: str) -> None:
        super().__init__(output, runtime, worker)
        self.witness_volume: str | None = None
        self.witness_publisher = Ed25519PrivateKey.generate()

    def run(self) -> None:
        # The independent crash fixture has its own keys/state and can outlast a
        # product approval intent. Complete the unchanged approved continuation
        # before stressing those unrelated fresh processes; both remain required.
        super().run()
        self.phase = "witness-process-crash"
        self.check_process_crash(self.controllers[-1])
        self.phase = "complete"

    def controller_mounts(self, role: str) -> list[str]:
        if self.witness_volume is None:
            raise ValueError("owned witness must precede recovery controllers")
        mode = "rw" if role == "source" else "ro"
        return [*super().controller_mounts(role), "-v", f"{self.witness_volume}:/witness:{mode}"]

    def anchor_read_args(self) -> list[str]:
        return ["--witness-directory", "/witness/head"]

    def controller(self, lab: LinuxLab, pg: OwnedPostgres, role: str) -> str:
        if self.witness_volume is None:
            if role != "source":
                raise ValueError("source must enroll the independent witness first")
            self.witness_volume = lab.volume("independent-witness")
            command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--network",
                    "none",
                    "--label",
                    f"{LABEL}={lab.owner}",
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
                    "16",
                    "--memory",
                    "64m",
                    "-v",
                    f"{self.witness_volume}:/witness",
                    self.runtime,
                    "python",
                    "-c",
                    "import os; os.chmod('/witness',0o700); os.chown('/witness',10001,10001)",
                ],
                output=self.output / "witness-volume-init.log",
            )
        identity = super().controller(lab, pg, role)
        if role == "source":
            self.write(identity, "/tmp/witness.key", self.witness_publisher.private_bytes_raw())
            assert self.anchor_binding is not None
            if self.anchor_binding.get("version") == "pajin-recovery-anchor-v1":
                output = self.execute(
                    identity,
                    [
                        "python",
                        "-m",
                        "pajin.operations.checkpoint_witness",
                        "init",
                        "--directory",
                        "/witness/head",
                        "--anchor-directory",
                        "/anchor/head",
                        "--anchor-binding",
                        "/evidence/anchor-binding.json",
                        "--output-binding",
                        "/evidence/witness-binding.json",
                        "--authority-id",
                        "owned-witness",
                        "--public-key",
                        self.witness_publisher.public_key().public_bytes_raw().hex(),
                    ],
                )
                self.anchor_binding = json.loads(output)
                self.write(identity, "/evidence/anchor-binding.json", output)
        return identity

    def cli(
        self, identity: str, args: list[str], *, succeeds: bool = True, error: str | None = None
    ) -> None:
        if args[0] in ("checkpoint", "restore", "verify", "resume"):
            args = [*args, *self.anchor_read_args()]
        if args[0] == "checkpoint":
            args += ["--witness-key", "/tmp/witness.key"]
        super().cli(identity, args, succeeds=succeeds, error=error)

    def before_restore(
        self, recovery: str, target_common: list[str], state_args: list[str]
    ) -> None:
        super().before_restore(recovery, target_common, state_args)
        publisher = self.controllers[0]
        # Remove a valid signed suffix from only the owned anchor volume.
        self.execute(
            publisher,
            [
                "python",
                "-c",
                "import os; from pathlib import Path; p=Path('/anchor/head/entries.jsonl'); "
                "data=p.read_bytes().splitlines(keepends=True); assert len(data)==2; "
                "f=p.open('wb'); f.write(data[0]); f.flush(); os.fsync(f.fileno()); f.close()",
            ],
        )
        checkpoint = self.read_json(recovery, "/evidence/checkpoint.json")
        for operation in ("restore", "verify"):
            self.cli(
                recovery,
                [
                    operation,
                    *target_common,
                    *state_args,
                    "--checkpoint-pin",
                    checkpoint["checkpoint_sha256"],
                    "--output",
                    f"/evidence/witness-denied-{operation}.json",
                ],
                succeeds=False,
                error="anchor differs from independently retained witness",
            )
        self.execute(
            recovery,
            [
                "python",
                "-c",
                "from pathlib import Path; from pajin.operations.hybrid_models import Deployment; "
                "from pajin.operations.hybrid_docker import Postgres; "
                "p=Deployment.model_validate_json(Path('/evidence/target.json').read_bytes()); "
                "Postgres(p).require_empty(); assert not Path('/target/host').exists()",
            ],
        )
        self.execute(
            publisher,
            [
                "python",
                "-m",
                "pajin.operations.checkpoint_witness",
                "restore-anchor",
                "--directory",
                "/witness/head",
                "--anchor-binding",
                "/evidence/anchor-binding.json",
                "--target-directory",
                "/anchor/reconstructed",
                "--output-binding",
                "/evidence/reconstructed-binding.json",
            ],
        )
        self.execute(
            publisher,
            [
                "python",
                "-c",
                "from pathlib import Path; "
                "assert len(Path('/anchor/head/entries.jsonl').read_bytes().splitlines())==1; "
                "p=Path('/anchor/reconstructed/entries.jsonl'); "
                "assert len(p.read_bytes().splitlines())==2",
            ],
        )
        self.anchor_path = "/anchor/reconstructed"
        self.checks.extend(
            [
                "anchor-suffix-rollback-denied-before-materialization",
                "explicit-new-anchor-restored-with-original-retained",
            ]
        )

    def check_restored(self, recovery: str, report: dict[str, Any]) -> None:
        super().check_restored(recovery, report)
        observed = json.loads(command(["docker", "inspect", recovery]))[0]
        mounts = [m for m in observed["Mounts"] if m.get("Name") == self.witness_volume]
        if len(mounts) != 1 or mounts[0]["RW"] or mounts[0]["Destination"] != "/witness":
            raise ValueError("recovery witness is not independently mounted read-only")
        for lab in self.labs:
            for identity in lab.containers.values():
                info = json.loads(command(["docker", "inspect", identity]))[0]
                if any(m.get("Name") == self.witness_volume for m in info["Mounts"]):
                    raise ValueError("application writer can reach witness volume")
        self.execute(
            recovery,
            [
                "python",
                "-c",
                "import errno; from pathlib import Path\n"
                "assert not Path('/tmp/witness.key').exists()\n"
                "try: Path('/witness/head/entries.jsonl').open('ab')\n"
                "except OSError as exc: assert exc.errno == errno.EROFS\n"
                "else: raise AssertionError('recovery witness is writable')\n",
            ],
        )
        self.checks.extend(
            [
                "recovery-witness-read-only-without-publisher-key",
                "application-writers-have-no-witness-mount",
            ]
        )

    def check_process_crash(self, recovery: str) -> None:
        # The probe has 35 bounded child processes, each with its own 30-second limit.
        # Keep those limits while allowing their cumulative work and durable publication.
        probe = command(
            [
                "docker", "exec", "-i", recovery,
                "python",
                "/app/tests/checkpoint_witness_process_probe.py",
                "/tmp/witness-crash",
            ],
            output=self.output / "process-crash.log",
            timeout=1200,
        )
        result = json.loads(probe)
        if result.get("complete") is not True or result.get("cycles") != 32:
            raise ValueError("independent process crash probe is incomplete")
        (self.output / "process-crash.json").write_bytes(probe)
        self.checks.extend(
            [
                "sigkill-after-witness-fsync-refused-and-explicitly-restored",
                "32-fresh-process-head-verification-cycles",
            ]
        )

    def close(self) -> bool:
        try:
            if self.controllers and self.anchor_binding is not None:
                retained = self.output / "retained-witness"
                retained.mkdir(mode=0o700)
                for filename in ("genesis.json", "entries.jsonl"):
                    content = self.execute(
                        self.controllers[0], ["cat", "/witness/head/" + filename]
                    )
                    (retained / filename).write_bytes(content)
        finally:
            clean = super().close()
        return clean


def run(output: Path, runtime: str, worker: str) -> None:
    output.mkdir(mode=0o700, exist_ok=False)
    exercise = WitnessedRehearsal(output, runtime, worker)
    report: dict[str, object] = dict(
        version="ops005-linux-rehearsal-v1",
        complete=False,
        cleanup="unknown",
        started_at=datetime.now(UTC).isoformat(),
        physical_separate_host_verified=False,
        anchor_volume_rollback_detected=True,
        simultaneous_store_rollback_detected=False,
        power_loss_verified=False,
        production_failover_verified=False,
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
