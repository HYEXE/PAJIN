"""CI-only OPS/SYS execution and independent residue audit on a fresh hosted Linux runner.

Private probe outputs never become public artifacts. Cleanup is authorized only after a
clean, empty, dedicated-runner preflight; this is not a local-machine cleanup command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

LABELS = {
    "ops": (
        "pajin.ops003-controller-owner",
        "pajin.ops002-linux-owner",
        "pajin.ops-002-owner",
        "pajin.execution-id",
    ),
    "sys": ("pajin.sys002-owner", "pajin.sys004-owner", "pajin.execution-id"),
}
KINDS = ("container", "network", "volume")
OPS_CHECKS = {
    "running-source-denied",
    "full-cold-checkpoint-source-stopped",
    "failed-pg-restore-kept-target-inactive",
    "exact-retry-restored",
    "fresh-process-domain-verification",
    "expired-recovery-authorization-denied",
    "unapproved-cp-resume-denied",
    "approver-role-rechecked",
    "approved-continuation-completed",
    "one-use-resume",
    "unacknowledged-call-charge-preserved",
}
OPS004_CHECKS = (
    OPS_CHECKS
    - {
        "failed-pg-restore-kept-target-inactive",
        "exact-retry-restored",
    }
) | {
    "two-durable-independent-checkpoints",
    "stale-archive-and-old-pin-denied-before-materialization",
    "latest-enrolled-checkpoint-restored",
    "fresh-process-latest-head-agrees",
    "recovery-anchor-read-only",
    "application-writers-have-no-anchor-mount",
}
OPS005_CHECKS = OPS004_CHECKS | {
    "anchor-suffix-rollback-denied-before-materialization",
    "explicit-new-anchor-restored-with-original-retained",
    "recovery-witness-read-only-without-publisher-key",
    "application-writers-have-no-witness-mount",
    "sigkill-after-witness-fsync-refused-and-explicitly-restored",
    "32-fresh-process-head-verification-cycles",
}


def command(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError("conformance command failed; details remain private")
    return result.stdout.strip()


def write(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        path.chmod(0o600)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def require_host() -> str:
    sha = os.environ.get("GITHUB_SHA", "")
    if (
        platform.system() != "Linux"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or re.fullmatch(r"[a-f0-9]{40}", sha) is None
    ):
        raise ValueError("requires the dedicated GitHub-hosted Linux runner")
    if command("git", "rev-parse", "HEAD") != sha:
        raise ValueError("conformance commit differs")
    return sha


def source_digest() -> str:
    paths = command("git", "ls-files", "-z").split("\0")
    inventory = {}
    for name in paths:
        if not name:
            continue
        path = Path(name)
        if path.is_symlink():
            raise ValueError("conformance source contains a symbolic link")
        inventory[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()


def residue(boundary: str) -> dict[str, list[str]]:
    result = {}
    for kind in KINDS:
        found = set()
        for label in LABELS[boundary]:
            args = ["docker", kind, "ls"]
            if kind == "container":
                args.append("--all")
            found.update(command(*args, "--quiet", "--filter", f"label={label}").splitlines())
        result[kind] = sorted(found)
    return result


def preflight(boundary: str, state: Path) -> None:
    sha = require_host()
    if command("git", "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("conformance requires an exact clean tree")
    if any(residue(boundary).values()):
        raise ValueError("runner already contains matching resources; cleanup is not authorized")
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    if state.resolve() != state.absolute():
        raise ValueError("conformance output contains a symbolic link")
    write(
        state / "preflight.json",
        dict(
            version=1,
            boundary=boundary,
            head=sha,
            source_sha256=source_digest(),
            empty=True,
            run_id=os.environ.get("GITHUB_RUN_ID"),
            attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
        ),
    )


def admitted(boundary: str, state: Path) -> dict[str, Any]:
    sha = require_host()
    marker = state / "preflight.json"
    if state.resolve() != state.absolute() or marker.is_symlink():
        raise ValueError("conformance state is not the admitted private directory")
    value = json.loads(marker.read_text())
    if not isinstance(value, dict):
        raise ValueError("conformance admission is not an object")
    if (
        value.get("version") != 1
        or value.get("boundary") != boundary
        or value.get("head") != sha
        or value.get("empty") is not True
        or value.get("run_id") != os.environ.get("GITHUB_RUN_ID")
        or value.get("attempt") != os.environ.get("GITHUB_RUN_ATTEMPT")
    ):
        raise ValueError("cleanup admission differs from the current workflow attempt")
    return dict(value)


def image_record(identity: str) -> dict[str, str]:
    if re.fullmatch(r"sha256:[a-f0-9]{64}", identity) is None:
        raise ValueError("conformance requires an observed immutable image ID")
    fields = command(
        "docker", "image", "inspect", identity, "--format", "{{.Id}} {{.Os}}/{{.Architecture}}"
    ).split()
    if fields != [identity, "linux/amd64"]:
        raise ValueError("conformance image identity or runner architecture differs")
    return dict(id=identity, platform=fields[1])


def verify_probe(boundary: str, private: Path, *, extended: bool = False) -> dict[str, object]:
    report = json.loads((private / "report.json").read_text())
    if not isinstance(report, dict) or report.get("complete") is not True:
        raise ValueError("actual probe is incomplete")
    if boundary == "ops":
        checks = report.get("checks")
        required = OPS004_CHECKS if extended else OPS_CHECKS
        if (
            report.get("checks_passed") is not True
            or report.get("cleanup") != "observed-absent"
            or not isinstance(checks, list)
            or not all(isinstance(check, str) for check in checks)
            or len(checks) != len(required)
            or len(set(checks)) != len(required)
            or set(checks) != required
        ):
            raise ValueError("OPS actual checks or cleanup are incomplete")
        if extended and (
            report.get("version") != "ops004-linux-rehearsal-v1"
            or report.get("physical_separate_host_verified") is not False
            or report.get("anchor_volume_rollback_detected") is not False
        ):
            raise ValueError("OPS-004 boundary claims differ from the actual fixture")
        return dict(actual_checks=len(required), cleanup_observed=True)
    cleanup = report.get("cleanup", {})
    if (
        not isinstance(cleanup, dict)
        or type(report.get("exitCode")) is not int
        or report.get("exitCode") != 0
        or report.get("sourceUnchanged") is not True
        or cleanup.get("ownedAgentContainersAbsent") is not True
        or cleanup.get("workerAndProxyResourcesAbsent") is not True
        or cleanup.get("independentObserver") is not True
        or cleanup.get("observedWorkerExecutions") != 4
    ):
        raise ValueError("SYS actual execution or cleanup is incomplete")
    log = (private / "pytest.log").read_text()
    if re.search(r"(?m)^1 passed in [0-9.]+s(?: \([^\n]+\))?\s*$", log) is None:
        raise ValueError("SYS actual pytest success is missing or skipped")
    if extended:
        _verify_aslr_independent(private)
    return dict(actual_tests_passed=1, worker_executions=4, cleanup_observed=True)


def _verify_aslr_independent(private: Path) -> None:
    evidence = json.loads((private / "independent-coreutils.json").read_text())
    compared = json.loads((private / "fresh-process-report.json").read_text())
    if not isinstance(evidence, dict) or not isinstance(compared, dict):
        raise ValueError("independent ASLR evidence is not an object")
    metadata = evidence.get("metadata")
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"randomizeVaSpace"}
        or type(metadata.get("randomizeVaSpace")) is not int
        or metadata["randomizeVaSpace"] not in (0, 1, 2)
        or evidence.get("bytes") != [48 + metadata["randomizeVaSpace"], 10]
        or evidence.get("match") is not True
        or evidence.get("physicalHostVerified") is not False
        or evidence.get("processAslrVerified") is not False
        or not isinstance(evidence.get("implementation"), str)
        or not evidence["implementation"].startswith("od (GNU coreutils)")
        or compared.get("version") != "pajin.sys-004.reexecution-report/v1"
        or compared.get("complete") is not True
        or compared.get("aslrMatch") is not True
    ):
        raise ValueError("independent ASLR observation differs")
    for name in ("source", "replay"):
        result = compared.get(name)
        if not isinstance(result, dict) or not isinstance(result.get("aslr"), dict):
            raise ValueError("independent ASLR report is incomplete")
        if result["aslr"].get("metadata") != metadata:
            raise ValueError("independent ASLR bytes disagree with the sealed result")


def failed_probe_observation(
    boundary: str, private: Path, *, extended: bool = False, witnessed: bool = False
) -> dict[str, object]:
    """Expose only an allowlisted OPS phase/count, never private command output."""
    unknown: dict[str, object] = dict(observed_phase="unknown", completed_checks=None)
    if boundary != "ops":
        return unknown
    from scripts.hybrid_operations_rehearsal import PHASES

    required = OPS005_CHECKS if witnessed else OPS004_CHECKS if extended else OPS_CHECKS
    version = (
        "ops005-linux-rehearsal-v1"
        if witnessed
        else ("ops004-linux-rehearsal-v1" if extended else "ops003-linux-rehearsal-v1")
    )
    try:
        path = private / "report.json"
        if path.stat().st_size > 65_536:
            return unknown
        report = json.loads(path.read_bytes())
        if not isinstance(report, dict):
            return unknown
        checks, phase = report.get("checks"), report.get("phase")
        if (
            report.get("version") != version
            or not isinstance(phase, str)
            or phase not in PHASES
            or not isinstance(checks, list)
            or len(checks) > len(required)
            or not all(isinstance(check, str) and check in required for check in checks)
            or len(set(checks)) != len(checks)
        ):
            return unknown
        return dict(observed_phase=phase, completed_checks=len(checks))
    except (OSError, ValueError):
        return unknown


def run(
    boundary: str, state: Path, primary: str, secondary: str, additional_image: str | None = None
) -> int:
    marker = admitted(boundary, state)
    if any(
        (state / name).exists()
        for name in (
            "private-runner.log",
            "private-probe",
            "private-additional-probe",
            "private-additional-runner.log",
            "private-witness-probe",
            "private-witness-runner.log",
            "public-summary.json",
        )
    ):
        raise ValueError("conformance execution requires a fresh workflow attempt")
    if source_digest() != marker["source_sha256"]:
        raise ValueError("conformance source changed after clean-commit gate")
    images = [image_record(primary), image_record(secondary)]
    if boundary == "sys":
        if additional_image is None or additional_image == primary:
            raise ValueError("SYS requires a separate observed ASLR image")
        images.append(image_record(additional_image))
    if boundary == "ops":
        from scripts.operational_postgres import IMAGE

        images.append(
            image_record(command("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"))
        )
    private = state / "private-probe"
    args = (
        [
            "-m",
            "scripts.hybrid_operations_rehearsal",
            "--runtime-image",
            primary,
            "--worker-image",
            secondary,
        ]
        if boundary == "ops"
        else [
            "scripts/operational_system_read.py",
            "--image-id",
            primary,
            "--proxy-image-id",
            secondary,
        ]
    )
    summary: dict[str, object] = dict(
        boundary=boundary,
        head=marker["head"],
        source_sha256=marker["source_sha256"],
        python=platform.python_version(),
        platform="linux/amd64",
        images=images,
        complete=False,
        finding_authority=False,
        production_recovery=False,
    )
    started = perf_counter()
    extended = False
    witnessed = False
    try:
        with (state / "private-runner.log").open("x") as log:
            result = subprocess.run(
                [sys.executable, *args, "--output", str(private)],
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=1800,
                check=False,
            )
        summary["exit_code"] = result.returncode
        if result.returncode != 0:
            raise ValueError("actual probe failed")
        summary.update(verify_probe(boundary, private))
        if source_digest() != marker["source_sha256"]:
            raise ValueError("conformance source changed before additional execution")
        extended = True
        private = state / "private-additional-probe"
        extra = (
            [
                "-m",
                "scripts.independent_checkpoint_rehearsal",
                "--runtime-image",
                primary,
                "--worker-image",
                secondary,
            ]
            if boundary == "ops"
            else [
                "scripts/operational_system_aslr.py",
                "--image-id",
                str(additional_image),
                "--proxy-image-id",
                secondary,
            ]
        )
        with (state / "private-additional-runner.log").open("x") as log:
            result = subprocess.run(
                [sys.executable, *extra, "--output", str(private)],
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=1800,
                check=False,
            )
        summary["additional_exit_code"] = result.returncode
        if result.returncode != 0:
            raise ValueError("additional actual probe failed")
        summary["additional_boundary"] = verify_probe(boundary, private, extended=True)
        if boundary == "ops":
            if source_digest() != marker["source_sha256"]:
                raise ValueError("conformance source changed before witness execution")
            witnessed = True
            private = state / "private-witness-probe"
            with (state / "private-witness-runner.log").open("x") as log:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "scripts.witness_checkpoint_rehearsal",
                        "--runtime-image",
                        primary,
                        "--worker-image",
                        secondary,
                        "--output",
                        str(private),
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=1800,
                    check=False,
                )
            summary["witness_exit_code"] = result.returncode
            if result.returncode != 0:
                raise ValueError("witness actual probe failed")
            summary["witness_boundary"] = verify_witness_probe(private)
        if source_digest() != marker["source_sha256"]:
            raise ValueError("conformance source changed during execution")
        summary["complete"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        summary["diagnostic"] = "actual-probe-or-evidence-failed; detail=omitted"
        summary["failed_probe"] = (
            "witness" if witnessed else "additional" if extended else "original"
        )
        summary.update(
            failed_probe_observation(boundary, private, extended=extended, witnessed=witnessed)
        )
    finally:
        summary["elapsed_seconds"] = perf_counter() - started
        write(state / "public-summary.json", summary)
    return 0 if summary["complete"] is True else 1


def verify_witness_probe(private: Path) -> dict[str, object]:
    report = json.loads((private / "report.json").read_text())
    probe = json.loads((private / "process-crash.json").read_text())
    if not isinstance(report, dict) or not isinstance(probe, dict):
        raise ValueError("OPS-005 witness evidence is not an object")
    checks = report.get("checks")
    if (
        report.get("version") != "ops005-linux-rehearsal-v1"
        or report.get("complete") is not True
        or report.get("checks_passed") is not True
        or report.get("cleanup") != "observed-absent"
        or not isinstance(checks, list)
        or len(checks) != len(OPS005_CHECKS)
        or not all(isinstance(check, str) for check in checks)
        or set(checks) != OPS005_CHECKS
        or report.get("anchor_volume_rollback_detected") is not True
        or any(
            report.get(key) is not False
            for key in (
                "physical_separate_host_verified",
                "simultaneous_store_rollback_detected",
                "power_loss_verified",
                "production_failover_verified",
            )
        )
        or probe.get("version") != "ops005-process-crash-v1"
        or probe.get("system") != "Linux"
        or probe.get("complete") is not True
        or type(probe.get("cycles")) is not int
        or probe.get("cycles") != 32
        or any(
            probe.get(key) is not True
            for key in (
                "sigkill_after_witness_fsync",
                "stale_head_denied",
                "original_retained",
            )
        )
        or probe.get("physical_host_failure_verified") is not False
        or probe.get("power_loss_verified") is not False
    ):
        raise ValueError("OPS-005 witness checks or boundary claims are incomplete")
    return dict(actual_checks=len(OPS005_CHECKS), process_restart_cycles=32, cleanup_observed=True)


def cleanup(boundary: str, state: Path, *, audit_only: bool) -> int:
    if not (state / "preflight.json").exists():
        # The run command cannot execute before successful preflight.
        print("No admitted fixture execution; no cleanup mutation performed.")
        return 0
    admitted(boundary, state)
    before = residue(boundary)
    failed = False
    if not audit_only:
        for kind in KINDS:
            for identity in before[kind]:
                try:
                    args = ["docker", kind, "rm"]
                    if kind == "container":
                        args.append("--force")
                    command(*args, identity)
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    failed = True
    after = residue(boundary)
    absent = not any(after.values())
    complete = absent and not failed and not any(before.values())
    write(
        state / ("public-residue.json" if audit_only else "public-cleanup.json"),
        dict(
            boundary=boundary,
            independent_observer=True,
            complete=complete,
            resources_absent=absent,
            before_counts={kind: len(ids) for kind, ids in before.items()},
            after_counts={kind: len(ids) for kind, ids in after.items()},
            fallback_needed=any(before.values()),
        ),
    )
    # Cleanup fallback does not turn a failed fixture cleanup into conformance success.
    return 0 if complete and not any(before.values()) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "run", "cleanup", "audit"))
    parser.add_argument("--boundary", choices=tuple(LABELS), required=True)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--primary-image")
    parser.add_argument("--secondary-image")
    parser.add_argument("--additional-image")
    args = parser.parse_args()
    try:
        if args.operation == "preflight":
            preflight(args.boundary, args.state)
            return 0
        if args.operation == "run":
            if not args.primary_image or not args.secondary_image:
                parser.error("run requires both observed image IDs")
            return run(
                args.boundary,
                args.state,
                args.primary_image,
                args.secondary_image,
                args.additional_image,
            )
        return cleanup(args.boundary, args.state, audit_only=args.operation == "audit")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("Linux conformance boundary rejected; detail=omitted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
