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
    "sys": ("pajin.sys002-owner", "pajin.execution-id"),
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


def verify_probe(boundary: str, private: Path) -> dict[str, object]:
    report = json.loads((private / "report.json").read_text())
    if not isinstance(report, dict) or report.get("complete") is not True:
        raise ValueError("actual probe is incomplete")
    if boundary == "ops":
        checks = report.get("checks")
        if (
            report.get("checks_passed") is not True
            or report.get("cleanup") != "observed-absent"
            or not isinstance(checks, list)
            or not all(isinstance(check, str) for check in checks)
            or len(checks) != 11
            or len(set(checks)) != 11
            or set(checks) != OPS_CHECKS
        ):
            raise ValueError("OPS actual checks or cleanup are incomplete")
        return dict(actual_checks=11, cleanup_observed=True)
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
    return dict(actual_tests_passed=1, worker_executions=4, cleanup_observed=True)


def failed_probe_observation(boundary: str, private: Path) -> dict[str, object]:
    """Expose only an allowlisted OPS phase/count, never private command output."""
    unknown: dict[str, object] = dict(observed_phase="unknown", completed_checks=None)
    if boundary != "ops":
        return unknown
    from scripts.hybrid_operations_rehearsal import PHASES

    try:
        path = private / "report.json"
        if path.stat().st_size > 65_536:
            return unknown
        report = json.loads(path.read_bytes())
        if not isinstance(report, dict):
            return unknown
        checks, phase = report.get("checks"), report.get("phase")
        if (
            report.get("version") != "ops003-linux-rehearsal-v1"
            or not isinstance(phase, str) or phase not in PHASES
            or not isinstance(checks, list) or len(checks) > len(OPS_CHECKS)
            or not all(isinstance(check, str) and check in OPS_CHECKS for check in checks)
            or len(set(checks)) != len(checks)
        ):
            return unknown
        return dict(observed_phase=phase, completed_checks=len(checks))
    except (OSError, ValueError):
        return unknown


def run(boundary: str, state: Path, primary: str, secondary: str) -> int:
    marker = admitted(boundary, state)
    if any(
        (state / name).exists()
        for name in (
            "private-runner.log",
            "private-probe",
            "public-summary.json",
        )
    ):
        raise ValueError("conformance execution requires a fresh workflow attempt")
    if source_digest() != marker["source_sha256"]:
        raise ValueError("conformance source changed after clean-commit gate")
    images = [image_record(primary), image_record(secondary)]
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
            raise ValueError("conformance source changed during execution")
        summary["complete"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        summary["diagnostic"] = "actual-probe-or-evidence-failed; detail=omitted"
        summary.update(failed_probe_observation(boundary, private))
    finally:
        summary["elapsed_seconds"] = perf_counter() - started
        write(state / "public-summary.json", summary)
    return 0 if summary["complete"] is True else 1


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
    args = parser.parse_args()
    try:
        if args.operation == "preflight":
            preflight(args.boundary, args.state)
            return 0
        if args.operation == "run":
            if not args.primary_image or not args.secondary_image:
                parser.error("run requires both observed image IDs")
            return run(args.boundary, args.state, args.primary_image, args.secondary_image)
        return cleanup(args.boundary, args.state, audit_only=args.operation == "audit")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("Linux conformance boundary rejected; detail=omitted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
