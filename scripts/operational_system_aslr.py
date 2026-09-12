"""Explicit owned SYS-004 Docker fixture; no caller-supplied target or cloud credentials."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import uuid4


def docker(*arguments: str) -> str:
    return subprocess.run(
        ["docker", *arguments], check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def inventory() -> dict[str, str]:
    paths = [
        p
        for directory in ("src/pajin", "containers/system-aslr")
        for p in Path(directory).rglob("*")
        if p.is_file() and (p.suffix == ".py" or p.name == "Dockerfile")
    ]
    paths += [
        Path("scripts/operational_system_aslr.py"),
        Path("tests/operational_system_aslr_probe.py"),
        Path("tests/sys_004_support.py"),
    ]
    return {str(p): sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def write(path: Path, value: object) -> None:
    with path.open("x") as handle:
        path.chmod(0o600)
        json.dump(value, handle, indent=2, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--proxy-image-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for image in (args.image_id, args.proxy_image_id):
        if re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None:
            raise ValueError("exact local OCI IDs required")
        if docker("image", "inspect", image, "--format", "{{.Id}}") != image:
            raise ValueError("image differs")
    output = args.output.absolute()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    if output.resolve() != output:
        raise ValueError("private output cannot contain symbolic links")
    owner = "pajin.sys004-owner=" + uuid4().hex
    before = inventory()
    write(output / "source-before.json", before)
    write(
        output / "invocation.json",
        {
            "owner": owner,
            "image": args.image_id,
            "proxyImage": args.proxy_image_id,
            "startedAt": datetime.now(UTC).isoformat(),
        },
    )
    code = 1
    cleanup: dict[str, object] = {}
    try:
        with (output / "pytest.log").open("x") as log:
            code = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "--tb=short",
                    "tests/operational_system_aslr_probe.py",
                ],
                env={
                    **os.environ,
                    "PAJIN_SYS004_ROOT": str(output),
                    "PAJIN_SYS004_OWNER": owner,
                    "PAJIN_SYS004_IMAGE": args.image_id,
                    "PAJIN_SYS004_PROXY": args.proxy_image_id,
                },
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=600,
            ).returncode
    finally:
        for identifier in docker(
            "ps", "--all", "--filter", "label=" + owner, "--format", "{{.ID}}"
        ).splitlines():
            logs = subprocess.run(
                ["docker", "logs", "--tail", "100", identifier],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            (output / (identifier + "-agent.log")).write_text(logs.stdout + logs.stderr)
            docker("rm", "--force", identifier)
        cleanup["ownedAgentContainersAbsent"] = not docker(
            "ps", "--all", "--filter", "label=" + owner, "--format", "{{.ID}}"
        )
        executions = sorted(
            {
                json.loads(path.read_text())["worker_result"]["execution_id"]
                for path in output.glob("*-outcome.json")
            }
        )
        residue = []
        for execution in executions:
            for command in (("ps", "--all"), ("network", "ls")):
                if docker(
                    *command,
                    "--filter",
                    "label=pajin.execution-id=" + execution,
                    "--format",
                    "{{.ID}}",
                ):
                    residue.append(execution)
        cleanup["observedWorkerExecutions"] = len(executions)
        cleanup["workerAndProxyResourcesAbsent"] = len(executions) == 4 and not residue
        cleanup["independentObserver"] = True
        cleanup["observedAt"] = datetime.now(UTC).isoformat()
        write(output / "cleanup.json", cleanup)
        after = inventory()
        write(output / "source-after.json", after)
        complete = code == 0 and before == after and all(
            cleanup[name]
            for name in (
                "ownedAgentContainersAbsent",
                "workerAndProxyResourcesAbsent",
                "independentObserver",
            )
        )
        write(
            output / "report.json",
            {
                "exitCode": code,
                "sourceUnchanged": before == after,
                "complete": complete,
                "cleanup": cleanup,
                "finishedAt": datetime.now(UTC).isoformat(),
            },
        )
    print(
        json.dumps(
            {
                "exitCode": code, "sourceUnchanged": before == after,
                "cleanup": cleanup, "complete": complete,
            },
            sort_keys=True,
        )
    )
    return code if code else int(not complete)


if __name__ == "__main__":
    raise SystemExit(main())
