"""Run owned, offline real-Docker APP-002 conformance; never accepts an external target."""

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
from time import monotonic


def inventory() -> dict[str, str]:
    paths: list[Path] = []
    for directory in (
        "src/pajin/application_elf",
        "src/pajin/capabilities",
        "src/pajin/graph",
        "src/pajin/tools",
        "src/pajin/runtime",
        "src/pajin/policy",
        "containers/application-elf",
    ):
        paths.extend(
            path
            for path in Path(directory).rglob("*")
            if path.is_file() and (path.suffix == ".py" or path.name == "Dockerfile")
        )
    paths.extend(
        Path(name)
        for name in (
            "scripts/operational_application_elf.py",
            "tests/operational_application_elf_probe.py",
            "tests/app_002_support.py",
            "pyproject.toml",
            "uv.lock",
        )
    )
    return {path.as_posix(): sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}


def private_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as handle:
        path.chmod(0o600)
        json.dump(value, handle, sort_keys=True, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if re.fullmatch(r"sha256:[a-f0-9]{64}", args.image_id) is None:
        raise ValueError("APP-002 requires an exact local OCI image ID")
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if output.resolve() != output:
        raise ValueError("APP-002 output cannot contain symbolic links")
    before = inventory()
    private_json(output / "source-before.json", before)
    observed = json.loads(
        subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                args.image_id,
                "--format",
                '{"id":{{json .Id}},"architecture":{{json .Architecture}},'
                '"os":{{json .Os}},"user":{{json .Config.User}},'
                '"entrypoint":{{json .Config.Entrypoint}},'
                '"volumes":{{json (index .Config "Volumes")}}}',
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
        ).stdout
    )
    if (
        observed["id"] != args.image_id
        or observed["os"] != "linux"
        or observed["user"] != "65532:65532"
        or observed["entrypoint"] != ["python", "-I", "/app/entry.py"]
        or observed["volumes"]
    ):
        raise ValueError("APP-002 local image configuration differs")
    private_json(output / "owned-fixture-suite.json", observed)
    environment = {
        **os.environ,
        "PAJIN_APP002_ROOT": str(output),
        "PAJIN_APP002_IMAGE": args.image_id,
    }
    started, started_at = monotonic(), datetime.now(UTC)
    with (output / "pytest.log").open("x", encoding="utf-8") as log:
        (output / "pytest.log").chmod(0o600)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--tb=short",
                "tests/operational_application_elf_probe.py",
            ],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=600,
        )
    after = inventory()
    private_json(output / "source-after.json", after)
    report = {
        "version": "pajin.app-002.local-conformance/v1",
        "image": observed,
        "startedAt": started_at.isoformat(),
        "finishedAt": datetime.now(UTC).isoformat(),
        "elapsedSeconds": monotonic() - started,
        "pytestExitCode": result.returncode,
        "sourceUnchanged": before == after,
        "complete": result.returncode == 0 and before == after,
        "remoteConformanceAdmitted": False,
        "generalApplicationSupport": False,
    }
    private_json(output / "conformance.json", report)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
