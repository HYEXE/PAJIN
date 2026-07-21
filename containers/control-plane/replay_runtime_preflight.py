"""Fail-closed Docker authority preflight for the Compose Replay Worker."""

from __future__ import annotations

import os
import re
import subprocess
import sys

_DOCKER = "/usr/local/bin/docker"
_IMAGE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:-]*\Z")
_NETWORK_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_CHECK_TIMEOUT_SECONDS = 10


def _configured(name: str, pattern: re.Pattern[str]) -> str | None:
    value = os.environ.get(name)
    return value if value is not None and pattern.fullmatch(value) is not None else None


def _check(arguments: list[str]) -> bool:
    try:
        completed = subprocess.run(
            [_DOCKER, *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_CHECK_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def main() -> int:
    worker_image = _configured("PAJIN_REPLAY_WORKER_IMAGE", _IMAGE_PATTERN)
    proxy_image = _configured("PAJIN_REPLAY_EGRESS_PROXY_IMAGE", _IMAGE_PATTERN)
    external_network = _configured("PAJIN_REPLAY_EXTERNAL_NETWORK", _NETWORK_PATTERN)
    if worker_image is None or proxy_image is None or external_network is None:
        print("Replay Docker preflight configuration is invalid", file=sys.stderr)
        return 2

    checks = (
        ["version", "--format", "{{.Server.Version}}"],
        ["image", "inspect", worker_image, proxy_image],
        ["network", "inspect", external_network],
    )
    if not all(_check(arguments) for arguments in checks):
        print("Replay Docker preflight failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
