"""Measured test durations are scheduling hints, never test-success or execution authority."""

from __future__ import annotations

import argparse
import heapq
import json
import math
import subprocess
from collections.abc import Iterable, Mapping
from hashlib import sha256
from pathlib import Path
from statistics import median

import pytest

_MAX_PROFILE_BYTES = 16 * 1024 * 1024


def canonical_nodeid(nodeid: str) -> str:
    path, separator, remainder = nodeid.partition("::")
    normalized = path.replace("\\", "/")
    return f"{normalized}{separator}{remainder}"


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duration profile contains duplicate fields")
        result[key] = value
    return result


def load_durations(path: Path) -> dict[str, float]:
    if path.stat().st_size > _MAX_PROFILE_BYTES:
        raise ValueError("duration profile exceeds its size limit")
    with path.open("rb") as stream:
        raw = stream.read(_MAX_PROFILE_BYTES + 1)
    if len(raw) > _MAX_PROFILE_BYTES:
        raise ValueError("duration profile exceeds its size limit")
    document = json.loads(raw, object_pairs_hook=_unique_fields)
    if (
        not isinstance(document, dict)
        or type(document.get("version")) is not int
        or document["version"] != 1
        or not isinstance(document.get("durations"), dict)
        or len(document["durations"]) > 100_000
    ):
        raise ValueError("duration profile schema is invalid")
    result: dict[str, float] = {}
    for nodeid, seconds in document["durations"].items():
        if (
            not isinstance(nodeid, str)
            or not 1 <= len(nodeid) <= _MAX_PROFILE_BYTES
            or nodeid != canonical_nodeid(nodeid)
            or type(seconds) not in {float, int}
            or not 0 <= seconds <= 86_400
            or not math.isfinite(seconds)
        ):
            raise ValueError("duration profile contains an invalid measurement")
        result[nodeid] = float(seconds)
    return result


def assign_duration_shards(
    nodeids: Iterable[str],
    durations: Mapping[str, float],
    total: int,
) -> dict[str, int]:
    """Assign every collected test exactly once using deterministic longest-first placement."""
    if total < 1:
        raise ValueError("shard count must be positive")
    canonical = [canonical_nodeid(nodeid) for nodeid in nodeids]
    if len(set(canonical)) != len(canonical):
        raise ValueError("collected test identities must be unique")
    observed = [durations[nodeid] for nodeid in canonical if durations.get(nodeid, 0) > 0]
    fallback = median(observed) if observed else 1.0
    weights = {nodeid: max(durations.get(nodeid, fallback), 0.000001) for nodeid in canonical}
    pending = [(0.0, index) for index in range(total)]
    heapq.heapify(pending)
    assignments: dict[str, int] = {}
    for nodeid in sorted(canonical, key=lambda item: (-weights[item], item)):
        elapsed, index = heapq.heappop(pending)
        assignments[nodeid] = index
        heapq.heappush(pending, (elapsed + weights[nodeid], index))
    return assignments


def write_durations(
    path: Path,
    durations: Mapping[str, float],
    metadata: Mapping[str, object],
) -> None:
    payload = (
        json.dumps(
            {"version": 1, "metadata": dict(metadata), "durations": dict(durations)},
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )
    if len(payload.encode()) > _MAX_PROFILE_BYTES:
        raise ValueError("duration profile exceeds its size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


class DurationRecorder:
    def __init__(self, output: Path, root: Path) -> None:
        self.output = output
        self.durations: dict[str, float] = {}
        self.source: dict[str, object] = {"commit": None, "worktreeClean": None}
        try:
            self.source = {
                "commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"],
                    cwd=root,
                    stderr=subprocess.DEVNULL,
                    text=True,
                ).strip(),
                "worktreeClean": not subprocess.check_output(
                    ["git", "status", "--porcelain"],
                    cwd=root,
                    stderr=subprocess.DEVNULL,
                ),
            }
        except (OSError, subprocess.CalledProcessError):
            self.source["gitStatus"] = "unavailable"

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        nodeid = canonical_nodeid(report.nodeid)
        self.durations[nodeid] = self.durations.get(nodeid, 0) + report.duration

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        write_durations(
            self.output,
            self.durations,
            {
                "source": self.source,
                "exitStatus": int(exitstatus),
                "selectedTests": session.testscollected,
                "reportedTests": len(self.durations),
                "measurement": "setup-call-teardown-seconds",
                "schedulingHintOnly": True,
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profiles", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    combined: dict[str, float] = {}
    sources: list[dict[str, object]] = []
    for path in arguments.profiles:
        durations = load_durations(path)
        if combined.keys() & durations.keys():
            parser.error("duration inputs overlap; select one measurement per test")
        combined.update(durations)
        with path.open("rb") as stream:
            raw = stream.read(_MAX_PROFILE_BYTES + 1)
        if len(raw) > _MAX_PROFILE_BYTES:
            parser.error("duration profile exceeds its size limit")
        sources.append(
            {"sha256": sha256(raw).hexdigest(), "metadata": json.loads(raw).get("metadata")}
        )
    write_durations(
        arguments.output,
        combined,
        {
            "sourceProfileCount": len(arguments.profiles),
            "sourceProfiles": sources,
            "schedulingHintOnly": True,
        },
    )


if __name__ == "__main__":
    main()
