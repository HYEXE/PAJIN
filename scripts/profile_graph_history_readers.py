"""Measure current/history API reads and sampled simultaneous Linux reader RSS."""

from __future__ import annotations

import argparse
import gc
import importlib
import json
import multiprocessing
import os
import platform
import resource
import shutil
import sqlite3
import subprocess
import sys
from multiprocessing.connection import Connection, wait
from multiprocessing.synchronize import Barrier
from pathlib import Path
from time import perf_counter, process_time
from typing import TypedDict, cast

from scripts.profile_graph_processes import FixtureHead, file_digest, prepare_cache

VIEWS = ("current", "catalog", "historical-page")
MODULES = (
    "pajin.graph.projection",
    "pajin.graph.sqlite_store",
    "pajin.graph.snapshot_cache",
    "pajin.graph.history",
    "pajin.control_plane.graph_views",
    "pajin.control_plane.graph_browser",
)
SAMPLE_INTERVAL = 0.005


class SelectedSnapshot(TypedDict):
    snapshot_id: str
    snapshot_digest: str
    nodes: int
    edges: int


class HistoryFixture(TypedDict):
    current: FixtureHead
    older: SelectedSnapshot
    catalog_ids: list[str]
    state: str


def loaded_sources(source: Path) -> dict[str, str]:
    pins = {}
    names = (
        (*MODULES, "pajin.graph.history_cache")
        if (source / "pajin/graph/history_cache.py").exists()
        else MODULES
    )
    for name in names:
        filename = importlib.import_module(name).__file__
        expected = source / (name.replace(".", "/") + ".py")
        if filename is None or Path(filename).resolve() != expected.resolve():
            raise ValueError("Graph history probe imported a different source tree")
        pins[name] = file_digest(expected)
    return pins


def fixture_expectations(directory: Path) -> HistoryFixture:
    from pajin.graph.models import graph_digest

    current = cast(dict[str, FixtureHead], json.loads((directory / "fixture.json").read_bytes()))[
        "changed"
    ]
    database = directory / "changed.db"
    if file_digest(database) != current["database_sha256"]:
        raise ValueError("Graph fixture bytes differ from their frozen commitment")
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT snapshot_id, snapshot_digest, "
            "json_array_length(snapshot_json, '$.projection.nodes'), "
            "json_array_length(snapshot_json, '$.projection.edges') "
            "FROM graph_snapshots ORDER BY ordinal DESC"
        ).fetchall()
        event = connection.execute(
            "SELECT event_digest FROM graph_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        projection = connection.execute(
            "SELECT projection_digest FROM graph_projections ORDER BY revision DESC LIMIT 1"
        ).fetchone()
    if len(rows) < 2:
        raise ValueError("history measurement requires at least two snapshots")
    return {
        "current": current,
        "older": SelectedSnapshot(
            snapshot_id=rows[1][0], snapshot_digest=rows[1][1], nodes=rows[1][2], edges=rows[1][3]
        ),
        "catalog_ids": [row[0] for row in rows],
        "state": graph_digest(
            "pajin.graph.history-state/v1",
            {
                "campaign": current["campaign"],
                "snapshotHead": rows[0][1],
                "eventHead": event[0] if event else None,
                "projection": projection[0],
            },
            max_bytes=4096,
        ),
    }


def query_worker(
    connection: Connection,
    barrier: Barrier,
    database: Path,
    source: Path,
    expected: HistoryFixture,
    view: str,
) -> None:
    from pajin.control_plane.graph_browser import GraphCampaignBrowser
    from pajin.control_plane.graph_pages import CanonicalGraphPageContent
    from pajin.control_plane.graph_views import VerifiedCanonicalGraphViewReader

    pins = loaded_sources(source)
    campaign = expected["current"]["campaign"]
    reader = VerifiedCanonicalGraphViewReader(database)
    browser = GraphCampaignBrowser({campaign: database})
    page: CanonicalGraphPageContent
    try:
        for batch in range(3):
            gc.collect()
            connection.send({"ready": batch, "pid": os.getpid(), "sources": pins})
            barrier.wait(timeout=60)
            before = resource.getrusage(resource.RUSAGE_SELF)
            wall, cpu = perf_counter(), process_time()
            if view == "catalog":
                catalog = browser.catalog(campaign, limit=25, cursor=None)
                payload = catalog
            else:
                selected = expected["current"] if view == "current" else expected["older"]
                if view == "current":
                    page = reader.read_page(
                        campaign=campaign,
                        snapshot_id=selected["snapshot_id"],
                        limit=100,
                        cursor=None,
                    )
                else:
                    page = browser.page(
                        campaign,
                        selected["snapshot_id"],
                        state=expected["state"],
                        limit=100,
                        cursor=None,
                    )
                payload = page.model_dump(mode="json", by_alias=True)
            elapsed, consumed = perf_counter() - wall, process_time() - cpu
            after = resource.getrusage(resource.RUSAGE_SELF)
            if view == "catalog":
                if (
                    catalog["total"] != len(expected["catalog_ids"])
                    or catalog["stateDigest"] != expected["state"]
                    or [
                        item["snapshot_id"]
                        for item in cast(list[dict[str, object]], catalog["items"])
                    ]
                    != expected["catalog_ids"]
                ):
                    raise ValueError("Graph catalog differs from frozen history")
            elif (page.node_count, page.edge_count) != (
                selected["nodes"],
                selected["edges"],
            ) or page.snapshot.snapshot_digest != selected["snapshot_digest"]:
                raise ValueError("Graph page differs from frozen snapshot")
            # This equality commitment is outside the API wall/CPU interval.
            import hashlib

            payload_digest = hashlib.sha256(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode()
            ).hexdigest()
            connection.send(
                {
                    "batch": batch,
                    "pid": os.getpid(),
                    "wall_seconds": elapsed,
                    "cpu_seconds": consumed,
                    "peak_rss_bytes": int(after.ru_maxrss * 1024),
                    "input_blocks": after.ru_inblock - before.ru_inblock,
                    "output_blocks": after.ru_oublock - before.ru_oublock,
                    "result_sha256": payload_digest,
                }
            )
    finally:
        connection.close()


def rss_bytes(pid: int) -> int:
    try:
        return int(Path(f"/proc/{pid}/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except FileNotFoundError:
        return 0


def receive(connection: Connection) -> dict[str, object]:
    if not connection.poll(900):
        raise TimeoutError("Graph child did not complete the bounded probe")
    value = connection.recv()
    if not isinstance(value, dict):
        raise ValueError("Graph child returned an invalid result")
    return cast(dict[str, object], value)


def observe_group(
    connections: list[Connection], pids: list[int]
) -> tuple[list[dict[str, object]], dict[str, object]]:
    pending = list(connections)
    received: dict[Connection, dict[str, object]] = {}
    samples = 0
    peak, combined_peak = 0, 0
    last, largest_gap = perf_counter(), 0.0
    deadline = last + 900
    while pending:
        now = perf_counter()
        if now >= deadline:
            raise TimeoutError("Graph concurrent read exceeded its bound")
        largest_gap = max(largest_gap, now - last)
        last = now
        total = sum(rss_bytes(pid) for pid in pids)
        peak = max(peak, total)
        combined_peak = max(combined_peak, total + rss_bytes(os.getpid()))
        samples += 1
        ready = wait(pending, timeout=SAMPLE_INTERVAL)
        for connection in list(pending):
            if connection in ready:
                received[connection] = receive(connection)
                pending.remove(connection)
    return [received[c] for c in connections], {
        "sampled_peak_reader_rss_bytes": peak,
        "sampled_peak_readers_plus_coordinator_rss_bytes": combined_peak,
        "samples": samples,
        "target_interval_seconds": SAMPLE_INTERVAL,
        "largest_observed_interval_seconds": largest_gap,
    }


def probe(
    directory: Path, source: Path, output: Path, *, workers: int, cold: bool, view: str
) -> dict[str, object]:
    if sys.platform != "linux" or workers not in (1, 2) or view not in VIEWS:
        raise ValueError("Graph history measurement requires Linux and a supported view")
    expected = fixture_expectations(directory)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = output / "graph.db"
    shutil.copyfile(directory / "changed.db", database)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(workers + 1)
    connections, children = [], []
    samples = []
    try:
        for _ in range(workers):
            parent, child_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=query_worker,
                args=(
                    child_connection,
                    barrier,
                    database,
                    source,
                    expected,
                    view,
                ),
            )
            process.start()
            child_connection.close()
            connections.append(parent)
            children.append(process)
        for batch in range(3):
            readiness = [receive(c) for c in connections]
            pids = [cast(int, r["pid"]) for r in readiness]
            if len(set(pids)) != workers or any(
                r["ready"] != batch or r["sources"] != loaded_sources(source) for r in readiness
            ):
                raise ValueError("Graph reader identity, batch or source differs")
            residency = prepare_cache(database, cold=cold and batch == 0)
            started = perf_counter()
            barrier.wait(timeout=60)
            results, memory = observe_group(connections, pids)
            elapsed = perf_counter() - started
            if (
                any(r["batch"] != batch for r in results)
                or len({r["result_sha256"] for r in results}) != 1
            ):
                raise ValueError("concurrent Graph results disagree")
            samples.append(
                {
                    "batch": batch,
                    "residency_before": residency,
                    "group_wall_seconds": elapsed,
                    "queries": results,
                    "memory": memory,
                }
            )
        for child in children:
            child.join(timeout=10)
            if child.exitcode != 0:
                raise ValueError("Graph reader did not exit successfully")
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
            child.join(timeout=10)
        for connection in connections:
            connection.close()
    if file_digest(database) != expected["current"]["database_sha256"]:
        raise ValueError("Graph history measurement modified fixture bytes")
    return {
        "workers": workers,
        "view": view,
        "first_guest_cache_cold": cold,
        "loaded_source_sha256": loaded_sources(source),
        "fixture": expected,
        "samples": samples,
        "rss_scope": (
            "sampled simultaneous summed RSS, shared pages count per reader; "
            "not unique physical memory"
        ),
        "cache_scope": "observed Linux guest file pages; host/device cache unknown",
    }


def measure(directory: Path, source: Path, output: Path, repetitions: int) -> None:
    if output.exists() or not 1 <= repetitions <= 3:
        raise ValueError("Graph measurement requires a new output and 1..3 repetitions")
    output.with_suffix("").mkdir(mode=0o700, parents=True, exist_ok=False)
    results = []
    for name in ("medium", "history"):
        for view in VIEWS:
            for workers in (1, 2):
                for cold in (False, True):
                    for repetition in range(repetitions):
                        child = (
                            output.with_suffix("") / f"{name}-{view}-{workers}-{cold}-{repetition}"
                        )
                        command = [
                            sys.executable,
                            "-m",
                            "scripts.profile_graph_history_readers",
                            "probe",
                            "--directory",
                            str(directory / name),
                            "--source-root",
                            str(source),
                            "--output",
                            str(child),
                            "--workers",
                            str(workers),
                            "--view",
                            view,
                        ]
                        if cold:
                            command.append("--cold")
                        try:
                            completed = subprocess.run(
                                command,
                                capture_output=True,
                                check=False,
                                timeout=900,
                                env={
                                    **os.environ,
                                    "PYTHONPATH": os.pathsep.join(
                                        (str(source), str(Path(__file__).resolve().parent.parent))
                                    ),
                                },
                            )
                        except subprocess.TimeoutExpired as exc:
                            child.with_suffix(".stdout.json").write_bytes(exc.stdout or b"")
                            child.with_suffix(".stderr.log").write_bytes(exc.stderr or b"")
                            raise
                        child.with_suffix(".stdout.json").write_bytes(completed.stdout)
                        child.with_suffix(".stderr.log").write_bytes(completed.stderr)
                        if completed.returncode:
                            # Preserve the child's actual error in the controller log as well.
                            sys.stderr.buffer.write(completed.stderr)
                            sys.stderr.buffer.flush()
                        completed.check_returncode()
                        results.append(
                            {
                                "fixture": name,
                                "repetition": repetition,
                                "result": json.loads(completed.stdout),
                            }
                        )
                        output.with_suffix(".partial.json").write_text(
                            json.dumps(
                                {"complete": False, "results": results},
                                allow_nan=False,
                            )
                        )
                        # Every successful child verified these owned copy bytes before exit.
                        # Retaining all copies would accumulate gigabytes outside the sample.
                        (child / "graph.db").unlink()
                        print(
                            json.dumps(
                                {
                                    "fixture": name,
                                    "view": view,
                                    "workers": workers,
                                    "cold": cold,
                                    "repetition": repetition,
                                }
                            ),
                            flush=True,
                        )
    with output.open("x") as stream:
        json.dump(
            {
                "version": "graph-perf-006-v1",
                "python": platform.python_version(),
                "system": platform.system(),
                "architecture": platform.machine(),
                "profiler_sha256": file_digest(Path(__file__)),
                "cache_helper_sha256": file_digest(
                    Path(__file__).with_name("profile_graph_processes.py")
                ),
                "results": results,
            },
            stream,
            indent=2,
            allow_nan=False,
        )
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("probe", "measure"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workers", type=int, choices=(1, 2), default=1)
    parser.add_argument("--view", choices=VIEWS, default="historical-page")
    parser.add_argument("--cold", action="store_true")
    parser.add_argument("--repetitions", type=int, choices=(1, 2, 3), default=3)
    args = parser.parse_args()
    paths = (args.directory.resolve(), args.source_root.resolve(), args.output.resolve())
    if args.operation == "measure":
        measure(paths[0], paths[1], paths[2], repetitions=args.repetitions)
    else:
        print(
            json.dumps(
                probe(*paths, workers=args.workers, cold=args.cold, view=args.view), allow_nan=False
            )
        )


if __name__ == "__main__":
    main()
