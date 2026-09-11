"""Measure verified Graph query memory and concurrent readers without changing authority."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import threading
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import perf_counter, process_time, thread_time
from typing import Any

MODULES = (
    "pajin.graph.projection",
    "pajin.graph.sqlite_store",
    "pajin.graph.snapshot_cache",
    "pajin.control_plane.graph_views",
)
EXPERIMENT_RSS_BUDGET_BYTES = 4 * 1024**3


def file_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def peak_rss() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def observe_verification_stages(stages: list[dict[str, Any]]) -> None:
    module = importlib.import_module("pajin.graph.sqlite_store")

    def observe(name: str) -> None:
        original = getattr(module, name)

        def measured(*args: Any, **kwargs: Any) -> Any:
            before = tracemalloc.get_traced_memory()[0]
            value = original(*args, **kwargs)
            live, peak = tracemalloc.get_traced_memory()
            stages.append(
                dict(
                    stage=name,
                    before_bytes=before,
                    live_bytes=live,
                    peak_bytes=peak,
                    returned_items=len(value[0]) if name == "_verified_snapshots" else len(value),
                )
            )
            return value

        setattr(module, name, measured)

    observe("_verified_projections")
    observe("_verified_snapshots")


def probe(
    directory: Path,
    source: Path,
    output: Path,
    *,
    workers: int,
    shared: bool,
    instrument: bool,
) -> dict[str, Any]:
    from pajin.control_plane.graph_views import VerifiedCanonicalGraphViewReader

    loaded = {}
    for name in MODULES:
        filename = importlib.import_module(name).__file__
        expected = (source / (name.replace(".", "/") + ".py")).resolve()
        if filename is None or Path(filename).resolve() != expected:
            raise ValueError("measurement imported a different source tree")
        loaded[name] = file_digest(expected)
    fixture = json.loads((directory / "fixture.json").read_text())
    for phase in ("base", "changed"):
        if file_digest(directory / f"{phase}.db") != fixture[phase]["database_sha256"]:
            raise ValueError("frozen benchmark fixture changed")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = output / "graph.db"
    shutil.copyfile(directory / "base.db", database)
    gc.collect()
    # Trace in a separate fresh process; imports and whole-file fixture verification are excluded.
    if instrument:
        tracemalloc.start()
    stages: list[dict[str, Any]] = []
    if instrument:
        observe_verification_stages(stages)
    readers = [VerifiedCanonicalGraphViewReader(database) for _ in range(1 if shared else workers)]
    samples = []
    for phase in ("base", "changed"):
        if phase == "changed":
            shutil.copyfile(directory / "changed.db", database)
        for batch in range(3):
            gc.collect()
            trace_before = tracemalloc.get_traced_memory()[0] if instrument else 0
            if instrument:
                tracemalloc.reset_peak()
            barrier = threading.Barrier(workers)

            def query(
                index: int,
                phase: str = phase,
                barrier: threading.Barrier = barrier,
            ) -> dict[str, float]:
                expected = fixture[phase]
                barrier.wait(timeout=60)
                wall, cpu = perf_counter(), thread_time()
                page = readers[0 if shared else index].read_page(
                    campaign=expected["campaign"],
                    snapshot_id=expected["snapshot_id"],
                    limit=100,
                    cursor=None,
                )
                elapsed, consumed = perf_counter() - wall, thread_time() - cpu
                if (page.node_count, page.edge_count) != (
                    expected["nodes"],
                    expected["edges"],
                ) or page.snapshot.snapshot_digest != expected["snapshot_digest"]:
                    raise ValueError("query result differs from the frozen Graph fixture")
                return dict(wall_seconds=elapsed, thread_cpu_seconds=consumed)

            usage = resource.getrusage(resource.RUSAGE_SELF)
            wall, cpu = perf_counter(), process_time()
            with ThreadPoolExecutor(max_workers=workers) as executor:
                queries = list(executor.map(query, range(workers)))
            elapsed, consumed = perf_counter() - wall, process_time() - cpu
            ended = resource.getrusage(resource.RUSAGE_SELF)
            live, peak = tracemalloc.get_traced_memory() if instrument else (0, 0)
            gc.collect()
            retained = tracemalloc.get_traced_memory()[0] if instrument else 0
            samples.append(
                dict(
                    phase=phase,
                    batch=batch,
                    queries=queries,
                    wall_seconds=elapsed,
                    process_cpu_seconds=consumed,
                    queries_per_second=workers / elapsed,
                    process_peak_rss_bytes=peak_rss(),
                    input_blocks=ended.ru_inblock - usage.ru_inblock,
                    output_blocks=ended.ru_oublock - usage.ru_oublock,
                    expected_explicit_hash_bytes=2 * workers * fixture[phase]["database_bytes"],
                    traced_before_bytes=trace_before,
                    traced_live_bytes=live,
                    traced_peak_bytes=peak,
                    traced_retained_after_gc_bytes=retained,
                )
            )
    allocations = []
    if instrument:
        allocations = [
            dict(
                file=Path(stat.traceback[0].filename).name,
                line=stat.traceback[0].lineno,
                bytes=stat.size,
                count=stat.count,
            )
            for stat in tracemalloc.take_snapshot().statistics("lineno")[:15]
        ]
        tracemalloc.stop()
    if file_digest(database) != fixture["changed"]["database_sha256"]:
        raise ValueError("measurement changed application state")
    return dict(
        fixture=fixture,
        workers=workers,
        shared_reader=shared,
        instrumented=instrument,
        loaded_source_sha256=loaded,
        samples=samples,
        retained_allocations=allocations,
        verification_stages=stages,
        process_peak_rss_bytes=peak_rss(),
        experiment_rss_budget_bytes=EXPERIMENT_RSS_BUDGET_BYTES,
        within_experiment_budget=peak_rss() <= EXPERIMENT_RSS_BUDGET_BYTES,
    )


def measure(directory: Path, source: Path, output: Path) -> None:
    if output.exists():
        raise ValueError("measurement output must be new")
    results = []
    # Same fixture bytes and workloads before/after; no physical-disk coldness claim.
    for name in ("medium", "history"):
        for workers, shared in ((1, True), (2, True), (2, False)):
            for repetition in range(3):
                args = [
                    sys.executable,
                    __file__,
                    "probe",
                    "--directory",
                    str(directory / name),
                    "--source-root",
                    str(source),
                    "--output",
                    str(output.with_suffix("") / f"{name}-{workers}-{shared}-{repetition}"),
                    "--workers",
                    str(workers),
                ]
                if shared:
                    args.append("--shared")
                result = subprocess.run(
                    args,
                    capture_output=True,
                    check=True,
                    timeout=1800,
                    env={**os.environ, "PYTHONPATH": str(source)},
                )
                results.append(
                    dict(name=name, repetition=repetition, result=json.loads(result.stdout))
                )
                print(
                    json.dumps(
                        dict(fixture=name, workers=workers, shared=shared, repetition=repetition)
                    ),
                    flush=True,
                )
        # Allocation distributions use three independent processes, without concurrent readers.
        for repetition in range(3):
            result = subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "probe",
                    "--directory",
                    str(directory / name),
                    "--source-root",
                    str(source),
                    "--output",
                    str(output.with_suffix("") / f"{name}-traced-{repetition}"),
                    "--workers",
                    "1",
                    "--shared",
                    "--instrument",
                ],
                capture_output=True,
                check=True,
                timeout=1800,
                env={**os.environ, "PYTHONPATH": str(source)},
            )
            results.append(dict(name=name, repetition=repetition, result=json.loads(result.stdout)))
            print(json.dumps(dict(fixture=name, traced=True, repetition=repetition)), flush=True)
    report = dict(
        version="graph-perf-003-v1",
        python=platform.python_version(),
        system=platform.system(),
        architecture=platform.machine(),
        experiment_sha256=file_digest(Path(__file__)),
        sources={name: file_digest(source / (name.replace(".", "/") + ".py")) for name in MODULES},
        scope="warm filesystem pages; query batches; shared or independent in-process readers",
        rss_scope="process high-water mark including imports; not live heap or cache capacity",
        io_scope="OS block counters; expected hash bytes are analytical, not total SQLite I/O",
        tracing_scope="separate fresh processes; live before GC and retained after GC; not latency",
        results=results,
    )
    with output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("measure", "probe"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workers", type=int, choices=(1, 2), default=1)
    parser.add_argument("--shared", action="store_true")
    parser.add_argument("--instrument", action="store_true")
    args = parser.parse_args()
    source = args.source_root.resolve()
    if args.operation == "measure":
        measure(args.directory, source, args.output)
    else:
        print(
            json.dumps(
                probe(
                    args.directory,
                    source,
                    args.output,
                    workers=args.workers,
                    shared=args.shared,
                    instrument=args.instrument,
                )
            )
        )


if __name__ == "__main__":
    main()
