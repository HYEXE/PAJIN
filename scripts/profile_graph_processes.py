"""Measure separate Linux Graph readers with observed file-page residency, not global eviction."""

from __future__ import annotations

import argparse
import cProfile
import ctypes
import gc
import hashlib
import importlib
import json
import mmap
import multiprocessing
import os
import platform
import resource
import shutil
import stat
import subprocess
import sys
from multiprocessing.connection import Connection
from multiprocessing.synchronize import Barrier
from pathlib import Path
from time import perf_counter, process_time
from types import CodeType
from typing import TypedDict, cast

MODULES = (
    "pajin.graph.projection",
    "pajin.graph.sqlite_store",
    "pajin.graph.snapshot_cache",
    "pajin.control_plane.graph_views",
)


class FixtureHead(TypedDict):
    campaign: str
    snapshot_id: str
    snapshot_digest: str
    nodes: int
    edges: int
    database_sha256: str


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def resident_pages(descriptor: int, size: int) -> dict[str, int]:
    """Observe a Linux mapping without reading or faulting its file data into memory."""
    if sys.platform != "linux" or size <= 0:
        raise ValueError("file residency observation requires Linux and a nonempty file")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = (
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_long,
    )
    libc.mmap.restype = ctypes.c_void_p
    libc.mincore.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte))
    libc.mincore.restype = ctypes.c_int
    libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    libc.munmap.restype = ctypes.c_int
    address = libc.mmap(None, size, 0, mmap.MAP_PRIVATE, descriptor, 0)
    if address == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), "file residency mapping failed")
    pages = (size + mmap.PAGESIZE - 1) // mmap.PAGESIZE
    vector = (ctypes.c_ubyte * pages)()
    try:
        if libc.mincore(address, size, vector) != 0:
            raise OSError(ctypes.get_errno(), "file residency observation failed")
        return {"pages": pages, "resident": sum(bool(value & 1) for value in vector)}
    finally:
        if libc.munmap(address, size) != 0:
            raise OSError(ctypes.get_errno(), "file residency mapping release failed")


def prepare_cache(path: Path, *, cold: bool) -> dict[str, int]:
    """Flush/advise only this owned fixture, then require the requested residency state."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_uid != os.geteuid():
            raise ValueError("cache probe requires its own nonempty regular fixture")
        os.fsync(descriptor)
        if cold:
            os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
        else:
            while os.read(descriptor, 1024 * 1024):
                pass
        result = resident_pages(descriptor, info.st_size)
        expected = 0 if cold else result["pages"]
        if result["resident"] != expected:
            raise ValueError("requested file page-cache state was not observed")
        return result
    finally:
        os.close(descriptor)


def loaded_sources(source: Path) -> dict[str, str]:
    result = {}
    for name in MODULES:
        filename = importlib.import_module(name).__file__
        expected = (source / (name.replace(".", "/") + ".py")).resolve()
        if filename is None or Path(filename).resolve() != expected:
            raise ValueError("Graph probe imported a different source tree")
        result[name] = file_digest(expected)
    return result


def query_worker(
    connection: Connection,
    barrier: Barrier,
    database: Path,
    source: Path,
    expected: FixtureHead,
    instrument: bool,
) -> None:
    from pajin.control_plane.graph_views import VerifiedCanonicalGraphViewReader

    sources = loaded_sources(source)
    reader = VerifiedCanonicalGraphViewReader(database)
    try:
        for batch in range(3):
            gc.collect()
            connection.send({"ready": batch, "pid": os.getpid(), "sources": sources})
            barrier.wait(timeout=60)
            before = resource.getrusage(resource.RUSAGE_SELF)
            profile = cProfile.Profile() if instrument and batch == 0 else None
            wall, cpu = perf_counter(), process_time()
            if profile is not None:
                profile.enable()
            page = reader.read_page(
                campaign=expected["campaign"],
                snapshot_id=expected["snapshot_id"],
                limit=100,
                cursor=None,
            )
            if profile is not None:
                profile.disable()
            elapsed, consumed = perf_counter() - wall, process_time() - cpu
            after = resource.getrusage(resource.RUSAGE_SELF)
            if (page.node_count, page.edge_count) != (
                expected["nodes"],
                expected["edges"],
            ) or page.snapshot.snapshot_digest != expected["snapshot_digest"]:
                raise ValueError("Graph page differs from the frozen fixture")
            functions = []
            if profile is not None:
                for entry in sorted(
                    profile.getstats(), key=lambda row: row.totaltime, reverse=True
                ):
                    if isinstance(entry.code, CodeType):
                        functions.append(
                            {
                                "file": Path(entry.code.co_filename).name,
                                "function": entry.code.co_name,
                                "calls": entry.callcount,
                                "cumulative_seconds": entry.totaltime,
                            }
                        )
                    if len(functions) == 30:
                        break
            connection.send(
                {
                    "batch": batch,
                    "pid": os.getpid(),
                    "wall_seconds": elapsed,
                    "cpu_seconds": consumed,
                    "peak_rss_bytes": int(after.ru_maxrss * 1024),
                    "input_blocks": after.ru_inblock - before.ru_inblock,
                    "output_blocks": after.ru_oublock - before.ru_oublock,
                    "profile": functions,
                }
            )
    finally:
        connection.close()


def receive(connection: Connection) -> dict[str, object]:
    if not connection.poll(900):
        raise TimeoutError("Graph child did not complete its bounded probe")
    value = connection.recv()
    if not isinstance(value, dict):
        raise ValueError("Graph child returned an invalid result")
    return cast(dict[str, object], value)


def probe(
    directory: Path, source: Path, output: Path, *, workers: int, cold: bool, instrument: bool
) -> dict[str, object]:
    if sys.platform != "linux" or workers not in (1, 2):
        raise ValueError("process probe requires Linux and one or two readers")
    fixture = cast(dict[str, FixtureHead], json.loads((directory / "fixture.json").read_text()))
    expected = fixture["changed"]
    if file_digest(directory / "changed.db") != expected["database_sha256"]:
        raise ValueError("frozen Graph fixture changed")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = output / "graph.db"
    shutil.copyfile(directory / "changed.db", database)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(workers + 1)
    connections, children = [], []
    samples = []
    identities: set[int] = set()
    try:
        for _ in range(workers):
            parent, child_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=query_worker,
                args=(child_connection, barrier, database, source, expected, instrument),
            )
            process.start()
            child_connection.close()
            connections.append(parent)
            children.append(process)
        for batch in range(3):
            readiness = [receive(connection) for connection in connections]
            if any(item["ready"] != batch for item in readiness):
                raise ValueError("Graph process batch differs")
            identities.update(cast(int, item["pid"]) for item in readiness)
            if len(identities) != workers or any(
                item["sources"] != loaded_sources(source) for item in readiness
            ):
                raise ValueError("Graph reader identity or source differs")
            residency = prepare_cache(database, cold=cold and batch == 0)
            started = perf_counter()
            barrier.wait(timeout=60)
            results = [receive(connection) for connection in connections]
            elapsed = perf_counter() - started
            if any(item["batch"] != batch for item in results):
                raise ValueError("Graph result batch differs")
            samples.append(
                {
                    "batch": batch,
                    "residency_before": residency,
                    "group_wall_seconds": elapsed,
                    "queries_per_second": workers / elapsed,
                    "queries": results,
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
    if file_digest(database) != expected["database_sha256"]:
        raise ValueError("Graph probe modified fixture bytes")
    return {
        "workers": workers,
        "first_guest_cache_cold": cold,
        "instrumented": instrument,
        "loaded_source_sha256": loaded_sources(source),
        "fixture": expected,
        "samples": samples,
        "rss_scope": "individual process high-water marks; not simultaneous aggregate RSS",
        "cache_scope": "Linux guest file pages observed by mincore; host/device cache unknown",
    }


def measure(directory: Path, source: Path, output: Path) -> None:
    if output.exists():
        raise ValueError("Graph measurement output must be new")
    results = []
    for name in ("medium", "history"):
        for workers in (1, 2):
            for cold in (False, True):
                for repetition in range(3):
                    child = output.with_suffix("") / f"{name}-{workers}-{cold}-{repetition}"
                    command = [
                        sys.executable,
                        __file__,
                        "probe",
                        "--directory",
                        str(directory / name),
                        "--source-root",
                        str(source),
                        "--output",
                        str(child),
                        "--workers",
                        str(workers),
                    ]
                    if cold:
                        command.append("--cold")
                    completed = subprocess.run(
                        command,
                        capture_output=True,
                        check=True,
                        timeout=1800,
                        env={**os.environ, "PYTHONPATH": str(source)},
                    )
                    results.append(
                        {
                            "fixture": name,
                            "repetition": repetition,
                            "result": json.loads(completed.stdout),
                        }
                    )
                    print(
                        json.dumps(
                            {
                                "fixture": name,
                                "workers": workers,
                                "cold": cold,
                                "repetition": repetition,
                            }
                        ),
                        flush=True,
                    )
    report = {
        "version": "graph-perf-004-v1",
        "python": platform.python_version(),
        "system": platform.system(),
        "architecture": platform.machine(),
        "profiler_sha256": file_digest(Path(__file__)),
        "results": results,
    }
    with output.open("x") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("probe", "measure"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, choices=(1, 2), default=1)
    parser.add_argument("--cold", action="store_true")
    parser.add_argument("--instrument", action="store_true")
    args = parser.parse_args()
    if args.operation == "measure":
        measure(args.directory.resolve(), args.source_root.resolve(), args.output.resolve())
    else:
        print(
            json.dumps(
                probe(
                    args.directory.resolve(),
                    args.source_root.resolve(),
                    args.output.resolve(),
                    workers=args.workers,
                    cold=args.cold,
                    instrument=args.instrument,
                ),
                allow_nan=False,
            )
        )


if __name__ == "__main__":
    main()
