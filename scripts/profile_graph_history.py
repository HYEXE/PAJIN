"""Compare cold, changed-history and repeated pages over identical private Graph fixtures."""

from __future__ import annotations

import argparse
import cProfile
import gc
import importlib
import json
import os
import platform
import resource
import shutil
import sqlite3
import subprocess
import sys
import tracemalloc
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from time import perf_counter, process_time
from types import CodeType
from typing import Any, cast


def identity(path: Path, source: dict[str, Any]) -> dict[str, Any]:
    with sqlite3.connect(path) as db:
        head = db.execute(
            "SELECT snapshot_id,snapshot_digest FROM graph_snapshots ORDER BY ordinal DESC LIMIT 1"
        ).fetchone()
        count = db.execute("SELECT count(*) FROM graph_snapshots").fetchone()[0]
    return {
        **source,
        "snapshot_id": head[0],
        "snapshot_digest": head[1],
        "snapshots": count,
        "database_bytes": path.stat().st_size,
        "database_sha256": sha256(path.read_bytes()).hexdigest(),
    }


def append_snapshot(path: Path, campaign: str, sequence: int) -> None:
    from pajin.graph import GraphSnapshotAuthority, GraphSnapshotReason, SQLiteGraphStore

    store = SQLiteGraphStore(path, campaign_id=campaign)
    GraphSnapshotAuthority(
        creator_id="pajin.graph.profile-snapshot",
        creator_digest="f" * 64,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: datetime(2026, 9, 2, tzinfo=UTC) + timedelta(seconds=sequence),
    ).capture(GraphSnapshotReason.REPLAN)


def generate(source: Path, target: Path) -> None:
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, count, history in [("medium", 1000, 0), ("large", 5000, 0), ("history", 5000, 6)]:
        original = source / str(count)
        metadata = json.loads((original / "fixture.json").read_text())
        data = original / "graph.db"
        if sha256(data.read_bytes()).hexdigest() != metadata["database_sha256"]:
            raise ValueError("source Graph fixture digest differs")
        directory = target / name
        directory.mkdir(mode=0o700)
        base = directory / "base.db"
        shutil.copyfile(data, base)
        for sequence in range(history):
            append_snapshot(base, metadata["campaign"], sequence)
        changed = directory / "changed.db"
        shutil.copyfile(base, changed)
        append_snapshot(changed, metadata["campaign"], history + 1)
        fixture = dict(base=identity(base, metadata), changed=identity(changed, metadata))
        if name == "history" and base.stat().st_size <= 128 * 1024 * 1024:
            raise ValueError("history fixture did not cross the previous DB cache bound")
        (directory / "fixture.json").write_text(json.dumps(fixture, indent=2) + "\n")
        print(json.dumps({"fixture": name, "bytes": base.stat().st_size}), flush=True)


def probe(directory: Path, work: Path, source: Path, *, instrument: bool = False) -> dict[str, Any]:
    from pajin.control_plane.graph_views import VerifiedCanonicalGraphViewReader

    loaded_sources = {}
    for name in (
        "pajin.graph.projection",
        "pajin.graph.sqlite_store",
        "pajin.graph.snapshot_cache",
        "pajin.control_plane.graph_views",
    ):
        filename = importlib.import_module(name).__file__
        expected = (source / (name.replace(".", "/") + ".py")).resolve()
        if filename is None or Path(filename).resolve() != expected:
            raise ValueError("measurement imported a different source tree")
        loaded_sources[name] = sha256(expected.read_bytes()).hexdigest()
    fixture = json.loads((directory / "fixture.json").read_text())
    for phase in ("base", "changed"):
        if (
            sha256((directory / (phase + ".db")).read_bytes()).hexdigest()
            != (fixture[phase]["database_sha256"])
        ):
            raise ValueError("frozen benchmark fixture changed")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = work / "graph.db"
    shutil.copyfile(directory / "base.db", database)
    reader = VerifiedCanonicalGraphViewReader(database)

    def query(view: Any, phase: str) -> None:
        expected = fixture[phase]
        page = view.read_page(
            campaign=expected["campaign"],
            snapshot_id=expected["snapshot_id"],
            limit=100,
            cursor=None,
        )
        assert (page.node_count, page.edge_count) == (expected["nodes"], expected["edges"])
        assert page.snapshot.snapshot_digest == expected["snapshot_digest"]

    samples = []
    for phase in ("base", "changed"):
        if phase == "changed":
            # Same inode, complete successor bytes, no active reader during replacement.
            shutil.copyfile(directory / "changed.db", database)
        for index in range(4):
            gc.collect()
            usage = resource.getrusage(resource.RUSAGE_SELF)
            wall, cpu = perf_counter(), process_time()
            query(reader, phase)
            ended = resource.getrusage(resource.RUSAGE_SELF)
            samples.append(
                dict(
                    phase=phase,
                    index=index,
                    wall_seconds=perf_counter() - wall,
                    cpu_seconds=process_time() - cpu,
                    filesystem_input_blocks=ended.ru_inblock - usage.ru_inblock,
                    filesystem_output_blocks=ended.ru_oublock - usage.ru_oublock,
                )
            )
    profiles = []
    for kind in ("cold", "warm") if instrument else ():
        view = VerifiedCanonicalGraphViewReader(database) if kind == "cold" else reader
        profile = cProfile.Profile()
        profile.runcall(query, view, "changed")
        stats = profile.getstats()
        functions = [entry for entry in stats if isinstance(entry.code, CodeType)]
        profiles.append(
            dict(
                kind=kind,
                functions=[
                    dict(
                        file=Path(cast(CodeType, entry.code).co_filename).name,
                        function=cast(CodeType, entry.code).co_name,
                        calls=entry.callcount,
                        seconds=entry.totaltime,
                    )
                    for entry in sorted(functions, key=lambda item: item.totaltime, reverse=True)[
                        :20
                    ]
                ],
                database_hash_calls=sum(
                    e.callcount
                    for e in functions
                    if cast(CodeType, e.code).co_name == "_database_digest"
                ),
                full_verifications=sum(
                    e.callcount
                    for e in functions
                    if cast(CodeType, e.code).co_name
                    == "_verified_current_snapshot_from_connection"
                ),
            )
        )
    memory = []
    for kind in ("cold", "warm") if instrument else ():
        gc.collect()
        view = VerifiedCanonicalGraphViewReader(database) if kind == "cold" else reader
        tracemalloc.start()
        query(view, "changed")
        retained, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        memory.append(dict(kind=kind, python_peak_bytes=peak, python_retained_bytes=retained))
    if sha256(database.read_bytes()).hexdigest() != fixture["changed"]["database_sha256"]:
        raise ValueError("measurement wrote application state")
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return dict(
        fixture=fixture,
        instrumented=instrument,
        loaded_source_sha256=loaded_sources,
        samples=samples,
        profiles=profiles,
        memory=memory,
        process_peak_rss_bytes=rss if sys.platform == "darwin" else rss * 1024,
    )


def measure(directory: Path, source: Path, output: Path) -> None:
    if output.exists():
        raise ValueError("measurement output must be new")
    results = []
    for name in ("medium", "large", "history"):
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
                str(output.with_suffix("") / f"{name}-{repetition}"),
            ]
            if repetition == 0:
                args.append("--instrument")
            result = subprocess.run(
                args,
                capture_output=True,
                check=True,
                timeout=1800,
                env={**os.environ, "PYTHONPATH": str(source)},
            )
            results.append(dict(name=name, repetition=repetition, result=json.loads(result.stdout)))
            print(json.dumps({"fixture": name, "repetition": repetition}), flush=True)
    paths = [
        source / "pajin/graph/projection.py",
        source / "pajin/graph/sqlite_store.py",
        source / "pajin/graph/snapshot_cache.py",
        source / "pajin/control_plane/graph_views.py",
    ]
    report = dict(
        version="graph-perf-002-v1",
        system=platform.system(),
        machine=platform.machine(),
        python=platform.python_version(),
        experiment_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        results=results,
        source_sha256={
            str(p.relative_to(source)): sha256(p.read_bytes()).hexdigest() for p in paths
        },
        scope="warm filesystem; fresh reader cold; same-inode changed history; "
        "3 processes per fixture; instrumented passes only on first repetition, "
        "outside latency samples",
    )
    output.write_text(json.dumps(report, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("generate", "measure", "probe"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-fixtures", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path("src"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--instrument", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.source_root.resolve()))
    if args.operation == "generate":
        if args.source_fixtures is None:
            parser.error("generate requires existing pinned source-fixtures")
        generate(args.source_fixtures, args.directory)
    elif args.operation == "probe":
        if args.output is None:
            parser.error("probe requires private working output")
        print(
            json.dumps(
                probe(args.directory, args.output, args.source_root, instrument=args.instrument)
            )
        )
    else:
        if args.output is None:
            parser.error("measure requires new output")
        measure(args.directory, args.source_root.resolve(), args.output)


if __name__ == "__main__":
    main()
