"""Measure repeated verified page reads on deterministic, synthetic canonical Graphs."""

from __future__ import annotations

import argparse
import cProfile
import gc
import json
import platform
import resource
import subprocess
import sys
import tracemalloc
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from time import perf_counter, process_time
from types import CodeType

from pajin.control_plane.graph_views import VerifiedCanonicalGraphViewReader
from pajin.graph import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphEdge,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphRelation,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    SQLiteGraphStore,
    TrustedGraphLineageRegistry,
    graph_node_ref,
)

NOW = datetime(2026, 9, 1, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def generate(directory: Path, count: int) -> None:
    """Admission uses trusted synthetic lineage; this fixture is not discovery evidence."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Reuse the existing valid observation fixture, then admit distinct observations through
    # the real SQLite authority. Shared action/evidence nodes and two edges per observation
    # represent repeated evidence from a single bounded source call.
    sys.path.insert(0, str(ROOT))
    from tests.test_control_plane_graph_views import _observation_proposal

    base = _observation_proposal()
    campaign = base.lineage.campaign_id
    proposals = []
    for index in range(count):
        observation = type(base.observation).model_validate(
            {
                **base.observation.model_dump(mode="python"),
                "node_id": "",
                "value_digest": sha256(f"profile-{index}".encode()).hexdigest(),
            }
        )
        edges = sorted(
            [
                GraphEdge(
                    campaignId=campaign,
                    relation=GraphRelation.PRODUCES,
                    source=graph_node_ref(base.action),
                    target=graph_node_ref(observation),
                    authorityId="pajin.graph.admission-authority",
                    authorityDigest="a" * 64,
                ),
                GraphEdge(
                    campaignId=campaign,
                    relation=GraphRelation.SUPPORTED_BY,
                    source=graph_node_ref(observation),
                    target=graph_node_ref(base.evidence_nodes[0]),
                    authorityId="pajin.graph.admission-authority",
                    authorityDigest="a" * 64,
                ),
            ],
            key=lambda edge: edge.edge_id,
        )
        proposals.append(
            type(base).model_validate(
                {
                    **base.model_dump(mode="python"),
                    "proposal_id": f"proposal:profile:{index}",
                    "observation": observation,
                    "edges": edges,
                }
            )
        )
    path = directory / "graph.db"
    store = SQLiteGraphStore(path, campaign_id=campaign)
    authority = GraphAdmissionAuthority(
        campaign_id=campaign,
        authority_id="pajin.graph.admission-authority",
        authority_digest="a" * 64,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=base.producer_id,
                    producerVersion=base.producer_version,
                    producerDigest=base.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.OBSERVATION,),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry([base.lineage]),
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    coordinator = GraphProjectionCoordinator(
        event_log=store.event_log, projection_store=store.projection_store
    )
    snapshots = GraphSnapshotAuthority(
        creator_id="pajin.graph.profile-snapshot",
        creator_digest="f" * 64,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    snapshot = None
    for index, proposal in enumerate(proposals, 1):
        assert authority.submit(proposal).event.decision == GraphAdmissionDecision.ADMITTED
        if index % (count // 5) == 0:
            coordinator.refresh()
            snapshot = snapshots.capture(GraphSnapshotReason.CHECKPOINT)
    assert snapshot is not None and len(snapshot.projection.nodes) == count + 2
    (directory / "fixture.json").write_text(
        json.dumps(
            {
                "campaign": campaign,
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_digest": snapshot.snapshot_digest,
                "nodes": count + 2,
                "edges": count * 2,
                "events": count,
                "snapshots": 5,
                "database_bytes": path.stat().st_size,
                "database_sha256": sha256(path.read_bytes()).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )


def measure_one(directory: Path) -> dict[str, object]:
    fixture = json.loads((directory / "fixture.json").read_text())
    path = directory / "graph.db"
    assert sha256(path.read_bytes()).hexdigest() == fixture["database_sha256"]
    reader = VerifiedCanonicalGraphViewReader(path)
    cursor: str | None = None

    def query() -> None:
        nonlocal cursor
        page = reader.read_page(
            campaign=fixture["campaign"],
            snapshot_id=fixture["snapshot_id"],
            limit=100,
            cursor=cursor,
        )
        assert page.node_count == fixture["nodes"] and page.edge_count == fixture["edges"]
        assert page.snapshot.snapshot_digest == fixture["snapshot_digest"]
        cursor = page.next_cursor

    samples = []
    for _ in range(4):
        gc.collect()
        wall, cpu = perf_counter(), process_time()
        query()
        samples.append({"wall_seconds": perf_counter() - wall, "cpu_seconds": process_time() - cpu})
    profile = cProfile.Profile()
    profile.runcall(query)
    stats = profile.getstats()
    hot = sorted(stats, key=lambda entry: entry.totaltime, reverse=True)[:12]
    gc.collect()
    tracemalloc.start()
    query()
    memory_current, memory_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert sha256(path.read_bytes()).hexdigest() == fixture["database_sha256"]
    rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        rss_kib /= 1024
    return {
        "fixture": fixture,
        "cold": samples[0],
        "repeated": samples[1:],
        "process_peak_rss_kib": rss_kib,
        "warm_query_python_peak_bytes": memory_peak,
        "warm_query_python_retained_bytes": memory_current,
        "full_projection_recomputations_in_profiled_query": sum(
            entry.callcount
            for entry in stats
            if isinstance(entry.code, CodeType)
            and entry.code.co_name == "project"
            and entry.code.co_filename.endswith("graph/projection.py")
        ),
        "profile": [
            {
                "file": Path(entry.code.co_filename).name
                if isinstance(entry.code, CodeType) else "~",
                "line": entry.code.co_firstlineno if isinstance(entry.code, CodeType) else 0,
                "function": entry.code.co_name if isinstance(entry.code, CodeType) else entry.code,
                "calls": entry.callcount,
                "cumulative_seconds": entry.totaltime,
            }
            for entry in hot
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["generate", "measure", "measure-one"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    if options.action == "generate":
        for count in (100, 1000, 5000):
            generate(options.directory / str(count), count)
            print(f"generated {count} events / {count + 2} nodes / {count * 2} edges", flush=True)
    elif options.action == "measure-one":
        print(json.dumps(measure_one(options.directory)))
    else:
        if options.output is None or options.output.exists():
            raise ValueError("a new output path is required")
        results = []
        for count in (100, 1000, 5000):
            result = subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "measure-one",
                    "--directory",
                    str(options.directory / str(count)),
                ],
                capture_output=True,
                check=True,
                timeout=1800,
            )
            results.append(json.loads(result.stdout))
            print(f"measured {count} events", flush=True)
        report = {
            "version": "graph-perf-001-v1",
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
            "results": results,
            "source_sha256": {
                str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest()
                for directory in ("src/pajin/graph", "src/pajin/control_plane")
                for p in sorted((ROOT / directory).glob("*.py"))
            },
            "scope": (
                "single fresh process per size; 100-item pages; cold plus three repeated queries; "
                "separate cProfile/tracemalloc passes; RSS includes interpreter and imports"
            ),
        }
        options.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
