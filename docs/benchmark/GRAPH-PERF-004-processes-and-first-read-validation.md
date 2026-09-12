# GRAPH-PERF-004: Separate processes and first-read validation cost

Status: Implemented; focused regressions and the complete frozen Linux comparison passed locally.

## Profile and bounded change

The large-history cProfile diagnostic measured 17.59 seconds, including 10.68 seconds in
historical Snapshot verification. Its instrumented numbers are not directly comparable with
the previous 11.17-second measurement or the uninstrumented comparison below. The diagnostic
observed all 38,626 database file pages nonresident before its first read.

For current-Snapshot reads, reuse a Projection fully verified in the same read transaction only
after comparing every embedded field. Continue full Snapshot model, original canonical-byte,
row-index, ordinal, chain and current-head checks. Preserve independent history objects and public
defensive copies. See [ADR 0289](../adr/0289-reuse-matching-projections-only-within-current-graph-verification.md).

## Frozen protocol

`scripts/profile_graph_processes.py` uses multiprocessing spawn and a barrier to coordinate one
or two separate readers. Each verifies its loaded Graph, Projection, cache and API-reader source
paths and hashes. Each performs one first-page query and two repeats against the same unchanged
database. Every query must return the expected Snapshot digest, node count and edge count.

- Reuse the exact changed medium and history fixtures from GRAPH-PERF-003: respectively
  1,002/5,002 nodes, 2,000/10,000 edges, 1,000/5,000 events and 6/12 Snapshots.
- Medium database: 20,406,272 bytes, SHA-256
  `e876fb0570e8bdd620d5c02cadbb4ad576c5430d1cea7b2c0992f54558c194f1`.
- History database: 158,212,096 bytes, SHA-256
  `3f09092598976ea4f012e416c8d01dcadf38c88f79697211901b9a3f7e455a7c`.
- Pin the same existing Linux arm64 runtime, two-CPU quota, 4 GiB memory limit and 64-process limit.
  No network or host cache-control privilege is granted. Source and original fixtures are read-only.
- Copy each fixture into the owned container's writable filesystem. Before a cold first query,
  fsync and issue POSIX_FADV_DONTNEED only for that file; mincore must observe zero resident pages.
  Before warm queries, read the file and require every page resident. Failure invalidates that probe.
- Two fixtures, one/two readers, cold/warm first query and three repetitions give 24 groups,
  36 reader processes and 108 queries per source. The after source differs only in the Graph store.
- Record per-process wall time, CPU, peak RSS and block input, plus group completion wall time and
  query throughput. Process high-water RSS values are never summed into simultaneous aggregate RSS.
- Keep all diagnostics and all uninstrumented groups. Freeze sources and protocol before comparison;
  no model evaluation or task-owned heavy checks overlap the load measurements.

```sh
python scripts/profile_graph_processes.py measure --directory <retained-fixtures> \
  --source-root <frozen-src-directory> --output <new-private-report.json>
```

A separate three-node Linux functional smoke completed two reader processes. It observed 0/69
resident pages before the first query and 69/69 before both repeats, unchanged fixture bytes,
successful child exits and no owned container residue. It is excluded from performance estimates.

## Interpretation limits

This controls and observes Linux guest file-page residency. Host hypervisor, device and SSD caches
are unknown; no physical cold-disk claim follows. Repeated readers share a kernel and bounded
container resources, not a Python process. Responses within a group are correlated. Three group
repetitions describe this fixture and runtime, not statistical confidence or a production SLO.
The previously measured in-process modes and absolute timings remain separate historical results.

## Complete comparison

All 24 uninstrumented groups per source passed, comprising 36 reader processes and 108 queries
per source. The 499-file source inventories differ only in `pajin/graph/sqlite_store.py`.
Source paths and hashes, all matrix coordinates, expected graph results, every cache observation,
resource limits, successful child/container exits and owned cleanup records were checked.

- Profiler SHA-256: `5e2fba43e9942f1ddbcc6a8f876f186d2f3aab2eda981d6792c12c37a12004df`.
- Before Graph SHA-256: `b7e0bb71602bd5891ee3299c9a39e7e084a01b4b2cf3e73eef20f9a06cf5485c`.
- After Graph SHA-256: `a03212eacdd4bfacc42ea6e34f9f01ae69d708394693a4ec0f1533da3eefb56e`.

First-group completion includes both concurrent queries for the two-reader mode. Values below
are seconds, mean ± population standard deviation across three groups. This is not a confidence interval.

| Fixture | Readers | First guest cache | Before group wall | After group wall | Reduction |
| --- | ---: | --- | ---: | ---: | ---: |
| medium | 1 | warm | 1.4236 ± 0.0109 | 1.1127 ± 0.0018 | 21.84% |
| medium | 1 | cold | 1.4223 ± 0.0232 | 1.1380 ± 0.0007 | 19.99% |
| medium | 2 | warm | 1.4843 ± 0.0105 | 1.1961 ± 0.0241 | 19.42% |
| medium | 2 | cold | 1.4865 ± 0.0113 | 1.2270 ± 0.0114 | 17.45% |
| history | 1 | warm | 12.6622 ± 0.0814 | 9.4898 ± 0.0418 | 25.05% |
| history | 1 | cold | 12.6702 ± 0.0518 | 9.5380 ± 0.0390 | 24.72% |
| history | 2 | warm | 13.3135 ± 0.0762 | 9.8877 ± 0.0287 | 25.73% |
| history | 2 | cold | 13.4525 ± 0.0936 | 10.0194 ± 0.0127 | 25.52% |

The following means are before → after. First CPU and peak RSS have three observations for one
reader or six for two readers. Repeat wall time pools the two later queries per process: six or
twelve correlated observations. RSS is a per-process high-water measurement in MiB.

| Fixture | Readers | First guest cache | First process CPU (s) | Process peak RSS (MiB) | Repeat process wall (s) |
| --- | ---: | --- | ---: | ---: | ---: |
| medium | 1 | warm | 1.4230 → 1.1120 | 327.41 → 313.80 | 0.0431 → 0.0415 |
| medium | 1 | cold | 1.4150 → 1.1298 | 326.79 → 313.75 | 0.0429 → 0.0419 |
| medium | 2 | warm | 1.4742 → 1.1864 | 326.94 → 313.04 | 0.0448 → 0.0457 |
| medium | 2 | cold | 1.4674 → 1.2099 | 327.54 → 313.73 | 0.0458 → 0.0457 |
| history | 1 | warm | 12.6600 → 9.4883 | 634.74 → 556.87 | 0.2586 → 0.2578 |
| history | 1 | cold | 12.6267 → 9.4918 | 634.84 → 554.78 | 0.2563 → 0.2585 |
| history | 2 | warm | 13.2409 → 9.8459 | 633.32 → 556.28 | 0.2632 → 0.2639 |
| history | 2 | cold | 13.3364 → 9.9090 | 636.06 → 556.43 | 0.2726 → 0.2721 |

All first-group means improved; repeated-query latency did not improve consistently. The largest
observed individual-process RSS was 641.18 MiB before and 558.00 MiB after. This is not aggregate RSS.
Containers retained the configured 4 GiB memory limit and none was OOM-killed.

A separate after-change diagnostic reduced instrumented Snapshot verification from 10.68 to
5.36 seconds. Edge identity validator calls fell from 150,000 to 50,000 and node identity calls from
90,038 to 40,014. That diagnostic remains excluded from the uninstrumented table. Focused Graph
history/cache regressions passed 32 tests, followed by 75 additional projection, SQLite, backup,
consistency and API-reader tests. Ruff and Linux strict mypy passed for the changed Graph code.
