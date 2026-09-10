# GRAPH-PERF-001: Current Graph Page Cost

Status: Implemented and locally measured on 2026-09-10.

## Profile and minimal change

`scripts/profile_graph_pages.py` creates deterministic synthetic canonical Graphs through the real
SQLite admission, projection and Snapshot APIs. A shared action/evidence pair supports distinct
observations, with two edges per observation. These are read-cost fixtures, not discovery or security
findings. Five evenly spaced Snapshots and six stored Projections are retained at every size.

Before the change, a profiled 5,002-node query took 16.82 seconds under cProfile, of which 11.36 seconds
were within historical Projection verification and 9.16 seconds within six Projection recomputations.
Those nested times must not be added. Pydantic validation accounted for 12.34 cumulative seconds.
The normal uninstrumented mean was 11.54 seconds; response slicing was not the dominant cost.

The paged reader now retains one verified Snapshot with a complete database SHA-256 binding. Each
request still opens a read-only transaction, checks schema/SQLite integrity and current heads, hashes
the entire file twice and returns a defensive copy. Changed bytes, inode, schema, verifier contract,
head or size eligibility invalidate reuse. Normal SQLite writers cannot commit during the checked
DELETE-journal read. There is no stat-only fast path or cached execution/authorization decision.
See [ADR-0275](../adr/0275-bind-graph-page-cache-to-complete-current-database-bytes.md).

## Same-fixture comparison

All comparisons used the identical database bytes and exact Snapshot/cursor semantics, macOS arm64,
Python 3.12.13, one fresh process per size, 100-item pages, one cold-reader query and three repeated
queries. The small fixture wraps back to its first page after exhaustion. Filesystem pages are warm
from fixture hash verification: cold means a new Python reader, not cold storage. cProfile and
tracemalloc run in separate subsequent passes, outside the latency samples. No other benchmark or
Docker workload ran concurrently with the measurements.

Repeated-query mean ± population standard deviation, seconds:

| Events / nodes / edges | DB MiB | Before wall | After wall | Before CPU | After CPU | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 / 102 / 200 | 2.04 | 0.169792 ± 0.000574 | 0.005539 ± 0.000128 | 0.169585 ± 0.000553 | 0.005517 ± 0.000133 | 30.66× |
| 1000 / 1002 / 2000 | 17.63 | 1.993639 ± 0.089015 | 0.038118 ± 0.000790 | 1.980690 ± 0.075001 | 0.038067 ± 0.000789 | 52.30× |
| 5000 / 5002 / 10000 | 87.01 | 11.538913 ± 0.062314 | 0.186437 ± 0.000799 | 11.502152 ± 0.057509 | 0.186190 ± 0.000798 | 61.89× |

Cold-reader and memory observations:

| Nodes | Cold wall before / after (s) | Warm query traced peak before / after (MiB) | Process peak RSS before / after (MiB) |
| --- | ---: | ---: | ---: |
| 102 | 0.173 / 0.176 | 7.69 / 2.54 | 283.41 / 278.70 |
| 1002 | 1.946 / 1.950 | 74.57 / 7.20 | 422.84 / 374.81 |
| 5002 | 11.485 / 11.009 | 372.21 / 31.19 | 1046.73 / 828.38 |

The warm query recomputed six Projections before the change and zero after it at each measured size;
complete byte/schema/head verification still ran. The new profiled bottleneck is defensive copying
of the already verified model. Cold-reader time remains essentially unchanged; no cold-read gain is
claimed from the single samples.

Tracemalloc measures incremental Python allocations during one warm query and excludes the cache
allocated before that pass and native SQLite allocations. RSS is the whole child-process high-water
mark including imports and instrumentation overhead; it is not an isolated production request RSS.
These complementary measurements must not be combined or advertised as a production memory budget.

## Limits and validation

- Cache limits are one Snapshot, a database <=128 MiB and serialized Snapshot <=16 MiB. The largest
  fixture is 87.01 MiB with a 9,558,021-byte Snapshot. Larger stores retain the original full path.
- Every hit performs O(database bytes) hashing and Snapshot copying. Frequently changing stores still
  pay cold verification, and one reader serializes concurrent cache use. No compaction or distributed
  cache is introduced. Arbitrary 100,000-node/200,000-edge or long-history workloads were not measured.
- Three repeated queries per size are a local diagnostic sample, not a load-test percentile or SLO.
  Other graph shapes, disk-cold/network filesystems, multiple processes and production hosts remain
  unmeasured. The cache does not detect rollback of all trusted state and its independent checkpoint.
- Existing Graph/page/store regressions plus the first cache cases passed: 63 tests / 8.77 seconds.
  Additional cases check raw file mutation between hashes and runtime limit eviction. Cache cases
  cover old-history corruption with restored mtime, current head independent of the byte key,
  inode/symlink replacement, WAL rejection, stale Snapshot, bounded fallback, caller mutation,
  concurrent writer exclusion, verifier configuration and per-request/reconfigured authentication.
- Repository Ruff and Linux strict mypy (436 source files) passed. No UI/wire, public import removal,
  migration, authorization relaxation, skip or weaker assertion was introduced.

Reproduce against the same generated fixture directory, using a fresh result destination each time:

```sh
.venv/bin/python scripts/profile_graph_pages.py generate --directory .pajin/graph-cost-fixtures
.venv/bin/python scripts/profile_graph_pages.py measure --directory .pajin/graph-cost-fixtures \
  --output .pajin/graph-cost-result.json
```

The JSON retains fixture digests, exact source-file digests, raw samples, profiles and memory fields.
Keep the before/after code checkpoints and fixture bytes; generated files are not execution authority.
