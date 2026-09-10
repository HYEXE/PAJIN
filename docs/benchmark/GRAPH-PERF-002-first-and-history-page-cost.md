# GRAPH-PERF-002: First and Changed-history Graph Page Cost

Status: Locally verified; same-byte before/after measurements complete. Remote conformance pending approval.

## Scope and experiment

GRAPH-PERF-001 established that repeated replay of historical Projection prefixes dominated the
first verified read. This experiment retains its 1,002-node/2,000-edge and 5,002-node/10,000-edge
fixtures. A third fixture keeps the latter node/edge set and adds six real Snapshots through the
existing Snapshot authority, producing 148,643,840 bytes, above the old 128 MiB cache bound. This
measures history growth, not a larger node count.

Each fixture has independently pinned base and successor bytes. The successor publishes one more
Snapshot without changing the projection. Each source version runs three fresh processes per fixture:
first reader query, three repeated queries, same-inode replacement with exact successor bytes,
first query after history change and three repeated successor queries. Page size is 100. File hashes
warm filesystem pages beforehand; first means a new verifier, not cold physical storage. There were
no concurrent task-owned tests, builds, model runs or Docker rehearsals during either measurement.
Normal host scheduling remains a source of variation.

Separate cProfile and tracemalloc passes measure cold and warm behavior outside latency samples
on the first repetition only. All three repetitions retain uninstrumented latency samples; allocation
profiles are single observations per fixture/version rather than repeated memory distributions.
Reports preserve wall/CPU samples, process high-water RSS, incremental Python peak/retained allocations,
filesystem block counters, full-verifier counts and whole-file SHA-256 pass counts. Filesystem counters
may be zero with warm pages; they do not measure all logical SQLite reads or physical-device latency.
Hash passes multiplied by database size measure only the explicit hashing portion of logical I/O.

```sh
.venv/bin/python scripts/profile_graph_history.py generate \
  --source-fixtures .pajin/graph-perf-001-fixture-v1 --directory .pajin/graph-history-fixtures
.venv/bin/python scripts/profile_graph_history.py measure --directory .pajin/graph-history-fixtures \
  --source-root <preserved-source-root> --output <new-private-report>
```

## Verification boundary

Compare all stored historical Projections with one incremental replay of the canonically decoded,
index-checked and hash-chained Event Log. Every stored Projection still passes its complete model,
canonical bytes, row index, digest, membership and dangling-edge checks. Compare every prefix's exact
nodes, edges and Event Log head. Admission rejection, identity equivocation, genesis and ahead-of-log
revisions retain their failure behavior. No persisted-object, schema, integrity, current-head or
authorization check is removed or trusted by age.

The default cache database cap is now 256 MiB; serialized Snapshots remain capped at 16 MiB and one entry.
Every eligible lookup still hashes the complete file twice under the existing read transaction.
Oversize/platform fallback performs full verification. The cap is an eligibility limit, not a capacity
or latency claim. No API, cursor, wire format, migration or stored artifact changes are introduced.

Regression requirements include current-head changes, same-inode bytes, inode replacement, stale
cursor, caller mutation, concurrent writer exclusion, key/configuration changes, tampering and fallback.
Additional cases recompute a false Projection's own valid hashes to test exact event-prefix comparison;
malformed JSON alone would not demonstrate that boundary.

## Observed results (2026-09-10)

Both versions ran on the same macOS arm64 host with Python 3.12.13, sequentially in that order.
Each version completed nine fresh processes and 72 uninstrumented queries. Baseline and candidate
fixture bytes, experiment digest and loaded module origins were checked. Only `sqlite_store.py` and
`snapshot_cache.py` differed among the four measured modules; `projection.py` and `graph_views.py`
were identical. Queries validated exact Snapshot digests and node/edge counts, and no fixture changed.

| Fixture | Nodes / edges | Base / successor Snapshots | Base / successor DB bytes |
| --- | ---: | ---: | ---: |
| medium | 1,002 / 2,000 | 5 / 6 | 18,489,344 / 20,406,272 |
| large | 5,002 / 10,000 | 5 / 6 | 91,234,304 / 100,802,560 |
| history | 5,002 / 10,000 | 11 / 12 | 148,643,840 / 158,212,096 |

Wall values are mean ± sample standard deviation in seconds. First-query rows have three samples;
repeated rows have nine samples nested within those three processes. These are descriptive statistics,
not independent-task confidence intervals. CPU columns are process CPU means in seconds. Import,
fixture copying, explicit pre-query garbage collection, instrumentation, HTTP/TLS transport and UI
rendering are outside these query timings.

| Fixture | Query | Samples | Before wall | After wall | CPU before → after |
| --- | --- | ---: | ---: | ---: | ---: |
| medium | first | 3 | 1.979 ± 0.048 | 1.231 ± 0.150 | 1.970 → 1.229 |
| medium | repeat | 9 | 0.039 ± 0.001 | 0.047 ± 0.006 | 0.038 → 0.047 |
| medium | changed first | 3 | 2.075 ± 0.024 | 1.536 ± 0.307 | 2.069 → 1.534 |
| medium | changed repeat | 9 | 0.040 ± 0.000 | 0.051 ± 0.008 | 0.040 → 0.051 |
| large | first | 3 | 13.481 ± 2.892 | 8.134 ± 0.065 | 13.430 → 8.122 |
| large | repeat | 9 | 0.241 ± 0.043 | 0.253 ± 0.023 | 0.240 → 0.252 |
| large | changed first | 3 | 15.646 ± 3.288 | 9.202 ± 0.246 | 15.606 → 9.182 |
| large | changed repeat | 9 | 0.243 ± 0.038 | 0.251 ± 0.005 | 0.242 → 0.251 |
| history | first | 3 | 20.810 ± 1.044 | 14.551 ± 0.566 | 20.787 → 14.525 |
| history | repeat | 9 | 20.801 ± 1.296 | 0.304 ± 0.004 | 20.760 → 0.304 |
| history | changed first | 3 | 22.720 ± 1.602 | 15.405 ± 0.309 | 22.619 → 15.377 |
| history | changed repeat | 9 | 22.403 ± 0.999 | 0.322 ± 0.012 | 22.354 → 0.321 |

Large-fixture first and changed-first means fell 39.7% and 41.2%. History-heavy first and
changed-first means fell 30.1% and 32.2%; repeated means fell about 98.5% after cache admission.
The medium fixture's repeated means rose by 8–10 ms, and the large fixture's by 9–12 ms. Their warm
path was not optimized, and this run establishes no repeated-read speedup for already eligible DBs.
Do not describe all queries as faster or turn these samples into a production SLO.

### CPU and repeated verification

The profiled cold large-fixture `_verified_projections` time fell from 11.844 to 3.169 seconds;
for history it fell from 15.771 to 3.088 seconds. Repeated `GraphProjector.project` calls disappeared
from the candidate verification path. Historical Snapshot decoding remains necessary: the candidate
history profile spent 12.729 seconds in `_verified_snapshots`. These inclusive instrumented times
are not added together or mixed into the uninstrumented latency table.

On the medium/large fixtures, both versions performed one full verification on a cold lookup and
zero on an unchanged warm lookup, with two whole-file hashes each time. For the history fixture,
baseline performed one full verification on both cold and warm calls and no cache hashing; candidate
performed one on cold and zero on warm, with two whole-file hashes on both. Every persisted-object,
chain, current-head and authorization requirement remains in force.

### Memory tradeoff

Process RSS below is the mean high-water mark of the two **uninstrumented** processes, with their
minimum/maximum in brackets, in MiB. It includes imports, fixture hashing and all eight queries; it
is not one query's live memory and cannot isolate allocator retention or cache memory by itself.
The separately instrumented process is excluded because tracing/profile overhead changes its RSS.

| Fixture | Before RSS MiB | After RSS MiB |
| --- | ---: | ---: |
| medium | 405.0 [404.2, 405.7] | 401.0 [400.8, 401.2] |
| large | 924.3 [924.2, 924.4] | 971.4 [971.3, 971.5] |
| history | 1313.3 [1238.2, 1388.4] | 1618.4 [1617.4, 1619.5] |

Separate tracemalloc observations on the successor report newly allocated Python bytes. Each cell
is before → after in MiB; warm observations exclude an already retained cache from the traced baseline.

| Fixture | Cold peak | Cold retained | Warm peak | Warm retained |
| --- | ---: | ---: | ---: | ---: |
| medium | 87.156 → 83.437 | 10.912 → 7.246 | 7.185 → 7.185 | 0.077 → 0.077 |
| large | 420.427 → 420.427 | 39.255 → 39.148 | 31.180 → 31.180 | 0.127 → 0.127 |
| history | 684.077 → 687.744 | 0.044 → 39.255 | 684.077 → 31.180 | 0.043 → 0.127 |

The larger cache trades retained memory for repeated-read cost. History cold retained Python
allocation rose from 0.044 to 39.255 MiB and observed uninstrumented process peak RSS rose about
305 MiB. Large-fixture RSS also increased about 47 MiB despite similar traced peak allocation.
This change is not a general memory reduction; the DB/Snapshot caps do not bound process RSS.

### I/O, scope and reproduction

All observed `ru_inblock`/`ru_oublock` deltas were zero. Pages were already warmed, and these OS
counters do not establish zero logical I/O or physical disk throughput. Each eligible query hashes
2 × DB bytes: 36,978,688/40,812,544 for medium base/successor, 182,468,608/201,605,120 for large,
and 297,287,680/316,424,192 for history after this change. SQLite validation reads are additional.
The profiled history warm hash work took 0.165 seconds; defensive model copies also remain material.

The local result justifies removing duplicate prefix replay and extending bounded cache eligibility,
with the recorded memory and small-warm-query tradeoffs. No schema, wire, cursor, public replay API
or artifact migration is required. Correctness checks cover 90 relevant regressions; the final
local suite passed 8,342 tests with the existing 76 opt-in skips. New remote CI/conformance remains
separate and requires approval.

Longer histories, 100,000-node limits, cold disks, network storage, multiple active readers,
production host memory budgets and production SLOs remain unmeasured. Warm reuse still copies the
Snapshot, hashes every DB byte twice and performs current schema/integrity/head checks. Oversize
DB/Snapshot and unsupported-platform fallback retain complete verification.

Private raw reports preserve all samples, CPU/block counters, instrumented/uninstrumented RSS,
allocation observations, profile call counts, fixture/source commitments and loaded module hashes.
They are `graph-history-before.json`, `graph-history-after.json` and `graph-history-summary.json`
under `.pajin/followup-five-20260910/`. The two raw report SHA-256 values are
`5049cf2ac553d49081dc376de85e8d1f2b24173302a1579cff4357f873e65c99` and
`6c1166246bf656bbd89f6af4f273cabfa65270485615421b8a2047642a35f6e5`.
The common experiment SHA-256 is `2a6fd95fb838ded20e8b51fb7ec1656a659ca585c7ff6d4a83f17acf90a4ca69`.
See [ADR-0280](../adr/0280-verify-historical-graph-projections-with-one-exact-replay.md).
