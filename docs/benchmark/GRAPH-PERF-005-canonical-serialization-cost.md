# GRAPH-PERF-005: Canonical Serialization Cost

The previous first-read profile identified repeated node/edge serialization inside
GraphProjection and GraphSnapshot validators, plus a full second validation of the
freshly verified cached Snapshot. The candidate serializes material once per validator
and retains all semantic, digest, canonical size and byte checks. The cache still
returns a deep copy and rechecks full database bytes, schema, integrity, heads and
file identity on each lookup. Disk bytes and public Graph identities are unchanged.

Use `scripts/profile_graph_processes.py` with immutable before/after source copies,
the same pinned Linux image, two existing fixtures and the same CPU/memory bounds.
The matrix covers 1/2 separate reader processes, observed guest file pages cold/warm,
initial/repeated reads, process CPU and individual peak RSS. Do not overlap timed
measurements with model evaluation. Keep instrumentation separate from headline timings.

## Paired Linux result

The completed run used Linux arm64, two CPUs and 4 GiB per owned container with
network access disabled. Both sides used the same immutable runtime image and
profiler. The before copy restores only `graph/projection.py`,
`graph/snapshot_cache.py` and `graph/sqlite_store.py` from baseline `b2fe5cb`;
the other 507 source files are identical. Source inventories, fixture hashes,
runtime identity, raw samples and cleanup observations are retained privately.

The medium fixture is 20,406,272 bytes with 1,002 nodes, 2,000 edges, 1,000 events
and six Snapshots. The history fixture is 158,212,096 bytes with 5,002 nodes,
10,000 edges, 5,000 events and twelve Snapshots. Each side has 24 process groups:
two fixtures, 1/2 readers, guest pages cold/warm, and three repetitions. Each
group performs an initial read followed by two repeated reads. Every requested
guest residency condition was observed with `mincore` before its first read;
repeated reads have warm guest pages.

Each cell below is **before → after**. Wall time is the group completion time;
CPU is the mean individual query CPU time. RSS is the mean individual process
high-water mark, not the simultaneous group total. First rows average three
groups and repeated rows average six group queries. The initial page condition
identifies the group even when the row reports a subsequent warm read.

| Fixture | Readers | Initial guest pages | Query | Wall seconds | CPU seconds | Peak RSS MiB |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| History | 1 | Warm | First | 9.8036 → 7.8723 | 9.8016 → 7.8706 | 556.0 → 556.8 |
| History | 1 | Warm | Repeated | 0.2738 → 0.2691 | 0.2733 → 0.2686 | 556.0 → 556.8 |
| History | 1 | Cold | First | 9.8673 → 7.9494 | 9.8213 → 7.9038 | 555.9 → 556.7 |
| History | 1 | Cold | Repeated | 0.2605 → 0.2776 | 0.2597 → 0.2768 | 555.9 → 556.7 |
| History | 2 | Warm | First | 10.7518 → 8.4966 | 10.6915 → 8.4547 | 556.1 → 555.7 |
| History | 2 | Warm | Repeated | 0.2830 → 0.2855 | 0.2815 → 0.2835 | 556.1 → 555.7 |
| History | 2 | Cold | First | 10.9121 → 8.7437 | 10.8090 → 8.6556 | 556.8 → 556.4 |
| History | 2 | Cold | Repeated | 0.2931 → 0.2850 | 0.2911 → 0.2838 | 556.8 → 556.4 |
| Medium | 1 | Warm | First | 1.1757 → 0.9809 | 1.1751 → 0.9802 | 313.5 → 313.0 |
| Medium | 1 | Warm | Repeated | 0.0445 → 0.0447 | 0.0441 → 0.0441 | 313.5 → 313.0 |
| Medium | 1 | Cold | First | 1.1858 → 0.9875 | 1.1785 → 0.9801 | 313.5 → 313.7 |
| Medium | 1 | Cold | Repeated | 0.0476 → 0.0456 | 0.0470 → 0.0450 | 313.5 → 313.7 |
| Medium | 2 | Warm | First | 1.2350 → 1.0395 | 1.2282 → 1.0322 | 314.1 → 313.4 |
| Medium | 2 | Warm | Repeated | 0.0481 → 0.0492 | 0.0473 → 0.0482 | 314.1 → 313.4 |
| Medium | 2 | Cold | First | 1.2506 → 1.0208 | 1.2342 → 1.0102 | 313.1 → 313.4 |
| Medium | 2 | Cold | Repeated | 0.0482 → 0.0470 | 0.0475 → 0.0465 | 313.1 → 313.4 |

History first-read wall time fell approximately 19–21% in this run. Peak RSS was
effectively unchanged; repeated-read results were mixed. Full-history validation,
hashing and copying still cost time and memory. These finite samples establish
the observed comparison, not statistical significance or a universal improvement.
Guest file residency does not establish host/device cache coldness, simultaneous
aggregate RSS, physical disk latency, maximum-size coverage or production
service-level guarantees. Historical browsing in UX-012 has a separate full-read
path; these measurements concern the existing current-Graph page path.
