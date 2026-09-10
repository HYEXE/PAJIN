# ADR-0280: Verify Historical Graph Projections with One Exact Replay

Status: Accepted; local correctness and same-fixture measurements verified.

## Context

Verified Graph reads decode every Event, check its row indexes/canonical bytes and verify its chain,
then recompute each stored Projection by replaying its complete prefix again. GRAPH-PERF-001 measured
repeated validation and prefix replay as the dominant first-read cost. The complete-byte cache avoids
this on unchanged small stores but not a changed or larger store.

## Decision

Keep all persisted-object and chain verification. Accumulate canonical admitted nodes and edges once
as successive verified Projection revisions are visited. Detect identity equivocation and compare
each stored Projection's exact sorted nodes, edges and Event Log head against that prefix. Canonical
Projection validation still recomputes all content digests and checks resolved edges. Supplied digests
never replace comparison. The accumulator exists only in the current read transaction and never
grants permission or becomes a cross-request authority cache.

Increase database cache eligibility from 128 to 256 MiB while retaining the 16 MiB Snapshot bound,
single private entry, defensive copies, two complete hashes and current-head checks. Ineligibility
or mismatch evicts reuse. Leave GraphProjector's public replay API unchanged as an independent
regression oracle. Preserve old artifacts and wire/cursor formats.

## Validation and consequences

Use preserved baseline source and identical medium, large and history-heavy bytes. Measure first,
changed and repeated pages separately with repeated fresh processes; report CPU, memory and I/O
limitations. Reject canonical but false historical projections, tampering, stale heads/cursors,
concurrent changes and changed configuration. The larger bound is not a production capacity promise.
Cold reads still scale with complete persisted history; there is no compaction, stat-only shortcut,
incremental trust in mutable history or cached authorization.

If correctness or measured behavior does not justify the candidate, retain the former reader and
report the unsuccessful comparison. Rollback selects the former implementation without schema or
evidence migration.

## Local validation (2026-09-10)

Ninety relevant regressions and the final 8,342-test local suite passed (76 existing opt-in skips).
The same-byte experiment used three fresh processes per fixture/version. Large-fixture first and
changed-first means fell 13.481 → 8.134 and 15.646 → 9.202 seconds. Above the former 128 MiB bound,
history repeated reads fell 20.801 → 0.304 seconds while retaining complete-byte/current-head gates.
Historical Snapshot validation still dominates remaining cold cost.

Accept the bounded latency improvement with explicit costs: already eligible warm queries were
8–12 ms slower in this run, history cold retained Python allocation rose to about 39.3 MiB and
uninstrumented process peak RSS rose about 305 MiB. The limits are not RSS or production capacity
guarantees. Full observations and measurement limits are in
[GRAPH-PERF-002](../benchmark/GRAPH-PERF-002-first-and-history-page-cost.md).
This does not establish remote conformance or a production SLO.
