# ADR-0285: Validate All Graph History with Bounded Current-Snapshot Retention

Status: Accepted for the current-read implementation; quiet performance comparison pending.

## Context

Historical projection replay was previously reduced without skipping validation, but peak process
RSS increased. New allocation tracing separates a roughly 35.5 MiB retained cache from hundreds
of MiB transiently held while all historical snapshots and their raw database rows coexist.

## Decision

Read projection/snapshot rows incrementally. Give only the private current-snapshot verification
path an optional retention selector: validate all historical models, canonical bytes, indices,
digests, ordinals, chain links and projection equality, but retain only the requested object and
the final chain head. A nonexistent or stale request still cannot bypass historical validation.
Default full-history, backup and recovery consumers retain all snapshots as before.

Keep complete database hashing, schema/integrity checks, current-head comparison, file identity,
defensive copying, bounded cache eligibility and authorization unchanged. Do not intern mutable
projection objects across returned public history snapshots. Measure source-pinned before/after
latency, CPU, RSS, allocation and concurrent reads on identical retained data; report regressions.

## Consequences

This targets transient memory of current reads, not an enforced process RSS limit. Full-history
exports still retain complete model history. Two readers in one process do not model many processes,
cold physical disk, maximum histories or production resource/SLO guarantees. A separate diagnostic
under unrelated workload is allocation evidence only, not comparative timing evidence.

## Verification addendum (2026-09-11)

The frozen comparison has now completed: 24 fresh processes per source, identical fixture bytes
and protocol, with only the Graph store file differing between the two source trees. History mean
peak RSS decreased from 1,424.56 to 769.73 MiB for one reader and from 1,928.19 to 1,278.38 MiB for
two independent readers. The changed-history single-reader first latency rose from 10.9536 to
11.1738 seconds. Post-GC retained allocation remained approximately 35.48 MiB. The original decision
and its limits remain in force; this observation does not establish a production SLO. Complete
measurements, dispersion, I/O interpretation and regressions are recorded in
[GRAPH-PERF-003](../benchmark/GRAPH-PERF-003-memory-and-concurrent-reads.md).
