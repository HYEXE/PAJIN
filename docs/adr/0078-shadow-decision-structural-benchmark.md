# ADR-0078: Shadow Decision Structural Benchmark Before Metric Comparison

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-006 provides a sealed Shadow Task and Stop Decision but no measured Benchmark Runs. BENCH-001
correctly requires two completed results and all twelve metrics before `BenchmarkComparison` can
exist. Filling absent values with zero or declaring the code-owned Shadow policy to be a measured
adaptive candidate would create false evidence and could incorrectly imply Supervisor activation
eligibility.

## Decision

1. Add a separate BENCH-003A structural-only comparison authority.
2. Require a BENCH-001 Manifest with exactly one deterministic baseline arm.
3. Bind the full Manifest and digest to the exact WALK-006 Campaign and sealed publication.
4. Derive a code-owned deterministic terminal Decision from the completed C2 lifecycle.
5. Compare that Decision with the exact Shadow Task and Stop Decision only.
6. Preserve the ordered twelve-metric contract but forbid every metric delta.
7. Fix benchmark comparison and Supervisor activation eligibility to false.
8. Reserve the existing numeric `BenchmarkComparison` for later measured baseline and candidate
   Results under identical coordinates.

## Consequences

- Baseline and Shadow decision lineage can be audited without inventing performance evidence.
- The added human review Task is visible while unchanged autonomous execution and Capability
  authority remain explicit.
- Ground Truth, seeds, budgets, and required metrics are pinned for BENCH-003B, but not claimed as
  executed or measured.
- BENCH-003B still needs a reset/isolation/cleanup harness and complete sealed `BenchmarkResult`
  artifacts before any improvement or activation threshold can be evaluated.

## Compatibility and rollback

The new models, Runner, reader, and exports are additive. BENCH-001 Manifest, Result, Comparison,
and existing comparison code are unchanged. Rollback removes only the structural comparison layer.

## Related documents

- [BENCH-003A contract](../benchmark/BENCH-003A-walking-shadow-decision-comparison.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [ADR-0077](0077-walking-shadow-supervisor-record.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
