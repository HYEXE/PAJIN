# BENCH-003A: Walking Shadow Decision Structural Comparison

- Status: Implemented
- Authority contract: `pajin.dev/walking-shadow-benchmark-comparison/v1alpha1`
- Decision: [ADR-0078](../adr/0078-shadow-decision-structural-benchmark.md)

## Scope

BENCH-003A binds one baseline-only BENCH-001 Manifest to a sealed WALK-006 Shadow record and
compares only their decision structure. It derives the deterministic lifecycle's terminal choice,
records the Shadow policy's additional human remediation-review Task, and proves that neither
autonomous execution nor the Capability set changed.

This slice creates no `BenchmarkResult`, numeric metric, metric delta, adaptive candidate arm, or
activation decision. Its state is `structural-decision-only` and its measurement state is
`not-measured-no-benchmark-results`.

## Required authority

The input BENCH-001 Manifest must:

- contain exactly one `deterministic-baseline` arm;
- set `adaptiveSupervisor=false`;
- bind the same Campaign digest as WALK-006; and
- preserve the complete target, Ground Truth digest, protocol, seed, repetition, budget, and
  required-metric contract for later measurement.

The WALK-006 source must be reloaded from its sealed publication Run and remain
`recorded-not-applied`, `shadowMode=true`, and `baselineMutated=false`.

## Structural comparison

`WalkingDeterministicBaselineDecision` is a code-owned projection of the completed C2 lifecycle:
no further Task was selected and execution stopped after Retest. `WalkingShadowDecisionDelta`
binds that projection to the exact Shadow authority, Task proposal, and Stop Decision. It fixes:

- `humanReviewTaskAdded=true`;
- `autonomousExecutionChanged=false`;
- `capabilitySetChanged=false`;
- `sourceBaselineMutated=false`; and
- `metricImpactMeasured=false`.

The authority carries all twelve BENCH-001 required metric names but an empty `metricDeltas` tuple.
`benchmarkComparisonEligible` and `supervisorActivationEligible` are both false.

## Negative boundaries

An unmeasured adaptive candidate arm, foreign Campaign, Manifest substitution, Shadow source
mutation, non-canonical required metrics, any numeric metric delta, changed execution or Capability
claim, forged digest, and output mutation fail closed. Zero is never used as a stand-in for missing
measurement.

## Compatibility and next step

The contract is additive and does not modify BENCH-001 wire formats or the existing
`compare_benchmark_results` function. BENCH-003B must produce sealed baseline and candidate
`BenchmarkResult` artifacts under identical coordinates before the canonical numeric
`BenchmarkComparison` or Supervisor activation evaluation becomes eligible.

## Related documents

- [BENCH-001 contract](BENCH-001-benchmark-contract.md)
- [WALK-006 contract](../orchestration/WALK-006-shadow-supervisor-decision-record.md)
- [ADR-0077](../adr/0077-walking-shadow-supervisor-record.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
