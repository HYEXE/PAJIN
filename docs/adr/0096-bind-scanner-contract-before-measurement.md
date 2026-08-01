# ADR-0096: Bind a Scanner Contract Before Claiming Measurement

## Status

Accepted.

## Context

P0-E2 calls for a generic Scanner baseline, but the repository contains no Scanner runtime,
SARIF/JSON parser, executable identity, or invocation receipt. Choosing an external product during
implementation would add a material product and trust decision. Using a fake adapter would test a
Python interface while falsely implying that a Scanner was measured.

## Decision

1. Split P0-E2 into P0-E2A contract planning and P0-E2B runnable measurement.
2. Define a code-owned generic Scanner contract that requires Scanner ID/version, executable
   artifact SHA-256, configuration digest, SARIF 2.1.0 raw output, and an exact parser contract.
3. Bind the contract to a single deterministic baseline arm and the complete seed/repetition set.
4. Reconstruct the existing P0-D1 Target selection before issuing a plan.
5. Do not select a Scanner product, execute a process, parse synthetic output, or emit a Result in
   P0-E2A.
6. Fix every execution, output, Result, comparison, and Supervisor activation flag to false.

## Consequences

- The next implementation cannot quietly substitute a Scanner or parser after the benchmark plan
  is reviewed.
- P0-E2A is useful for compatibility and threat review but is not a measured baseline.
- P0-E2B remains blocked on an explicit concrete Scanner artifact and provider boundary; that
  decision must be recorded without rewriting this ADR.

## Compatibility and rollback

The change is additive and non-executable. Rollback removes the new plan types and leaves all prior
benchmark artifacts unchanged.

## References

- [P0-E2A contract](../benchmark/P0-E2A-generic-scanner-baseline-plan.md)
- [P0-E1 contract](../benchmark/P0-E1-deterministic-pajin-baseline-measurement.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [ADR-0095](0095-catalog-and-registry-governed-deterministic-baseline.md)
