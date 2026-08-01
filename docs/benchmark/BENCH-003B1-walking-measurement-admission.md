# BENCH-003B1: Walking Measurement Admission and Numeric Comparison

- Status: Implemented
- Observation contract: `pajin.dev/walking-benchmark-run-observation/v1alpha1`
- Comparison authority: `pajin.dev/walking-benchmark-measured-comparison/v1alpha1`
- Decision: [ADR-0079](../adr/0079-sealed-raw-observation-benchmark-admission.md)

## Scope

BENCH-003B1 admits externally measured raw observations for a deterministic baseline and an
adaptive candidate. Every observation is recorded in its own sealed Run and binds the complete
BENCH-001 Manifest, arm configuration, measurement authority, seed, repetition, budgets, reset,
isolation, cleanup, Ground Truth counts, timing, cost, Replay, policy, and human-decision facts.

The comparison Harness requires the exact Cartesian product of both arms, every Manifest seed,
and every repetition exactly once. It then computes all twelve `BenchmarkMetricObservation`
values in code, creates two completed `BenchmarkResult` artifacts, calls the existing canonical
`compare_benchmark_results` function, and seals the raw observation bundles, Results, Comparison,
authority, and publication event together.

## Measurement boundary

The recorder preserves and seals values emitted by the named external measurement authority; it
does not independently prove that the target or Oracle told the truth. Both arms must use the same
authority ID, version, and digest. A later provider-backed measurement adapter or attestation layer
may strengthen that trust root without changing the Result schema.

BENCH-003B1 does not yet bind the adaptive arm configuration to the exact WALK-006 Shadow policy
digest. That binding is BENCH-003B2. Therefore a numeric Comparison is benchmark-contract eligible,
but `supervisorActivationEligible` remains false and this slice does not claim measured Shadow
effectiveness.

## Deterministic aggregation

The Harness derives metrics only from admitted raw facts:

- Surface Recall, Finding Recall, Finding Precision, Chain Completion, Replay Success, Human
  Intervention, and Cleanup Success use summed exact numerators and denominators;
- Unexpected Valid Finding Yield and Policy Rejection/Violation Count use exact sums;
- Time to First Valid/Confirmed Finding is the arithmetic mean of measured per-Run durations;
- Cost per Confirmed Finding is total observed cost divided by confirmed Finding count; and
- Run-to-run Variance is the population variance of per-Run Finding Recall.

All required denominators are positive by contract. Count coherence, timestamp bounds, protocol
budgets, evidence bundle SHA-256 values, source Run roots, and Result/Comparison digests are
reconstructed and checked by the sealed reader.

## Negative boundaries

The Harness fails closed on missing, duplicate, foreign, or reordered coordinates; a baseline-only
Manifest; arm/configuration/Manifest substitution; mixed measurement authorities; reused source
Run/root/Observation identities; budget excess; impossible counts; zero denominators; unsealed or
mutated observations; forged aggregates or digests; evidence bundle mutation; and output event
mutation. It never accepts caller-supplied aggregate metrics.

## Compatibility and next step

BENCH-001 models and `compare_benchmark_results` are unchanged. BENCH-003A remains readable and
continues to represent structural-only comparison. BENCH-003B2 must bind the adaptive arm's
implementation/version/configuration digest to the exact sealed WALK-006 policy and its source
publication before the pair can be described as a measured Shadow comparison.

## Related documents

- [BENCH-001 contract](BENCH-001-benchmark-contract.md)
- [BENCH-003A contract](BENCH-003A-walking-shadow-decision-comparison.md)
- [WALK-006 contract](../orchestration/WALK-006-shadow-supervisor-decision-record.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
