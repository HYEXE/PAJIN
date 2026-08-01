# ADR-0079: Sealed Raw Observation Admission Before Measured Comparison

- Status: Accepted
- Date: 2026-08-01

## Context

BENCH-001 defines complete Result and Comparison schemas, but WALK-006 contains no raw values for
the twelve benchmark metrics. Copying baseline values into a candidate, filling missing values with
zero, or treating a structural Shadow Decision as measured performance would create false evidence.
At the same time, an external target/Oracle adapter needs a narrow artifact boundary through which
actual per-Run facts can enter the benchmark system.

## Decision

1. Admit only raw per-arm, per-seed, per-repetition observations published in sealed Runs.
2. Bind every observation to the complete Manifest, arm configuration, protocol, Ground Truth
   digest, measurement authority identity, and reset/isolation/cleanup facts.
3. Require the exact two-arm Cartesian coordinate set and one common measurement authority.
4. Reject caller-supplied aggregate metrics and compute all twelve values deterministically.
5. Preserve every source Run/root/artifact digest in the measured comparison authority.
6. Publish raw observation bundles, both completed Results, the canonical Comparison, and the
   content-addressed authority in one sealed output Run.
7. Keep Supervisor activation ineligible until policy binding and threshold decisions exist.
8. Treat external measurement truth as an explicit trust root; sealing proves integrity and
   provenance, not semantic truth independently of that producer.

## Consequences

- Numeric values can no longer appear without complete raw denominators and exact coordinates.
- Baseline and candidate are evaluated with the same target, protocol, budgets, and measurement
  authority.
- The aggregation formulas are stable, replayable, and independently auditable.
- The recorder remains an integrity boundary, so provider-backed measurement attestation is still
  required for stronger external trust.
- BENCH-003B2 must bind the adaptive candidate configuration to the exact sealed WALK-006 policy
  before the output is called a measured Shadow comparison.

## Compatibility and rollback

The observation, binding, measured authority, Runner, and reader are additive. BENCH-001 and
BENCH-003A wire formats are unchanged. Rollback removes only BENCH-003B1 artifacts and exports.

## Related documents

- [BENCH-003B1 contract](../benchmark/BENCH-003B1-walking-measurement-admission.md)
- [BENCH-003A contract](../benchmark/BENCH-003A-walking-shadow-decision-comparison.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [ADR-0078](0078-shadow-decision-structural-benchmark.md)
