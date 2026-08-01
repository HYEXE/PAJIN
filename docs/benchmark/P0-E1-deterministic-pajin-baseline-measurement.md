# P0-E1 Deterministic PAJIN Baseline Measurement

## Status

Implemented as a sealed `v1alpha1` baseline-only measurement authority for the runnable P0-D1
Traditional Web/API target. Candidate comparison and Supervisor activation remain ineligible.

## Goal and trust boundary

P0-C2B2A2 proves that one raw Observation came from a registry-governed Target lifecycle. P0-D1
proves that a Docker provider and its fixed probe match a code-registered catalog entry and private
Ground Truth. Neither predecessor alone proves that a published aggregate Result used both
authorities for every required seed and repetition.

P0-E1 reopens every registry-governed Harness Run, its Target authority, the current signed registry
activation, and the execution receipt. It then asks the catalog-bound provider to reload the exact
receipt-bound Docker evidence and rerun the private Ground Truth matcher. Only those reconstructed
raw Observations can be aggregated into the twelve BENCH-001 metrics and sealed as a baseline
Result.

## Versioned authorities

| Authority | API version | Role |
| --- | --- | --- |
| `DeterministicBaselineSourceBinding` | `pajin.dev/deterministic-baseline-source-binding/v1alpha1` | One Harness, Target, registry, catalog-evidence, and raw-Observation binding |
| `DeterministicBaselineMeasurementAuthority` | `pajin.dev/deterministic-baseline-measurement/v1alpha1` | Exact Manifest, catalog selection, complete source set, and computed baseline Result |

Both authorities use bounded canonical JSON and separate digest domains. The measurement Run also
seals the Manifest, catalog selection, source bindings, raw Observation bundle, baseline Result,
authority, and exact audit-event sequence.

## Invariants

1. The Manifest contains exactly one deterministic baseline arm and no adaptive candidate.
2. The catalog selection must reconstruct from the exact Manifest, registered adapter, Docker
   image identities, public catalog, and private Ground Truth.
3. Every source must reopen through the registry-governed Harness reader and its current durable
   registry activation.
4. The source Target authority, attestation, execution receipt, coordinate, and raw Observation must
   agree with the Harness authority.
5. The provider must reload evidence whose digest equals the sealed execution receipt and whose
   operation, coordinate, images, fixed probe, and Observation counts pass the catalog matcher.
6. The source set contains every Manifest seed/repetition coordinate exactly once. Replayed Runs,
   roots, or Observation digests are rejected.
7. The Result is rebuilt from the complete sealed raw Observation tuple. Caller-supplied metrics or
   partial Results are never accepted.
8. The Result identity binds the Manifest, catalog selection authority, and every source-binding
   digest.
9. `candidateComparisonEligible` and `supervisorActivationEligible` are literal `false`.

## Required rejection behavior

- direct or stale source artifacts that fail Harness, Target, registry, or Run-seal verification;
- catalog/profile/adapter/Ground Truth substitution or provider identity changes;
- provider evidence substitution after the Target Run was sealed;
- missing, duplicate, extra, or reordered seed/repetition coverage;
- candidate-bearing Manifests and baseline-arm identity changes;
- raw Observation, aggregate Result, evidence bundle, source binding, or audit-event mutation; and
- attempts to promote comparison or Supervisor activation eligibility.

## Audit and benchmark impact

The published baseline Result is a real registry- and catalog-governed measurement of the fixed
local Docker scenario, not a synthetic aggregate fixture. It reports all twelve BENCH-001 metrics
and keeps the raw Observation evidence bundle addressable by SHA-256.

This authority does not compare PAJIN with another scanner or agent topology. It also does not
generalize the P0-D1 deterministic lab into production Web/API conformance.

## Compatibility, migration, and rollback

The implementation is additive. Existing Manifest, Result, Target, registry, catalog, and
BENCH-003 wire formats are unchanged. Metric aggregation is exposed as a public helper but retains
the previous calculation and ordering used by BENCH-003B1.

Rollback removes the P0-E1 runner and catalog audit method. Existing sealed Harness and Target Runs
remain independently readable, while no remaining authority may claim the P0-E1 baseline Result.

## Verification

Positive coverage seals and reopens one complete baseline, validates all twelve metrics, and checks
receipt-bound provider evidence. Negative coverage rejects incomplete or duplicate coordinates,
candidate Manifests, post-seal evidence substitution, and forged eligibility flags. Regression
coverage includes the catalog, registry distribution/admission, prior measured benchmark, Holdout,
and Mutation authorities.
