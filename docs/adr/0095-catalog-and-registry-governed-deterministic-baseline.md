# ADR-0095: Require Catalog and Registry Evidence for a Deterministic Baseline

## Status

Accepted.

## Context

The registry-governed Harness seals measurement-key admission and a complete Target lifecycle, but
it does not select a Target catalog entry or rerun its private Ground Truth matcher. The P0-D1
catalog wrapper checks provider evidence during execution, but that decision was not represented in
the later aggregate Result. Attaching a catalog selection digest after the fact would therefore be
insufficient: an identical adapter digest could have produced a Target Run without the catalog
matcher participating.

The BENCH-003B1 aggregate path also accepts its own sealed Observation records. It should remain a
generic contract harness rather than be reinterpreted as proof of the runnable P0-D1 target.

## Decision

1. Add a catalog audit operation that accepts a sealed Target authority, reloads evidence by the
   exact execution receipt, and reruns the existing registered matcher.
2. Reopen each source through the registry-governed Harness and Target readers before aggregation.
3. Bind Harness, registry admission, activation, Target, attestation, coordinate, execution receipt,
   provider evidence, and raw Observation into one source digest.
4. Require exact and complete baseline seed/repetition coverage with fresh Run, root, and
   Observation identities.
5. Reuse the BENCH-003B1 metric calculation, but compute it only from the reconstructed source
   tuple and bind the Result identity to the catalog selection plus all source digests.
6. Seal the Manifest, catalog selection, sources, evidence bundle, Result, final authority, and
   exact audit events in a separate Run.
7. Keep candidate comparison and Supervisor activation eligibility false.

## Consequences

- A baseline Result cannot claim catalog governance merely because its adapter digest resembles a
  registered adapter.
- Provider evidence changes after execution fail because its digest must still equal the sealed
  execution receipt and pass the private matcher.
- Partial coordinate coverage and caller-computed aggregates cannot become completed Results.
- The first measured baseline remains intentionally limited to the deterministic local P0-D1
  scenario. Scanner and single-agent baselines require separate authorities.

## Compatibility and rollback

The decision adds new opt-in `v1alpha1` types and one audit method on the catalog wrapper. Existing
wire schemas and execution methods are unchanged. Rollback removes the new measurement path; prior
Target, Harness, and BENCH-003 artifacts retain their original meaning.

## References

- [P0-E1 contract](../benchmark/P0-E1-deterministic-pajin-baseline-measurement.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [P0-D1 contract](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [ADR-0085](0085-mandatory-registry-governed-benchmark-harness.md)
- [ADR-0087](0087-traditional-web-api-target-catalog.md)
