# ADR-0094: Bind Mutation Semantics Before Provider Materialization

## Status

Accepted.

## Context

The benchmark Manifest and Target registration schemas anticipated mutations through
`mutationProfileId` and `mutationProfileIds`. The first concrete Target catalogs intentionally kept
their allowlists empty. Adding an identifier to that tuple would authorize selection without
defining operation order, mutation seed, base reset provenance, expected state, or provider
evidence. It could also make the existing runnable adapter appear to support a mutation it cannot
materialize or verify.

## Decision

1. Preserve the existing P0-D1 registration and empty mutation allowlist.
2. Add a separate content-addressed Mutation profile and registration bound to the exact base
   registration digest.
3. Define an exact three-step state chain: restore base, apply seeded layout, and verify expected
   state. Bind the public deterministic mutation seed and every input/output state digest.
4. Derive a separate BENCH-001 Manifest whose only difference from the verified base Manifest is the
   registered `mutationProfileId`.
5. Require the derivation helper itself to validate the base registration and Manifest identities;
   do not rely only on the final selector to catch cross-base replay.
6. Bind the base selection, both Manifests, registration, benchmark seeds, mutation seed, state
   digests, and ordered operation digests into a reset plan and final selection authority.
7. Mark the plan declared-not-applied and fix receipt binding, materialization, execution, and
   measurement admission to false.

## Consequences

- Mutation semantics are reviewable and content-addressed before the runnable catalog is widened.
- Unknown mutation IDs, alternate base images, catalog expansion, operation reorder, seed changes,
  state substitution, and false reset receipt claims fail closed.
- The existing provider remains unable to run the mutation, which accurately reflects its current
  implementation.
- A future runnable mutation must add provider-specific materialization and observed reset evidence
  under a new authority instead of changing this record to claim execution.

## Compatibility and rollback

The change adds new opt-in `v1alpha1` types and exports. It does not change existing Manifest,
catalog, receipt, provider, or measurement schemas. Rollback removes the new derivation and
selection path. The original P0-D1 catalog remains an unmutated runnable baseline throughout.

## References

- [P0-D5 contract](../benchmark/P0-D5-mutation-target-factory-authority.md)
- [P0-D1 contract](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [ADR-0087](0087-traditional-web-api-target-catalog.md)
