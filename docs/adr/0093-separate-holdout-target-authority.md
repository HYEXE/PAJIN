# ADR-0093: Separate Holdout Target Authority from the Active Target Catalog

## Status

Accepted.

## Context

BENCH-001 already labels Ground Truth cases as `seeded` or `holdout`, and the public Manifest keeps
complete Ground Truth outside its wire format. The existing Target catalog boundary, however, was
built for seeded profiles. It had no separate Holdout Factory identity, no private evaluation seed
boundary, and no authority preventing active and Holdout material from being replayed across roles.

Adding Holdout cases directly to an active Ground Truth object would bind their digest but would not
establish who may see the cases, which Factory owns them, or whether the active protocol reused the
same seed. Making the active catalog carry matcher or seed data would also disclose the material the
holdout is intended to protect.

## Decision

1. Keep the existing Traditional Web/API active catalog and Ground Truth unchanged.
2. Add a separate content-addressed Holdout Factory profile bound to the exact active registration
   digest but using a different Factory ID and digest.
3. Store Holdout cases and evaluation seeds only in a private suite. Commit to that suite through a
   public registration containing digests, not contents.
4. Reconstruct the existing active catalog selection during Holdout selection instead of trusting a
   caller-supplied selection object.
5. Require active cases to be seeded, Holdout cases to be holdout, identity and matcher fields to be
   disjoint, and active and Holdout seed sets not to overlap.
6. Emit a public-safe, content-addressed selection authority with execution, measurement admission,
   and content disclosure fixed to false.
7. Keep the first slice code-registered and non-runnable. Do not add a provider adapter or pretend a
   digest commitment supplies confidentiality.

## Consequences

- Public benchmark configuration can prove which private Holdout suite is committed without
  exposing its cases, matchers, or evaluation seed.
- Active catalog expansion, alternate-image replay, seeded/holdout substitution, and forged nested
  digests fail before any provider call.
- The repository contains a deterministic contract fixture, so it demonstrates public/private wire
  separation rather than production secrecy. Real Holdout contents must live behind a separate
  access-controlled evaluator.
- P0-D4 does not improve or measure benchmark results. All runtime and admission flags remain false.
- The design currently covers one Traditional Web/API Holdout authority. AI/RAG/MCP and Hybrid
  Holdout providers can reuse the separation pattern only after their own exact contracts are
  defined.

## Compatibility and rollback

The change adds new `v1alpha1` types and public imports without modifying existing BENCH-001,
catalog, provider, or measurement schemas. Rollback removes the new opt-in construction path.
Existing artifacts retain their original meaning because none of their API versions or digest
domains change.

## References

- [P0-D4 contract](../benchmark/P0-D4-holdout-target-factory-authority.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [ADR-0087](0087-traditional-web-api-target-catalog.md)
