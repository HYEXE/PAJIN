# ADR-0084: Sign and Durably Order Benchmark Measurement Registries

- Status: Accepted
- Date: 2026-08-01

## Context

ADR-0083 made measurement-key lifecycle transitions content-addressed and required the exact
predecessor during admission. It did not prove who published a registry or remember the last
accepted revision across process restart. A caller that lost every predecessor could replay an old
bootstrap registry. Replay Target registry distribution already demonstrates the required pattern,
but its keys and statements attest a different trust domain.

## Decision

1. Define a Benchmark-specific Ed25519 distribution Trust Anchor, statement, and bundle. Do not
   reuse measurement-attestation or Replay Target registry keys.
2. Bind the complete P0-C2B1 transition, including current and predecessor registries, to a sequence
   equal to the registry revision and the previous signed-bundle digest.
3. Limit bundle lifetime to seven days and require current validity at activation.
4. Reject unknown or revoked distribution keys; permit retired keys only for bundles issued inside
   their historical validity window.
5. Persist accepted bundles in a host-local append-only SQLite activation store using full sync,
   immediate write transactions, and update/delete/replace guards.
6. Bootstrap only at revision one and reject rollback, gaps, equivocation, predecessor mismatch,
   Trust Anchor substitution, unsafe linked files, and row/content mismatch.
7. Leave mandatory sealed Harness admission to P0-C2B2A2 and live provider/network enforcement to
   P0-C2B2B.

## Consequences

- A clean restart remembers the exact last accepted bundle and cannot silently return to an older
  revision while the activation database remains intact.
- Registry origin and bounded freshness are independently verifiable without exposing private keys.
- The complete predecessor inside each bundle increases payload size but makes one transition
  independently auditable.
- The local database is not an external anti-rollback anchor. Deleting or replacing the complete
  trusted filesystem state remains outside this slice.
- Distribution Trust Anchor rotation requires a future explicit authority; silently replacing the
  anchor digest for an existing registry scope is rejected.

## Compatibility and rollback

All new models and storage are additive. Removing this layer returns callers to P0-C2B1's explicit
predecessor-only admission and therefore removes signed origin and durable ordering claims without
changing existing wire formats.

## Related documents

- [P0-C2B2A1 contract](../benchmark/P0-C2B2A1-signed-measurement-registry-distribution.md)
- [ADR-0083](0083-benchmark-measurement-trust-registry.md)
- [ADR-0043](0043-signed-target-registry-distribution-and-rotation.md)
