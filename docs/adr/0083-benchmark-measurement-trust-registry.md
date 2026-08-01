# ADR-0083: Separate Benchmark Measurement Key Lifecycle from Replay Target Trust

- Status: Accepted
- Date: 2026-08-01

## Context

P0-C1 verifies one explicit Ed25519 measurement Trust Anchor but has no rotation, retirement,
revocation, or registry revision semantics. PAJIN already has similar lifecycle rules for Replay
Target receipts and signed HTTPS route registries, but those keys attest different statements and
trust domains. Reusing them directly would conflate Target application truth with Benchmark
measurement authority.

## Decision

1. Define a Benchmark-specific, content-addressed Trust Registry whose entries preserve the exact
   P0-C1 public Trust Anchor and add active/retired/revoked lifecycle windows.
2. Require exactly one active key; allow retired keys only for bounded historical verification;
   reject revoked keys for all verification.
3. Require contiguous revision and predecessor-digest transitions, immutable retained key material,
   and terminal revocation. Every revision after bootstrap carries its exact predecessor in the
   sealed admission authority.
4. Preflight the active registry key against the adapter definition before provider reset.
5. Expose a common runner Protocol implemented by both P0-C1 and P0-C2A rather than duplicating
   provider lifecycle logic.
6. Seal registry admission separately and bind it to the exact source Run/root/artifact/signature.
7. Keep registry distribution signatures, durable latest-revision persistence, live provider
   evidence, network enforcement, and mandatory BENCH-003B admission in P0-C2B2.

## Consequences

- Measurement key compromise can invalidate historical evidence through explicit revocation.
- Normal rotation preserves old evidence only inside the retired key's bounded issue window.
- Old-key adapters fail before reset when fresh measurement requires a new active key.
- Registry continuity depends on operator retention of the predecessor until a durable signed
  distribution/checkpoint mechanism is added.
- Existing Target receipt registries remain semantically isolated and unchanged.

## Compatibility and rollback

The registry models, transition verifier, common runner surface, wrapper, admission authority,
reader, artifacts, and events are additive. Direct P0-C1/P0-C2A use remains compatible and is the
rollback path, but it does not claim registry-governed measurement.

## Related documents

- [P0-C2B1 contract](../benchmark/P0-C2B1-benchmark-measurement-trust-registry.md)
- [ADR-0082](0082-durable-target-operation-recovery.md)
- [ADR-0081](0081-provider-neutral-benchmark-target-lifecycle.md)
- [ADR-0043](0043-signed-target-registry-distribution-and-rotation.md)
