# ADR-0081: Provider-Neutral Benchmark Target Lifecycle with External Measurement Signature

- Status: Accepted
- Date: 2026-08-01

## Context

BENCH-003B1 can seal observations supplied by a named producer, but it does not execute Target
reset, isolation, measurement, or cleanup and does not verify an external signature. A provider-
specific implementation embedded directly in the benchmark core would couple measurement
authority to Docker or one cloud API and make fail-closed lifecycle review harder.

## Decision

1. Define a provider-neutral async adapter Protocol with reset, isolation, execution, cleanup, and
   attestation operations.
2. Bind one content-addressed coordinate to the exact Manifest arm, seed, and repetition.
3. Validate reset and isolation receipts before dispatching the next provider operation.
4. Require fresh operation/evidence identities, one environment, one post-reset isolation, and
   non-overlapping ordered timestamps.
5. Always attempt cleanup after a valid isolation when execution raises or its output is rejected.
6. Preserve the adapter's raw Observation identity and reject foreign lineage instead of rewriting
   it; only final cleanup status and content identity are rebuilt.
7. Sign the complete lifecycle/Observation digest set with an externally provisioned Ed25519 key
   and verify it against an explicit public Trust Anchor.
8. Emit the standard B1 Observation artifact/event in the same sealed Run.
9. Keep the actual Docker/external provider implementation and key registry in P0-C2.

## Consequences

- Provider implementations share one auditable lifecycle and measurement admission contract.
- B1 can consume P0-C1 output without a compatibility adapter or duplicate Observation schema.
- A provider signature binds integrity and issuer identity, while the provider still remains the
  semantic truth root for its evidence.
- Cleanup failure is measurable rather than erased, and execution failure cannot skip cleanup.
- No current production Target is claimed; the deterministic test adapter verifies only contract
  behavior.

## Compatibility and rollback

All models, Protocols, Runner, reader, exports, and artifacts are additive. Existing Worker,
Target-attestation, Benchmark, and Walking wire formats are unchanged. Rollback removes only the
P0-C1 layer.

## Related documents

- [P0-C1 contract](../benchmark/P0-C1-provider-neutral-target-factory-lifecycle.md)
- [BENCH-003B1 contract](../benchmark/BENCH-003B1-walking-measurement-admission.md)
- [ADR-0079](0079-sealed-raw-observation-benchmark-admission.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
