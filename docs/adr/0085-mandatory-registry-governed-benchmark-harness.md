# ADR-0085: Require One Sealed Authority for Registry-Governed Measurements

- Status: Accepted
- Date: 2026-08-01

## Context

ADR-0083 added measurement-key lifecycle admission, and ADR-0084 added signed distribution plus a
durable activation head. Both layers were additive. A caller could still unwrap the target outcome
and pass its Observation to an older BENCH-003B reader without proving which signed activation had
authorized it. Signed origin, durable order, provider lifecycle, and registry admission therefore
needed one non-optional publication boundary.

## Decision

1. Introduce a registry-governed Harness runner that activates the signed bundle before any
   provider reset and uses the existing P0-C2B1 wrapper for execution.
2. Reopen the target and registry Admission Runs after execution and reject publication if the
   activation changed during the measured lifecycle.
3. Seal a new Harness Authority containing the complete activation, current distribution Trust
   Anchor, complete registry Admission Authority, and exact source Run/root/artifact/digest bindings.
4. Expose no convenience conversion on the governed outcome. The dedicated reader is the only API
   that returns a registry-governed Observation.
5. Require the reader to find the exact accepted activation revision in durable storage and to
   reopen every source and audit stream.
6. Require the caller's current out-of-band distribution Trust Anchor at read time, so signing-key
   revocation invalidates previously sealed bundles.
7. Preserve historical measurement-registry rotations by verifying the exact accepted revision
   rather than requiring it to remain the latest head.

## Consequences

- A governed metric consumer cannot accidentally omit signed registry activation or P0-C2B1
  admission while using the governed API.
- Rotation during execution is conservative: provider cleanup can complete, but no governed result
  is published under the stale activation.
- Historical results remain readable after ordinary measurement-key rotation, while distribution
  signing-key revocation remains retroactive.
- Direct lower-level outcomes remain available for compatibility and diagnostics but make no
  registry-governed claim.
- Live provider evidence and network enforcement remain outside this authority until P0-C2B2B.

## Compatibility and rollback

The Harness Authority, runner, outcome, and reader are additive. Rolling back removes only the
registry-governed claim and returns callers to explicitly composing P0-C1/P0-C2A/B1 outputs. No
existing artifact or reader changes shape.

## Related documents

- [P0-C2B2A2 contract](../benchmark/P0-C2B2A2-mandatory-registry-governed-harness.md)
- [ADR-0084](0084-signed-measurement-registry-distribution.md)
- [ADR-0083](0083-benchmark-measurement-trust-registry.md)
