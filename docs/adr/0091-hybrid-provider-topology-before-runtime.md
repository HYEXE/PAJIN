# ADR-0091: Bind Hybrid Provider Topology Before Runtime Registration

- Status: Accepted
- Date: 2026-08-01

## Context

P0-D3 binds two exact independently runnable Target selections but intentionally has no combined
provider. The current SQLi Target response does not contain the document body required by the AI
Target, and the existing Manifest, coordinate, Docker evidence, and recoverable adapter each bind
one Target Factory. Reusing those records or concatenating two successful runs would not prove a
causal Hybrid bridge.

A runnable implementation also needs new multi-container lifecycle semantics. Building that
provider without first fixing its transfer and ordering contract would allow implementation details
to become an accidental authority.

## Decision

1. Add a separate content-addressed topology authority bound to the complete P0-D3 selection and
   exact private Ground Truth binding.
2. Reserve new Hybrid Factory and adapter identities rather than overloading either predecessor.
3. Require two Target services and one Worker on one internal network, with exact startup, bridge,
   and reverse-cleanup order under one coordinate and fence.
4. Define a canonical transfer artifact whose document body is extracted from a required field in
   the sealed Traditional response and whose source response has an independent digest.
5. Bind the transfer schema to the predecessor bridge and both component digests.
6. Keep image binding, adapter registration, Manifest eligibility, execution, bridge observation,
   and measurement admission false until real runtime evidence exists.

## Consequences

- The missing source document and single-target lifecycle assumptions are explicit prerequisites,
  not hidden runtime behavior.
- A future provider cannot substitute an internally generated prompt for data derived from the
  Traditional observation.
- Service expansion, order reversal, cross-composition binding, and transfer substitution fail
  closed before any Docker call.
- P0-D3B2 must introduce Hybrid-specific container semantics and a multi-container evidence
  contract; the existing single-target wire formats remain stable.

## Compatibility and rollback

The change is additive and grants no execution authority. Existing component profiles, providers,
Manifest, evidence, recovery, and measurement contracts retain their wire identity.

Rollback stops registering the topology. Previously recorded topology authorities remain valid as
non-executable historical records and must not be interpreted as bridge receipts.

## Related documents

- [P0-D3B1 contract](../benchmark/P0-D3B1-hybrid-provider-topology-contract.md)
- [P0-D3 contract](../benchmark/P0-D3-hybrid-target-composition.md)
- [ADR-0090](0090-non-runnable-hybrid-target-composition.md)
- [P0-C2A recovery contract](../benchmark/P0-C2A-durable-target-operation-recovery.md)
