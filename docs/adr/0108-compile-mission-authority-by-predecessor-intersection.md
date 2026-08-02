# ADR-0108: Compile Mission Authority by Predecessor Intersection

## Status

Accepted

## Context

ENG-002B2B proves Profile-adapter behavior for exact fixtures, but parity is not Campaign
authorization. PROF-002 preserves the complete Campaign and exact Profile mapping, while CAP-005
holds the verified signed Capability releases. GRAPH-006 already defines the `MissionEnvelope`
ceiling and Permit algebra. Creating a second Envelope schema or treating parity as execution
authority would duplicate those contracts and could expand Scope, budget, or Capability authority.

The existing Envelope cannot represent recurring weekly testing windows or bind every planned
request parameter by itself. Those limitations must not be silently approximated during migration.

## Decision

PAJIN will compile the existing GRAPH-006 `MissionEnvelope` only from the exact intersection of:

1. the PROF-002 compilation embedded in the complete B2B parity authority;
2. the measured normalized Plan and successful trusted B2B receipts;
3. exact CAP-005 activated signed releases that uniquely materialize each Plan request; and
4. the source Campaign Scope, ROE, risk, budget, rate, and authorization ceilings.

Compilation attenuates Capability and target sets to the measured requests, time to Campaign plus
signed-release/review authority, and count/unit/rate budgets to the measured Plan. Any recurring
testing-window policy that the Envelope cannot preserve is rejected, except an exact full-week
full-day equivalent.

The content-addressed compilation authority fixes Permit issuance, Common dispatch, and Common
execution authorization to false. It is an audit and migration checkpoint, not a bearer token.

## Consequences

- Existing MissionEnvelope and GRAPH-006 algebra remain the only Envelope and Permit contracts.
- A measured request must resolve to exactly one verified activated Capability.
- Profile defaults, registered-but-unmeasured Capabilities, new targets, and unused Campaign budget
  cannot be introduced by the compiler.
- Restricted recurring testing windows block compilation instead of losing their semantics.
- The compilation authority can be reloaded structurally, but signed lifecycle trust must be
  revalidated against a current activation before any later Permit or dispatch.
- Planned parameter binding remains explicit in C1 Capability bindings and must be consumed by the
  next opt-in execution gate.

## Compatibility and rollback

The compiler is an additive direct-call module and does not change legacy defaults or predecessor
wire formats. It is not eagerly exported from `pajin.workflow` because doing so would introduce an
existing Capability replay import cycle. Rollback removes the C1 module, contract, and callers;
PROF-002, B2B, CAP-005, GRAPH-006, and all legacy execution paths remain valid.

## Related documents

- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0103: Compile Legacy Modes to Profile Semantics Only](0103-compile-legacy-modes-to-profile-semantics-only.md)
- [ADR-0107: Admit Parity Only from Sealed Semantic Behavior](0107-admit-parity-only-from-sealed-semantic-behavior.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [ENG-002C1 contract](../orchestration/ENG-002C1-parity-bound-mission-envelope-compilation.md)
- [ENG-002C2 contract](../orchestration/ENG-002C2-explicit-common-execution-gate.md)
