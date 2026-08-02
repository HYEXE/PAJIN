# ADR-0109: Activate Common Execution with a Separate Compiler

## Status

Accepted

## Context

ENG-002C1 produces a non-expanding MissionEnvelope, but its compiler contract deliberately fixes
Permit issuance and Common dispatch authorization to false. Reusing that compiler identity to
write GRAPH-006 Permits would contradict the authority object even if the runtime path passed its
tests. Mutating the C1 object in place would also erase the distinction between evidence
compilation and explicit execution activation.

B2B request IDs are fixture identities. GRAPH-006 stores request IDs as Campaign-database-wide
unique values, so directly executing those IDs would prevent independent C1 Runs from using the
same measured ordinal safely.

## Decision

PAJIN will activate Common execution through a separate code-owned C2 compiler and
content-addressed gate authority. The C2 Envelope copies every authority field from the C1 Envelope
except compiler identity. Scope, Capability, target, risk, budget, rate, autonomy, and time cannot
change. C1 remains non-executable and auditable as originally issued.

Each dispatch starts from a non-executable intent that binds C1, C2, one exact request binding, a
fresh deterministic execution request identity, parameter and target digests, and a budget
reservation. An exact Graph Decision over the latest Snapshot is the explicit opt-in. The gate
then reuses the existing atomic Permit authority and signed-Capability Gateway dispatcher without
introducing a second enforcement path.

The execution request ID is derived from the fresh C1 Run and binding digest. All other measured
request semantics remain exact. One gate instance pins one C2 authority and reuses one Permit
writer so exact retries converge on the existing stored Permit instead of reclaiming the writer or
redispatching.

## Consequences

- Evidence compilation and execution activation have different compiler identities and digests.
- Enabling execution is explicit and reviewable without widening the C1 ceiling.
- Current signed release authority is checked at gate activation and again for the selected action
  immediately before Gateway entry.
- Latest Graph Snapshot, durable budget/rate accounting, one-time Permit consumption, Gateway
  Policy, and dispatch audit remain the existing authorities.
- A Permit consumed before a failed or uncertain Gateway outcome remains terminal and is not
  automatically retried.
- Caller-declared cost reservation is bound into the intent and Graph Decision but is not measured
  provider billing evidence.

## Compatibility and rollback

C2 is additive, direct-call, and not selected by legacy defaults. It changes no existing wire
schema or package export. Rollback removes the C2 gate and its explicit callers; the C1 authority
and every legacy execution path remain valid and non-Common by default.

## Related documents

- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0050: Consumed ActionPermit Dispatch Claim](0050-consumed-action-permit-dispatch-claim.md)
- [ADR-0108: Compile Mission Authority by Predecessor Intersection](0108-compile-mission-authority-by-predecessor-intersection.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [ENG-002C2 contract](../orchestration/ENG-002C2-explicit-common-execution-gate.md)
