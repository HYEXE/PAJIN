# ADR-0074: Plan-Bound Fresh MCP Claim Replay

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-005B1 provides a non-executable validity Claim Replay Plan. Accepting an arbitrary later
Gateway result would make that Plan advisory rather than authoritative. Reusing the original
approval or execution identities would also fail the independent-replay boundary, while projecting
directly into the KISA `ReplayOutcome` contract would claim materializer and Oracle semantics that
are not registered for this MCP A02 chain.

## Decision

1. Require a content-addressed replay approval receipt that binds the exact B1 Plan and validity
   Claim to the existing exact Tool intent, request, approval, and CapabilityGrant receipt.
2. Seal both receipts before the consumed Permit's dispatch claim in the replay execution Run.
3. Reuse the WALK-005A sealed Permit/Gateway verifier without admitting a second product Candidate.
4. Require fresh Run, request, approval, Grant, Permit, dispatch, and Worker execution identities.
5. Preserve exact agent, Tool, target, method, arguments, and normalized parameter digest.
6. Re-derive Candidate observables and the validity Atomic Claim from replay evidence. Require its
   statement to equal the planned Claim statement.
7. Publish only a `reproduced`, independently executed projection with confirmation eligibility
   fixed to false. Confirmation and reporting remain later policy boundaries.

## Consequences

- The B1 Plan is enforceable before dispatch evidence can be admitted.
- Original execution replay, cross-Plan evidence, changed arguments, late receipts, and forged
  target conclusions fail closed.
- The MCP replay remains explicit and narrow without weakening or pretending to generalize the KISA
  Replay contract.
- WALK-005C must decide how reproduced validity, impact, severity, reporting, and remediation Retest
  compose into a confirmed product Finding.

## Compatibility and rollback

The new receipt, authority, projection, Runner, reader, and public exports are additive. The existing
WALK-005A verifier gains public composition helpers but its artifact and wire format are unchanged.
Rollback removes B2 composition without changing sealed B1 Plans or legacy Replay artifacts.

## Related documents

- [WALK-005B2 contract](../orchestration/WALK-005B2-plan-bound-mcp-claim-replay.md)
- [ADR-0073](0073-claim-bound-non-executable-mcp-replay-plan.md)
- [ADR-0072](0072-approved-permitted-walking-candidate-admission.md)
- [ADR-0036](0036-claim-bound-replay-execution-authority.md)
