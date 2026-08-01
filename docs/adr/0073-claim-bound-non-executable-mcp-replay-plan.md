# ADR-0073: Claim-Bound Non-Executable MCP Replay Plan

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-005A yields a sealed, unconfirmed A02 Candidate with canonical validity, impact, and severity
Claims. PAJIN's existing executable Replay path has strong compilation, ticket, fresh-session,
Oracle, and receipt boundaries, but its registered materializers and success policies intentionally
cover only exact KISA M03, M06, and A04 scenarios.

Reusing that implementation for an MCP authorization Candidate by changing labels would falsely
claim a Mode contract and Oracle that do not exist. Dispatching first and constructing replay
authority afterward would also make the restriction post-hoc.

## Decision

1. Split WALK-005B into a non-executable Claim-bound Plan (`WALK-005B1`) and a later Plan-bound
   fresh execution plus verification projection (`WALK-005B2`).
2. Reopen the sealed WALK-005A authority and select only its canonical validity Claim. Do not accept
   a caller-authored Candidate, Claim, request, Tool, target, arguments, or scenario mapping.
3. Bind the WALK-005A publication Run root and artifact SHA-256, the exact original execution and
   request identities, and the Tool, target, method, and normalized parameter digest into a
   content-addressed Plan.
4. Require fresh replay Run, request, approval, Grant, Permit, dispatch, and Worker identities in the
   Plan contract.
5. Keep Plan state `planned-not-authorized`. WALK-005B1 creates no executable or confirmation
   authority.
6. Require WALK-005B2 to seal a receipt carrying this Plan digest before any replay Permit claim and
   to derive its projection only from independently reloaded sealed execution evidence.

## Consequences

- MCP Replay gets a real pre-execution authority boundary without pretending to have a KISA
  materializer or Oracle.
- A mutated WALK-005A artifact, cross-Candidate Claim, altered request semantics, or weakened
  freshness set fails before any later replay execution can be accepted.
- The Hybrid Chain remains unconfirmed until WALK-005B2 proves a fresh Plan-bound execution.

## Compatibility and rollback

The new Plan, Runner, loader, exports, and documents are additive. Existing Replay and validation
formats are unchanged. Rollback removes Plan construction while retaining sealed non-executable
Plans for audit.

## Related documents

- [WALK-005B1 contract](../orchestration/WALK-005B1-claim-bound-mcp-replay-plan.md)
- [ADR-0072](0072-approved-permitted-walking-candidate-admission.md)
- [ADR-0036](0036-claim-bound-replay-execution-authority.md)
