# WALK-005B2: Plan-Bound MCP Claim Replay

- Status: Implemented
- Authority contract: `pajin.dev/walking-mcp-claim-replay/v1alpha1`
- Decision: [ADR-0074](../adr/0074-plan-bound-fresh-mcp-claim-replay.md)

## Scope

WALK-005B2 verifies one fresh replay of the validity Claim planned by WALK-005B1. It does not
dispatch a Tool itself. It accepts only a separately approved, Grant-bound, Permit-consumed, sealed
Gateway execution whose B1 Plan receipt was written before the dispatch claim.

The result is a `reproduced` validity projection with `confirmationEligible=false`. It is not a
generic `ReplayOutcome`, KISA Oracle result, confirmed Finding, report eligibility decision, or
Retest result.

## Required authority

The replay execution Run must contain:

- the existing exact independent-approval receipt required by WALK-005A;
- one `WalkingMCPReplayApprovalReceipt` binding the B1 Plan/Claim, request, and CapabilityGrant;
- that Plan receipt before the exact `capability.dispatch.claimed` event;
- one completed, reconciled Permit-to-Gateway lifecycle with sealed evidence; and
- explicit target observations for document-derived MCP influence, absent independent
  authorization enforcement, and internal-data access.

The execution Run, request, approval, Grant, Permit, dispatch, and Worker execution IDs must all
differ from the original WALK-005A execution. Agent, Tool, target, method, and arguments must remain
exactly equal to the B1 Plan. The freshly derived validity Atomic Claim statement must equal the
planned Claim statement.

## Output and negative boundaries

`WalkingMCPClaimReplayAuthority` binds the complete B1 Plan, replay approval receipt, verified
execution, and `WalkingMCPClaimReplayProjection`. The output Run copies the exact replay evidence,
seals the authority and one publication event, and is reconstructed by
`load_walking_mcp_claim_replay_authority`.

Missing, late, duplicated, cross-Plan, or forged replay receipts; reused freshness identities;
request semantic changes; failed or mutated Gateway evidence; and Claim statement substitution fail
closed. Candidate confirmation remains a separate WALK-005C policy decision.

## Compatibility and rollback

This contract and the reusable WALK-005A execution verifier are additive. Existing WALK, Gateway,
Capability, KISA Replay, validation, report, and Retest wire formats remain unchanged. Rollback
stops accepting new B2 Runs; sealed projections remain non-confirming audit evidence.

## Related documents

- [WALK-005B1 contract](WALK-005B1-claim-bound-mcp-replay-plan.md)
- [WALK-005A contract](WALK-005-approved-execution-candidate-admission.md)
- [ADR-0073](../adr/0073-claim-bound-non-executable-mcp-replay-plan.md)
- [ADR-0036](../adr/0036-claim-bound-replay-execution-authority.md)
