# WALK-005C1: MCP Confirmation, Report, and Remediation Baseline

- Status: Implemented
- Authority contract: `pajin.dev/walking-mcp-confirmation/v1alpha1`
- Decision: [ADR-0075](../adr/0075-mcp-replay-confirmation-baseline.md)

## Scope

WALK-005C1 reopens one sealed WALK-005B2 authority and applies the MCP-specific product
confirmation policy. It publishes one validated `Finding`, a typed report projection and exact
Markdown rendering, and a non-executable remediation Plan. It does not execute remediation or a
Retest.

The policy treats the independently approved, Plan-bound fresh validity replay as the product
confirmation basis. Impact and severity remain source-bound information-only Claims. This contract
does not synthesize a KISA `ReplayOutcome`, typed Oracle result, replay ticket, external-host
attestation, or remediation evidence.

## Required authority

The source must be an exactly reloaded WALK-005B2 authority with:

- a `reproduced` validity Claim projection;
- `independentExecutionAttested=true` and `confirmationEligible=false` at the B2 boundary;
- the complete B1 Plan and exact WALK-005A Candidate;
- exactly one impact Claim and one severity Claim; and
- unchanged Campaign, Candidate, Finding, Claim, replay authority, and projection identities.

`WalkingMCPConfirmationDecision` records the new policy boundary explicitly. Its confirmation basis
is `plan-bound-fresh-mcp-validity-replay`, while impact and severity assurance are fixed to
`source-bound-information-only`.

## Output and negative boundaries

`WalkingMCPConfirmationAuthority` content-addresses the complete B2 source, Decision, validated
Finding, impact and severity Claims, remediation Plan, and typed report. The sealed Run contains:

- `walking-mcp-confirmation-authority.json`;
- `walking-mcp-remediation-plan.json` with state `planned-not-applied`;
- `walking-mcp-finding-report.json`;
- the exact deterministic `walking-mcp-finding-report.md`; and
- one exact publication event.

Source substitution, Claim replacement, Campaign drift, forged digests, report or remediation
projection mismatch, Markdown mutation, and publication-event mutation fail closed. The
remediation Plan requires human assignment and a later fresh Retest. No result can be labeled
`fixed` or `still-vulnerable` in C1.

## Compatibility and rollback

The contract is additive and leaves existing Candidate, validation, KISA Replay, report, and Retest
wire formats unchanged. Rollback stops producing new C1 baselines; sealed B2 projections remain
non-confirming until an explicit confirmation policy consumes them.

## Related documents

- [WALK-005B2 contract](WALK-005B2-plan-bound-mcp-claim-replay.md)
- [ADR-0074](../adr/0074-plan-bound-fresh-mcp-claim-replay.md)
- [ADR-0025](../adr/0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR-0007](../adr/0007-kisa-remediation-and-retest-loop.md)
