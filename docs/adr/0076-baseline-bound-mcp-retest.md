# ADR-0076: Baseline-Bound MCP Remediation Retest

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-005C1 creates a confirmed Finding and a non-executable remediation baseline. Closing the
Walking lifecycle requires a later observation tied to that exact baseline. Reusing the B2 replay
that caused confirmation would not be a Retest, and treating a failed or unverified execution as
proof of remediation would create a false `fixed` result.

The existing KISA Retest contract has the right conservative principles but requires KISA-specific
ReplayOutcome, Oracle, and lineage types that the MCP chain does not possess.

## Decision

1. Consume only an exactly reloaded C1 baseline and another exactly reloaded B2 authority.
2. Require the B1 Plan, Candidate, Finding, and validity Claim to remain exactly equal.
3. Require the Retest approval and execution to occur after C1 confirmation publication.
4. Require fresh Run, request, approval, Grant, Permit, dispatch, and Worker identities relative to
   the baseline replay.
5. Bind both publication Run IDs and root digests into the assessment.
6. Because B2 represents positive reproduction only, publish only `still-vulnerable`.
7. Fix `fixedEligible=false`, `remediationAppliedAttested=false`, and regression to `not-measured`.
8. Reject missing, negative, failed, reused, or forged evidence instead of converting it into
   `fixed` or another successful lifecycle result.

## Consequences

- The first Walking chain reaches a real, separately executed Retest checkpoint without replaying
  the same request identity.
- A positive post-baseline result has an honest `still-vulnerable` meaning.
- C2 cannot report remediation success or normal-function regression coverage.
- Future `fixed` support requires a distinct negative-observation authority, independent
  remediation attestation, and explicit regression evidence rather than loosening C2.

## Compatibility and rollback

The new authority, assessment, report, Runner, reader, and exports are additive. Existing KISA
Retest and validation artifacts are unchanged. Rollback removes C2 composition without changing
C1 baselines or B2 evidence.

## Related documents

- [WALK-005C2 contract](../orchestration/WALK-005C2-baseline-bound-mcp-remediation-retest.md)
- [ADR-0075](0075-mcp-replay-confirmation-baseline.md)
- [ADR-0074](0074-plan-bound-fresh-mcp-claim-replay.md)
- [ADR-0007](0007-kisa-remediation-and-retest-loop.md)
