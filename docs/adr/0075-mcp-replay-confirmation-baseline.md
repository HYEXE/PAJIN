# ADR-0075: MCP Replay Confirmation and Remediation Baseline

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-005B2 proves that one validity Claim was reproduced by a separately approved, Plan-bound
fresh Gateway execution, but deliberately fixes `confirmationEligible=false`. Promoting it by
fabricating the existing KISA ReplayOutcome, Oracle, ticket, or external-host attestation would
misrepresent authority that the MCP chain does not possess. A product confirmation boundary must
also preserve the distinction between replayed validity and unreplayed impact or severity.

## Decision

1. Add an MCP-specific confirmation Decision that consumes only an exactly reloaded B2 authority.
2. Accept the Plan-bound fresh validity replay as the explicit product confirmation basis.
3. Mark impact and severity as source-bound information-only; do not claim that either was replayed.
4. Project the existing Candidate Finding with only `validated=true` changed.
5. Derive a content-addressed, non-executable remediation Plan from the Finding's existing controls.
6. Publish a typed report projection and verify its exact deterministic Markdown rendering.
7. Keep remediation application, Retest execution, `fixed`, and `still-vulnerable` outside C1.

## Consequences

- Confirmation is explicit, narrow, and auditable without weakening generic KISA contracts.
- The report states both the evidence-backed validity decision and the weaker impact/severity
  assurance instead of presenting them as equally replayed.
- The remediation baseline is usable by a later Retest but grants no execution authority and makes
  no claim that a human or target applied its controls.
- WALK-005C2 must require another fresh execution and preserve the existing conservative rule that
  `fixed` is unavailable without independent remediation attestation.

## Compatibility and rollback

The new authority, Decision, remediation Plan, report projection, Runner, reader, and public exports
are additive. Existing validation and Retest artifacts remain unchanged. Rollback removes the C1
composition while leaving sealed B2 evidence intact and non-confirming.

## Related documents

- [WALK-005C1 contract](../orchestration/WALK-005C1-mcp-confirmation-report-remediation-baseline.md)
- [ADR-0074](0074-plan-bound-fresh-mcp-claim-replay.md)
- [ADR-0025](0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR-0007](0007-kisa-remediation-and-retest-loop.md)
