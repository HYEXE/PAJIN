# WALK-005C2: Baseline-Bound MCP Remediation Retest

- Status: Implemented
- Authority contract: `pajin.dev/walking-mcp-retest/v1alpha1`
- Decision: [ADR-0076](../adr/0076-baseline-bound-mcp-retest.md)

## Scope

WALK-005C2 closes the first Walking Candidate lifecycle by comparing a sealed WALK-005C1
confirmation baseline with another WALK-005B2 validity replay created after that baseline. The
Retest Runner does not execute a Tool. It consumes only already approved, permitted, sealed
Gateway evidence and publishes a conservative `still-vulnerable` assessment.

WALK-005B2 admits only positive validity reproduction. Therefore C2 cannot interpret an invalid,
missing, failed, or negative execution as `fixed`. Such inputs fail closed before an assessment is
published. A separate future negative-observation authority with independent remediation
attestation would be required to make `fixed` eligible.

## Required authority

The Retest must:

- reopen the exact C1 authority, report, remediation Plan, and publication event;
- reopen a separate sealed B2 authority and its copied Gateway evidence;
- use the exact same B1 Plan, Candidate, Finding, validity Claim, Tool, target, method, and
  arguments;
- have approval and terminal execution times after the C1 confirmation publication; and
- differ from the baseline replay in Run, request, approval, CapabilityGrant, Permit, dispatch, and
  Worker execution IDs.

The C1 and Retest publication Run IDs and root digests are also bound into the assessment.

## Output and negative boundaries

`WalkingMCPRetestAuthority` binds the full C1 baseline, fresh B2 Retest authority, and
`WalkingMCPRetestAssessment`. Its lifecycle state is
`retest-completed-still-vulnerable`. The assessment fixes:

- `status=still-vulnerable`;
- `fixedEligible=false`;
- `remediationAppliedAttested=false`; and
- `regressionStatus=not-measured`.

The sealed output contains the authority, typed assessment, exact Markdown report, and one
publication event. Reused baseline evidence, cross-Plan substitution, pre-baseline approval,
Campaign or Claim drift, forged `fixed`, report mutation, and event mutation fail closed. The C2
Run creates no approval, Grant, Permit, dispatch, remediation action, or regression execution.

## Compatibility and rollback

The contract is additive. It does not modify existing KISA Retest, Candidate, validation, Replay,
or report wire formats. Rollback stops producing new C2 assessments; C1 baselines remain confirmed
with remediation and Retest still required.

## Related documents

- [WALK-005C1 contract](WALK-005C1-mcp-confirmation-report-remediation-baseline.md)
- [WALK-005B2 contract](WALK-005B2-plan-bound-mcp-claim-replay.md)
- [ADR-0075](../adr/0075-mcp-replay-confirmation-baseline.md)
- [ADR-0007](../adr/0007-kisa-remediation-and-retest-loop.md)
