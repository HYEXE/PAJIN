# WALK-006: Shadow Supervisor Decision Record

- Status: Implemented
- Authority contract: `pajin.dev/walking-shadow-supervisor/v1alpha1`
- Decision: [ADR-0077](../adr/0077-walking-shadow-supervisor-record.md)

## Scope

WALK-006 records what one code-registered Shadow policy would select after the completed Walking
chain. It consumes only a sealed WALK-005C2 `still-vulnerable` lifecycle and emits a human
remediation-review Task proposal plus a decision to stop autonomous execution and escalate.

The Runner does not call a model, schedule a Task, mutate a `TaskGraph`, change the source Run,
create a Capability, or execute a Tool. It is the first narrow Shadow record, not completion of the
Phase 6 SupervisorModelBinding, checkpoint scheduler, dedicated budget, activation gate, or
adversarial evaluation milestones.

## Input and policy

`WalkingShadowInputSnapshot` binds:

- the exact Campaign and C2 authority identity;
- the sealed C2 publication Run, root digest, artifact path, and artifact SHA-256;
- Candidate, Finding, remediation Plan, and Retest assessment identities; and
- the exact `still-vulnerable` lifecycle state with autonomous execution already stopped.

`RegisteredWalkingShadowPolicy` is code-owned and content-addressed. Its only accepted lifecycle is
`retest-completed-still-vulnerable`. It selects `human-remediation-review` and
`stop-autonomous-execution`.

## Output and negative boundaries

The selected `WalkingShadowTaskProposal` is assigned to `human:remediation-owner`, has an empty
Capability set, and is fixed to `proposed-not-authorized`. `WalkingShadowStopDecision` requires
escalation and fixes `executionAllowed=false`.

`WalkingShadowSupervisorAuthority` embeds the complete source, registered policy, input Snapshot,
Task proposal, and Stop Decision. It fixes `shadowMode=true`, `baselineMutated=false`, and
`decisionState=recorded-not-applied`. The sealed output contains one authority and one exact
publication event; no execution event is permitted.

Source mutation, foreign Campaign or authority substitution, lifecycle drift, policy substitution,
Capability requests, execution enablement, Task or Stop replacement, forged digests, and output
mutation fail closed.

## Compatibility and rollback

The contract is additive. Existing Supervisor, TaskGraph, Benchmark, Walking, Capability, and
execution wire formats remain unchanged. Rollback stops producing new Shadow records and leaves
the deterministic Walking baseline intact.

## Related documents

- [WALK-005C2 contract](WALK-005C2-baseline-bound-mcp-remediation-retest.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [ADR-0047](../adr/0047-mission-envelope-and-action-permit-algebra.md)
