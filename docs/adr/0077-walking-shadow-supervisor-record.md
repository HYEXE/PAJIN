# ADR-0077: Walking Shadow Supervisor Decision Record

- Status: Accepted
- Date: 2026-08-01

## Context

The completed Walking chain provides a sealed deterministic lifecycle through Retest. Before any
adaptive Supervisor can affect execution, PAJIN needs an auditable record of what a Shadow policy
would have selected. Reusing the existing local execution Supervisor as if it were a bounded model
Supervisor would conflate orchestration ownership with adaptive proposal authority. Mutating the
baseline TaskGraph would also make a fair later benchmark comparison impossible.

## Decision

1. Consume only an exactly reloaded C2 `still-vulnerable` authority.
2. Project a minimal content-addressed input Snapshot with exact publication provenance.
3. Use one code-registered deterministic Shadow policy for this Walking state.
4. Propose only a human remediation-review Task with no Capability and no execution authority.
5. Record a separate Stop Decision that forbids autonomous execution and requires escalation.
6. Bind the policy, Snapshot, Task, Stop Decision, and full C2 source into one sealed authority.
7. Never mutate the source Run, TaskGraph, Campaign, budget, Graph, or Capability state.
8. Do not claim model binding, adaptive quality, activation eligibility, or measured benchmark
   improvement from this structural record.

## Consequences

- The deterministic baseline remains available for exact later comparison.
- A human follow-up choice and autonomous Stop Decision are explicit and content-addressed.
- Prompt injection cannot grant Capability or execution through this record because neither field
  is representable as enabled.
- BENCH-003 still needs to compare deterministic baseline and Shadow records under identical
  benchmark coordinates; Phase 6 model and scheduler work remains later.

## Compatibility and rollback

The new policy, Snapshot, Task proposal, Stop Decision, authority, Runner, reader, and exports are
additive. Existing TaskGraph and Supervisor behavior is unchanged. Rollback removes only the
Shadow-record composition.

## Related documents

- [WALK-006 contract](../orchestration/WALK-006-shadow-supervisor-decision-record.md)
- [WALK-005C2 contract](../orchestration/WALK-005C2-baseline-bound-mcp-remediation-retest.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0047](0047-mission-envelope-and-action-permit-algebra.md)
