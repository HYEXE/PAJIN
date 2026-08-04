# ADR-0113: Mediate Handoffs with Existing Agent and Task Lineage

- Status: Accepted
- Date: 2026-08-04

## Context

Phase 5 needs explicit sender/receiver handoff without turning Agent text into commands. Existing
`AgentNode`, `TaskNode`, and MEM-003 already describe execution identity, dependency, and current
collaboration state. WALK-006 is a scenario-specific Shadow authority and cannot serve as a general
handoff Supervisor.

## Decision

Use a process-local single Supervisor authority to admit a content-addressed proposal only when
the complete canonical existing Agent/Task models prove a completed-to-dependent-waiting
transition and both Agents are children of that Supervisor. Store only safe identity projections,
an enum purpose, and the exact current Collaboration Snapshot identity. Admit at most one record
per Proposal and keep every read/execution authority false.

## Consequences

- no Agent registry, TaskGraph, message bus, prompt relay, or execution adapter is duplicated;
- source model mutation and Supervisor substitution change identity and fail verification;
- direct Agent-to-Agent commands cannot be represented; and
- authority is process-local and non-durable until a later storage/signing contract is justified.

## Rejected alternatives

Reusing WALK-006 was rejected because its policy and source are fixed to one remediation scenario.
Embedding Task requests or free-form purpose was rejected because it creates a prompt/command
relay. Scheduling the destination Task was rejected because handoff admission is not a Permit.
