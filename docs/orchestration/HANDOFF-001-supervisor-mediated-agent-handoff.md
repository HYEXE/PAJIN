# HANDOFF-001: Supervisor-Mediated Agent Handoff

- Status: Implemented additive authority
- Date: 2026-08-04
- API: `pajin.dev/agent-handoff/v1alpha1`
- Implementation: `pajin.collaboration.handoff`

## Outcome

HANDOFF-001 adds a bounded, non-executable handoff from one completed Agent/Task to one distinct
Supervisor-owned Agent and dependent waiting Task. It reuses `AgentNode`, `TaskNode`, and the exact
current MEM-003 `CollaborationSnapshot`; it adds no Agent registry, TaskGraph, message bus, content
reader, Capability, Permit, or execution path.

An unprivileged `AgentHandoffProposal` binds safe Agent/Task identity projections, one code-enum
purpose, and the Collaboration Snapshot ID/digest. The process-local `AgentHandoffAuthority`
reparses the full source models, reverifies the current Collaboration Snapshot, requires both
parties to name that Supervisor as parent, and emits one immutable
`SupervisorMediatedAgentHandoff` per Proposal.

## Required transition

- sender and receiver are distinct non-Supervisor Agents;
- sender is `completed` and source Task is `succeeded` and assigned to it;
- receiver is `spawned` or `running` and destination Task is `waiting` and assigned to it;
- destination Task explicitly depends on source Task; and
- both Agents have `parentAgentId` equal to the admitting Supervisor.

Agent and Task refs contain only safe IDs, role where applicable, and domain-separated digest of
the complete canonical source model. Task titles, requests, Tool arguments, and Agent errors are
not copied into the wire.

## Negative and authority boundary

Purpose is limited to `continue-task`, `independent-review`, `validate-result`, or
`prepare-report`; arbitrary purpose text, prompt, message, or command is impossible. Self-handoff,
direct Agent command, foreign parent/Supervisor, lineage substitution, stale/cross-Snapshot,
cross-Campaign, same-ID equivocation, and unsafe identifiers fail closed. Exact Proposal retry
returns the first admission record even if a later caller supplies another admission time.

The record fixes Supervisor mediation true and content read, prompt interpretation, Scope
expansion, Capability, Permit, and execution authority false with strict JSON booleans.

## Compatibility and boundaries

All existing Agent, Task, Graph, Snapshot, and execution formats remain unchanged. Removing the
module and exports needs no migration. This slice does not schedule the destination Task, deliver
content, prove a durable or signed Supervisor identity, or persist records across processes.
HANDOFF-002 binds terminal result metadata to this admitted handoff through a later current
Collaboration Snapshot and exact sealed Artifact reference; HANDOFF-004 owns receiver-bound content
access.
