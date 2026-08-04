# ADR-0114: Bind Terminal Results Through Existing Handoff and Artifact Authorities

- Status: Accepted
- Date: 2026-08-04

## Context

Phase 5 needs to associate a destination Task outcome with a prior Supervisor-mediated handoff.
HANDOFF-001 already owns Agent/Task transition identity, MEM-003 owns current collaboration
membership, MEM-002 owns sealed Artifact metadata, and the Graph Snapshot store owns ordering.
Creating another result content store or accepting caller-declared status would duplicate authority
and create prompt relay and confused-deputy risks.

## Decision

Create a process-local terminal-result authority that resolves an exact historical HANDOFF-001
admission, proves that its Graph Snapshot precedes the current MEM-003 Snapshot in one contiguous
store chain, reverifies the current Snapshot and sealed result Artifact, and derives status only
from an exact terminal destination Agent/Task pair. Persist only content-addressed metadata and
admit one semantic result per handoff.

Historical HANDOFF-001 resolution deliberately does not claim that its old Collaboration Snapshot
is still current. Current authority comes from the later MEM-003 verification; continuity comes
from the existing Graph Snapshot store.

## Consequences

- result bytes, prompts, Task requests, Tool requests, and filesystem paths are not relayed;
- lifecycle success cannot be mistaken for Finding confirmation or semantic validation;
- foreign chains, stale views, lineage mutation, Artifact substitution, and result equivocation
  fail closed;
- no second Graph, Artifact, Agent, Task, or execution authority is introduced; and
- records remain process-local and require a later signed or durable contract before cross-process
  use.

## Rejected alternatives

Embedding result content was rejected because it bypasses HANDOFF-004 receiver-scoped reading.
Accepting a free-form result status was rejected because Agent/Task lifecycle already owns that
state. Comparing Snapshot revision numbers without proving one stored predecessor chain was rejected
because unrelated stores can produce plausible but foreign revisions.
