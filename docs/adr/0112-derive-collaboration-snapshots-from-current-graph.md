# ADR-0112: Derive Collaboration Snapshots from the Current Graph

- Status: Accepted
- Date: 2026-08-04

## Context

Phase 5 needs a minimal team-state checkpoint that lets later handoff policy name admitted Facts
and sealed artifact references. GRAPH-003 already provides content-addressed immutable projections,
Snapshot references, append-only storage, and exact resolution. Rebuilding Graph state in a new
collaboration store would create two membership authorities.

MEM-002 intentionally did not claim that a valid `GraphEvidence` was admitted. That missing link
must be proven through the existing Graph Snapshot authority without exposing artifact bytes or
Fact text.

## Decision

Add a receiver-neutral `CollaborationSnapshot` projection whose only Graph authority is one exact
current stored `GraphSnapshotRef`.

The compiler derives every admitted Campaign Fact reference from the resolved projection. It
accepts bounded process-local MEM-002 verification inputs, reverifies each sealed source, and
requires exact full `GraphEvidence` membership in the same projection. The resulting Fact and
Artifact memberships are unique, sorted, and content-addressed with the Graph reference.

Require the referenced Snapshot to equal the store head before and after resolution and again
after Artifact verification. Do not copy the Graph projection, Fact statements, artifact content,
or filesystem paths into the collaboration wire.

## Consequences

- Graph Event Log, projection, Snapshot, and store remain the single admission/membership authority.
- Admitted Facts cannot be selectively omitted from a valid current collaboration view.
- Shared Artifact references cannot promote unadmitted or structurally different Evidence.
- An advancing Graph head invalidates current verification rather than silently yielding stale
  collaboration state.
- Later handoff code can bind one compact collaboration identity without receiving content or
  execution authority.

The head checks are intentionally cooperative. Distributed atomicity across the Graph store and
multiple Run stores requires a separate architecture decision if the storage boundary becomes
cross-host.

## Rejected alternatives

### Add a collaboration event log or Snapshot store

Rejected because GRAPH-002/003 already own ordered admission and immutable Snapshot history.

### Embed the complete Graph Snapshot

Rejected because it duplicates potentially large Fact/Evidence content, including target-derived
prompt-like text, and weakens the minimal handoff boundary.

### Let callers supply Fact references

Rejected because callers could omit an admitted Fact while presenting a superficially valid team
state. Fact membership is deterministic from the exact Graph projection.

### Accept content-addressed Evidence without Graph membership

Rejected because node construction is unprivileged. Only presence in the authoritative resolved
Graph projection establishes admitted membership.

### Add receiver and content-reader policy now

Rejected because receiver mediation and content access have different threat boundaries. They
remain HANDOFF-001 and HANDOFF-004 work respectively.
