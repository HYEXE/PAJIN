# ADR-0118: Preserve Target Taint in Supervisor Snapshot Input

- Status: Accepted
- Date: 2026-08-04

## Context

SUP-001 pins safe input schema identities but intentionally accepts no Snapshot instance. MEM-003
contains only safe references, so copying that wire into a model request would omit the provenance
of model-visible Fact text. Conversely, copying the full Graph or shared Artifact bytes would
expand disclosure and prompt-injection exposure.

## Decision

1. Reverify the exact SUP-001 binding and current MEM-003 Snapshot before projection.
2. Reuse the existing Graph Snapshot store as the only Fact membership and content authority.
3. Project every admitted Fact statement with node/value/text digests, exact origin, and taint.
4. Conservatively mark both agent-derived and target-derived text as target-tainted untrusted.
5. Keep operator and trusted-core text as trusted metadata without granting instruction authority.
6. Project every Fact and shared Artifact as a content-free safe reference; treat Artifact content
   as target-tainted because Graph Evidence does not attest a stronger content origin.
7. Require complete exact membership, stable Graph head, schema equality, and consumer-side rebuild.
8. Do not create messages, prompts, model calls, drafts, proposals, Capabilities, Permits, or
   execution authority.

## Consequences

- Prompt-shaped target or Agent-derived text cannot silently become a trusted instruction.
- Taint cannot be removed by omitting text or substituting a clean reference.
- Artifact bytes stay behind the existing HANDOFF-004 reader boundary.
- This slice supports current Collaboration Snapshot projection. WALK-006 Snapshot materialization
  may be added without changing this wire when its model-visible provenance requirements are known.
- SUP-003 can consume only a separately verified input and still must compile untrusted drafts into
  typed non-executable proposals.

## Compatibility and rollback

SUP-002 is additive and not connected to an execution path. Existing authorities and readers are
unchanged, and rollback requires no migration.

## Related documents

- [SUP-002 contract](../orchestration/SUP-002-snapshot-only-target-taint-input.md)
- [SUP-001 contract](../orchestration/SUP-001-supervisor-model-binding.md)
- [MEM-003 contract](../graph/MEM-003-current-graph-collaboration-snapshot.md)
- [ADR-0112](0112-derive-collaboration-snapshots-from-current-graph.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
