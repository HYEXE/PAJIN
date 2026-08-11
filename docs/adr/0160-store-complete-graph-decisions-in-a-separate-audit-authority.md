# ADR-0160: Store Complete Graph Decisions in a Separate Audit Authority

## Status

Accepted

## Context

`GraphDecision` is already a canonical, content-addressed record bound to one immutable Graph
Snapshot, but the durable Graph Permit tables retain only its ID and digest. UX-003A therefore
cannot reconstruct a trustworthy decision history from Permit references. Adding decisions to the
existing Graph Store schema would also force an unrelated migration of the schema-v4 backup,
encrypted-retention, and immutable-inventory wire contracts.

UX-003B needs the smallest durable authority that preserves complete decisions and lets an
Operator inspect them without turning the view into decision, approval, Permit, or execution
authority.

## Decision

### 1. Use a separate single-Campaign SQLite audit authority

`SQLiteGraphDecisionAuditStore` owns one exact Campaign and one pinned recorder identity. It is
configured independently from `PAJIN_CP_GRAPH_DATABASE` and must never share the Graph database
path or a SQLite sidecar path.

The audit database stores complete canonical `GraphDecision` material in a content-addressed,
append-only hash chain. Schema metadata, recorder identity, and records are protected by an exact
schema fingerprint plus no-update, no-delete, and no-replace triggers.

### 2. Verify current Snapshot freshness before first append

Before appending a new Decision, the store query-only verifies the existing Canonical Graph Store
and requires the Decision's complete `GraphSnapshotRef` to equal the exact current Snapshot head.
The Decision creation time cannot predate that Snapshot. An exact retry returns the already stored
record even if the Graph later advances; it does not create a duplicate or rewrite history.

The Graph and audit databases are not one physical transaction. This record is audit evidence, not
dispatch authority. Existing GRAPH-006 Permit issuance continues to perform its own final atomic
freshness check.

### 3. Retain historical records but expose only the requested current Snapshot

The v1 store has no update, delete, compaction, or retention-expiry operation. Query-only reads
verify the exact schema, SQLite integrity, pinned recorder, every canonical record, contiguous
sequence, and previous-record digest chain.

The Operator view also revalidates the complete Graph Snapshot history. Every retained Decision
must resolve to its exact historical Snapshot, while the requested Snapshot must still be the
current canonical head. The response returns at most 500 Decisions bound to that current Snapshot
and rejects rather than truncates an oversized result.

### 4. Redact identities and omit payload content

The response includes audit and Decision identities, digests, kind, timestamps, and actor/recorder
digests. Raw actor and recorder IDs are not returned. `GraphDecision` contains only an opaque
`decisionPayloadDigest`; the payload itself is neither stored by this authority nor exposed by the
view.

Literal response markers state that the complete audit chain, historical Snapshot bindings, and
current Snapshot were verified and that the view cannot record a Decision, select a Hypothesis,
schedule work, grant a Capability, issue a Permit, approve an action, or authorize execution.

## Consequences

- Complete Graph Decisions can be retained and audited without treating Permit references as
  Decision material.
- Existing Graph Store schema-v4 and backup/retention wire contracts remain unchanged.
- A Decision audit database can be backed up with ordinary deployment controls, but UX-003B does
  not claim signed off-host retention or an independently persisted anti-rollback anchor.
- Local replacement with an older otherwise valid audit database cannot be detected without an
  external head anchor. The view reports the verified local head but does not claim external
  transparency.
- Decision producers must explicitly use the audit store. UX-003B does not silently intercept or
  reinterpret every historical Decision construction path.

## Rejected alternatives

### Reconstruct complete Decisions from Permit tables

Rejected because a Decision ID and digest cannot recover actor, kind, payload digest, Snapshot
reference, or creation time.

### Add a schema-v5 Decision table to the Canonical Graph Store

Rejected for this slice because it would couple Decision audit delivery to migrations of the
existing Graph backup, encrypted retention, and immutable inventory contracts.

### Store Decisions in RunStore

Rejected because RunStore owns one sealed Run while Graph Decisions are Campaign-wide and may
span Runs.

### Let the Web Console record Decisions

Rejected because a review surface must not manufacture decision authority.

## Compatibility and rollback

The authority, environment setting, endpoint, and Web Console panel are additive. Existing Graph,
Run, Permit, approval, and Control Plane database formats are unchanged. Omitting the audit database
keeps the authenticated route fail-closed with `503`.

Rollback removes the route and stops new audit appends while retaining the audit database as
evidence. Deleting or rewriting retained records is not a rollback operation.

## Related documents

- [GRAPH-004 consistency and stale-decision contract](../graph/GRAPH-004-consistency-recovery-stale-decision.md)
- [GRAPH-005 durable Graph Store](../graph/GRAPH-005-durable-sqlite-graph-store.md)
- [GRAPH-006 atomic ActionPermit authority](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [UX-003A Hypothesis attention ranking](../orchestration/UX-003A-canonical-hypothesis-attention-ranking.md)
- [UX-003B Decision audit contract](../orchestration/UX-003B-durable-graph-decision-audit.md)
