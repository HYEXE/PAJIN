> Languages: [English](0049-durable-single-campaign-sqlite-graph-store.en.md) | [한국어](0049-durable-single-campaign-sqlite-graph-store.ko.md)

# ADR-0049: Durable Single-Campaign SQLite Graph Store

- Status: Accepted
- Date: 2026-07-26

## Context

ADR-0048 left the first durable Canonical Graph storage location open between the existing
`RunStore` and a separate Graph module. GRAPH-002 through GRAPH-004 established the conformance
contract: append-only admissions, exact retry/equivocation, deterministic projection, immutable
Snapshots, lag recovery, contradiction preservation, and stale-decision rejection.

`RunStore` is deliberately bound to one Run and seals artifacts and audit history. Canonical Graph
revision is Campaign-wide, continues across Runs, and needs cross-process revision/head CAS plus
independent Snapshot publication. Putting both responsibilities in `RunStore` would either split
one Campaign across Run directories or create a second Campaign authority inside a Run boundary.

The first durable adapter should add no production service dependency while preserving a clear
upgrade path to a Control Plane database.

## Decision

### 1. Use a separate Graph Store

The first durable backend is `SQLiteGraphStore` in `pajin.graph.sqlite_store`. It does not modify
the `RunStore` format. One database owns exactly one Campaign and exposes Event Log, Projection
Store, and Snapshot Store protocol adapters.

### 2. Keep authoritative history append-only

Admission Events, admitted-node lookup rows, Projection revisions, and Snapshots are append-only.
Projection current state is the greatest stored revision, not a mutable last-write-wins row.
Metadata and Event/Snapshot writer identities are immutable after initialization.

### 3. Pin schema, Campaign, and writers

The database fingerprints its exact schema objects and pins schema version/digest, SQLite
application ID, and Campaign ID. Event and Snapshot writer ID/digest pairs are independently
inserted once. A process may reopen with the same identity; another identity fails closed.

### 4. Use SQLite transactions for host-local serialization

Writes use `BEGIN IMMEDIATE`, DELETE journal mode, and `synchronous=FULL`.

- Event append atomically writes the Event and newly admitted-node index.
- Projection CAS requires an exact prefix of the same durable Event Log and appends one immutable
  revision.
- Snapshot append requires an exact predecessor and a Projection already published in the same
  database.

An Event committed before Projection publication is a supported recovery state.
`GraphProjectionReconciler` repairs it after reopen. It never rewrites divergent history.

### 5. Preserve canonical validation at storage reads

Models are stored as bounded canonical UTF-8 JSON BLOBs. Reads revalidate the typed model, its
content-addressed identity, canonical bytes, and duplicated index columns. SQLite schema,
foreign-key, and integrity checks run on reopen.

### 6. Keep execution authority separate

This store does not turn `GraphDecisionPreflight` into an ActionPermit. Atomic latest-revision
comparison plus ActionPermit issuance/consumption and Worker dispatch is a separate decision and
trust-boundary slice.

## Alternatives considered

### Extend `RunStore`

Rejected for the first adapter because its one-Run lifecycle and sealing semantics do not naturally
own a Campaign-wide sequence and cross-Run projection head. `RunStore` remains valuable as source
evidence and legacy migration input.

### Add Graph tables to the Control Plane database now

Deferred. It could provide PostgreSQL HA and shared operational leases, but would couple the first
Graph conformance slice to optional service deployment and database migrations before the local
contract is exercised.

### Persist JSONL files beside Runs

Rejected because multi-process append, exact CAS, schema constraints, and Event/Projection/Snapshot
transactions would require a new filesystem database protocol.

## Compatibility and migration

The adapter is opt-in. Existing Modes, manifests, CLI/API contracts, Run directories, and in-memory
Graph tests are unchanged. No production Graph database exists to migrate.

Future legacy adapters emit typed Proposals with original Run/artifact digests as provenance.
Conversion never grants admission authority.

## Rollback

Before runtime integration, stop creating the SQLite store and retain its file as audit evidence.
After a Campaign treats it as canonical, rollback must preserve and verify the exact Event chain;
deleting, truncating, or rewriting admitted history is forbidden. A replacement backend must
import the canonical Events and reproduce Projection/Snapshot digests through conformance tests.

## Consequences

Positive:

- Campaign-wide Graph ownership no longer conflicts with one-Run sealing.
- Cross-process host-local Event append and Projection CAS have one database serialization point.
- Events, revisions, and Snapshots survive restart without a new runtime dependency.
- The same storage-neutral Graph protocols remain available for a future PostgreSQL adapter.

Costs and limits:

- SQLite is one-host storage, not multi-host leader election or HA.
- Event append and Projection publication are separate transactions by design; reconciliation is
  required after an interruption.
- Backup/restore, compaction, encryption at rest, external anchoring, and process-kill fault
  injection remain incomplete.
- Final ActionPermit dispatch atomicity remains open.

## Implementation

[GRAPH-005](../graph/GRAPH-005-durable-sqlite-graph-store.en.md) records schema, recovery,
filesystem, conformance, compatibility, and remaining boundaries.

## Related documents

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.en.md)
- [ADR-0048: Minimum Graph and Admission Consistency](0048-minimum-graph-and-admission-consistency.en.md)
- [GRAPH-004: Consistency, Recovery, and Stale Decision](../graph/GRAPH-004-consistency-recovery-stale-decision.en.md)
