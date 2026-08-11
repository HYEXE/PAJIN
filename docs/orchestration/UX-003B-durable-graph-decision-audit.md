# UX-003B: Durable Graph Decision Audit

- Status: Implemented and verified
- Decision: [ADR-0160](../adr/0160-store-complete-graph-decisions-in-a-separate-audit-authority.md)
- Predecessors: GRAPH-004, GRAPH-005, GRAPH-006, UX-003A
- Record schema: `pajin.dev/graph-decision-audit-record/v1alpha1`
- Response schema: `pajin.control-plane/verified-graph-decision-audit-view/v1alpha1`

## Scope

UX-003B closes the Decision Audit half of the Hypothesis Ranking and Decision Audit product unit.
It adds a durable append/read authority for complete canonical `GraphDecision` records and one
Operator-only redacted view:

`GET /v1/decisions/campaigns/{campaign}/snapshots/{snapshot_id}/audit`

The endpoint is query-only. It cannot initialize either database, append a record, choose a
Hypothesis, construct a Decision, schedule a Task or Plan, grant a Capability, approve an action,
issue or consume a Permit, or dispatch a Worker.

## Durable audit authority

`SQLiteGraphDecisionAuditStore` is a separate schema-v1 SQLite database pinned to one Campaign and
one recorder ID/digest. Its exact schema contains metadata, the recorder identity, and an ordered
Decision record table. Every table is immutable after insert.

Each `GraphDecisionAuditRecord` binds:

- contiguous sequence and previous-record digest;
- complete canonical `GraphDecision` material;
- Campaign and exact Snapshot identity through that Decision;
- recorder ID/digest and UTC record time; and
- a content-addressed record ID/digest.

The initial append of a Decision requires the existing Canonical Graph Store to verify that exact
Snapshot reference as its current head and requires `decision.createdAt >= snapshot.createdAt`.
Exact retry is idempotent. Foreign Campaigns, stale or substituted Snapshots, non-canonical
Decisions, recorder substitution, identity equivocation, and database path aliasing fail closed.

The v1 retention rule is indefinite append-only retention. No delete, update, compaction, expiry,
or payload reconstruction API exists. Signed off-host retention and an independent anti-rollback
anchor are outside this slice.

## Read verification

A read requires both configured existing regular files:

- `PAJIN_CP_GRAPH_DATABASE`; and
- `PAJIN_CP_GRAPH_DECISION_AUDIT_DATABASE`.

The files must be distinct and cannot be each other's SQLite sidecars. The reader verifies the
complete Canonical Graph Event/Projection/Snapshot state, exact current requested Snapshot, the
audit schema and recorder, the complete record chain, and every retained Decision's exact
historical Snapshot reference. It rechecks the requested current Snapshot after audit verification.

Only Decisions bound to the requested current Snapshot are returned. At most 500 are allowed;
larger current-Snapshot sets are rejected and never truncated.

## Response and redaction

The response binds Campaign, current Snapshot and Projection identities, audit schema version,
recorder digest, total retained record count, current-Snapshot Decision count, and audit head
digest. Each current item includes:

- audit sequence and record ID/digest;
- previous-record digest;
- Decision ID/digest and kind;
- opaque Decision payload digest;
- actor and recorder digests; and
- Decision creation and audit record timestamps.

Actor ID, recorder ID, payload content, Hypothesis statements, Observation content, Evidence,
Action parameters, paths, credentials, Grants, Permits, and approval material are excluded.

The authority boundary requires these literal claims:

- current Canonical Graph Snapshot verified: `true`;
- complete audit chain and historical Snapshot bindings verified: `true`;
- append-only historical retention and identifier redaction: `true`; and
- Hypothesis selection, Decision recording, scheduling, approval, Capability, Permit, and execution
  authority: `false`.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Approver-, Auditor-, or Worker-only credential | `403` |
| Non-canonical Campaign or Snapshot ID | `422` |
| Graph or Decision audit database not configured | `503` |
| Exact current Graph Snapshot absent | `404` |
| Stale/foreign Snapshot, path alias, schema, chain, record, or cross-store disagreement | `409` |
| More than 500 Decisions for the current Snapshot | `413` |

Responses retain the existing `/v1` no-store and no-referrer headers. Filesystem, SQLite, and
parser details are not reflected.

## Web Console

The same-origin panel accepts an exact Campaign and current Snapshot ID. JavaScript validates all
protocol literals, identifiers, digests, count bounds, ascending unique audit sequence, Snapshot
and Campaign binding, and redaction boundaries before replacing the DOM. Rendering uses created
nodes and `textContent` only.

## Completion criteria

- canonical append, reopen, exact retry, and multi-instance single-winner behavior;
- stale, foreign, forged, equivocated, reordered, deleted, or modified records fail closed;
- every retained Decision resolves to one verified historical Graph Snapshot;
- current-Snapshot filtering, 500-record rejection, role isolation, and read-only files are tested;
- the Web Console rejects forged authority markers and renders desktop/mobile without overflow or
  console errors; and
- focused tests, Ruff, Linux-target mypy, relevant regression tests, and documentation checks pass
  or record an environment limitation.
