# UX-002B: Current Canonical Graph View

- Status: Implemented
- Response schema: `pajin.control-plane/verified-canonical-graph-view/v1alpha1`
- Decision: [ADR-0158](../adr/0158-project-current-canonical-graph-without-read-authority-expansion.md)
- Predecessors: GRAPH-002 Admission Event Log, GRAPH-003 Projection/Snapshot, GRAPH-005 SQLite store

## Scope

UX-002B completes the first Attack Surface, Graph, and Wave Timeline product unit with a bounded
read-only projection of one exact current Canonical Graph Snapshot:

`GET /v1/graphs/campaigns/{campaign}/snapshots/{snapshot_id}`

Only an Operator may call it. The endpoint and Web Console do not create or mutate a Graph Event,
Projection, Snapshot, node, edge, Control Plane row, Run, Artifact, approval, Capability, Permit,
Tool request, or Worker dispatch.

## Configuration and request

Configure one existing server-owned single-Campaign database:

```powershell
$env:PAJIN_CP_GRAPH_DATABASE='C:\private\pajin-graph\canonical.sqlite3'
```

`campaign` must match `^[a-z0-9][a-z0-9-]{2,79}$`. `snapshot_id` must match
`^graph-snapshot_[a-f0-9]{64}$`. There is no request body, database-path parameter, head alias,
Projection selector, node selector, or edge selector.

## Verification

The reader opens the existing database with SQLite read-only and query-only settings. It verifies:

- regular-file identity with no link/junction leaf or direct parent and a single hard link;
- exact current schema fingerprint, application/version metadata, Campaign binding, foreign keys,
  and SQLite quick integrity;
- canonical Event bytes, indexes, Campaign, sequence, predecessor, and Event digest across the
  complete Admission Event Log;
- exact equality between the admitted-node index and admitted Event material;
- every Projection against its exact Event prefix, including genesis;
- every Snapshot's canonical identity, ordinal, predecessor, and published Projection;
- current Projection revision/head against the complete Event Log; and
- requested Snapshot ID against the Snapshot head and current Projection.

The query never initializes, migrates, reconciles, captures, or writes the Graph store. Event,
Projection, or Snapshot lag is an integrity conflict requiring the owning Graph authority to
publish a new current state.

## Response

| Group | Fields |
| --- | --- |
| Campaign | canonical Campaign ID |
| Snapshot | ID/digest, predecessor digest, reason, creation and creator authority |
| Projection | schema, revision, Event head, Projection/node/edge digests |
| Node | exact node ID/kind plus bounded kind-specific display key/value and safe metadata |
| Edge | exact edge ID/relation, typed endpoints, edge authority ID/digest |
| Boundary | current Canonical Snapshot verified, content redacted, all write/execution authority false |

The response contains at most 500 nodes and 1,000 edges and is never truncated. Hypothesis and Fact
statements, expected observables, Observation summaries/value digests, Evidence references/content
digests, request/target digests, full canonical node payloads, Events, Proposals, paths, Grants, and
Permits are excluded.

## Snapshot-bound pages

The additive `GET /v1/graphs/campaigns/{campaign}/snapshots/{snapshot_id}/pages` route returns
`pajin.control-plane/verified-canonical-graph-page/v1`. `limit` is an integer from 1 to 500
(default 100); optional `cursor` is a canonical, unpadded URL-safe base64 JSON position bound to
the Campaign, Snapshot ID/digest, Projection digest, page size, and aligned offset. It is a
position, not a signed credential or read grant. Operator authentication is still required.

`nodeCount` and `edgeCount` describe the complete projection, bounded by 100,000 and 200,000.
`pageOffset` and `pageSize` select the same slice of each sorted array; one array may be empty
on later pages. `nextCursor` is null at completion. Endpoint IDs/kinds may refer to nodes on other
pages. No full payloads or additional authority are exposed. Every request repeats the complete
store verification; this bounds response and browser memory, not server verification cost.

Malformed/mixed cursors and invalid limits return `422`; advancing the Graph makes the old
Snapshot return `409`. A cursor cannot resume historical state. The legacy full endpoint still
returns `413` above its original limits. See [ADR-0271](../adr/0271-page-the-verified-current-graph-with-snapshot-bound-cursors.md).

## Web Console

The same-origin `/ui` shell accepts one exact Campaign and current Snapshot ID from an Operator. It
renders canonical node cards and admitted relationship cards with current-Snapshot, redaction,
read-only, no-admission, and no-execution boundary labels. JavaScript validates identifier and
digest shapes, revision/head consistency, node/edge cardinalities, unique IDs, endpoint membership,
relation direction, authority identity, timestamps, bounds, and literal authority markers before
replacing the DOM. Rendering uses `textContent` only. The Console uses pages of 100 with keyboard
accessible previous/next controls. Navigation verifies identity and counts against the preceding
page, and replaces all rows. Input edits and authentication changes invalidate pending requests;
failures clear content and navigation. No stale page is combined with another Snapshot.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Approver-, Auditor-, or Worker-only credential | `403` |
| Non-canonical Campaign or Snapshot ID | `422` |
| Graph database not configured | `503` |
| Exact Snapshot absent from an otherwise valid store | `404` |
| Historical Snapshot, publication lag, foreign Campaign, or integrity disagreement | `409` |
| Exact current Snapshot exceeds node/edge view limits | `413` |

Responses use the existing `/v1` no-store and no-referrer headers. Database paths and parser
details are not reflected.

## Compatibility and next slice

This is additive and requires no schema or data migration. It supports one configured
single-Campaign Graph database and exact current Snapshot reads only. Historical browsing,
multi-Campaign routing, full Graph export, content resolution, admission, and execution remain out
of scope. The next Phase 9 product unit is Hypothesis Ranking and Decision Audit.
