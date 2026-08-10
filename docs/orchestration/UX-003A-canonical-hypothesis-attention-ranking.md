# UX-003A: Canonical Hypothesis Attention Ranking

- Status: Implemented
- Response schema: `pajin.control-plane/verified-hypothesis-attention-ranking-view/v1alpha1`
- Decision: [ADR-0159](../adr/0159-rank-current-hypotheses-without-decision-authority.md)
- Predecessors: GRAPH-004 consistency, GRAPH-005 SQLite store, UX-002B current Graph view

## Scope

UX-003A is the ranking half of the Hypothesis Ranking and Decision Audit product unit. It derives a
bounded review-attention order for every Hypothesis in one exact current Canonical Graph Snapshot:

`GET /v1/hypotheses/campaigns/{campaign}/snapshots/{snapshot_id}/attention-ranking`

Only an Operator may call it. The endpoint and Web Console do not create or mutate an Event,
Projection, Snapshot, Graph node, consistency view, Decision, Task, Plan, Run, Capability, Permit,
Tool request, or Worker dispatch.

## Verification

The reader uses the existing `PAJIN_CP_GRAPH_DATABASE` and UX-002B path-identity checks. A
query-only transaction verifies the schema, Campaign binding, complete Admission Event chain,
admitted-node index, every Projection, the immutable Snapshot chain, complete current Projection,
and requested current Snapshot head. The immutable Event tuple and Snapshot are then passed to the
existing `GraphConsistencyAnalyzer`, which replays the Event Log and derives each Hypothesis state
from canonical `supports` and `contradicts` relations.

The resulting consistency view must exactly match the Snapshot's Campaign, revision, Event head,
Projection ID, and Projection digest. Every assessment must bind the exact canonical Hypothesis node
reference, and assessment coverage must equal the Hypothesis membership of the Projection.

## Deterministic order

The complete list is sorted by:

1. state priority: `contested`, `supported`, `open`, `contradicted`;
2. producer confidence descending; and
3. Hypothesis node ID ascending.

Ranks are contiguous and start at one. The state-derived attention bands are respectively
`conflict-review`, `evidence-supported`, `evidence-needed`, and `contradicted-review`. These labels
describe operator review attention only. No score or automatic selection is created.

## Response and redaction

The response binds Campaign, Snapshot ID/digest, Projection ID/digest, consistency-view ID/digest,
ranking method, and Hypothesis count. Each item includes only rank, canonical node ID, Hypothesis
type, producer ID, origin, producer confidence, canonical state, support/contradiction counts, and
attention band.

At most 500 Hypotheses are returned. Oversized current Snapshots are rejected, never truncated.
Hypothesis statements and expected observables, Observation IDs/content, Evidence, Action payloads,
Events, database paths, Decisions, Grants, and Permits are excluded.

The authority boundary requires all of these literals:

- current Canonical Graph Snapshot verified: `true`;
- consistency view verified: `true`;
- deterministic review order and content redaction: `true`; and
- Hypothesis selection, Decision recording, work scheduling, and execution authorization: `false`.

## Web Console

The same-origin `/ui` panel accepts an exact Campaign and current Snapshot ID. Before DOM
replacement, JavaScript validates content-addressed identities, bounded cardinality, unique nodes,
contiguous ranks, state/count consistency, attention-band mapping, the full deterministic order,
and all authority literals. Rendering uses `createElement` and `textContent` only.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Approver-, Auditor-, or Worker-only credential | `403` |
| Non-canonical Campaign or Snapshot ID | `422` |
| Graph database not configured | `503` |
| Exact Snapshot absent from an otherwise valid store | `404` |
| Historical/foreign Snapshot, publication lag, or integrity disagreement | `409` |
| More than 500 canonical Hypotheses | `413` |

Responses use existing `/v1` no-store and no-referrer headers. Parser, filesystem, and database
details are not reflected.

## Compatibility and next slice

This slice is additive and requires no schema or data migration. It preserves the UX-002B
single-Campaign and local-filesystem limits. Full Decision Audit is not inferred from action or
permit references: UX-003B must first define durable complete `GraphDecision` storage, freshness,
redaction, and audit retrieval authority.
