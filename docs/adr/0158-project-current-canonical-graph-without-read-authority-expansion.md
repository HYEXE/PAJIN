# ADR-0158: Project the Current Canonical Graph without Read-Authority Expansion

## Status

Accepted

## Context

UX-002A exposes verified Discovery Surface and wave lineage but intentionally excludes the
Canonical Graph. PAJIN already has a separate single-Campaign `SQLiteGraphStore` whose append-only
Admission Event Log, deterministic Projection history, and immutable Snapshot chain are the
canonical Graph authority. The Control Plane does not currently own or deploy that store.

Inferring nodes or edges from Discovery or generic Control Plane events would create a second,
plausible-looking Graph. Copying Graph rows into the Control Plane database would likewise create
competing membership and freshness authorities. Opening `SQLiteGraphStore` normally can initialize
or migrate a database, which is also inappropriate for an HTTP read path.

## Decision

UX-002B adds the optional server-owned `PAJIN_CP_GRAPH_DATABASE` and one Operator-only endpoint:

`GET /v1/graphs/campaigns/{campaign}/snapshots/{snapshot_id}`

The caller supplies one canonical Campaign ID and one exact content-addressed Snapshot ID. It
cannot select a database path, Projection, Event Log prefix, node subset, edge subset, or current
head. The configured database must already exist and be the current Graph authority for that
Campaign.

Add a read-only verifier over the existing SQLite schema. In one query-only transaction it:

1. verifies the database path identity, schema fingerprint, metadata, SQLite integrity, and
   Campaign binding;
2. reparses the complete canonical Admission Event Log and checks its contiguous hash chain;
3. checks the admitted-node index against those Events;
4. rebuilds every stored Projection from the exact corresponding Event prefix;
5. revalidates the complete immutable Snapshot predecessor chain against published Projections;
6. requires the current Projection to include the complete latest Event Log; and
7. requires the requested Snapshot to be the Snapshot head and to embed that current Projection.

The verifier does not call database initialization, schema migration, Projection reconciliation,
Snapshot capture, admission, or any writer-capability path. Missing Projection publication or a
new Event without a current Snapshot fails closed instead of being repaired by the GET request.

The response is limited to 500 nodes and 1,000 edges. It preserves canonical Snapshot,
Projection, node, edge, endpoint, relation, and edge-authority identities. Node display fields are
an explicitly redacted kind-specific projection. Hypothesis statements, expected observables,
Observation summaries and values, Campaign Fact statements and values, Evidence references and
content digests, request and target digests, raw Events, Proposals, Grants, Permits, and database
paths are excluded. Oversized Snapshots are rejected rather than truncated.

The response states that the Canonical Graph Snapshot and current head were verified, content is
redacted, and the view cannot admit nodes, grant Capability or Permit authority, or authorize
execution.

The dependency-free Web Console validates the complete bounded response before rendering
Canonical node cards and admitted relationship cards. It uses created nodes and `textContent`
only.

## Consequences

- The Attack Surface, Graph, and Wave Timeline product unit now displays all three areas from their
  existing authorities without creating a second Graph store.
- Only the exact current Snapshot can be presented as current. Historical browsing, Snapshot
  listing, and automatic reconciliation remain outside this slice.
- The first deployment supports one configured single-Campaign Graph database per Control Plane
  process. Multi-Campaign database routing needs a separately governed registry rather than a
  caller-supplied path.
- The view is bounded and redacted. It is not a Graph export, evidence reader, content handoff, or
  execution interface.
- The local SQLite path and service-account filesystem boundary remain trusted. No off-host
  authenticity, multi-tenant isolation, or distributed atomicity is claimed.

## Rejected alternatives

### Infer a Graph from UX-002A Surface and wave data

Rejected because those values do not carry Canonical Graph admission membership or edge
authority.

### Copy Graph rows into the Control Plane database

Rejected because it creates a second membership and freshness authority.

### Initialize, migrate, or reconcile the Graph store on GET

Rejected because a read endpoint must not obtain Graph write authority or hide an incomplete
publication state.

### Return the full canonical node payload

Rejected because Graph nodes can contain target-derived text, evidence references, and other
content not required for relationship inspection.

## Compatibility and rollback

The setting, read-only verifier, route, DTO, and console panel are additive. No Control Plane or
Graph schema changes and no data migration are required. Omitting the database leaves the route
authenticated but fail-closed with `503`. Rollback removes the adapter and panel without changing
the Graph database.

## Related documents

- [GRAPH-003 Projection and Snapshot contract](../graph/GRAPH-003-projection-revision-immutable-snapshot.md)
- [GRAPH-005 durable SQLite Graph Store](../graph/GRAPH-005-durable-sqlite-graph-store.md)
- [UX-002B contract](../orchestration/UX-002B-current-canonical-graph-view.md)
