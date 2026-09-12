# ADR-0292: Browse Verified History Without Current Graph Authority

- Status: Accepted
- Date: 2026-09-12
- Contracts: [UX-012](../orchestration/UX-012-registered-campaign-and-snapshot-history.md),
  [GRAPH-PERF-005](../benchmark/GRAPH-PERF-005-canonical-serialization-cost.md)

## Decision

Register at most 100 Campaign-to-database mappings in deployment configuration.
Operator requests select only registered identities. New historical endpoints verify
schema, admitted-node index, events, every projection and every Snapshot before
returning a bounded catalog or one page. Only requested page summaries and the selected
Snapshot are retained. Catalog cursors bind Campaign, page size and the verified
Snapshot/event/projection heads, so a head change requires reloading the catalog.

The new history page explicitly marks historical read-only status and does not claim
current-Snapshot authority, even when the selected Snapshot was latest at verification.
Existing current-only endpoints keep refusing earlier Snapshots. There is no action,
capability, admission, permit, raw export or filesystem-selection route here.

## Verification cost

Reuse one serialized node/edge material inside existing digest validators instead
of serializing it repeatedly. Preserve every semantic check, domain-separated digest,
canonical size bound and original-byte comparison. A just-validated cache miss needs
one defensive outward copy rather than revalidating its entire object graph again.
No unverified or caller-held object is reused, and cache hits still rehash all bytes,
check schema, current head and inode, and copy before returning.

## Consequences

History remains expensive because complete integrity verification is retained.
Registered Operators share the deployment's browse scope; this does not introduce
tenant isolation. Old APIs and persisted Graph formats stay compatible. The changes
can be rolled back without rewriting any Graph data; the new browser becomes unavailable.
