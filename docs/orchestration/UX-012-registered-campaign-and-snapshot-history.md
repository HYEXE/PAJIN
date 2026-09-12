# UX-012: Registered Campaign and Snapshot History

Configure `ControlPlaneSettings.graph_campaign_databases` or the JSON environment
variable `PAJIN_CP_GRAPH_CAMPAIGNS` as Campaign IDs mapped to existing database paths.
Each database must be distinct and its verified Campaign must match its registration.
Paths are deployment input and are never returned to the browser. The default empty
mapping exposes an empty registered list. The existing `graph_database` setting and
current-only Graph/attention/audit routes retain their contracts.

| Endpoint | Result |
| --- | --- |
| `GET /v1/graph-browser/campaigns` | Sorted registered Campaign IDs; no execution authorization |
| `GET /v1/graph-browser/campaigns/{campaign}/snapshots` | Newest-first catalog, default 25/max 50 entries |
| `GET /v1/graph-browser/campaigns/{campaign}/snapshots/{snapshot_id}/pages` | Redacted historical page, default 100/max 500 nodes and edges |

All endpoints require an authenticated Operator. Unknown Campaigns return 404;
malformed identifiers/cursors are rejected, body/path-selection input is refused,
and changed or invalid history returns 409 without content or filesystem disclosure.
Catalog continuation uses `cursor` and the original `limit`. Historical pages require
the catalog's `stateDigest` as `state`; their node/edge cursors additionally bind the
exact Campaign, Snapshot and page size. Recheck the catalog after 409.

Catalog version is `pajin.control-plane/graph-history-catalog/v1`; entry field names
are `ordinal`, `snapshot_id`, `snapshot_digest`, `revision`, `created_at`, `reason`,
`node_count`, `edge_count`. `currentSnapshotId` is null if no stored Snapshot matches
the current verified projection. `pajin.control-plane/historical-graph-page/v1`
has `historicalReadOnly=true`, `isCurrent` at verification, and
`authorityBoundary.currentSnapshotVerified=false`. Every grant/execute flag is false.

The Console has explicit registration refresh, Campaign selection, older catalog
pages and historical node/edge navigation. Changing Campaign or authentication
invalidates pending responses; duplicate clicks are bounded, failure preserves an
explicit retry path, and status/focus feedback remains available without animation.
No background job or server-side cancellation is claimed for these reads.

Verification covers multiple Campaigns, old/current separation, original-byte
preservation, unselected-history tampering, cursor scope/head changes, role denial,
reordered responses, duplicate clicks, offline recovery and authentication reset.
History grants no execution or approval authority and is not a general raw export.

A real local browser, backed by the API and two owned SQLite Campaign fixtures,
verified registration, Campaign switching, the two-entry history catalog, selection
of an older Snapshot and its redacted read-only page. Desktop and 390 × 844 layouts,
keyboard activation, authentication reset and an actual offline failure followed
by explicit online reload were exercised. The mobile viewport had no horizontal
overflow. The owned browser and API server were closed afterward. This does not
claim screen-reader coverage or a production deployment.
