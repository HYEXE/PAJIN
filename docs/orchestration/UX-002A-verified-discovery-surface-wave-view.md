# UX-002A: Verified Discovery Surface and Wave View

- Status: Implemented
- Response schema: `pajin.control-plane/verified-discovery-surface-wave-view/v1alpha1`
- Decision: [ADR-0157](../adr/0157-project-verified-discovery-surface-waves-without-graph-authority.md)
- Predecessors: sealed Recon projection, ORCH-001 Surface Snapshot, Discovery Hypothesis Wave

## Scope

UX-002A is the first vertical slice of the Attack Surface, Graph, and Wave Timeline product area.
It exposes only the already-sealed Attack Surface and Recon-to-Hypothesis wave lineage:

`GET /v1/discovery/campaigns/{campaign}/hypothesis-runs/{hypothesis_run_id}`

Only an Operator may call it. The endpoint and Web Console create no file, database row, managed
Artifact, Graph record, approval, Capability, Permit, Run, Tool call, or Worker dispatch.

## Configuration and request

Configure the optional server-owned root:

```powershell
$env:PAJIN_CP_DISCOVERY_RUN_ROOT='C:\private\pajin-discovery-runs'
```

`campaign` must match `^[a-z0-9][a-z0-9-]{2,79}$`. `hypothesis_run_id` must match the exact generated
Run pattern `^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$`. There is no request body, root parameter,
artifact path, source Run parameter, or projection Run parameter.

## Verification

The server verifies the complete Hypothesis Run and then follows only the IDs and digests in its
validated `SurfaceSnapshotAuthority`. It reopens the exact Recon source and Surface projection Runs
under the same configured root. Every Run goes through bounded, sealed, stable-revision snapshot
verification.

Admission requires agreement across:

- Campaign value and canonical digest;
- Hypothesis Run ID/root, terminal state, successful results, Set/Plan/Task identities, and unique
  compiled/completed/terminal events;
- Recon source Run ID/root, Campaign, Plan target, completed state, evidence reference binding, and
  unique completed/terminal events; and
- projection Run ID/root, exact artifact path/SHA-256, Surface Set source lineage, required Surface
  kinds, observation/request counts, and unique publication event.

Directory links/junctions, path escape, malformed identifiers, missing artifacts, hash drift,
cross-Campaign substitution, stale projection substitution, and event equivocation are rejected.

## Response

| Group | Fields |
| --- | --- |
| Campaign | `campaign.name`, `campaign.digest` |
| Hypothesis authority | `hypothesisRun.runId`, `rootDigest`, `state=completed` |
| Snapshot | Snapshot/Surface Set IDs, revision, source/projection Run IDs and roots, artifact SHA-256 |
| Surface Set | generated time, Surface/observation counts, bounded normalized Surface rows |
| Surface row | Surface/Target IDs, normalized locator, confidence, observation count, first/last time |
| Waves | one completed Recon stage and one completed Hypothesis stage with bounded task identities |
| Boundary | Snapshot verified; canonical Graph, capability, permit, and execution authority all false |

Observations, evidence references, raw results, request arguments, grants, permits, paths, and
unrelated Run events are excluded.

## Web Console

The same-origin `/ui` shell adds an Operator-only form for the exact Campaign and Hypothesis Run
ID. It renders verified Surface cards and the two-stage wave timeline. The panel always labels the
canonical Graph as not included. JavaScript validates all identifiers, digests, cardinalities,
timestamps, locator bounds, wave ordering, Surface-task references, and false authority markers
before replacing the DOM. Rendering uses `textContent` and created nodes only.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Approver-, Auditor-, or Worker-only credential | `403` |
| Non-canonical Campaign or Run ID | `422` |
| Root not configured | `503` |
| Exact Campaign/Run tuple absent | `404` |
| Tampered, substituted, stale, foreign, ambiguous, or otherwise disagreeing authority | `409` |

Responses use the existing `/v1` no-store and no-referrer headers. Filesystem paths and parser
details are not reflected.

## Compatibility and next slice

This is additive and read-only. It does not change Run or Graph schemas and requires no migration.
UX-002B may add canonical Graph visualization only after identifying an existing Graph snapshot and
admission authority that can be reverified without duplicating a store or inferring edges from the
Surface/Wave projection.
