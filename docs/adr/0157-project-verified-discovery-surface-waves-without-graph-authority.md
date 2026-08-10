# ADR-0157: Project Verified Discovery Surface Waves without Graph Authority

## Status

Accepted

## Context

The next Phase 9 product area is Attack Surface, Graph, and Wave Timeline UI. These are separate
authority domains. PAJIN already seals Recon source Runs, publishes an `AttackSurfaceSet` in a
separate projection Run, and binds a Hypothesis Run to that exact projection through
`SurfaceSnapshotAuthority` and `SurfaceBoundPlan`. The base Control Plane API does not expose these
authorities and does not own a general canonical Graph deployment.

Treating Control Plane Run input or its generic audit events as Discovery, or drawing inferred
Graph nodes from those values, would create a plausible but false read model. Adding a new Graph
store merely to render the first screen would also duplicate existing Graph admission authority.

## Decision

UX-002A adds an optional server-owned `PAJIN_CP_DISCOVERY_RUN_ROOT` and one Operator-only endpoint:

`GET /v1/discovery/campaigns/{campaign}/hypothesis-runs/{hypothesis_run_id}`

The request contains only canonical Campaign and generated Run identifiers. It cannot select a
filesystem root, relative path, artifact path, or projection Run. The reader resolves the exact
`<root>/<campaign>/<run>` tuple and rejects links, junctions, path escapes, missing components, and
non-canonical identifiers.

Before returning data, the reader uses the existing bounded verified Run snapshot loader and
revalidates three sealed authorities:

1. the Hypothesis Run Campaign, Hypothesis Set, Wave Plan, Surface-bound Plan, successful results,
   terminal state, compilation event, completion event, and terminal event;
2. the referenced Recon source Run Campaign, root digest, Recon Plan, target binding, terminal
   state, completion event, and terminal event; and
3. the referenced Surface projection Run root digest, artifact SHA-256, `AttackSurfaceSet`
   lineage, required Surface kinds, and unique publication event.

All cross-Run IDs, root digests, Campaign digest, Snapshot identity, Surface Set identity, artifact
digest, Plan digest, Task digests, request IDs, and event payloads must agree. Missing, stale,
foreign, forged, substituted, or equivocal authority fails closed.

The response is a bounded projection containing Campaign identity, the verified Hypothesis Run,
Surface Snapshot identity, redacted Attack Surface rows, and a two-stage Recon-to-Hypothesis wave
trace. Surface rows retain their normalized non-executable locator but omit observations, evidence
references, raw Tool results, Tool arguments, Capability grants, Permits, and filesystem paths.

The response states:

- `surfaceSnapshotVerified=true`;
- `canonicalGraphIncluded=false`;
- `viewGrantsCapability=false`;
- `viewGrantsPermit=false`; and
- `viewAuthorizesExecution=false`.

The dependency-free same-origin Web Console accepts one exact Campaign/Run tuple from an Operator,
validates the complete response protocol, and renders the Surface cards and sealed wave timeline
with a persistent "Graph not included" boundary. Approver-, Auditor-, and Worker-only credentials
cannot read this projection.

The verified snapshot loader may coordinate through its existing per-user temporary advisory lock.
That coordination file is outside immutable Run trees and is not a Run, Graph, audit, Capability,
Permit, or execution write.

## Consequences

- Operators can inspect actual sealed Discovery lineage without relabeling generic Control Plane
  state.
- The view cannot mint, mutate, admit, dispatch, approve, or execute anything.
- Canonical Graph visualization remains a later UX-002B slice that must reuse an existing Graph
  snapshot/admission authority rather than infer edges from this response.
- The root must be readable by the Control Plane service account and protected from untrusted
  writers. The Run format remains the existing local sealed format; no off-host attestation is
  claimed.
- Rendering up to the existing bounded 500 Surface and 100 Hypothesis limits is supported. The
  browser rejects over-limit, malformed, authority-promoting, or cross-boundary responses.

## Compatibility and rollback

The setting, route, response model, and console panel are additive. No database, Run, Discovery,
Graph, or artifact schema changes. Omitting the root leaves the authenticated route present but
fail-closed with `503`. Rollback removes the route, reader, and panel; existing sealed Runs are
unchanged.

## Related documents

- [ORCH-001 Surface Snapshot binding](0065-surface-snapshot-bound-orchestration.md)
- [UX-002A contract](../orchestration/UX-002A-verified-discovery-surface-wave-view.md)
