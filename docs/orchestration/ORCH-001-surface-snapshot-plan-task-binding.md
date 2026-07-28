# ORCH-001: Surface Snapshot to Plan and Task Binding

- Status: Implemented
- Contract version: `pajin.dev/surface-bound-orchestration/v1alpha1`
- Decision: [ADR-0065](../adr/0065-surface-snapshot-bound-orchestration.md)

## Scope

ORCH-001 binds every executable Hypothesis follow-up Plan and Task to the exact immutable Surface
projection that authorized it. It is an additive orchestration layer over the existing
`pajin.dev/discovery-hypothesis/v1alpha1` artifacts; it does not change their wire shapes or grant
new Tool authority.

## Authority chain

`SurfaceSnapshotAuthority` identifies one immutable revision of a sealed Surface projection with:

- `revision` fixed to `1`;
- Campaign, projection Run ID/root digest, and source Run ID/root digest;
- portable projection artifact path and its sealed SHA-256;
- exact `AttackSurfaceSet` ID; and
- a domain-separated canonical `snapshotDigest` and derived `snapshotId`.

`SurfaceBoundTask.taskDigest` covers the Snapshot ID, revision, and digest; Hypothesis Set and
Hypothesis Wave Plan IDs; Hypothesis and Surface IDs; and the complete Specialist step, including
its Tool request.

`SurfaceBoundPlan.planDigest` covers the complete Snapshot authority, Hypothesis Set and Wave Plan
IDs, and the canonically sorted full Task set. Tasks from another Snapshot, Plan, or Hypothesis Set
are rejected even when each Task is independently well formed.

## Execution gate and audit

The Dynamic Hypothesis Wave writes `surface-bound-plan.json` beside the unchanged Hypothesis
artifacts. Before capability issuance and again immediately before each Tool dispatch, it:

1. verifies the source and projection Run integrity;
2. reloads the exact sealed Surface artifact;
3. revalidates artifact SHA-256, publication event, Surface Set identity, and source lineage;
4. reconstructs the current Snapshot, Plan, and Task digests; and
5. requires exact equality with the compiled `SurfaceBoundPlan`.

Failure occurs before the affected Tool dispatch. Compilation, Specialist creation, completion,
and terminal Run state record the Snapshot and Plan digests; each Specialist event also records
its Task digest.

## Negative cases

Validation fails closed for:

- forged Snapshot ID or digest;
- Snapshot revision other than `1`;
- non-portable artifact paths;
- modified Task payload with a retained Task digest;
- modified Plan membership with a retained Plan digest;
- duplicate or non-canonically ordered Tasks;
- a Task copied from another Snapshot, Hypothesis Set, or Wave Plan; and
- source/projection replacement or artifact mutation after compilation.

## Compatibility, migration, and rollback

Existing `AttackHypothesisSet`, `HypothesisWavePlan`, and Specialist-step v1alpha1 wire contracts
remain unchanged. Existing sealed runs remain readable by their existing loaders; new runs add one
artifact and additive audit fields. Consumers that execute a new Hypothesis Wave must treat the
Surface-bound Plan as mandatory execution authority.

Rollback disables new Hypothesis Wave execution and readers may ignore the additive artifact and
event fields. Rollback must not reinterpret an unbound legacy Plan as ORCH-001-authorized or
rewrite already sealed runs.
