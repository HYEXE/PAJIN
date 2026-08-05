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
- Campaign name, additive complete Campaign digest, projection Run ID/root digest, and source Run
  ID/root digest;
- portable projection artifact path and its sealed SHA-256;
- exact `AttackSurfaceSet` ID; and
- a domain-separated canonical `snapshotDigest` and derived `snapshotId`.

The runtime now emits `campaignDigest` and uses the strengthened v2 Snapshot digest domain when it
is present. The v1alpha1 reader still accepts historical records without this additive field under
their original v1 digest domain. When absent, the field also stays absent from nested serialization
so retained Plan, WALK, and multi-wave parent digests remain stable. Later authority boundaries
such as PERMIT-001 must reject those legacy records because they cannot prove full Campaign
identity.

Strengthened WALK-002 and WALK-003 parents carry the same complete Manifest digest separately from
their pre-existing WALK-domain `campaignDigest`. This prevents a same-name foreign v2 Snapshot
from being relabeled while preserving field-absent historical WALK authority identities.

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
2. reloads sealed `campaign.json` and `recon-plan.json` and requires exact equality with the
   current Campaign and Recon outcome;
3. reloads the exact sealed Surface artifact;
4. revalidates artifact SHA-256, publication event, Surface Set identity, and source lineage;
5. reconstructs the current Snapshot, Plan, and Task digests; and
6. requires exact equality with the compiled `SurfaceBoundPlan`.

Failure occurs before the affected Tool dispatch. Compilation, Specialist creation, completion,
and terminal Run state record the Snapshot and Plan digests; each Specialist event also records
its Task digest.

## Negative cases

Validation fails closed for:

- forged Snapshot ID or digest;
- Campaign digest substitution when a strengthened Snapshot is used;
- Snapshot revision other than `1`;
- non-portable artifact paths;
- modified Task payload with a retained Task digest;
- modified Plan membership with a retained Plan digest;
- duplicate or non-canonically ordered Tasks;
- a Task copied from another Snapshot, Hypothesis Set, or Wave Plan; and
- source/projection replacement or artifact mutation after compilation; and
- same-name Campaign relabeling of a sealed Recon source.

## Compatibility, migration, and rollback

Existing `AttackHypothesisSet`, `HypothesisWavePlan`, and Specialist-step v1alpha1 wire contracts
remain unchanged. Existing sealed runs and v1-domain Snapshot records remain readable; new
Snapshots add `campaignDigest` and use the strengthened digest domain. New runs add one artifact
and additive audit fields. Consumers that execute a new Hypothesis Wave must treat the
Surface-bound Plan as mandatory execution authority, and consumers requiring full Campaign
identity must require the additive digest.

Rollback disables new Hypothesis Wave execution but must retain reader support for the additive
Snapshot field. Code that predates that reader support must treat strengthened Snapshot runs as
non-executable historical artifacts. Rollback must not reinterpret an unbound legacy Plan as
ORCH-001-authorized or rewrite already sealed runs.
