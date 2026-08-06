# ADR-0137: Bind Reversible Batch Items to Existing Cleanup Authority

- Status: Accepted
- Date: 2026-08-06

## Context

APPROVAL-001C1 coordinates bounded asynchronous no-write approvals without duplicating the Graph
execution authority. A reversible-write item has a stronger boundary: approval, ActionPermit,
approval receipt, and cleanup capacity must commit together before dispatch, and a terminal batch
record must not imply that the target was restored without authenticated evidence.

Creating a batch-level cleanup pool would detach cleanup capacity from the exact source Permit.
Treating Worker completion as restored-state proof would collapse source execution, cleanup
execution, and independent target observation into one unauthenticated assertion.

## Decision

1. Reuse `GraphApprovedReversibleActionPermitAuthority` for every reversible batch item. It remains
   the only authority that atomically consumes the approval, unchanged ActionPermit, non-reusable
   receipt, and exact `ActionCleanupReservation`.
2. Pair each reversible approval with one canonical `ActionCleanupReservationRequest` inside the
   content-addressed batch. Require exact Campaign, Run, MissionEnvelope, Proposal, target, and
   cleanup lineage. No-write items must carry no cleanup request.
3. Persist the complete cleanup reservation beside the Permit and receipt before invoking the
   asynchronous consumer. The coordinator stores a reference to existing authority; it cannot
   mint, replace, release, or aggregate cleanup capacity.
4. Keep the C1 state machine unchanged. Any failure or cancellation after the combined Graph claim
   remains `dispatch-started-outcome-unknown` and cannot redispatch the source write.
5. Require every reversible terminal completion to exact-bind the cleanup reservation ID and
   digest plus a `restoredStateEvidenceDigest`. A deployment-pinned completion authority must
   authenticate that digest against the existing cleanup/restored-state path or equivalent sealed
   evidence before the journal transition commits.
6. Apply the same rule to manual reconciliation. Missing, partial, stale, cross-item, or
   equivocated cleanup/restored-state evidence fails closed and leaves the item unknown.
7. Keep cleanup execution, CleanupPermit issuance, restored-state observation, and reservation
   lifecycle under their existing authorities. A batch terminal record never grants source-action
   redispatch or cleanup-capacity reuse.
8. Keep General Attack and Control Plane batch workflow integration out of this slice. Runtime
   composition must supply the existing cleanup assessment as completion authority evidence.

## Consequences

- Partial reversible batches retain one cleanup hold per consumed source write.
- A Worker callback cannot close a reversible item merely by reporting source success.
- Unknown write or cleanup outcomes require authenticated adjudication and cannot silently replay.
- The Graph schema, Permit, receipt, cleanup reservation, CleanupPermit, and restored-state models
  remain unchanged.
- The batch journal schema gains only coordinator copies of exact cleanup references and canonical
  reservation bytes; those copies are not execution authority.
- The completion verifier remains process-local deployment TCB until a signed durable verifier
  inventory is introduced.

## Rejected alternatives

### Reserve one aggregate cleanup budget for the batch

Rejected because cleanup reservations bind distinct Proposals, Permits, targets, mappings, and
budgets. Aggregate capacity would not prove that any individual write can be restored.

### Let the coordinator create cleanup reservations

Rejected because that would duplicate APPROVAL-001B's atomic writer and split approval from cleanup
capacity across databases.

### Mark reversible completion terminal before restored-state evidence

Rejected because successful dispatch or cleanup execution does not independently prove the target
is restored. The item must remain unknown until the pinned completion authority authenticates the
exact evidence digest.

### Redispatch after cleanup succeeds

Rejected because restored state does not restore approval, ActionPermit, or source dispatch
authority.

## Compatibility and rollback

The change is additive to the C1 coordinator surface. Existing APPROVAL-001A/B callers,
Graph schema v4, backup wire v1alpha3, General Attack, CleanupPermit, and restored-state assessment
remain unchanged. Rollback removes reversible batch composition but preserves every consumed Graph
record and coordinator journal for audit. It must not delete cleanup holds or reinterpret unknown
items as safe to replay.
