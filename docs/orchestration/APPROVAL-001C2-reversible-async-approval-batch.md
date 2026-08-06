# APPROVAL-001C2: Reversible Asynchronous Approval Batch Coordination

- Status: Locally implemented
- Date: 2026-08-06
- Prerequisites: APPROVAL-001B, APPROVAL-001C1, PERMIT-004B1, PERMIT-004B2, ADR-0137

## Purpose

Extend the bounded asynchronous approval coordinator to `reversible-write +
cleanupRequired=true` items while retaining the exact APPROVAL-001B execution and cleanup
authorities. The batch journal coordinates partial and unknown outcomes but never grants approval,
ActionPermit, cleanup reservation, CleanupPermit, restored-state, or redispatch authority.

This direct-call slice does not add a default General Attack or Control Plane workflow. It provides
the authority-preserving primitive that a later opt-in runtime composition can call.

## Batch input

`ActionApprovalBatchEnvelope.cleanupRequests` is an ordered tuple aligned with `approvals`:

- a no-write approval has `null` and `cleanupRequired=false`;
- a reversible-write approval has one canonical `ActionCleanupReservationRequest` and
  `cleanupRequired=true`; and
- irreversible-write and every other side-effect shape are rejected.

The cleanup request exact-binds the approval's Campaign, Run, MissionEnvelope, Proposal, target,
cleanup Capability, handler, executor, budget, and claim window. Cleanup request identities cannot
repeat within the batch. The existing batch input authority authenticates the complete mixed
ordered set before and inside every journal mutation.

## Atomic item authorization

`dispatch_reversible_item_once` calls the existing
`GraphApprovedReversibleActionPermitAuthority`. The Graph store atomically commits:

1. the existing operator approval;
2. the unchanged consumed `ActionPermit`;
3. the non-reusable approval consumption receipt; and
4. the exact `ActionCleanupReservation` built from the paired request and Permit.

Only after that transaction succeeds does the coordinator bind the Permit, receipt, and complete
cleanup reservation to the claimed item. The journal reaches
`dispatch-started-outcome-unknown` before the asynchronous consumer receives detached copies of all
three records.

The journal cannot manufacture an authorization. No-write authorization is rejected for a
reversible item, reversible authorization is rejected for a no-write item, and substituted Permit,
receipt, request, reservation, target, compiler, handler, executor, or dispatch lineage fails
closed.

## Terminal and restored-state evidence

Every reversible `ActionApprovalBatchCompletion` must include:

- the exact cleanup reservation ID and digest; and
- `restoredStateEvidenceDigest`, authenticated by the deployment-pinned completion authority.

The completion authority is responsible for resolving that digest to the existing sealed cleanup
and independent restored-state evidence, such as a canonical `GeneralAttackCleanupAssessment`, and
for checking that it belongs to the same source Permit and reservation. The coordinator deliberately
stores only the digest because the Graph layer does not own General Attack runtime evidence.

The requirement applies to both `worker-completion` and `manual-reconciliation`. A missing or
partial restored-state binding, cross-item reservation, stale evidence, verifier drift, or terminal
equivocation rolls back the journal transition. The item remains outcome-unknown and cannot
redispatch.

Terminal status records adjudication of the complete action-and-restoration workflow. It does not
release cleanup capacity or make the source approval or Permit reusable. Existing CleanupPermit and
reservation lifecycle rules remain authoritative.

## Partial and unknown outcomes

Each item advances independently through the C1 state machine. Therefore a bounded batch can
contain succeeded, failed, pending, cancelled-before-dispatch, and unknown reversible items without
collapsing their authorities.

- pending cancellation consumes no approval, Permit, or cleanup hold;
- a combined Graph claim failure leaves `claim-started` for conservative recovery;
- a callback exception, task cancellation, or crash after authorization leaves the exact cleanup
  hold attached to `dispatch-started-outcome-unknown`;
- exact retry returns the durable four-record authorization with `newlyConsumed=false` and never
  calls the consumer; and
- only authenticated terminal/manual evidence can close an unknown item.

## Persistence and compatibility

The host-local journal stores a cleanup-request digest as immutable item identity and canonical
cleanup-reservation bytes as coordinator evidence. Schema fingerprinting, transition triggers,
event-chain verification, filesystem checks, `DELETE` journal mode, and `synchronous=FULL` apply
unchanged.

Graph schema v4/v1alpha3, APPROVAL-001A/B wires, ActionPermit, approval receipt,
`ActionCleanupReservation`, CleanupPermit, backup formats, and existing runtime dispatchers do not
change. Existing no-write batch callers omit `cleanupRequests`; canonical normalization records an
aligned tuple of nulls without granting write support to the no-write dispatcher.

## Verification

Tests cover reversible request pairing, four-record atomic authorization, durable reservation
binding, restored-state evidence requirements, single async dispatch, exact non-redispatch,
unknown outcome recovery, cross-reservation forgery, manual reconciliation, wrong-dispatcher
rejection, and the existing no-write partial/cancellation boundaries.

## Follow-up

- APPROVAL-001C3: compose an opt-in General Attack/Control Plane workflow that maps the existing
  sealed cleanup assessment into the completion authority and defines journal retention/backup.
- Cross-host execution requires external fencing/consensus and a signed deployment inventory; it
  must not reinterpret this host-local coordinator as distributed exactly-once authority.
