# ADR-0136: Coordinate Bounded Async Approval Batches Without Duplicating Execution Authority

- Status: Accepted
- Date: 2026-08-06

## Context

APPROVAL-001A atomically consumes one authenticated approval with one unchanged ActionPermit.
APPROVAL-001B additionally consumes one reversible cleanup hold. Neither contract defines ordered
batch membership, a pre-dispatch asynchronous claim, partial cancellation, or reconciliation after
an uncertain callback.

Treating a batch as one large ActionPermit would merge independent requests, reservations, and
outcomes. Calling the single-action dispatcher in a loop without a durable preclaim would allow a
crash to lose the current item and redispatch it. Moving the approvals into another database would
split the final Graph execution authority.

## Decision

1. Define a separately versioned `ActionApprovalBatchEnvelope` containing exactly two through eight
   canonical APPROVAL-001A envelopes in stable order. Require one issuer, Campaign, Run,
   MissionEnvelope, activation set, principal pair, and approval window.
2. Keep the existing Graph approval/ActionPermit transaction as the only execution authority. The
   batch journal records coordination state and exact Graph receipt/Permit references but cannot
   mint, restore, or redispatch them.
3. Record `claim-started` before entering the Graph authority. After the exact Graph authorization
   is bound durably, record `dispatch-started-outcome-unknown` before the async Worker callback.
4. Never return a claimed item to pending. A callback exception, cancellation, or crash remains
   unknown. Existing or recovered Graph consumption never grants automatic callback replay.
5. Accept terminal evidence only through a deployment-pinned completion authority. Distinguish
   direct Worker completion from manual reconciliation and fix `redispatchAuthority=false` in both.
6. Permit cancellation only for an authenticated exact subset whose items are all still pending;
   commit or roll back the subset atomically.
7. Derive the batch aggregate from every verified item/event chain. Any claim-started or
   dispatch-started item requires manual review.
8. Limit this slice to the existing no-write APPROVAL-001A authority. Version reversible cleanup
   composition and runtime integration separately.

## Consequences

- Async orchestration can crash without silently granting a second Worker call.
- Partial success, failure, pending work, cancellation, and unknown outcomes remain distinguishable.
- A conservative crash window can require manual review even if no Worker ran; availability is
  intentionally traded for at-most-once execution.
- Graph schema v4 and existing backup wires remain unchanged.
- The coordinator journal and verifier implementations are host/process-local TCB and are not
  distributed exactly-once authority.
- Existing single-action and reversible-write runtimes remain unchanged and fail closed for batch.

## Rejected alternatives

### Add one batch ActionPermit

Rejected because a single Permit would collapse distinct Proposals, requests, reservations,
approval consumptions, cleanup needs, and outcomes into one ambiguous execution authority.

### Store batch approvals in a parallel approval database

Rejected because approval and Permit consumption would gain different serial orders. The journal
stores coordination state only; Graph still owns every item authorization.

### Dispatch first and record the batch item afterward

Rejected because a crash would leave no durable evidence that the callback may already have run.

### Automatically retry an unknown item

Rejected because a transport error cannot prove non-execution. A new attempt requires new approval
authority rather than a state transition that fabricates redispatch rights.

### Include reversible writes immediately

Rejected because a partial write batch also needs per-item cleanup reservation, CleanupPermit,
restored-state, and release policy. Reusing the no-write completion shape would hide those
authorities.

## Compatibility and rollback

The change is additive. Existing public wires, Graph schema, approval ledgers, Permit and cleanup
records, Gateway, Worker, and backup readers do not change. Rollback removes the new coordinator
composition but retains its journal and all Graph evidence for audit. Unknown records require manual
adjudication and cannot be deleted to simulate rollback.
