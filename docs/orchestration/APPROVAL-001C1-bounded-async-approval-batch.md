# APPROVAL-001C1: Bounded Asynchronous Approval Batch Coordination

- Status: Locally implemented
- Date: 2026-08-06
- Prerequisites: APPROVAL-001A, GRAPH-006, ADR-0134, ADR-0136

## Purpose

Coordinate two through eight existing single-action approvals as one authenticated, ordered batch
without creating another execution authority. Each item still consumes its approval and unchanged
`ActionPermit` through the APPROVAL-001A Graph transaction. A separate host-local SQLite journal
records only the batch membership and asynchronous coordination state before any Worker callback.

This first APPROVAL-001C slice supports no-write approvals accepted by
`GraphApprovedActionPermitAuthority`. Reversible-write batches, cleanup-hold aggregation, General
Attack or Control Plane default integration, T3+, lease transfer, and cross-host coordination remain
closed.

## Batch authority

`ActionApprovalBatchEnvelope` is content addressed and binds:

- one deployment/operator issuer, Campaign, Run, and exact shared MissionEnvelope;
- exactly two through eight canonical APPROVAL-001A envelopes in a stable order;
- one shared requester, approver, activation set, and approval time window; and
- `mode=batch`, the exact JSON integer `maxActions`, and `asynchronous=true`.

Every approval, Proposal, request, and expected Permit identity must be unique. The batch digest is
integrity evidence, not issuer authentication. A deployment-pinned
`ActionApprovalBatchInputAuthority` verifies the complete batch before and inside each journal
mutation. The existing per-item `ActionApprovalInputAuthority`, deployment policy registry, and
path-specific Graph writer continue to authenticate and consume the actual execution authority.
For the C1 no-write dispatcher, the aligned `cleanupRequests` tuple contains only null values;
APPROVAL-001C2 defines the separately guarded reversible shape.

## Durable state machine

The journal stores one immutable canonical batch, one row per ordered item, and a content-addressed
append-only event chain. It permits only these transitions:

```text
pending
  -> claim-started
  -> dispatch-started-outcome-unknown
  -> terminal-succeeded | terminal-failed

pending
  -> cancelled-before-dispatch
```

`claim-started` is written before the Graph approval/Permit transaction. It does not claim that a
Permit or Worker dispatch exists. The coordinator binds the exact durable approval receipt and
Permit before calling the async consumer, then moves the item to
`dispatch-started-outcome-unknown`. A crash or exception never returns the item to pending.

An exact retry of `claim-started` may continue the Graph claim. Once the Graph authority reports an
existing consumption or the journal has reached dispatch-started, retry cannot call the consumer.
This conservatively turns a crash between authorities into manual review rather than duplicate
execution. Exact terminal and cancelled reads remain available after the approval expires.

## Completion, reconciliation, and cancellation

`ActionApprovalBatchCompletion` exact-binds the batch, ordinal, approval, Permit, receipt, outcome,
evidence digest, source, and completion time. `redispatchAuthority=false` is fixed. Worker returns
must use `source=worker-completion`; an unknown outcome can be closed only by a separately supplied
completion with `source=manual-reconciliation`. A deployment-pinned completion authority verifies
the exact record before and inside the terminal mutation.

`ActionApprovalBatchCancellation` names a canonical ordered subset of still-pending items and a
reason digest. Its deployment authority is verified before and inside one transaction. If any named
item is already claimed, the entire cancellation rolls back. Claimed or unknown items cannot be
cancelled, reused, or redispatched.

The aggregate publication is derived from all verified item and event records:

- `pending`: every item is pending;
- `active`: pending and terminal items coexist without an unknown claim;
- `manual-review-required`: any item is claim-started or dispatch-started/unknown;
- `terminal-succeeded`: every item succeeded;
- `terminal-partial`: all items are terminal or cancelled, but not all succeeded or all cancelled;
  and
- `cancelled`: every item was cancelled before claim.

## Persistence and trust boundary

`SQLiteActionApprovalBatchJournal` is a distinct host-local coordination journal with schema and
application IDs, a canonical schema digest, immutable batch identity, constrained item transitions,
append-only event rows, `DELETE` journal mode, `synchronous=FULL`, filesystem link checks, and
reopen-time schema/integrity verification.

It is not an approval or Permit ledger and cannot mint or restore execution authority. The Graph
schema remains v4/v1alpha3; APPROVAL-001A/B records and backup formats do not change. The journal
and its input/completion/cancellation verifier implementations are process-local deployment TCB.
Cross-host consensus, journal backup/restore, and durable verifier-code identity are not claimed.

## Fail-closed conditions

- forged batch, completion, cancellation, or event digest;
- batch size outside two through eight or non-exact JSON integer/boolean fields;
- duplicate approval, Proposal, request, or expected Permit identity;
- cross-issuer, Campaign, Run, Envelope, activation, principal, or time-window substitution;
- unauthenticated batch, completion, reconciliation, or cancellation;
- Graph approval/Permit/receipt mismatch or pre-existing foreign consumption;
- cancellation of any claimed item or terminal outcome equivocation;
- malformed, replaced, linked, partially written, or schema-modified journal; and
- callback exception, task cancellation, process crash, or recovery ambiguity.

## Compatibility and rollback

All existing approval, ActionPermit, cleanup, Gateway, Worker, Graph schema, and backup identities
remain unchanged. The new models, journal, dispatcher, and exports are additive direct-call APIs.
Existing single-action and reversible-write paths do not instantiate the batch coordinator.

Rollback removes the coordinator from runtime composition but preserves its journal for audit and
manual adjudication. It must not delete per-item Graph approval/Permit evidence or reinterpret an
unknown state as non-execution.

## Verification

Tests cover strict bounds and duplicate rejection, pinned verifier composition, durable
registration/reopen, batch and terminal post-verifier drift rollback, concurrent claim
serialization, async success and exact non-redispatch, pre-dispatch authority recovery, unknown
Worker outcome and authenticated manual reconciliation, atomic partial cancellation, and direct
SQLite mutation rejection.

## Follow-up

- APPROVAL-001C2 now binds reversible-write batch items to exact cleanup reservations and
  authenticated restored-state evidence without releasing or reusing cleanup capacity.
- APPROVAL-001C3: opt-in General Attack/Control Plane composition with durable operator workflow,
  journal retention/backup, and cancellation delivery.
- Cross-host coordination requires external fencing/consensus and a signed deployment inventory;
  it must not treat this host-local journal as distributed exactly-once authority.
