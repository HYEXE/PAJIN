# ADR-0313: Enter the Specialist Dispatch Crash Fence inside the Approved-Permit Callback

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003C3B2 approved specialist callback and durable crash fence
- Implementation status: Implemented in the local working tree

## Context

ADR-0312 transfers one live specialist reservation into a durable `awaiting-permit` plan and a
process-local `VerifiedSpecialistDispatchPlan`. That plan binds the exact Campaign, preparation,
Capability action, child Grant, approval tuple, and expected Permit, but it deliberately does not
authenticate the approval, consume a Permit or Grant call, or enter specialist execution.

The remaining transition crosses two independent authorities. The Graph Store owns signed approval
verification, current-Graph and budget checks, and atomic approval-plus-Permit consumption. The
descriptor-bound agentic coordination Store owns the specialist plan and execution rows. Those two
SQLite databases do not share a transaction. Treating a Permit object, approval receipt, or legacy
execution row as transferable authority would either permit substitution or hide the crash window
between the Graph commit and the coordination callback.

The callback also needs the exact live `CapabilityLedger`. Its in-memory call accounting cannot be
rolled back with a failed coordination transaction. The implementation therefore needs a
fail-closed ordering that may conservatively burn a Grant but can never refund authority or repeat
an uncertain action.

## Decision

Implement AGENTIC-003C3B2 as a direct-call, pre-Target boundary on the existing schema-version-4
dispatch plan.

`AgenticCoordinationStore.bind_specialist_permit_dispatcher()` accepts the original live plan
handle and exact C3B1 inputs plus the concrete `SQLiteGraphStore` and one
`WebActionApprovalInputAuthority` in the `source` role. Binding verifies the signed source approval,
requires the mutable Graph Store to be the same physical database pinned by the current-head
resolver, and builds the exact `ActionCapabilityRegistry`, read-only approval policy,
`GraphApprovedActionPermitAuthority`, and `GraphApprovedActionPermitDispatcher` internally. The
returned `VerifiedSpecialistPermitDispatcher` pins those object identities, their unmodified
implementations, the underlying `SQLiteGraphActionPermitStore`, the live Ledger and Grant, and the
plan identity. The caller cannot supply a Permit callback tuple or a substitute dispatcher.

Binding does not consume approval, Permit, or Capability budget. Before dispatch,
`dispatch_specialist_permit_once()` revalidates the current Graph and durable heads, complete
history, awaiting plan and reserved execution row, Campaign, preparation, activation, prepared
action, current profile and executor catalogs, signed source approval, concrete Graph Store, and
live one-call child Grant. It then claims the process-local plan callback so concurrent callers
cannot enter it together.

The exact `GraphApprovedActionPermitDispatcher` remains the one-winning authority. Its Graph Store
transaction authenticates the signed approval, rechecks the current Graph Decision and budgets,
and commits the approval, single-use `ActionPermit`, and non-reusable approval-consumption receipt
before invoking the callback. An exact terminal retry does not invoke the callback again.

Inside the first callback, the coordination Store strictly reloads and compares the Permit and
receipt with the plan, repeats every current-state check, and holds both its write transaction and
the live Ledger lock. It requires the exact child Grant and its lineage to remain consumable,
consumes that Grant call, and then compare-and-swaps both durable rows in the same coordination
transaction:

```text
dispatch plan:        awaiting-permit -> dispatch-started-outcome-unknown
specialist execution: reserved        -> dispatch-started-outcome-unknown
```

Both rows use the same callback timestamp, which must be at or after Permit consumption and before
Permit expiry. The child and ancestor Capability call budgets are consumed before the two row
updates. A failed second row update rolls back both database rows, but Capability budget is not
refunded. After commit and strict reload, the callback returns a non-copyable, non-serializable,
store-local `VerifiedPlannedSpecialistDispatchStarted` that binds the plan, execution row, Permit,
and approval receipt. The original plan handle is then consumed. This new handle is only proof of
the C3B2 crash fence; it is not a Gateway, Worker, Target, Finding, or Graph-admission bearer.

The legacy `begin_specialist_dispatch()` and `VerifiedSpecialistDispatchStarted` are not used by
this path. Updating the legacy execution row first and the plan later would admit a split state and
is forbidden.

## Cross-store reconciliation and recovery

The Graph approval transaction and the coordination transaction are intentionally not described as
atomic together. If dispatch raises after the Graph Store may have committed, the sealed runtime
performs an exact read-only `approved_authorization()` lookup against its pinned Permit Store. A
caller-supplied Permit or receipt is never accepted for reconciliation.

When the lookup proves the exact planned approval, Permit, and receipt but durable callback entry
is absent, the coordination Store advances only the plan:

```text
dispatch plan:        awaiting-permit -> permit-consumed-entry-unknown
specialist execution: reserved        -> reserved
```

The reconciled row records the exact Permit and receipt, leaves `callbackEnteredAt` absent, records
`reconciledAt`, returns no started handle, and grants no execution inference. If both crash-fence
rows already committed, reconciliation only verifies their equality and still does not reissue the
lost handle. If no terminal authorization exists, the in-process callback claim is released and
the pre-consumption error is propagated; there is no automatic retry loop.

`permit-consumed-entry-unknown` proves only terminal Permit consumption and the absence of durable
callback-entry proof. It does not prove whether the in-memory Grant call was consumed. The Grant
binding stored in the plan is a planning-time snapshot, not a durable consumption receipt. A
post-Grant coordination failure conservatively burns the live child and ancestor call budget, and
no path refunds it. Durable Grant-outcome proof would require a later schema and an independent
Grant reservation or receipt.

A hard process failure after the Graph commit but before in-process reconciliation can leave an
`awaiting-permit` audit row even though the Permit Store has a terminal authorization. Restart does
not reconstruct the Ledger, plan handle, Permit-dispatcher handle, or started handle, and recovery
does not automatically redispatch. Such a row remains audit-only until a separately designed
authenticated recovery authority can reconcile it; raw persisted values are insufficient.

## Consequences

### Positive

- One signed source approval and one single-use Permit can enter at most one callback.
- The plan and execution rows cannot diverge during successful callback entry.
- The concrete Graph database, Permit writer, signed source verifier, Capability policy, live
  Ledger, child Grant, Campaign, preparation, and code-owned action remain pinned together.
- Exact retry and reconciliation never recreate process-local execution authority.
- A failure after Capability consumption sacrifices availability and budget rather than risking a
  repeated action.

### Tradeoffs and residual risks

- The Graph and coordination Stores remain separate crash domains without two-phase commit.
- The live `CapabilityLedger` remains process-local, and schema version 4 contains no durable Grant
  consumption receipt.
- A crash after the coordination commit but before the started handle reaches its caller leaves
  durable outcome-unknown audit state with no recoverable C3C authority.
- A hard crash in the Graph-commit/callback gap requires future authenticated recovery work; it
  never authorizes automatic retry.
- C3B2 performs no Gateway, Worker, browser, network, or Target I/O and creates no Evidence,
  Finding, Canonical Graph admission, report, SARIF, PoC, or delivery artifact.

## Compatibility, migration, and rollback

C3B2 activates only the terminal states and columns reserved by C3B1. The coordination schema
remains version 4, and the dispatch-plan wire remains
`pajin.dev/agentic-specialist-dispatch-plan/v1alpha1`. Version-3 and older draft Stores remain
strictly rejected; no migration, downgrade, or handle reconstruction is attempted.

Existing version-4 `awaiting-permit` rows do not gain authority on upgrade. They can enter C3B2 only
while their original process-local plan and deployment-bound runtime handles are still live.
Existing terminal rows remain audit-only on reopen.

Rollback removes or disables the C3B2 binding, dispatch, reconciliation, and plan-bound-started
handle paths while retaining the version-4 readers and C3B1 plan records. It must not delete or
rewind either durable row, refund Capability budget, revoke a durable approval receipt, recreate a
Permit, or reissue any process-local handle. No Target-side rollback is required because C3B2
performs no Target I/O.

## Rejected alternatives

### Call the legacy execution transition and update the plan separately

Rejected because a crash between the writes would leave the execution and plan rows in an
impossible split state.

### Treat the plan, Permit, receipt, or legacy started handle as bearer authority

Rejected because serialized values do not prove the concrete Graph Store, signed source verifier,
live Ledger, one-winning callback, or process-local ownership.

### Claim atomicity across the Graph and coordination databases

Rejected because the current architecture has two independent SQLite transactions and no
two-phase-commit authority.

### Refund the Grant or rewind state after a post-consumption failure

Rejected because the action outcome may be uncertain and refunded authority could repeat it.

### Reissue a plan-bound started handle from durable audit state

Rejected because persistence cannot recover process locality, live deployment objects, or unique
ownership of the original callback result.

### Reuse the aggregate Web Gateway or Worker in C3B2

Rejected because C3B2 is only the approval and crash-fence boundary. Specialist-specific dispatch,
Worker provenance, Evidence, and result handling belong to C3C and must consume the distinct
plan-bound started handle.

## Related documents

- [ADR-0312: Transfer Specialist Reservations into Durable Awaiting-Permit Plans](0312-transfer-specialist-reservations-into-durable-awaiting-permit-plans.md)
- [ADR-0311: Define and Activate Exact Specialist Capabilities without Dispatch Authority](0311-define-and-activate-exact-specialist-capabilities-without-dispatch-authority.md)
- [ADR-0310: Bind Specialist Action Preparation without Execution Authority](0310-bind-specialist-action-preparation-without-execution-authority.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
