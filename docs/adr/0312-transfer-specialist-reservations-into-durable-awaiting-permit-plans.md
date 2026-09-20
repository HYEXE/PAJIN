# ADR-0312: Transfer Specialist Reservations into Durable Awaiting-Permit Plans

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003C3B1 durable specialist dispatch planning
- Implementation status: Implemented in the local working tree

## Context

AGENTIC-003C3A can deterministically prepare one exact specialist Capability action, but neither
that action nor the original process-local reservation records the complete approval-to-Permit
handoff. Issuing a Permit before a durable local plan exists would leave no exact reconciliation
record if the Graph transaction commits and the callback is never entered. Conversely, entering
the specialist execution crash fence before approval and Permit consumption would turn ordinary
pre-authorization failure into an outcome-unknown execution.

The durable plan must bind all future callback inputs without claiming that a supplied approval
envelope has already passed signed approval verification. It must also prevent restart, duplicate
planning, or a raw database row from recreating process-local dispatch authority.

## Decision

Add AGENTIC-003C3B1 and advance the local pre-release coordination schema to version 4.

`AgenticCoordinationStore.plan_specialist_dispatch()` accepts the original live
`VerifiedSpecialistExecutionReservation` together with the exact C3A preparation, signed
activation, `PreparedCapabilityAction`, Campaign, live `CapabilityLedger`, one-call child
`CapabilityGrant`, approval envelope, and current verified Graph head. It independently re-runs
the C2 preparation and C3A action compiler, revalidates the current Graph and durable heads, and
requires the exact Campaign, Target, profile, executor, Capability, Tool request, budget, Grant,
proposal, Graph Decision, MissionEnvelope, approval tuple, and expected ActionPermit identity.

The child Grant must be live, unrevoked, non-delegable, exactly T2, limited to one call, one exact
Tool, one exact Target, and the assigned specialist agent and Campaign. Planning records and
uniquely reserves its identity for one plan but does not call `CapabilityLedger.consume()`.

The store inserts one content-addressed `AgenticSpecialistDispatchPlanEntry` in
`awaiting-permit`. The entry keeps approval, Permit, Gateway, Worker, execution, Finding, Graph,
and automatic-redispatch authority literally false. It contains no Permit or approval-consumption
receipt. The supplied approval envelope is an exact planned tuple only; signed approval
verification and Permit consumption remain the responsibility of the later
`GraphApprovedActionPermitDispatcher` boundary.

Planning first commits and reloads the durable plan, then consumes the original process-local
reservation handle and returns one non-copyable, non-serializable, store-local
`VerifiedSpecialistDispatchPlan`. The durable specialist execution row remains `reserved`; only
the process-local authority moves from the reservation handle to the plan handle. A committed plan
row blocks every concurrent legacy transition during the post-commit handoff. Unique constraints
cover the reservation, command, preparation, prepared action, request, Grant, approval, proposal,
and expected Permit identities, so an existing plan is never returned as renewed authority.

Restart and recovery expose awaiting rows as audit state only and never reconstruct the plan
handle. This phase implements plan creation and audit reload only. The schema reserves
`dispatch-started-outcome-unknown` and `permit-consumed-entry-unknown` representations for the
next callback/reconciliation slice, but C3B1 exposes no transition into either state and performs
no approval verification, Permit issuance or consumption, Grant consumption, Gateway, Worker,
browser, network, Target, report, or delivery I/O.

This decision supersedes only ADR-0310's forecast that the original reservation would remain the
direct callback input and that all Grant binding would first occur inside that callback. ADR-0310's
implemented C2 preparation, non-authority, and no-I/O decisions remain unchanged. Grant call
consumption and the execution crash-fence transition still belong inside the future one-winning
Permit callback.

## Consequences

### Positive

- A precise local reconciliation record exists before signed approval verification and Permit
  dispatch can begin.
- One assignment, action, Grant, approval, proposal, and expected Permit can belong to only one
  durable plan.
- The original reservation cannot also enter the legacy dispatch transition after authority has
  moved to the plan handle.
- Restart preserves auditability without reissuing bearer authority or automatically retrying an
  uncertain action.
- Current Campaign, Graph, durable head, lifecycle release, code-owned action, and live Grant are
  checked together before the plan is published.

### Tradeoffs and residual risks

- An invalid, expired, rejected, or never-submitted approval can leave an `awaiting-permit` audit
  row. It cannot execute and is not automatically recycled.
- The Graph and coordination stores remain separate transactions. C3B2 must revalidate both inside
  the one-winning callback and record Permit-consumed uncertainty without redispatch.
- C3B2 must receive deployment-owned opaque Ledger/Grant and Graph dispatcher/Permit-store
  authority; the caller-supplied objects structurally captured by a C3B1 plan are not sufficient
  proof of deployment ownership.
- The live CapabilityLedger remains process-local. Restart preserves the Grant binding as audit
  material but does not recreate ledger or plan-handle authority.
- A crash after the durable commit but before the new handle is returned leaves an audit-only
  awaiting plan and reduces availability; neither the prior reservation nor a new plan handle is
  reissued automatically.
- Gateway/Worker execution, independent Evidence and Replay, Finding promotion, Graph admission,
  report, SARIF, and PoC projection are still unavailable.

## Compatibility, migration, and rollback

The public Campaign, Capability, Permit, Gateway, Worker, Finding, and Graph APIs are unchanged.
The plan API and table are additive to the local pre-release runtime, but schema version 4
intentionally rejects version-3 and older draft stores rather than guessing a migration. Existing
draft stores must be retained only as audit evidence or recreated from original immutable inputs;
they must not be silently upgraded or downgraded.

Rollback removes the dispatch-plan table, state model, store methods, opaque handle, and tests and
restores the prior code schema. A version-4 draft store cannot be opened by the older runtime. No
Target-side rollback is required because C3B1 performs no Target I/O.

## Rejected alternatives

### Create the durable plan only after Permit consumption

Rejected because a committed Permit followed by a missed callback would lack an exact local plan
for authenticated reconciliation.

### Begin specialist execution while waiting for approval

Rejected because approval rejection or expiry would become an outcome-unknown execution even
though no Target I/O was authorized.

### Keep both the original reservation and a plan handle live

Rejected because two process-local paths could race to enter one specialist execution.

### Reissue a plan handle from an awaiting database row after restart

Rejected because serialized audit state cannot prove process locality, one-use ownership, or a
still-live CapabilityLedger.

### Treat the approval envelope as already signed and consumed

Rejected because structural equality to the prepared action does not replace the configured
approval verifier, replay protection, or one-winning Permit transaction.

## Related documents

- [ADR-0311: Define and Activate Exact Specialist Capabilities without Dispatch Authority](0311-define-and-activate-exact-specialist-capabilities-without-dispatch-authority.md)
- [ADR-0310: Bind Specialist Action Preparation without Execution Authority](0310-bind-specialist-action-preparation-without-execution-authority.md)
- [ADR-0309: Reserve Receiver-Acknowledged Specialist Assignments before Dispatch](0309-reserve-receiver-acknowledged-specialist-assignments-before-dispatch.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
