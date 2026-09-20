# ADR-0314: Pin Specialist Permit Dispatch to One Deployment and Record Grant Consumption

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003C3B2 specialist Permit deployment authority and Grant-consumption proof
- Implementation status: Implemented in the local working tree

## Context

ADR-0313 correctly places the specialist execution crash fence inside the one-winning approved-
Permit callback. Its first implementation nevertheless left two authority ambiguities. The binder
accepted a concrete Graph Store and a ready-made signed-approval verifier from its caller, so an
object that opened the same database path or a self-selected signing key could appear structurally
compatible without being the deployment owner. It also constructed a one-Capability Graph Permit
writer per plan even though the Permit Store admits one exact approved writer. A later valid plan
could therefore conflict with the writer sealed by the first plan.

ADR-0313 also records the child Grant identity but deliberately leaves Grant consumption without a
durable receipt. A successful crash-fence row proves callback entry, while a failed coordination
transaction can burn the process-local Ledger budget without leaving durable proof of that burn.
The successful state needs a narrowly scoped receipt without claiming that the in-memory Ledger
and either SQLite database participate in one transaction.

## Decision

### Own the Permit trust root at deployment construction

An `AgenticCoordinationStore` configured for specialist dispatch receives one deployment inventory
at construction time. The Graph Store, Ledger, and key ring are all-or-none inputs; the approval
clock is explicit or defaults to the Store clock:

- the exact concrete `SQLiteGraphStore` already used by the current-head resolver;
- that object's exact `SQLiteGraphActionPermitStore`;
- the exact live `CapabilityLedger`, including its record inventory, lock, clock, and depth policy;
- an immutable ACTION_APPROVER verification-key ring; and
- the approval-verification clock.

The resulting process-local deployment authority retains exact object and runtime-file identity.
Opening the same path through another `SQLiteGraphStore` is not equivalent and is rejected. Plan
creation and Permit binding must use the pinned Ledger object; a structurally equal replacement is
not authority.

The deployment and approval trust-root handles are immutable, non-copyable, and non-serializable.
The coordination Store, every plan handle, and every bound dispatcher independently capture the
exact deployment runtime identity rather than trusting the deployment object's current fields. That
identity includes the Graph and Permit Store objects, Graph file identity, Ledger object and
record/lock/clock/depth internals, approval authority, key-ring mapping and recomputed digest,
approval clock/lock/registry objects, and deployment lock. The runtime pins the unbound approval
registry methods as well. Replacing internal fields, even with same-path or equal-content objects,
therefore fails before approval, Permit, or Grant consumption.

The process-local `VerifiedSpecialistDispatchPlan` captures that exact deployment object when the
plan is created. Permit binding cannot transfer the plan to a different deployment with equal
serialized inputs.

The public Permit binder accepts the exact `SignedWebActionApproval`, not a caller-created
`WebActionApprovalInputAuthority`, Graph Store, Permit Store, policy, writer, or dispatcher. The
deployment key ring verifies that the artifact has the `source` role, names a trusted key, and
matches the plan's exact approval envelope before registering its internal verifier. A self-signed
artifact under an unregistered key fails before Permit or Grant consumption.

The deployment seals one complete registry containing all three exact specialist Capabilities,
one complete read-only approval-policy registry, one compiler identity, one
`GraphApprovedActionPermitAuthority`, and one `GraphApprovedActionPermitDispatcher`. Every valid
specialist plan reuses that shared writer. Per-plan approval verification remains exact, but no
plan can replace the Permit Store writer or narrow it to a competing one-Capability registry. A
repeated bind of the same exact signed approval returns the deployment's existing canonical
verifier rather than installing a second object under the same approval identity.

The first bind also pins the shared `GraphApprovedActionPermitAuthority` clock and the code-owned
30-second Permit TTL. Later plans must reuse that exact clock and TTL; reflective replacement is
rejected before Permit consumption.

The plan-bound started handle performs its one-use transition under an internal lock. Concurrent
consumers can therefore obtain at most one successful transfer into the future C3C boundary.

### Persist an exact successful Grant-consumption receipt

Advance the local pre-release coordination schema to version 5 and add a content-addressed
`AgenticSpecialistCapabilityGrantConsumptionReceipt` to the successful specialist plan state. The
receipt API is `pajin.dev/agentic-specialist-capability-grant-consumption-receipt/v1alpha1`. It
binds the coordination Store and deployment binding, plan, reservation, command, child Grant,
ActionPermit, approval-consumption receipt, exact one-call consumption, and consumption timestamp.
Its identity is derived under the dedicated
`pajin.agentic.specialist-capability-grant-consumption-receipt/v1` digest domain.

Inside the one-winning callback, while holding the coordination write transaction and the exact
Ledger lock, the Store snapshots the child Grant and its ancestor lineage, consumes the child
call, then proves that every same Grant record remains unrevoked and has decreased by exactly one
call. It constructs the specialist Grant-consumption receipt and compare-and-swaps that receipt,
the Permit and approval receipt, the plan state, and the specialist execution state. A durable
`dispatch-started-outcome-unknown` plan must contain the exact receipt; an `awaiting-permit` or
`permit-consumed-entry-unknown` plan must not contain one.

The successful state also fixes one causal chain:

```text
plan.plannedAt <= permit.issuedAt <= permit.consumedAt
               <= callbackEnteredAt <= grantReceipt.consumedAt
```

A clock-rewound Permit that predates the plan can be retained only as conservative terminal Permit
evidence. It cannot consume the Grant, create a Grant receipt, or enter the dispatch-started state.

The receipt proves only the observed Ledger transition that preceded the successful coordination
commit for the bound child Grant. The callback verifies the ancestor decrements while holding the
Ledger lock, but the receipt does not enumerate or independently attest every ancestor record. It
does not make the process-local Ledger transactional with the Graph or coordination database,
authorize a Gateway or Worker, or allow a consumed Grant to be reconstructed after restart.

### Preserve conservative crash semantics

The Graph approval/Permit transaction, process-local Ledger mutation, and coordination transaction
remain three separate failure domains. If the Ledger call is consumed and the coordination
transaction rolls back, no durable specialist Grant-consumption receipt is published, but the
child and ancestor budgets remain burned. The runtime never refunds, recredits, or retries them.

If exact terminal Permit evidence exists without durable callback entry, reconciliation may record
only `permit-consumed-entry-unknown`; it cannot invent a Grant receipt or started handle. A hard
process failure can still leave an `awaiting-permit` audit row beside terminal Graph authorization.
Reopen remains audit-only: it recreates no Ledger, plan handle, Permit dispatcher, Grant receipt
authority, or started handle, and performs no automatic reconciliation, refund, reissue, or
redispatch.

This decision supersedes ADR-0313 only where that ADR accepts caller-supplied Graph/verifier
objects, constructs per-plan Permit authority, leaves started-handle consumption without an atomic
lock, and states that schema version 4 has no durable Grant-consumption receipt. ADR-0313's
callback ordering, cross-store non-atomicity, no-refund rule, outcome-unknown recovery semantics,
and no-I/O boundary remain in force.

## Consequences

### Positive

- The Graph Store, Permit Store, Ledger, approval key ring, Capability inventory, policy, compiler,
  and writer form one explicit process-local deployment trust root.
- Same-path wrappers, foreign self-signed approvals, caller-built verifiers, and competing Permit
  writers cannot enter specialist dispatch.
- Multiple valid plans can reuse one complete deployment writer while retaining exact per-plan
  approval verification.
- Successful callback entry carries exact durable proof for the child Grant only after the runtime
  has verified each locked ancestor's one-call decrease; the ancestor snapshots themselves are not
  persisted.
- Started-handle transfer is an atomic one-shot operation under concurrency.

### Tradeoffs and residual risks

- The deployment trust root and Ledger remain process-local and are not reconstructed from audit
  rows after restart.
- The receipt cannot prove a Ledger burn when the subsequent coordination transaction fails.
- The three failure domains still do not provide two-phase commit; availability and budget are
  sacrificed rather than risking duplicate execution.
- The deployment currently seals one compiler identity and one complete specialist Capability
  inventory. Changing either requires a new deployment composition rather than an in-place writer
  replacement.
- C3B2 still performs no Gateway, Worker, browser, network, or Target I/O and creates no Evidence,
  Finding, Canonical Graph admission, report, SARIF, PoC, or delivery artifact.

## Compatibility, migration, and rollback

The public Campaign, Capability, Permit, Gateway, Worker, Finding, and Graph APIs are unchanged.
Specialist deployment inputs are additive and opt-in; the Graph Store, Ledger, and approval key
ring must be supplied together, while the approval clock may use the Store default. The Permit
binder intentionally stops accepting a caller-selected Graph Store or approval-verifier object.

Schema version 5 is a strict local pre-release schema. Version-4 and older draft Stores are
rejected rather than silently upgraded, downgraded, or interpreted as having Grant-consumption
proof. They may be retained as audit evidence or recreated from original immutable inputs; they
must not be migrated into new bearer authority.

Rollback disables the deployment-bound binder and schema-version-5 callback path. It must not
delete or rewind either durable row, remove a published receipt, refund any child or ancestor
budget, revoke a committed approval or Permit, replace the shared writer, or recreate a process-
local handle. No Target-side rollback is required because this slice performs no Target I/O.

## Rejected alternatives

### Trust any Graph Store that opens the same database path

Rejected because a path is a mutable alias and does not prove ownership of the resolver, Permit
Store, open file, or approved writer.

### Accept a caller-created signed-approval verifier

Rejected because a caller could choose both the verification key and the artifact it signs. The
deployment must own the key ring and accept only the signed artifact as data.

### Create one Permit writer per specialist plan

Rejected because the Permit Store has one approved-writer boundary and later valid plans would
either conflict with or replace the first plan's authority. One complete deployment registry is
the correct writer scope.

### Publish a Grant receipt before consuming the Ledger

Rejected because intent is not consumption. The receipt is created only after exact before/after
lineage comparison and is committed with the successful crash fence.

### Refund a consumed Grant when receipt persistence fails

Rejected because callback outcome is uncertain and restored authority could repeat an action.

### Reconstruct a receipt or handle from terminal audit rows after restart

Rejected because serialized rows do not restore the exact Ledger, one-use process ownership, or
deployment runtime identities.

## Related documents

- [ADR-0313: Enter the Specialist Dispatch Crash Fence inside the Approved-Permit Callback](0313-enter-specialist-dispatch-crash-fence-inside-approved-permit-callback.md)
- [ADR-0312: Transfer Specialist Reservations into Durable Awaiting-Permit Plans](0312-transfer-specialist-reservations-into-durable-awaiting-permit-plans.md)
- [ADR-0311: Define and Activate Exact Specialist Capabilities without Dispatch Authority](0311-define-and-activate-exact-specialist-capabilities-without-dispatch-authority.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
