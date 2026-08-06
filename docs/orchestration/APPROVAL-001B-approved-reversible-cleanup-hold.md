# APPROVAL-001B: Atomic Approval and Cleanup Hold for One Reversible Write

- Status: Implemented
- Date: 2026-08-06
- Prerequisites: APPROVAL-001A, PERMIT-004B1, PERMIT-004B2, GRAPH-006, ADR-0135

## Purpose

APPROVAL-001B opens one bounded T2 write path without creating a second execution authority. A
deployment-authenticated single-action approval, the existing consumed `ActionPermit`, its
non-reusable approval receipt, and the existing reversible-action cleanup reservation commit in
one GRAPH SQLite transaction before the Worker callback can run.

This slice supports only `reversible-write + cleanupRequired=true`. It does not admit
`irreversible-write`, T3+, batch, asynchronous claims, or automatic recovery from unknown
outcomes.

## Authority composition

`GraphApprovedReversibleActionPermitAuthority` intersects the existing authorities instead of
duplicating their records or policies:

1. `ActionApprovalEnvelope` exact-binds the Campaign, Run, MissionEnvelope, source intent,
   activation, release, Decision, Proposal, request, target, risk, reservation, expected Permit,
   issuer, principals, time window, `sideEffectClass=reversible-write`, and
   `cleanupRequired=true`.
2. `ActionApprovalInputAuthority` authenticates the exact approval before and inside the durable
   claim.
3. `ReversibleActionPermitInputAuthority` authenticates the current signed source Definition and
   code-owned source-to-cleanup mapping before and inside the durable claim.
4. The pinned full activation policy must name the exact source Capability as
   `reversible-write + cleanupRequired=true`. T2 implies approval; a T0/T1 write may use this path
   only when its Definition explicitly sets `approvalRequired=true`.
5. The ordinary Action and cleanup reservations must fit the same MissionEnvelope aggregate and
   rolling budgets.

The combined path has a distinct non-transferable writer claim. Plain, approved-no-write,
approval-free reversible, cleanup, and generic writer tokens cannot invoke it.

## Atomic durable result

The first successful claim inserts all of the following in one SQLite transaction:

- one existing `ActionApprovalEnvelope` record;
- one unchanged consumed `ActionPermit`;
- one existing `ActionApprovalConsumptionReceipt`; and
- one existing `ActionCleanupReservation` bound to that Permit and dispatch ID.

Any validation, collision, budget, latest-Snapshot, insert, or transaction-internal post-verifier
failure rolls back all four records. GRAPH schema and backup wire versions remain v4/v1alpha3;
APPROVAL-001B adds no new table or record shape.

An exact retry returns the same four-record tuple with `newlyConsumed=false` and never calls the
Worker again, including after the approval time window has expired. A callback failure or unknown
outcome does not restore approval, Permit, or dispatch authority.

Backup verification requires every consumed approval with `cleanupRequired=true` to have the
matching cleanup reservation, and every cleanup-free approval to have none. Partial or substituted
cross-ledger material fails restore verification.

## General Attack integration

The General Attack Permit gate selects this combined authority when the current signed Definition
is reversible-write, cleanup is required, and approval is required by T2 risk or Definition
policy. It exact-binds both deployment providers before the transaction and returns both the
approval receipt and cleanup reservation in `GeneralAttackActionPermitResult`.

The existing authenticated outcome core reloads the durable approval receipt and additionally
cross-checks its side-effect and cleanup flags against the current Definition. PERMIT-004B2 then
uses the pre-action hold, distinct CleanupPermit, sealed cleanup lifecycle, and independent
restored-state verifier unchanged.

The current production Capability inventory remains no-write. The positive vertical slice uses an
isolated synthetic T2 state-write/state-restore fixture. `capability-graph-v1`, Common Engine, and
legacy execution remain write-closed because they do not compose the code-owned cleanup mapping
and reversible input authority required here.

## Fail-closed conditions

- missing or unauthenticated approval or cleanup authority;
- unpaired approval side-effect and cleanup flags;
- cross-Campaign, Run, Envelope, Decision, Proposal, request, target, release, activation,
  Capability, reservation, Permit, or cleanup mapping substitution;
- stale approval, latest-Snapshot drift, policy inventory drift, or provider equivocation;
- T3+, irreversible write, cleanup-free write, or approval that current policy does not require;
- aggregate or rolling budget overflow;
- generic or wrong-path writer use;
- partial durable state, duplicate identity with different bytes, or post-verifier failure; and
- batch, async, lease transfer, partial claim, cancellation, or automatic redispatch.

## Compatibility and rollback

The `ActionProposal`, `ActionPermit`, approval receipt, cleanup reservation, CleanupPermit,
Gateway, Worker, Graph schema, and backup wire identities remain unchanged. The approval envelope
additively permits the paired `reversible-write/cleanupRequired=true` scope; the APPROVAL-001A
no-write authority still rejects it.

Rollback removes the combined runtime composition, not durable evidence. A v4 store containing a
four-record consumption must retain v4 readers and immutable records. Unknown write or cleanup
outcomes require manual adjudication; deleting a hold or replaying the source Action is not a
rollback strategy.

## Verification

Tests cover strict approval scope pairing, four-record commit, exact retry after backup/restore,
single Worker dispatch, generic-writer isolation, cleanup-insert rollback, transaction-internal
post-verifier rollback, T2 General Attack write execution, durable outcome authentication, and the
existing one-shot cleanup/restored-state path.

## Follow-up

- APPROVAL-001C1 now defines the separately versioned bounded no-write batch coordinator,
  partial-claim handling, pending-only cancellation, and unknown-outcome reconciliation.
- APPROVAL-001C2 now binds reversible batch items to exact cleanup reservations and authenticated
  restored-state evidence without duplicating this combined authority.
- A future deployment-security slice may durably bind verifier inventory across process or host
  restart. Existing process-local pins must not be reinterpreted as durable identity.
