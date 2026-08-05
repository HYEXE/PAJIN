# ADR-0132: Pre-reserve Cleanup Capacity Before Reversible Write Dispatch

- Status: Accepted
- Date: 2026-08-05

## Context

ADR-0131 keeps all writes closed until cleanup has a typed request, a separately domain-separated
one-shot Permit, and aggregate budgeting in the existing GRAPH durability domain. Issuing a
CleanupPermit only after a write result is authenticated would account for the cleanup at claim
time, but would not guarantee capacity. Another ordinary Action could consume the remaining
Envelope budget between the write and cleanup claims, leaving an admitted reversible write without
the capacity required to compensate it.

Changing `ActionProposal` or `ActionPermit` would break the established v1alpha2 wire and readers.
A disconnected cleanup store or writer would race the ordinary Action ledger. Reusing the original
ActionPermit would turn historical lineage into a second bearer authority and would bypass fresh
request, Capability, budget, and at-most-once semantics.

## Decision

1. Keep the existing ActionProposal, ActionPermit, ordinary authority/store Protocol, and dispatch
   behavior unchanged.
2. Add a parallel `GraphReversibleActionPermitAuthority` whose final store transaction consumes
   the ordinary ActionPermit and creates an immutable `ActionCleanupReservation` before the write
   callback may run.
3. Require an exact pre-dispatch `ActionCleanupReservationRequest` that binds the source proposal,
   distinct cleanup Capability, unchanged target, Handler and Executor identities, one
   `ActionBudgetReservation`, and a bounded claim deadline inside the Envelope.
4. Aggregate ordinary ActionPermit reservations plus cleanup reservations under the same Envelope
   Tool-call, request-unit, fixed-point cost, and rolling-rate limits. Count a CleanupPermit zero
   additional times because its capacity was already held.
5. Keep an unclaimed hold in the rolling budget until it is consumed. After consumption, move its
   rolling coordinate to CleanupPermit time without double counting. Do not automatically release
   an expired or abandoned hold.
6. Add a content-addressed non-executable `CleanupRequest` and a fully separate
   consumed-on-issuance `CleanupPermit`. The source ActionPermit is exact lineage only.
7. Use the existing Campaign-pinned ActionPermit writer identity and token for cleanup claims. Add
   no cleanup writer table, process-local ledger, or alternate database.
8. Add fingerprinted append-only cleanup reservation and Permit tables in SQLite schema v3. Verify
   exact v1/v2 schemas before destination migration and never fabricate cleanup authority.
9. Emit a new v1alpha2/schema-v3 backup manifest with cleanup count/head bindings. Advance the
   retained statement and detached-manifest outer APIs to v1alpha2 as well. Preserve strict
   historical v1alpha1 outer and low-level readers, signature domain, and AEAD domain without
   reinterpreting the v1alpha1 payload shape; migrate only a verified restored destination.
10. Require `ReversibleActionPermitInputAuthority` and `CleanupPermitInputAuthority` at the two
    public B1 claim boundaries, with no permissive default. The first must authenticate the current
    signed reversible Definition and cleanup mapping. The second must authenticate sealed outcome,
    current Handler/Executor plan, exact request, price, target, and hold. PERMIT-004B2 must supply
    production implementations and restored-state verification.

## Consequences

- A reversible write cannot enter its callback unless both the write claim and cleanup capacity
  are durable under one SQLite commit.
- Ordinary Actions observe outstanding cleanup holds and cannot starve them by consuming the same
  Envelope budget.
- Exact retries and cross-instance races have one Action-plus-hold winner and one CleanupPermit
  winner. Unknown callback outcomes remain consumed and are never automatically replayed.
- Existing Action wire formats and ordinary call sites remain compatible. The database schema and
  backup producer wire advance explicitly.
- Schema v3 is forward-only for code rollback. Older code correctly rejects the unknown schema;
  operators must retain v3-aware recovery tooling and immutable authority history.
- The current production Capability inventory remains no-write. A synthetic reversible-write
  authority test proves store semantics but does not activate a production write path.
- A canonical CleanupRequest does not authenticate its caller-supplied outcome or Handler plan.
  A claim cannot run without an explicitly injected input authority, and production consumers must
  wait for PERMIT-004B2's sealed exact-rebuild implementation and dispatch binding.

## Rejected alternatives

### Charge cleanup only after the write

Rejected because exact accounting at cleanup time does not prevent another Action from starving a
required compensation between the two claims.

### Increase or reset the budget for cleanup

Rejected because a new Envelope, Grant, or Handler-provided price cannot expand the original
Campaign authority after a write.

### Add cleanup fields to ActionProposal or ActionPermit

Rejected because it would silently change established content-addressed identities and public
wire readers. The separate reservation record is additive and binds the unchanged Permit.

### Add a cleanup writer or another SQLite database

Rejected because independently serialized claims could each pass a stale budget view. The same
writer and `BEGIN IMMEDIATE` transaction are required.

### Release an expired hold automatically

Rejected because expiry proves only that automatic cleanup authority is late; it does not prove
that the target is restored or that the reserved capacity is safe to spend elsewhere.

### Treat the CleanupRequest digest as result authentication

Rejected because self-consistent caller material cannot prove the managed Run, terminal lifecycle,
sealed evidence, current Handler output, or restored target state.

## Compatibility, migration, and rollback

ActionProposal, ActionPermit, MissionEnvelope, GraphDecision, and ordinary dispatcher wires remain
unchanged. Exact schema v1 and v2 stores migrate transactionally to v3 with empty cleanup tables.
New v1alpha2 backup and retained-backup manifests bind v3 cleanup state; strict v1alpha1 low-level
and retained-backup wires remain restorable by version-dispatched verification followed by
destination-only migration. No in-place backup-source migration occurs.

Direct downgrade to v2 code is unavailable after v3 creation. Rollback of higher-level consumers
must retain v3 store/restore support and every consumed ActionPermit, reservation, and
CleanupPermit as immutable audit history.

## Related documents

- [PERMIT-004B1 contract](../orchestration/PERMIT-004B1-pre-reserved-one-shot-cleanup-permit.md)
- [ADR-0131](0131-authenticate-sealed-action-results-before-oracle.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [GRAPH-005 contract](../graph/GRAPH-005-durable-sqlite-graph-store.md)
