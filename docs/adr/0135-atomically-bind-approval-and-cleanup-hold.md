# ADR-0135: Atomically Bind Approval and Cleanup Hold

- Status: Accepted
- Date: 2026-08-06

## Context

APPROVAL-001A consumes one operator approval with an unchanged ActionPermit, but deliberately
supports only no-write actions. PERMIT-004B1 independently consumes one reversible ActionPermit
with a pre-action cleanup reservation. Calling these transactions sequentially for a T2 write
would allow approval without cleanup capacity or cleanup capacity without authenticated approval
after a crash, collision, or verifier failure.

The existing records already contain the necessary exact lineage. A new bearer token, parallel
database, replacement Permit, or schema version would duplicate authority without solving the
atomicity boundary.

## Decision

1. Reuse the existing approval, ActionPermit, receipt, and cleanup-reservation records. Commit all
   four in one GRAPH SQLite transaction under a distinct combined writer claim.
2. Extend `ActionApprovalEnvelope` only to permit the exact paired scope
   `reversible-write + cleanupRequired=true`. Keep the APPROVAL-001A authority explicitly
   restricted to cleanup-free no-write policy.
3. Split common approval and cleanup lineage validation from path-selection policy. The combined
   authority applies both common validators, then enforces reversible cleanup and required
   approval as one policy intersection.
4. Pin both deployment input authorities and their provider identities at writer claim. Verify
   detached canonical inputs before claim, inside the transaction before writes, inside the
   transaction after writes, and once more at the high-level boundary.
5. Preserve exact retry semantics. A durable four-record tuple is terminal and returns no new
   dispatch authority, even after approval expiry.
6. Extend backup logical verification so approval `cleanupRequired` exactly matches the presence
   of a cleanup reservation for the consumed Permit. Keep schema v4/v1alpha3 because no wire or
   table changes are needed.
7. Compose the positive path only in General Attack, where the current signed Definition and
   code-owned cleanup mapping already exist. Keep Control Plane, Common Engine, legacy execution,
   production inventory, T3+, batch, and async write-closed.
8. Reuse PERMIT-004B2 outcome and cleanup execution. Add an exact current-Definition cross-check
   for approval side-effect and cleanup flags before the result can become cleanup source
   authority.

## Consequences

- A T2 reversible write cannot reach its Worker unless approval consumption and cleanup capacity
  are durable together.
- Insert, budget, Snapshot, collision, and transaction-internal verifier failures leave none of
  the four records.
- Existing schema, backup wire, Permit, receipt, cleanup reservation, Gateway, and Worker
  identities remain stable.
- The combined class and store path add code surface, but no duplicate durable authority or policy
  record.
- Process-local verifier pinning remains a deployment TCB limitation. Reopening a database still
  requires trusted code to re-inject the complete policy and verifier inventory.
- APPROVAL-001C remains necessary for batch and asynchronous semantics.

## Rejected alternatives

### Consume approval and cleanup hold in two transactions

Rejected because either ordering admits a partial authority state and ambiguous retry after a
crash or verifier failure.

### Add a new combined durable record

Rejected because the four existing content-addressed records already express the exact lineage.
A fifth authority would duplicate state and require another migration and reconciliation rule.

### Change ActionPermit to embed approval and cleanup

Rejected because the ordinary Permit identity is already shared by GRAPH, Gateway, outcome,
backup, and cleanup paths. The new authority is additive composition, not a replacement Permit.

### Let General Attack call both existing dispatchers

Rejected because high-level sequencing cannot make two independent store transactions atomic.

### Open every T2 write surface

Rejected because only General Attack currently composes the signed Definition, code-owned cleanup
mapping, authenticated outcome, CleanupPermit, and restored-state verifier. Other runtimes remain
closed until they provide the same authorities.

### Treat successful cleanup as permission to redispatch the source write

Rejected because cleanup restores target state, not approval or source Action authority. Exact
retry remains non-dispatching.

## Compatibility and rollback

APPROVAL-001A no-write callers retain their existing path and identity. Approval envelopes with
the new paired scope are additive and are rejected by old no-write composition. Schema v4 remains
forward-only in place. Rollback must preserve consumed approvals, Permits, receipts, and cleanup
holds and must not infer restored state or reusable authority.

## Related documents

- [APPROVAL-001B contract](../orchestration/APPROVAL-001B-approved-reversible-cleanup-hold.md)
- [APPROVAL-001A contract](../orchestration/APPROVAL-001A-single-action-approval.md)
- [PERMIT-004B1 contract](../orchestration/PERMIT-004B1-pre-reserved-one-shot-cleanup-permit.md)
- [PERMIT-004B2 contract](../orchestration/PERMIT-004B2-authenticated-reversible-cleanup-dispatch.md)
- [ADR-0134](0134-consume-single-approval-with-action-permit.md)
- [ADR-0133](0133-authenticate-and-verify-reversible-cleanup.md)
