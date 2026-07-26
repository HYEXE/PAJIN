> Languages: [English](0050-consumed-action-permit-dispatch-claim.en.md) | [한국어](0050-consumed-action-permit-dispatch-claim.ko.md)

# ADR-0050: Consumed-on-Issuance ActionPermit Dispatch Claim

- Status: Accepted
- Date: 2026-07-26

## Context

GRAPH-004 `GraphDecisionPreflight` detects Snapshot-bound stale decisions but is audit-only. A
Graph change between preflight and an external Worker call makes the earlier check unusable as
execution authority. GRAPH-005 persists Events, Projections, and Snapshots in one single-Campaign
SQLite database, allowing the final authority comparison and Permit state change to share a writer
transaction.

An SQLite commit and an external Worker side effect cannot be one physical transaction. Calling the
Worker before commit permits duplicate execution after a process crash. Committing first can leave
an unexecuted but consumed action after a crash. For security-validation actions, omission is the
safer failure than a duplicate side effect.

## Decision

1. Add append-only `graph_action_permit_writers` and `graph_action_permits` tables in Graph Store
   schema v2.
2. Implement canonical, digest-bound immutable `MissionEnvelope`, `ActionProposal`, registered
   Capability, and `ActionPermit` contracts.
3. Always revalidate the latest durable Event Log, Projection, and Snapshot within the same
   `BEGIN IMMEDIATE` transaction that issues a Permit.
4. Calculate budgets/rates and append the Permit inside that transaction.
5. Make every Permit a `status=consumed` non-bearer proof at issuance. Commit is the authoritative
   one-time dispatch-claim point.
6. Derive the Permit ID from exact authority material without clock values. An exact retry resolves
   the stored Permit but receives no new dispatch authority.
7. Let `GraphActionPermitDispatcher` call the Worker callback only for
   `newlyConsumed=true`. Callback failure or uncertain response is terminal and never automatically
   redispatched.
8. Migrate v1 only after verifying its full fingerprint; preserve Events, Projections, and
   Snapshots and never backfill Permit authority.

## Authority and failure semantics

```text
Graph mutation ─┐
                ├─ same SQLite writer serialization
dispatch claim ─┘

COMMIT ActionPermit(consumed)
  -> optional one-time Worker callback
  -> success: result path continues
  -> failure/uncertain: terminal consumed, no automatic retry
```

A Graph change before commit rejects the stale decision. A Graph change after commit is later than
the dispatch claim. This boundary prevents duplicate execution but does not guarantee execution.

## Consequences

- The preflight-to-dispatch race closes at the final authority transaction.
- Only one cross-process exact-retry caller can obtain callback eligibility.
- Response-loss and crash ambiguity retain at-most-once semantics.
- A crash after commit can leave an unexecuted action consumed.
- Tool Gateway wiring, lifecycle events, a durable Capability Registry, and multi-host backends
  remain follow-up work.

## Related documents

- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.en.md)
- [ADR-0049: Durable Single-Campaign SQLite Graph Store](0049-durable-single-campaign-sqlite-graph-store.en.md)
- [GRAPH-006: Atomic ActionPermit Authority](../graph/GRAPH-006-atomic-action-permit-authority.en.md)
