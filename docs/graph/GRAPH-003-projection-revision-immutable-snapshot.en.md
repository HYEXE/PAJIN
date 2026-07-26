> Languages: [English](GRAPH-003-projection-revision-immutable-snapshot.en.md) | [한국어](GRAPH-003-projection-revision-immutable-snapshot.ko.md)

# GRAPH-003: Projection, Revision, and Immutable Snapshot

- Status: Implemented reference spike, local commit `c8268e3`, CI pending
- Date: 2026-07-26
- Implementation: `pajin.graph.projection`
- Tests: `tests/test_graph_projection.py`

## Outcome

GRAPH-003 adds a deterministic Canonical Graph read model over the GRAPH-002 Event Log. A
`GraphProjection` identifies one exact Event Log prefix by Campaign, graph schema version,
revision, Event Log head digest, canonical node/edge digests, and a content-derived projection
ID/digest.

`GraphSnapshot` then seals the complete projection into an append-only, content-addressed
checkpoint chain. A decision-safe `GraphSnapshotRef` must exact-match the stored snapshot ID,
digest, Campaign, schema, revision, Event Log head, and projection digest.

## Projection contract

```text
authority-owned Event Log prefix
  -> revalidate every admission/rejection event
  -> verify Campaign, sequence, predecessor, and event digest
  -> materialize admitted nodes and edges only
  -> require unique canonical identities and closed edge endpoints
  -> compute node/edge and whole-projection digests
  -> compare-and-set revision + Event Log head
```

- Revision is the number of events in the exact prefix, including rejection events. A rejection
  advances revision and head for audit fidelity but cannot change node/edge material.
- Exact repeated canonical node or edge material is folded in the read model. Its source events
  remain in the Event Log. The same canonical identity with different material fails closed.
- Projection material is sorted by canonical ID and every edge endpoint must resolve inside that
  exact projection.
- Event `campaignId` is owned by the Admission Authority. An untrusted foreign Proposal Campaign
  is recorded separately as `proposalCampaignId`, so its rejection remains replayable in the
  authority Campaign log.
- Empty genesis is revision `0` with no Event Log head. Every positive revision has an exact head.

## Atomic revision publication

`InMemoryGraphProjectionStore` is the storage-neutral reference implementation of the
`GraphProjectionStore` protocol. It accepts the complete captured Event Log prefix and publishes
the candidate only when:

1. caller `expected_revision` and `expected_head_digest` match current state;
2. the candidate does not roll the revision back; and
3. the candidate prefix through the current revision reconstructs the current projection exactly.

The projection object, revision, head, and digests swap together under one lock. A stale caller,
rollback, or divergent Event Log prefix leaves state unchanged. Replaying the exact current prefix
is idempotent.

The GRAPH-002 Event Log and this reference projection store are still separate in-memory
components. The Event Log may therefore be ahead until `GraphProjectionCoordinator.refresh()`
replays it; the projection cannot publish an event that is absent from its validated prefix.
Cross-store durable transactions and crash recovery remain GRAPH-004 and durable-adapter work.

## Immutable Snapshot contract

`GraphSnapshotAuthority` is the only Snapshot writer. Each snapshot binds:

- Campaign and graph schema version;
- projection revision and Event Log head digest;
- projection ID/digest and node/edge projection digests;
- the complete canonical projection;
- `checkpoint`, `handoff`, `replan`, or `recovery` reason;
- creator ID/digest and authority-owned UTC creation time; and
- previous Snapshot digest.

`InMemoryGraphSnapshotStore` provides one opaque writer capability, append-only predecessor
validation, exact-append idempotency, content-derived snapshot identity, defensive read copies,
and exact reference resolution. Caller mutation of a returned nested model cannot mutate stored
authority; all values are revalidated at the append and resolve boundaries.

## Verified negative contract

The GRAPH-003 tests cover:

- deterministic replay, genesis, exact-prefix idempotency, and canonical duplicate folding;
- rejected-event revision/head advancement without material changes;
- stale compare-and-set, rollback, and divergent-prefix rejection without partial publication;
- mutated, non-contiguous, and foreign-Proposal Campaign events;
- projection identity tampering and dangling edges;
- exact Snapshot-to-projection binding and predecessor chaining;
- invalid/second writer capabilities and stale predecessors;
- tampered Snapshot references; and
- caller mutation of returned Snapshot material.

The combined GRAPH-001/002/003 focused suite currently passes 36 tests locally.

## Deliberate boundaries and next step

GRAPH-003 does not choose a durable database or Event Store, implement cross-process fencing, or
claim an atomic transaction across the Event Log and projection store.

[GRAPH-004](GRAPH-004-consistency-recovery-stale-decision.en.md) now exercises concurrent
admission/projection CAS, duplicate and contradiction semantics, recoverable projection lag,
Snapshot decision staleness, and graph-change-before-dispatch. Durable crash atomicity and atomic
ActionPermit issuance remain separate adapter work.
