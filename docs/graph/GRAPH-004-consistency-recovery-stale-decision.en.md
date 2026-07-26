> Languages: [English](GRAPH-004-consistency-recovery-stale-decision.en.md) | [한국어](GRAPH-004-consistency-recovery-stale-decision.ko.md)

# GRAPH-004: Consistency, Recovery, and Stale Decision

- Status: Implemented reference conformance slice, locally verified; Linux CI pending
- Date: 2026-07-26
- Implementation: `pajin.graph.consistency`, `pajin.graph.admission`
- Tests: `tests/test_graph_consistency.py`

## Outcome

GRAPH-004 exercises the process-local consistency boundaries established by GRAPH-001 through
GRAPH-003. It adds a real Hypothesis admission path, deterministic duplicate/contradiction
analysis, bounded projection reconciliation, and an exact Snapshot-bound decision preflight.

This slice deliberately does not claim durable crash recovery or a cross-process dispatch
transaction. It supplies the reference semantics and negative tests that a durable Graph Store
adapter must preserve.

## Reachable contradiction vocabulary

The minimum vocabulary already contained `Hypothesis`, `supports`, and `contradicts`, but the first
three Proposal types could not admit a Hypothesis. `HypothesisProposal` closes that unreachable
path:

```text
admitted Surface or Observation
  -> Surface motivates Hypothesis
     or Observation enables Hypothesis
  -> registered Hypothesis producer and exact lineage
  -> single Admission Authority
  -> Hypothesis admission event
```

The Hypothesis producer ID/version/digest must match the outer Proposal. Every edge must target
that exact Hypothesis and resolve against a node admitted in the same Campaign. A dangling
motivation is rejected.

An `ObservationProposal` may support or contradict a Hypothesis, but one Observation cannot claim
both positions against the same Hypothesis. Distinct Observations can disagree.

## Duplicate and contradiction semantics

`GraphConsistencyAnalyzer` revalidates the exact Event Log and requires it to reproduce the
provided projection before analysis.

- Same Proposal ID and digest remains an idempotent retry with one Event.
- Same Proposal ID and another digest serializes into one recorded winner and one audited
  `proposal-equivocation` rejection; no material is overwritten.
- Different Proposal IDs with the same canonical node retain both admission Events. Projection
  material remains deduplicated by canonical identity, while
  `duplicateNodeOccurrenceCount`/`duplicateEdgeOccurrenceCount` expose the retained occurrences.
- Hypothesis state is derived, never assigned or mutated:

```text
no position                 -> open
support only                -> supported
contradiction only          -> contradicted
distinct support + conflict -> contested
```

Supporting and contradicting Observation IDs remain sorted in the content-addressed
`GraphConsistencyView`. A contested state never deletes a prior Observation, Edge, or Event.

## Concurrent admission and projection

The reference admission authority continues to serialize Proposal submission under its
single-writer lock. Conformance tests start exact retry and same-ID/different-content calls from
separate threads and require a contiguous Event Log hash chain with no lost update.

Projection publication remains revision/head compare-and-set. Concurrent reconcilers may race;
one publishes and the other retries from the new revision. Bounded retry exhaustion fails closed.

## Partial-write reconciliation

`GraphProjectionReconciler` handles the recoverable process-local case where an Event append
succeeded but projection publication did not run or lost a CAS race.

1. Capture current projection and authoritative Event Log.
2. Reject a projection ahead of the Event Log.
3. Rebuild the Event Log prefix through current revision and require an exact projection digest.
4. If lagging, publish the complete captured prefix with revision/head CAS.
5. Retry a bounded number of CAS conflicts.

An exact current state returns `in-sync`; a repaired lag returns `recovered` with the count of
replayed Events. A divergent projection is never replaced silently.

This reference algorithm is replay recovery, not durable two-store crash atomicity.
[GRAPH-005](GRAPH-005-durable-sqlite-graph-store.en.md) now applies it to a separate
single-Campaign SQLite store with cross-process host-local CAS and reopen persistence. Multi-host
leadership, process-kill fsync fault injection, and verified backup restore remain open.

## Snapshot-bound stale decision preflight

`GraphDecision` is a non-executable, content-addressed record binding:

- Campaign and decision kind;
- opaque decision-payload digest;
- exact `GraphSnapshotRef`;
- actor ID/digest; and
- UTC creation time.

`GraphDecisionGuard.validate_for_dispatch()`:

1. revalidates the Decision identity;
2. exact-resolves its immutable Snapshot;
3. rebuilds the latest projection directly from the Event Log;
4. rejects when the published projection needs recovery; and
5. rejects when Snapshot revision/head/projection identity is no longer latest.

Success returns `GraphDecisionPreflight`, an audit-only check record. It is explicitly not an
ActionPermit and grants no execution authority.

The reference guard catches graph changes already present before the check, including Events not
yet projected. It cannot close the race after preflight and before an external Worker dispatch.
The durable adapter and deterministic ActionPermit compiler must perform this comparison inside
their dispatch transaction or recheck it at the final authority boundary.

## Verified negative contract

The combined focused suite now passes 46 tests locally, including:

- unresolved Hypothesis motivation and Hypothesis producer mismatch;
- one Observation claiming both support and contradiction;
- duplicate provenance with canonical projection folding;
- `open -> supported -> contested` deterministic state;
- concurrent exact retry and same-ID/different-digest admission;
- concurrent projection reconciliation with CAS retry;
- lag recovery, idempotent reconciliation, and divergent-prefix rejection;
- stale Decision while Event Log is ahead of projection;
- stale Decision after projection catches up; and
- Decision identity tampering.

## Remaining boundary

GRAPH-005 closes the first durable Event/Projection/Snapshot adapter and host-local CAS boundary.
The following remain open:

- multi-host leader fencing, lease expiry, and PostgreSQL/HA storage;
- process-kill/fault-injection testing across fsync boundaries;
- atomic preflight plus ActionPermit issuance/consumption;
- semantic CampaignFact corroboration/invalidation workflows;
- retention, compaction, backup, restore, and external integrity anchoring; and
- live sealed-Run/Scope/Capability adapters, B2.9 Handoff projections, and Supervisor execution.

Runtime dispatch integration remains a separate trust-boundary change and must recheck the latest
durable revision inside ActionPermit issuance/consumption rather than trusting a prior preflight.
