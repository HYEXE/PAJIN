# ADR-0159: Rank Current Hypotheses without Decision Authority

## Status

Accepted

## Context

UX-002B exposes the exact current Canonical Graph, while GRAPH-004 already derives deterministic
`open`, `supported`, `contradicted`, and `contested` states for every admitted Hypothesis by
replaying the complete Admission Event Log. Operators need a compact review order, but PAJIN has no
general durable repository of complete `GraphDecision` records. Permit stores retain only bound
Decision identities and cannot reconstruct a trustworthy Decision Audit.

Creating a score from UI data would duplicate consistency authority. Treating producer confidence
as truth, selecting a Hypothesis, or presenting Permit references as full Decisions would create
plausible but false authority.

## Decision

UX-003A adds one Operator-only endpoint:

`GET /v1/hypotheses/campaigns/{campaign}/snapshots/{snapshot_id}/attention-ranking`

The reader reuses the UX-002B database identity and complete read-only verification. From the same
verified immutable Event Log input and exact current Snapshot, it invokes the existing
`GraphConsistencyAnalyzer` and requires the resulting consistency view to bind the same Campaign,
revision, Event head, Projection ID, and Projection digest.

The review order is deterministic:

1. canonical state: `contested`, `supported`, `open`, then `contradicted`;
2. producer confidence descending within one state; and
3. canonical Hypothesis node ID ascending as the final tie-breaker.

This is not a composite risk score. Confidence remains producer-supplied metadata and never changes
the canonical consistency state. The response is capped at 500 Hypotheses and is rejected rather
than truncated.

Only redacted review metadata is returned: rank, node identity, Hypothesis type, producer identity,
origin, confidence, canonical state, support and contradiction counts, and a state-derived attention
band. Statements, expected observables, Observation identities or content, Evidence, Actions,
Events, paths, Grants, Permits, and Decisions are excluded.

The response states literally that the Snapshot and consistency view were verified, the order is
deterministic and redacted, and the view cannot select a Hypothesis, record a Decision, schedule
work, or authorize execution. The Web Console validates those invariants and the complete ordering
before rendering with created nodes and `textContent`.

## Consequences

- Operators receive one compact, reproducible review queue from existing Graph authorities.
- A highly confident `open` or `contradicted` Hypothesis cannot outrank a `contested` Hypothesis.
- The GET path remains query-only and cannot initialize, reconcile, snapshot, admit, decide,
  schedule, grant, permit, or execute.
- Decision Audit remains incomplete until a separate authority durably stores and verifies complete
  `GraphDecision` records. That work is UX-003B.
- The single-Campaign database and local service-account trust limits from UX-002B remain unchanged.

## Rejected alternatives

### Compute a composite risk score

Rejected because no accepted authority defines calibrated weights and producer confidence is not
validation truth.

### Select the first ranked Hypothesis automatically

Rejected because review order is not Task, Plan, Decision, Capability, Permit, or execution
authority.

### Reconstruct Decisions from Permit tables

Rejected because those tables retain Decision references, not the complete canonical Decision
material required for an audit record.

### Rank a caller-selected historical Snapshot

Rejected because the product presents current review attention; stale and cross-Campaign Snapshot
substitution must fail closed.

## Compatibility and rollback

The route, DTO, verifier composition, and console panel are additive. No Graph or Control Plane
schema changes and no data migration are required. Omitting the existing Graph database leaves the
authenticated route fail-closed with `503`. Rollback removes the route and panel without modifying
Graph state.

## Related documents

- [GRAPH-004 consistency contract](../graph/GRAPH-004-consistency-recovery-stale-decision.md)
- [UX-002B current Canonical Graph view](../orchestration/UX-002B-current-canonical-graph-view.md)
- [UX-003A contract](../orchestration/UX-003A-canonical-hypothesis-attention-ranking.md)
