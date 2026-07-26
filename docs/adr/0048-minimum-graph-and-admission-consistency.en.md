> Languages: [English](0048-minimum-graph-and-admission-consistency.en.md) | [한국어](0048-minimum-graph-and-admission-consistency.ko.md)

# ADR-0048: Minimum Graph and Admission Consistency

- Status: Accepted
- Date: 2026-07-26

## Context

The existing `TaskGraph` models execution dependencies, while A5 `ObservationGraphSnapshot` models
limited follow-up replanning. Architecture v2 needs canonical campaign state shared across
Specialists and surfaces with deterministic provenance, duplicate, contradiction, concurrency,
and stale-decision semantics. Direct mutation of a shared dictionary or free-form memory would
introduce last-write-wins behavior, authority ambiguity, and irreproducible planning.

## Decision

### 1. Minimum vocabulary

Canonical nodes are `Surface`, `Hypothesis`, `Action`, `Observation`, `Evidence`, and
`CampaignFact`.

Canonical edges are:

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports/contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

A new node or edge kind requires a schema version and benchmark evidence in a separate change.

### 2. Single write authority

Specialists and Supervisors submit typed `ObservationProposal`, `SurfaceProposal`, and
`CampaignFactProposal` values. Only the `GraphAdmissionAuthority` consuming the Admission Queue can
validate them and append admission/rejection events to the Canonical Event Log. Graph Projections
and Snapshots derive only from that log.

### 3. Proposal binding

Each proposal's canonical digest includes:

- schema and proposal kind/ID;
- campaign, run, agent, and task identity;
- source request/action and Capability/Permit identity;
- node/edge payload;
- evidence reference and digest; and
- metadata needed for authority-assigned admission ordering.

An untrusted producer timestamp may be provenance but is not canonical-order authority.

### 4. Consistency

- Re-submitting the same proposal ID and digest is idempotent and creates no new semantic event.
- Reusing an ID with another digest is rejected and audited as equivocation.
- Separate proposals with equal content retain provenance. A deterministic dedup relation may
  connect them, but no prior event is deleted.
- Contradictory Observations and CampaignFacts coexist with their validation state and lineage.
  Silent overwrite and last-write-wins are forbidden.
- One admission transaction compare-and-sets the previous revision and atomically advances event
  sequence, projection revision, and digest.
- Projection revision cannot advance after a partial event write or without an event.

### 5. Immutable snapshot and stale decisions

A Checkpoint Snapshot is immutable and includes campaign ID, graph schema, revision, event-log head
digest, canonical node/edge projection digest, and creation reason. Every Planner/Supervisor
decision binds exact snapshot ID, revision, and digest. A changed current revision before dispatch
requires revalidation and a new decision/Permit or denial.

### 6. Existing-data migration

A trusted adapter may convert existing `SurfaceObservation`, `AttackSurfaceSet`, A5
`ObservationGraphSnapshot`, and sealed Artifacts into proposals. It preserves the original digest
and legacy schema as provenance; adapter output is not automatically admitted.

B2.9 facts/snapshot/handoff are Event-Log projections. Free-form memory is never canonical
authority.

## Storage choice

This ADR does not decide whether the first Event Store lives in the existing RunStore or a separate
Graph module. Every implementation must pass shared conformance tests for ordering, idempotency,
equivocation, contradiction, atomic revision, and snapshots. A later decision uses spike metrics
and rollback cost to choose storage.

## Required negative tests

- duplicate exact retry and same-ID/different-digest equivocation;
- contradiction coexistence and silent-overwrite rejection;
- foreign campaign/run/evidence lineage;
- evidence-digest or registered-producer mismatch;
- concurrent admission race and revision-CAS failure;
- event/projection partial-write recovery; and
- stale snapshot decision and graph change before dispatch.

## Consequences

Agents can share admitted facts and snapshots, and every state change is reconstructable from
events. A single-writer admission bottleneck and projection operations add cost. Optimization uses
batching, partitioning, and read models without weakening semantic consistency.

## Implementation status

[GRAPH-002](../graph/GRAPH-002-single-admission-event-log.en.md) implements the process-local
single writer, append-only hash chain, registered producer and exact lineage gate, retry,
equivocation, materialization, and dangling-edge checks.
[GRAPH-003](../graph/GRAPH-003-projection-revision-immutable-snapshot.en.md) implements
deterministic exact-prefix projection, atomic process-local revision/head CAS, content-addressed
Snapshot chaining, and exact Snapshot reference resolution.
[GRAPH-004](../graph/GRAPH-004-consistency-recovery-stale-decision.en.md) implements the missing
Hypothesis admission path, duplicate/contradiction analysis, concurrent admission and projection
CAS tests, bounded lag reconciliation, and exact Snapshot-bound stale-decision preflight. Durable
cross-process CAS/crash recovery and atomic preflight plus ActionPermit issuance remain open.

## Related documents

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.en.md)
- [ADR-0046: Common Engine and Campaign Profiles](0046-common-engine-and-campaign-profiles.en.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.en.md)
