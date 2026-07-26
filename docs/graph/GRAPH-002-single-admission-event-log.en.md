> Languages: [English](GRAPH-002-single-admission-event-log.en.md) | [한국어](GRAPH-002-single-admission-event-log.ko.md)

# GRAPH-002: Single Admission Authority and Append-only Event Log

- Status: Implemented reference spike, local WIP
- Date: 2026-07-26
- Implementation: `pajin.graph.admission`

## Outcome

GRAPH-002 turns a validated GRAPH-001 Proposal into an append-only admission or rejection event.
Only `GraphAdmissionAuthority` receives the Event Log writer capability. Producers, Specialists,
Agents, and Supervisors remain unprivileged Proposal submitters and cannot assign canonical
CampaignFact validation state or append canonical events directly.

The spike intentionally exposes a storage-neutral `GraphEventLog` contract and an
`InMemoryGraphEventLog` reference implementation. It does not select the durable Graph store.

## Admission pipeline

```text
typed Proposal
  -> parse again at the authority boundary
  -> proposal-ID/digest retry check
  -> registered producer/version/digest/kind check
  -> exact trusted lineage check
  -> canonical node materialization
  -> edge resolution against this attempt or prior admitted nodes
  -> authority-owned append
```

The authority-owned clock assigns event ordering time. Producer time remains provenance only.
Every event records the proposal and lineage digests, Campaign/Run/Agent/Task/request identity,
CapabilityGrant and Capability identity, optional ActionPermit, source-root and evidence bindings,
producer contract, decision, reason, and admitted canonical material.

## Consistency contract

### One writer

The reference Event Log issues one opaque writer capability. A second writer claim, an unclaimed
writer object, or an event whose authority differs from the claimed writer fails closed. This is a
process-local single-writer proof for the spike; a durable deployment still needs database or
service-level leadership fencing.

### Append-only hash chain

Events have a monotonic sequence, previous-event digest, authority-assigned timestamp, canonical
event digest, and content-derived event ID. The Log rejects stale sequence/predecessor values,
duplicate semantic attempts, duplicate event identities, and post-validation object mutation.
Read APIs return deep copies and expose no update or delete operation.

### Retry and equivocation

- same proposal ID + same digest returns the original event with `idempotent=true` and appends
  nothing;
- same proposal ID + different digest appends one `proposal-equivocation` rejection event; and
- an exact retry of that equivocation returns the existing rejection event.

The first recorded digest reserves the proposal ID even when the first attempt was rejected.
Corrected content therefore requires a new proposal ID.

### Trusted producer and lineage

`GraphProducerRegistry` fixes producer ID, version, digest, and allowed Proposal kinds in
application code. Observation and CampaignFact payload producer fields must exactly match the
outer Proposal producer contract.

`TrustedGraphLineageRegistry` is the reference verifier for a source already authenticated by a
sealed-Run adapter. It exact-matches Campaign, Run, Agent, Task, request ID/digest,
CapabilityGrant ID/digest, Capability ID/version/digest, optional ActionPermit ID/digest,
source-root digest, evidence reference/digest, and producer time. Registering different lineage
under the same source identity is rejected as trusted-source equivocation.

### Materialization and edge resolution

- `SurfaceProposal` admits its Surface and permitted discovery edges.
- `HypothesisProposal` admits its registered-producer Hypothesis and exact motivation/enablement
  edges after their source resolves.
- `ObservationProposal` admits the full Action, Observation, Evidence nodes, and typed edges. The
  Action must exactly match request, Capability, and execution-authority lineage.
- `CampaignFactProposal` materializes a canonical CampaignFact with
  `validation_state=admitted`; the producer cannot provide that state.

Each edge endpoint must resolve to a node admitted in the same attempt or an exact node already in
the Event Log. Dangling edges are rejected and audited.

## Verified negative contract

The GRAPH-001/002 tests cover:

- mutated Proposal revalidation and canonical identity tampering;
- unknown producer, version/digest mismatch, kind denial, and payload-producer mismatch;
- foreign Campaign and unregistered or equivocated trusted lineage;
- incomplete Action/request/Capability/authority bindings;
- dangling edges;
- exact retry and same-ID/different-digest equivocation;
- rejected-event material injection and event-digest mutation;
- stale sequence/predecessor append;
- invalid or second writer capability; and
- caller mutation of Event Log read copies.

## Deliberate boundaries

This spike does not implement:

- a durable RunStore or separate Graph Store adapter;
- cross-process leader election, database transaction/CAS, or crash recovery;
- durable Graph Projection/Snapshot storage or snapshot-bound decisions;
- semantic duplicate folding, contradiction state transitions, or stale-decision handling;
- live adapters from sealed Run, Scope, Capability Registry, or legacy A5 artifacts; or
- Supervisor scheduling and B2.9 fact/snapshot/handoff projections.

RunStore already demonstrates private append, locking, hash chaining, and sealed integrity, but it
is scoped to one Run. A separate Graph Store could better own Campaign-wide revision and
projection transactions. The `GraphEventLog` protocol keeps both options open until durable
adapter measurements and conformance tests exist.

## Next step

[GRAPH-003](GRAPH-003-projection-revision-immutable-snapshot.en.md) now implements the in-memory
reference Projection, revision/head compare-and-set, and immutable Snapshot chain rebuilt from the
complete admission/rejection Event Log.
[GRAPH-004](GRAPH-004-consistency-recovery-stale-decision.en.md) now exercises duplicate and
contradiction semantics, concurrent admission/projection, recoverable projection lag, and
stale-decision preflight. Durable transaction and crash boundaries remain open.
