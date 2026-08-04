# HANDOFF-003: Bounded Urgent Observation Fast Gate

- Status: Implemented additive authority
- Date: 2026-08-04
- API: `pajin.dev/urgent-observation-fast-gate/v1alpha1`
- Implementation: `pajin.collaboration.urgent_observation`

## Outcome

HANDOFF-003 admits one metadata-only `stop-and-escalate` decision when a HANDOFF-002 terminal
result is supported by one urgent Observation already present in the exact same current Canonical
Graph Snapshot. It reuses Graph Observation membership, MEM-002 Artifact identity, MEM-003 current
Snapshot verification, and HANDOFF-001/002 lineage. It creates no Observation store, message bus,
replanner, scheduler, Capability, Permit, or execution path.

The decision is `admitted-not-applied`: it is an authority record for a downstream enforcement
point, not proof that an Agent or Worker has already stopped. `autonomousExecutionAllowed` and all
execution authority flags are false.

## Code-owned urgent policy

The fixed `UrgentObservationFastGatePolicy` accepts only these typed Observations:

- `credential-material-exposure`;
- `scope-boundary-violation`; and
- `unsafe-side-effect`.

Origin must be `operator` or `trusted-core`, and confidence must be exactly `1.0`. Agent-derived and
target-derived content cannot directly select the fast path. The gate accepts a `GraphNodeRef`, not
an Observation summary, prompt, message, or command. The policy maps every accepted type to the one
deterministic disposition `stop-and-escalate`.

## Required authority chain

Admission requires all of the following:

1. the terminal result resolves exactly from its process-local HANDOFF-002 authority;
2. the supplied MEM-003 Snapshot rebuilds from the current Graph head and exactly matches the
   Snapshot bound into that terminal result;
3. the terminal result Artifact remains an exact member of the Snapshot and is reverified against
   its sealed Run source;
4. the Observation ref resolves to one exact `GraphObservation` in that Graph projection;
5. exactly one `produces` edge links an existing Graph Action to the Observation;
6. exactly one `supported-by` edge links the Observation to the terminal result Artifact Evidence;
7. the Observation `valueDigest` equals the sealed result Artifact SHA-256;
8. the trusted type, origin, confidence, Campaign, and timestamps match the fixed policy and
   terminal result; and
9. the Graph head does not change during reconstruction.

## Bounds, retry, and negative boundary

The policy fixes one urgent Observation, one decision, and one local budget unit per handoff. There
is no predecessor decision, so a decision chain and cycle cannot be represented. An exact semantic
retry returns the first record even with a later `decidedAt`; a second distinct Observation or any
other semantic result for the same handoff is equivocation and fails closed.

Unregistered type, agent/target-derived origin, confidence below `1.0`, prompt-shaped full-node
input, stale or foreign Snapshot/ref, cross-Campaign substitution, missing or duplicate lineage
edges, Artifact/value mismatch, repeated decision, forged digest, non-null predecessor, counter or
budget expansion, and authority substitution fail closed.

The record embeds no Observation summary or result bytes. `contentEmbedded`, `promptInterpreted`,
`replanSelected`, `scopeExpansionAuthorized`, `capabilityGranted`, `permitGranted`, and
`executionAuthorized` are strict JSON `false`; `escalationRequired` is strict JSON `true`.

## Compatibility and boundaries

All Graph, Observation, Snapshot, HANDOFF-001/002, Artifact, replanning, and execution formats remain
unchanged. Removing this module and exports requires no migration. The authority, one-decision map,
and budget counter are process-local and non-durable. The slice does not reserve a runtime Budget,
revoke an existing Permit, apply the stop decision, notify a human, or read Artifact content.
HANDOFF-004 provides receiver-bound content access and explicitly denies reads when this authority
contains an admitted stop decision. A later runtime consumer must still apply the stop to execution.
