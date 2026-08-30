# GRAPH-001: Minimum Canonical Graph Model

- Status: Implemented contract
- Date: 2026-07-26
- Implementation: `pajin.graph`

## Purpose

This non-executable typed contract fixes the minimum campaign-knowledge vocabulary shared across
Specialists and attack surfaces. It does not implement an Event Store, Admission Queue, Graph
Projection, Snapshot, or Supervisor. Agent-produced values are Proposals, not canonical state.

## Nodes

| Kind | Core binding |
| --- | --- |
| `Surface` | Campaign, Target, surface type, locator schema/digest, and origin |
| `Hypothesis` | Statement, expected observable, producer version/digest, origin, and confidence |
| `Action` | Request, Capability/Permit plus registered Capability, or mutually exclusive sealed-source projection authority; Tool, target digest, and result time |
| `Observation` | Typed summary/value digest, producer version/digest, taint origin, confidence, and time |
| `Evidence` | Normalized relative reference, content/root digest, media type, and data classification |
| `CampaignFact` | Fact key/value digest, validation state, producer provenance, origin, and time |

A Node ID is a domain-separated canonical digest of its Campaign and complete semantic payload.
Different provenance or contradictory values produce separate Node IDs, allowing coexistence
without overwrite. Target-derived text uses `origin=target-derived` so a later Supervisor input can
preserve taint.

## Edges

Only these eight relations are accepted, each with fixed source and target kinds:

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports Hypothesis
Observation contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

An Edge has a canonical ID bound to Campaign, typed endpoints, relation, and authority ID/digest.
Reverse direction, wrong endpoint kinds, self-edges, cross-Campaign endpoints, and ID tampering are
rejected.

## Proposals

Agents and Specialists can submit only four write-intent types.

### `SurfaceProposal`

- binds exact campaign/run/agent/task/request/evidence lineage;
- allows a seed Surface without an edge; and
- permits only `Observation discovers Surface` when edges are present.

### `HypothesisProposal`

- carries one registered-producer Hypothesis;
- exact-matches Hypothesis producer ID/version/digest to the outer Proposal; and
- requires at least one exact `Surface motivates Hypothesis` or
  `Observation enables Hypothesis` edge, resolved by the Admission Authority.

### `ObservationProposal`

- carries the exact Action, one Observation, and at least one Evidence node;
- requires exactly one `Action produces Observation`;
- requires `Observation supported-by Evidence` for every Evidence node;
- exact-matches Action request and either Capability plus Grant/Permit authority or the mutually
  exclusive sealed-source authority against lineage;
- exact-matches lineage evidence reference/digest and Evidence source root; and
- connects every additional support/contradict/discover/enable edge to the proposed Observation.

### `CampaignFactProposal`

- carries a `CampaignFactPayload` without canonical `validation_state`;
- lets an Agent propose a fact but not assign `admitted`, `corroborated`, `contested`, or
  `invalidated`; and
- leaves canonical `CampaignFact` materialization to the GRAPH-002 Admission Authority.

Every Proposal binds its registered producer ID/version/digest plus campaign, run, agent, task,
request ID/digest, source root, evidence, and production time. Execution-backed lineage carries a
Capability ID/version/digest plus CapabilityGrant or ActionPermit. Knowledge-only sealed-source
lineage instead carries an exact source-authority ID/digest and no Capability/Grant/Permit fields.
Every paired authority is complete or absent. The Proposal digest includes its ID and complete
canonical content so GRAPH-002 can distinguish exact retry from same-ID/different-content
equivocation.

## A5 compatibility boundary

Existing `SurfaceObservation`, `AttackSurfaceSet`, `AttackHypothesis`, and
`ObservationGraphSnapshot` types remain unchanged. They are sealed legacy Artifacts. A later
trusted adapter converts them into Proposals while preserving original schema, root, and Artifact
digests. Successful conversion does not imply admission.

`TaskGraph` also remains separate: it models execution dependencies, while the Minimum Canonical
Graph models admitted campaign knowledge and provenance.

## Verified rejection contract

- unknown fields, naive timestamps, control characters, and unsafe evidence paths;
- canonical Node/Edge ID tampering;
- relation endpoint kind/direction mismatch and cross-Campaign edges;
- foreign-Campaign Proposal nodes or edges;
- Hypothesis producer mismatch or unresolved motivation;
- evidence reference/content/source-root lineage mismatch;
- missing Action production or Evidence support edges;
- Agent-supplied CampaignFact validation state;
- partial or mixed CapabilityGrant, ActionPermit, Capability, and sealed-source authority; and
- overwrite of contradiction instead of a separate identity.

## Next step

[GRAPH-002](GRAPH-002-single-admission-event-log.md) implements the single Admission Authority
and append-only Event Log reference spike.
[GRAPH-003](GRAPH-003-projection-revision-immutable-snapshot.md) adds projection, atomic
process-local revision, and immutable Snapshot contracts.
[GRAPH-004](GRAPH-004-consistency-recovery-stale-decision.md) adds the Hypothesis admission path,
duplicate/contradiction analysis, bounded reconciliation, and stale-decision preflight.
[GRAPH-005](GRAPH-005-durable-sqlite-graph-store.md) selects a separate single-Campaign SQLite
Graph Store and adds host-local cross-process CAS. Atomic ActionPermit dispatch remains open.
