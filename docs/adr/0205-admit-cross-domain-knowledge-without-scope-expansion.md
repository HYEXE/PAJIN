# ADR-0205: Admit Cross-domain Knowledge without Scope Expansion

## Status

Accepted

## Context

The ARCH-001 Canonical Graph already allows an Observation to discover a Surface or enable a
Hypothesis. Multi-domain analysis needs those relationships to connect Web, Network, System,
Application, Mobile, Cloud, AI, Cryptography, and Forensics knowledge. A discovered endpoint,
credential hint, host, resource, Tool, or artifact may be valuable campaign knowledge, but the
source action's authority does not cover a later action against it.

Creating one graph per domain would fragment campaign provenance. Treating cross-domain discovery
as Scope expansion would let target-controlled or model-derived content become execution authority.

## Decision

All domains reuse the one Canonical Graph, its existing node vocabulary, typed relations,
single-writer Admission Authority, append-only Event Log, Projection, and Snapshot.

A cross-domain Observation may propose `discovers` and `enables` edges through a code-registered
producer and exact evidence lineage. An admitted discovered Surface is knowledge only and starts as
registered-not-authorized in the domain admission projection. Graph admission does not mutate the
Campaign, Scope, Capability activation, budget, egress, credential, Worker, approval, or Permit
authorities.

A later action against that Surface requires a new Proposal compiled from the current Snapshot and
intersected with current Campaign Scope, exact registered Capability and release activation,
Policy, approval where required, ActionPermit, and deployment-owned Worker boundary. The source
ActionPermit and Capability Grant are not transferable.

Forensic evidence may enable a Hypothesis such as possible credential material. It cannot authorize
credential use, lateral movement, mutation, or another domain's active probe.

## Consequences

- Cross-domain chains remain queryable in one campaign knowledge graph.
- Domain-specific Graph ledgers and reconciliation protocols are unnecessary.
- Discovery adapters and models must emit bounded classification and provenance, never executable
  parameters or implied Scope.
- Graph readers must not expose a Surface's presence as an authorization signal.
- Positive and adversarial tests must cover stale Snapshot, producer substitution, cross-Campaign
  lineage, domain relabeling, and attempts to reuse source authority.

## Rejected alternatives

### Create one graph ledger per domain

Rejected because it fragments provenance, introduces multiple writers, and makes cross-domain
consistency and Snapshot binding ambiguous.

### Automatically add discovered targets to Scope

Rejected because discovery results can be target-controlled and are not authorization evidence.

### Transfer the source Permit to a discovered Surface

Rejected because a Permit is exact, single-use, target-bound authority for one compiled action.

## Compatibility and rollback

The existing Graph v1alpha1 nodes and relations remain unchanged. Domain admission is additive.
Rollback stops producing the projection while retaining canonical Graph events and evidence.

## Related documents

- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [GRAPH-001](../graph/GRAPH-001-minimum-canonical-graph-model.md)
- [GRAPH-002](../graph/GRAPH-002-single-admission-event-log.md)
- [WALK-004](../orchestration/WALK-004-observation-graph-replan.md)
