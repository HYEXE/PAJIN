# MEM-001: Sealed Campaign Fact Admission

- Status: Implemented additive adapter
- Date: 2026-08-04
- Implementation: `pajin.graph.campaign_fact`

## Outcome

MEM-001 does not introduce a second collaboration ledger or new Fact wire shape. It connects the
existing GRAPH-001 `CampaignFactProposal` to the existing GRAPH-002
`GraphAdmissionAuthority` only after the proposal's source Campaign, Run, current integrity root,
and evidence bytes have been verified from one sealed `RunStore` snapshot.

The resulting immutable record remains the existing `GraphAdmissionEvent` containing one
authority-materialized `GraphCampaignFact(validationState=admitted)`. Exact retries and
same-ID/different-content equivocation retain GRAPH-002 semantics.

## Admission pipeline

```text
unprivileged CampaignFactProposal
  -> canonical Proposal reparse
  -> bounded current sealed-Run snapshot
  -> exact Run ID and Campaign manifest/start-event match
  -> exact latest source-root match
  -> every evidence artifact SHA-256 match
  -> existing producer and full-lineage verification
  -> existing single Graph Admission Authority
  -> existing append-only GraphAdmissionEvent and GraphCampaignFact
```

The adapter accepts at most 64 evidence references and loads at most 1 MiB per evidence artifact.
`campaign.json` is loaded separately with a 1 MiB bound and cannot be reused as Fact evidence.

## Authority separation

The adapter authenticates the sealed source boundary only. It neither registers nor promotes
caller-supplied lineage. The configured `GraphAdmissionAuthority` still requires its independent
`GraphProducerRegistry` and `GraphLineageVerifier` checks for producer, request, Grant,
Capability, optional Permit, Agent, and Task identity.

Capability and Permit identifiers in a Graph event are provenance references, not transferable
authority. The admitted `GraphCampaignFact` has no command, prompt, message, Scope, ToolRequest,
Grant, Permit, or execution-authorization field. Target-derived statements preserve
`origin=target-derived`; MEM-002/003 readers must continue treating that content as tainted data.

## Verified negative contract

- a missing, unsealed, mutated, foreign, or unexpected Run fails before Graph append;
- a foreign Campaign manifest or non-exact `campaign.started` event fails before Graph append;
- a stale source root after a new Run seal fails before Graph append;
- missing, oversized, or digest-substituted evidence fails before Graph append;
- forged full lineage remains a normal audited GRAPH-002 rejection;
- exact retry is idempotent and same proposal ID with different Fact content is audited as
  equivocation; and
- Agents still cannot provide `validationState` or append canonical events.

## Compatibility and rollback

GRAPH-001 Proposal/Node, GRAPH-002 Event, Projection, Snapshot, SQLite storage, public readers, and
legacy execution paths are unchanged. Removing the adapter and its exports restores the previous
state without data migration; already admitted records remain valid GRAPH-002 events.

## Deliberate boundaries

MEM-001 does not implement `SharedArtifactRef`, collaboration Snapshots, Agent handoff, semantic
fact corroboration/invalidation, prompt interpretation, an execution Capability, Scope changes, or
a new durable store. Cross-store atomicity remains the responsibility of the existing sealed
source snapshot and Graph admission authorities; the record preserves the exact historical root.

The next slice is MEM-002: a bounded, content-addressed reference to already sealed shared
artifacts without embedding or relaying their content.
