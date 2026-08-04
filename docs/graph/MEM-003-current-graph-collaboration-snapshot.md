# MEM-003: Current Graph Collaboration Snapshot

- Status: Implemented additive projection
- Date: 2026-08-04
- API: `pajin.dev/collaboration-snapshot/v1alpha1`
- Implementation: `pajin.collaboration.snapshots`

## Outcome

MEM-003 introduces a bounded, receiver-neutral `CollaborationSnapshot` over one exact current
GRAPH-003 `GraphSnapshotRef`. It reuses the existing Graph Snapshot store and projection as the
only membership authority; it does not add a collaboration ledger, duplicate Graph content, or
create a second Snapshot store.

The collaboration wire contains every `GraphCampaignFact(validationState=admitted)` reference in
the resolved Graph projection and only those MEM-002 `SharedArtifactRef` values whose complete
`GraphEvidence` nodes are exact members of that same projection. All members are deterministic,
unique, sorted, and content-addressed with the complete Graph Snapshot reference.

## Compilation pipeline

```text
exact GraphSnapshotRef + existing GraphSnapshotStore
  -> require reference digest is current store head
  -> exact store resolve and canonical Graph Snapshot reparse
  -> require unchanged head after resolve
  -> derive all admitted CampaignFact GraphNodeRefs
  -> bounded MEM-002 source verification
  -> exact full GraphEvidence membership equality
  -> require unchanged Graph head after artifact checks
  -> canonical CollaborationSnapshot identity
```

Fact membership is derived rather than caller-selected, so an admitted Fact cannot be silently
omitted while retaining a valid collaboration identity. Shared Artifact membership is explicitly
supplied because the Graph does not own Run paths; each supplied process-local
`SharedArtifactSource` is fully reverified and never enters the wire form.

## Wire contract

`CollaborationSnapshot` contains:

- `collaborationSnapshotId` and `collaborationSnapshotDigest`;
- `campaignId` and one exact `GraphSnapshotRef`;
- up to 256 admitted Campaign Fact `GraphNodeRef` values;
- up to 256 verified MEM-002 `SharedArtifactRef` values; and
- literal boolean-false markers for content embedding, prompt relay, receiver authority, Scope
  expansion, Capability grant, and execution authorization.

The canonical wire is limited to 1 MiB. It contains no Graph projection, Fact statement, artifact
bytes, prompt, messages, source Run filesystem path, receiver, Scope, ToolRequest, Grant, Permit,
credentials, or execution result.

## Authority separation

The existing Graph Snapshot store proves exact immutable Graph membership. MEM-003 neither admits
nodes nor changes their validation state. A `SharedArtifactRef` must separately pass MEM-002 sealed
source verification and exact full-node equality with an admitted Graph Evidence member.

Target-derived Facts and Evidence remain tainted non-executable data. The collaboration reference
does not resolve their content. HANDOFF-001 must add Supervisor-mediated sender/receiver context,
and HANDOFF-004 must add the only receiver-bound reader with Capability, TTL, and byte limits.

## Verified negative contract

- an unadmitted, substituted, or omitted Fact or Evidence member fails exact verification;
- duplicate Fact, Artifact, or Evidence membership fails at the wire boundary;
- same-ID/different-content equivocation fails canonical identity validation;
- cross-Campaign, unknown or non-current Graph Snapshot, and cross-Run substitution fails closed;
- an old Graph Snapshot and a head change during compilation fail closed;
- oversized member collections fail before member verification; and
- true, integer-zero, or string authority-marker forgery fails strict boolean validation.

## Compatibility and rollback

GRAPH-001/002/003 nodes, Event Log, projections, Snapshots, references, stores, MEM-001 Fact
admission, MEM-002 Artifact references, and all existing readers are unchanged. The new type and
compiler are additive and opt-in. Removing the module and exports restores the previous behavior
without data migration or invalidating Graph or Run records.

## Deliberate boundaries

The current-head checks are cooperative store checks around exact resolution and bounded artifact
verification; they do not claim a distributed cross-store transaction. A new Graph head published
after compilation produces a new collaboration state on the next verification and makes the old
one fail current verification.

MEM-003 does not select a receiver, authorize handoff, return content, interpret a Fact, relay a
prompt, mint Capability or Permit authority, expand Scope, dispatch a Tool, or persist another
ledger. The next slice is HANDOFF-001: a Supervisor-mediated `AgentHandoff` that binds sender,
receiver, purpose, and one exact current `CollaborationSnapshot` without granting execution or
content-read authority.
