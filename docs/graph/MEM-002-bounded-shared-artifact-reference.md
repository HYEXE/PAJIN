# MEM-002: Bounded Shared Artifact Reference

- Status: Implemented additive projection
- Date: 2026-08-04
- API: `pajin.dev/shared-artifact-ref/v1alpha1`
- Implementation: `pajin.collaboration.artifacts`

## Outcome

MEM-002 introduces a content-addressed, metadata-only `SharedArtifactRef` for one existing
`GraphEvidence` artifact in one current sealed `RunStore` snapshot. It does not add a blob store,
transport manifest, Graph node, admission event, or content reader.

The reference binds the exact Campaign, typed Evidence node identity, source Run, current source
root, normalized relative path, SHA-256, media type, and byte size. Construction and verification
both reparse the Evidence and verify all source metadata from one bounded Run snapshot.

## Verification pipeline

```text
existing GraphEvidence
  -> canonical Graph node reparse
  -> reject campaign.json authority artifact
  -> bounded current sealed-Run snapshot
  -> exact Run ID and Campaign manifest/start-event match
  -> exact current source-root match
  -> exact sealed path, SHA-256, media type, and size match
  -> typed GraphNodeRef equality
  -> canonical SharedArtifactRef identity
```

The referenced artifact is limited to 1 MiB. The verifier reads `campaign.json` and the exact
artifact internally through `load_verified_run_artifacts`; it returns only a canonical reference,
never bytes or a filesystem path.

## Wire contract

`SharedArtifactRef` contains:

- `sharedArtifactId` and `sharedArtifactDigest`, derived from the complete canonical reference;
- `campaignId` and an Evidence-kind `GraphNodeRef`;
- `sourceRunId` and the current `sourceRootDigest`;
- normalized `relativePath`, `sha256`, canonical lowercase `mediaType`, and bounded `sizeBytes`;
- literal-false markers for embedded content, prompt relay, receiver authority, Scope expansion,
  Capability grant, and execution authorization.

The reference deliberately contains no artifact bytes, Base64 payload, prompt, messages, absolute
filesystem path, Scope, ToolRequest, Grant, Permit, credentials, or execution result.

## Authority separation

The Evidence node reference authenticates exact node identity; it does not prove that the node was
admitted to a Graph Snapshot. Run sealing authenticates filesystem integrity; it does not prove
producer, request, Agent, Task, Capability, or semantic trust.

MEM-003 must select references only through an exact Graph Snapshot and preserve target-derived
content as tainted data. HANDOFF-004 must separately bind a receiver, Capability, TTL, and read
budget before any artifact content can be returned.

## Verified negative contract

- traversal, absolute, non-normalized, reserved Run paths, and `campaign.json` fail closed;
- missing, unsealed, mutated, symlink-substituted, or oversized artifacts fail closed;
- digest, media-type, or size substitution fails closed;
- cross-Campaign, cross-Run, and stale-root replay fails closed;
- a forged authority marker fails at wire validation;
- exact construction is deterministic; and
- retaining an existing ID or digest while changing any reference material is rejected as
  equivocation.

Duplicate list membership is outside this single-reference wire type and remains a MEM-003
Snapshot invariant.

## Compatibility and rollback

GraphEvidence, GraphSnapshotRef, Control Plane ArtifactRef, portable Artifact transport,
RunStore seals, and all existing readers remain unchanged. The new collaboration package is
additive and opt-in. Removing it and its exports restores the previous behavior without data
migration or invalidating existing Graph or Run records.

## Deliberate boundaries

MEM-002 does not establish Graph admission, copy or transport content, interpret prompts, select a
receiver, mint Capability or Permit authority, expand Campaign Scope, dispatch a Tool, or create a
durable collaboration store. It does not expose a convenience reader because doing so before
receiver binding would create the confused-deputy boundary that HANDOFF-004 is intended to solve.

The next slice is MEM-003: a minimal, receiver-neutral `CollaborationSnapshot` rebuilt from one
exact Graph Snapshot, with unique admitted Fact and SharedArtifactRef membership and no content
access authority.
