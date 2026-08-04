# ADR-0111: Reference Shared Artifacts Through Existing Authorities

- Status: Accepted
- Date: 2026-08-04

## Context

Phase 5 needs Agents to identify a shared artifact without copying its content into collaboration
state. PAJIN already has three relevant authorities: `GraphEvidence` provides content-addressed
evidence identity, `RunStore` seals provide artifact path/hash/size/media metadata and a current Run
root, and the portable Artifact transport moves larger Control Plane payloads.

A second artifact manifest, blob store, or unscoped content reader would duplicate those
authorities and could turn a reference into prompt relay or ambient filesystem access.

## Decision

Add a non-authoritative `SharedArtifactRef` projection that links one existing `GraphEvidence`
identity to one exact current sealed `RunStore` artifact record.

Creation and verification use the existing bounded, symlink-safe verified snapshot reader. The
projection binds Campaign, Evidence node, source Run/root, normalized relative path, SHA-256, media
type, and size. It is content-addressed over the complete canonical wire form and fixes every
authority-bearing marker to false.

Do not return bytes or a filesystem path from the verifier. Do not claim that an Evidence node is
Graph-admitted merely because its node identity and sealed source are valid. Snapshot membership
and receiver-bound content access remain separate later authorities.

## Consequences

- No new storage, transport, admission log, or ArtifactRef replacement is introduced.
- Existing Graph and Run readers remain the source of truth and exact retries are deterministic.
- Path, content metadata, Campaign, Run, root, identity, and authority substitution fail closed.
- MEM-003 can compose admitted references without embedding content.
- HANDOFF-004 must introduce the only receiver-bound content read path with explicit Capability,
  TTL, and byte limits.

The 1 MiB limit is intentionally smaller than portable Control Plane transport limits. Larger
collaboration artifacts require a separately reviewed receiver-bound design, not a relaxed
metadata reference.

## Rejected alternatives

### Reuse Control Plane `ArtifactRef`

Rejected because that type identifies a whole managed sealed Run in a repository and its version;
it does not identify one Graph Evidence file or its Campaign/root binding.

### Add a collaboration blob store or manifest

Rejected because RunStore seals and portable Artifact transport already own bytes and transport.
A second copy could diverge from both.

### Return bytes from the verifier

Rejected because MEM-002 has no receiver, TTL, Capability, or read budget. Returning content would
grant ambient reader authority and allow prompt relay before HANDOFF policy exists.

### Treat every valid GraphEvidence as admitted

Rejected because content-addressed node construction is unprivileged. Only the existing Graph
Admission Event and Snapshot authorities can establish admitted membership.
