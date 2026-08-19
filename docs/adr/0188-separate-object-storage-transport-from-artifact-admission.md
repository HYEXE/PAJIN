# ADR-0188: Separate Object Storage Transport from Artifact Admission

## Status

Accepted

## Context

ADR-0045 introduced a bounded multipart transport backed by the Control Plane host's private
filesystem. Its public request carries a server-issued staging capability, manifest, exact Replay
lease and fence, and executor attestation; it carries no filesystem path, object key, upload URL,
tenant selector, or expiry. The Control Plane reassembles and hashes every file before the existing
managed repository imports and verifies the sealed Run.

Replacing the local byte transport with an external object store introduces values that look
authoritative: a bucket or namespace, object key, pre-signed URL, expiry, tenant label, provider
completion result, ETag, or object version. If any of those values can select the admitted object
or declare finalization, storage transport can bypass the existing Replay and Artifact authority.
Provider integration also needs a rotation and rollback rule before mutable deployment
configuration becomes executable.

## Decision

### Define a non-executable deployment authority first

Add `pajin.control-plane.object-storage-deployment-authority/v1`. It content-addresses one
deployment and tenant identity, canonical HTTPS endpoint origin, deployment-owned object-key
prefix, bounded upload TTL, external multipart transport profile, and the current local multipart
limits. It names the existing managed repository as the only Artifact admission profile and fixes
provider integration, Artifact admission, and finalization eligibility to false.

Revision one starts the chain. A successor must be contiguous, bind the exact predecessor digest,
have a strictly later issue time, and retain deployment, tenant, transport, and admission identity.
An exact same-revision replay is idempotent. Rollback, gaps, predecessor mismatch, equivocation,
and cross-tenant substitution fail closed.

This pure selector does not claim durable anti-rollback by itself. Future activation must persist
the remembered head in a deployment-owned store and refuse an unexpected bootstrap after state
loss.

### Bind transport without granting admission

Add `pajin.control-plane.object-storage-transport-binding/v1`. It binds the complete deployment
authority to the server-issued staging capability, canonical multipart manifest,
executor-attestation digest, exact TTL, and a server-derived object-key root. Exact per-part keys
are derived from the manifest coordinate. The model accepts no upload URL and fixes transport-only,
provider-integration, Artifact-admission, and finalization flags so they cannot be escalated.

A future provider may issue an ephemeral pre-signed URL only after this binding is verified. The
full URL and credentials must remain outside durable authority and logs. Endpoint origin, expiry,
returned provider metadata, and retrieved bytes will still require adapter verification, but none
can replace server-side manifest hashing, managed import, Run integrity verification, or Replay
finalization.

### Preserve the current executable path

Do not add a public route, provider client, environment variable, remote read, URL issuer, garbage
collector, KMS/HSM integration, or Distributed Worker change. `ReplayFinalizeRequest` does not
accept the new transport binding or external locator fields. Inline and local multipart paths
remain the only executable portable transports.

## Consequences

- External object keys become deterministic server-derived transport locators, not caller input.
- Upload URL and expiry are explicitly temporary credential boundaries, not Artifact authority.
- Tenant identity cannot move inside one deployment revision chain.
- Integrity inputs stay bound to existing Replay authority while final admission remains
  server-recomputed and repository-owned.
- Provider success, ETag, version, or remote presence cannot finalize a Replay Artifact.
- The first external adapter must add durable head activation, ephemeral credential handling,
  remote byte retrieval/verification, expiry cleanup, and failure recovery without changing these
  ceilings.

## Rejected alternatives

### Accept a Worker-provided object key or upload URL at finalization

Rejected because it lets an untrusted execution host choose the object being admitted and revives
the path-substitution class that the managed staging capability removed.

### Treat provider completion or ETag as Artifact integrity

Rejected because provider metadata is transport observation and does not prove the canonical tree,
sealed Run, executor statement, or Replay lineage.

### Add provider, Distributed Worker, and KMS/HSM support together

Rejected because transport addressing, off-host identity, and key custody are separate trust
boundaries with different rollback and recovery requirements.

### Claim anti-rollback from a content digest alone

Rejected because an attacker can replay an older self-consistent document if no durable remembered
head is consulted.

## Compatibility and rollback

The change is additive and non-executable. It changes no existing database, wire, route, Worker,
repository, or finalization behavior. Removing the new internal models is safe before provider
activation. A later executable adapter must preserve the remembered revision head during rollback
and must never admit remaining remote bytes through a downgraded or missing authority.

## Related documents

- [UX-007L contract](../orchestration/UX-007L-object-storage-deployment-authority.md)
- [ADR-0045 local multipart transport](0045-resumable-multipart-portable-artifact-transport.md)
- [ADR-0039 executor-attested portable transport](0039-executor-attested-portable-artifact-transport.md)
- [ADR-0187 Replay Worker deployment unit](0187-bind-replay-worker-credential-to-executor-profiles.md)
