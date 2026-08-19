# UX-007M Object Storage Durable Authority Head

## Status

Implemented as a provider-ineligible Phase 9 activation boundary. This slice durably remembers
which UX-007L deployment authority revision is current, but it does not issue a pre-signed URL,
contact an external provider, retrieve remote bytes, expose a public API, or admit an Artifact.

## Purpose

Make the UX-007L revision chain operationally meaningful before external storage is executable.
The deployment must not accept an old self-consistent revision as a new bootstrap after restart,
must not use an authority before its head is committed, and must have a bounded recovery path when
the local database is lost or a process exits at a transaction boundary.

## Durable store identity and bootstrap

`ObjectStorageAuthorityHeadStore.bootstrap()` is an explicit first-provisioning operation. It
requires both the SQLite database and its fixed `.identity.json` sidecar to be absent. The sidecar
content-addresses the immutable deployment, tenant, genesis authority digest, and provisioning
time. It is published before the database so an interrupted provisioning attempt cannot be
silently retried as a fresh deployment.

`open()` never creates either file. Restart requires both files, exact canonical identity bytes,
the expected schema and append-only triggers, a successful SQLite integrity check, and the complete
contiguous activation history. A missing database or identity marker is state loss and fails closed
with restore required. If both local files are deliberately removed, only the operator can invoke
the distinct bootstrap API; normal restart cannot do so.

The identity sidecar is an independent local loss marker, not an off-host transparency service. A
deployment should retain the latest secret-free checkpoint independently. Losing the database,
identity marker, backups, and external checkpoint together is outside this host-local guarantee.

## Write-before-use activation

`pajin.control-plane.object-storage-authority-head-activation/v1` binds the complete UX-007L
authority, immutable store identity, and activation time. SQLite uses `synchronous=FULL`, a
single-writer transaction, schema guards, and update/delete/replace triggers. A successor is
inserted and committed before `activate()` returns. The method reopens and revalidates the durable
head before returning it.

The caller must present a previously retained
`pajin.control-plane.object-storage-authority-head-checkpoint/v1`. The checkpoint must occur in the
same durable history. UX-007L selection then permits only an exact current retry or a contiguous
successor with the exact predecessor. Exact retry returns the original stored activation, including
its original activation time. Rollback, gap, wrong predecessor, same-revision equivocation,
cross-deployment or cross-tenant substitution, cross-store checkpoint replay, and backwards
activation time fail closed.

A crash before SQLite commit leaves no successor. A crash after `activate()` returns leaves the
successor committed. On restart, the previous external checkpoint may be used as a lower bound so
the complete committed successor can be recovered and a new checkpoint retained; it cannot make a
database behind that checkpoint acceptable.

## Pre-operation gate

`require_current()` is the only result in this slice intended for a future provider adapter. It
requires both the exact latest authority and the exact latest checkpoint. A historical checkpoint
is sufficient for crash recovery and activation retry but is not sufficient for remote use.

The returned activation fixes `providerIntegrationEligible=false`,
`artifactAdmissionEligible=false`, and `finalizationEligible=false`. Therefore this method does not
itself authorize URL issuance, upload, download, cleanup, managed import, Replay finalization, or
Artifact admission. The next provider slice must call this gate immediately before every remote
operation and must retain all UX-007L transport/admission separation.

## Backup and restore

`pajin.control-plane.object-storage-authority-head-backup/v1` binds:

- the exact schema version and digest;
- immutable store identity;
- canonical latest head checkpoint;
- backup time; and
- bounded SQLite byte length and SHA-256.

Backup uses the SQLite online backup API, validates the complete copied chain, and publishes the
database and canonical manifest exclusively. Restore accepts only an absent destination database,
verifies both physical bytes and logical history, requires an expected checkpoint to occur in the
backup, and reuses an existing identity marker only when it is exact. This permits recovery after
database-only loss while rejecting a stale backup behind the external checkpoint.

The backup is local, secret-free integrity metadata. It is not signed, encrypted, remote,
immutable, or independently anti-rollback. Off-host retention, signing, encryption, and inventory
anchoring remain separate deployment work.

## Threat model and negative cases

An attacker may replay an older authority or backup, substitute a deployment, tenant, identity,
checkpoint, predecessor, activation row, database schema, trigger, manifest, or database byte, or
terminate the process immediately before or after commit. They may also present a valid historical
checkpoint as if it were current for a remote call.

The implementation rejects missing paired state, implicit restart bootstrap, unsafe links and
SQLite sidecars, schema or metadata drift, non-canonical identity and manifest bytes, row/content
drift, incomplete or non-contiguous history, stale restore, scalar type coercion, backup tampering,
existing restore destinations, historical-checkpoint use, and all UX-007L transition violations.

## Compatibility, migration, and rollback

This slice adds one internal module, one SQLite schema, two sidecar formats, and no environment
variable, route, client, Worker wire, finalization request, managed repository behavior, or provider
dependency. Existing inline and local multipart transports remain the only executable paths.

There is no legacy store migration because no prior durable Object Storage head existed. First
deployment provisions revision one explicitly. Later revisions are append-only. Rollback of product
code must disable future provider use while preserving the database, identity marker, latest
checkpoint, and recoverable backups. It must never call bootstrap over a previously provisioned
deployment or reinterpret remote bytes under an older head.

## Audit and benchmark impact

The store identity, activation, checkpoint, and backup manifest are content-addressed and contain no
pre-signed URL or credential. They are suitable inputs to a future deployment audit, but this slice
creates no Run event, Artifact, Finding, benchmark observation, comparison, execution, or provider
eligibility.

## Validation

- Explicit revision-one bootstrap, immutable identity publication, and restart without auto-create.
- Write-before-use successor activation, exact retry, checkpoint recovery, and exact current-use
  gate.
- Rollback, gap, equivocation, cross-store checkpoint, state-loss, schema, identity, scalar, backup,
  and stale-restore rejection.
- Hard process exit before commit and immediately after successful activation return.
- Verified database-only loss recovery with the original immutable identity marker.

## Related documents

- [ADR-0189](../adr/0189-activate-object-storage-authority-head-before-provider-use.md)
- [UX-007L deployment authority](UX-007L-object-storage-deployment-authority.md)
- [ADR-0188 transport/admission separation](../adr/0188-separate-object-storage-transport-from-artifact-admission.md)
- [ADR-0049 SQLite backup pattern](../adr/0049-durable-single-campaign-sqlite-graph-store.md)
