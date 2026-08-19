# UX-007N Object Storage Provider Revalidation

## Status

Implemented as an internal provider-neutral direct-call boundary. This slice can issue checked
ephemeral upload credentials through a deployment-supplied adapter and can retrieve and revalidate
remote parts into existing managed staging. It does not select a concrete cloud provider, add a
public route, persist a provider attempt, activate a Distributed Worker, or grant Artifact
finalization authority.

## Purpose

Consume the durable UX-007M authority head at the first remote side-effect boundary while
preserving ADR-0188's rule that external storage only moves bytes. A provider response must never
be enough to admit a Replay output. The Control Plane must regain byte authority by reading the
complete remote tree and passing it through its existing managed repository path.

## Trusted composition

`pajin.control-plane.object-storage-provider-adapter/v1` identifies one non-secret adapter by a
content digest, canonical HTTPS endpoint origin, external multipart profile, and object-key-parts
operation profile. Caller-selected locators, Artifact admission, and finalization eligibility are
fixed false. The concrete implementation is injected by trusted deployment code and must keep
native upload IDs, service credentials, signing keys, and provider response metadata private.

The adapter methods receive stable server-derived operation IDs. A conforming provider must make
credential issuance, completion, and cleanup idempotent for those IDs and must not follow a
redirect to another origin. This repository does not yet contain a concrete S3, MinIO, Azure, or
other cloud implementation because no provider selection or signer configuration exists.

## Current-head gate

`ObjectStorageProviderRuntime` revalidates the complete UX-007L binding and exact adapter identity.
It then invokes `ObjectStorageAuthorityHeadStore.require_current()` immediately before each of:

- one part upload credential issuance;
- provider upload completion;
- every exact remote part read; and
- explicit upload cleanup.

Both the authority and latest checkpoint must equal the durable head. A revision activation
between two reads therefore stops the next read before a remote call. Historical checkpoints,
stale bindings, and adapter origin/profile substitutions fail closed.

## Ephemeral upload credential

`EphemeralObjectStorageUploadCredential` is a slots-based runtime dataclass, not a `StrictModel`.
Its URL is excluded from equality and redacted from `repr`; no durable model, event, API, or log
field accepts it. After provider issuance the runtime checks:

- method is `PUT`;
- object key is the exact `object_storage_part_key()` result;
- expiry is exactly the UX-007L binding expiry;
- scheme is HTTPS with no user information or fragment; and
- URL origin is exactly the deployment-pinned origin.

The provider-specific implementation remains responsible for proving that its actual signature
covers the same method, key, and expiry and for disabling cross-origin redirects.

## Completion and remote-byte revalidation

Completion is transport observation only. The provider method must return `None`; returning an
ETag, version, locator, or other metadata is rejected. A successful call still creates no Artifact
and no finalization record.

The runtime derives every expected part key from the binding. Each read is bounded to the exact
remaining part size. It rejects non-`bytes`, short, or oversized responses, reconstructs every
file, recomputes each file SHA-256, rebuilds the canonical
`PortableArtifactMultipartManifest`, and requires exact equality with the executor-attested
manifest. The existing 64 MiB total and 16 MiB per-file limits bound this pre-staging buffer.

Only the fully verified tree enters `ManagedArtifactRepository` through the existing local
multipart begin, part, and materialization methods. Finalization then uses the unchanged
`ReplayFinalizeRequest` manifest and executor attestation path, which performs managed import,
sealed Run inspection, Replay gate checks, and database admission. The new runtime neither calls
nor substitutes those authorities.

## Expiry, cleanup, and unknown outcomes

Upload credential issuance and complete/read reject a time before `issuedAt` and a time equal to or
after `expiresAt`. Explicit cleanup can still target that current-head binding after expiry or when
the caller has classified it as abandoned. Only typed `cleaned` and `already-absent` dispositions
are accepted. String coercion and `unknown` are rejected.

Mutating provider calls are never automatically retried by the runtime. A provider-declared
unknown exception or any unexpected mutating exception is reported without the original exception
text and requires explicit cleanup. An unknown cleanup result requires operator reconciliation.
Remote read errors are non-authoritative and fail closed without staging.

## Threat model and negative cases

An attacker may attempt to return a different URL origin, method, key, expiry, part length, file
content, completion metadata, cleanup scalar, or stale authority. They may rotate the durable head
between remote parts or cause response loss after a remote mutation. They may also try to make a
credential appear in an exception or durable model.

The implementation rejects all listed substitutions, rechecks the head before each call, redacts
the credential representation, sanitizes provider exceptions, buffers and hashes the complete
tree before staging, and treats unknown mutation state as unresolved. The provider adapter remains
trusted to implement its native signature, credential custody, redirect behavior, and operation-ID
idempotency correctly.

## Compatibility, migration, and rollback

The slice adds one internal module, tests, one contract, and one ADR. There is no schema,
environment, dependency, route, Worker, client, or finalization wire change. Existing local and
inline transports remain executable as before.

Rollback stops adapter use and preserves UX-007M state. Operators must reconcile remote state that
may already exist; deleting the runtime does not prove that provider objects are absent. Because
there is no durable provider-attempt journal yet, restart discovery, automatic expired cleanup,
unknown-completion reconciliation, cleanup of an old revision after head advancement, and
cross-host fencing remain follow-up boundaries.

## Validation

- Definition content address and exact deployment origin/profile matching.
- URL method, key, origin, expiry, runtime-only representation, and secret-free errors.
- Stale head rejection before provider call and head rotation rejection before the next part read.
- Completion metadata rejection and unknown completion without remote reads or managed staging.
- Exact part-size reads, complete file and canonical manifest recomputation before staging.
- Explicit expiry cleanup, typed disposition enforcement, and unknown cleanup blocking.
- POSIX-only proof that verified remote bytes enter an Artifact only through the existing managed
  import.

## Related documents

- [ADR-0190](../adr/0190-revalidate-remote-object-storage-before-managed-admission.md)
- [UX-007M durable head](UX-007M-object-storage-durable-authority-head.md)
- [UX-007L deployment authority](UX-007L-object-storage-deployment-authority.md)
- [ADR-0045 local multipart transport](../adr/0045-resumable-multipart-portable-artifact-transport.md)
