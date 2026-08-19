# UX-007O Durable Object Storage Provider Recovery

## Status

Implemented as an internal, host-local concrete-provider activation and recovery boundary. Trusted
deployment code still supplies the provider implementation and its credentials. This slice makes
that exact implementation durable, journals every provider intent before its remote call, fences
restart recovery, and blocks new work and authority-head succession while an attempt is unresolved.
It does not add a public route, choose a cloud vendor, manage secrets, schedule garbage collection,
or grant Artifact admission or finalization authority.

## Purpose

Close the crash window left by UX-007N. A process may exit after a remote mutation but before its
result is observed. Absence of an in-memory result cannot mean that the upload is absent, safe to
retry, or safe to strand behind a successor authority head. Recovery must start from durable
intent, ask the activated provider to classify its own remote state, and clean that state before
new work can start.

## Concrete provider activation

`ObjectStorageProviderDeploymentProfile` records the non-secret guarantees required from the
deployment-supplied implementation:

- credentials remain inside the deployment runtime;
- native multipart mutations are idempotent for an operation ID with a monotonic fence;
- upload signatures cover exact `PUT`, server-derived key, and binding expiry;
- redirects are rejected;
- a named server-side encryption policy is required;
- reads after writes are strongly consistent;
- prefix cleanup is idempotent and returns an observed disposition; and
- a named local conformance profile identifies the tested environment.

The profile contains no key, token, endpoint credential, bucket credential, or signed URL.
`ObjectStorageConcreteProviderActivation` binds its digest, the exact UX-007N adapter definition,
and the exact UX-007M authority checkpoint into an append-only activation chain. Its transport flag
is true while Artifact admission and finalization eligibility remain false.

`ObjectStorageProviderAttemptJournal.bootstrap()` is an explicit provisioning action. `open()`
never creates missing state and fully checks SQLite integrity, foreign keys, schema inventory,
schema metadata, the activation chain, every stored attempt, and every record chain. A different
provider profile or adapter cannot reopen the runtime as the active provider.

The repository deliberately does not choose S3, MinIO, Azure, or another vendor. A production
deployment must supply a concrete implementation and truthful profile after its inventory,
credential custody, native multipart semantics, signature behavior, encryption policy,
consistency, cleanup semantics, and conformance environment are established.

## Attempt and operation journal

At most one provider attempt is open in this host-local journal. The attempt binds:

- concrete activation and adapter digests;
- exact authority checkpoint and transport binding digest;
- start time inside the binding's active window; and
- a transactional monotonic fence.

Every credential issue, upload completion, remote part read, cleanup, and restart reconciliation
is represented by a content-addressed operation. Its public operation ID carries a fixed-width
numeric fence. A conforming provider maintains a high-water fence per binding and rejects an older
operation that arrives after recovery has claimed a newer fence.

The journal writes an `intent` record before invoking the provider. It then appends exactly one
`succeeded`, `rejected`, or `unknown` outcome. Records form a digest-linked append-only chain and
contain no signed URL, credential, provider exception text, or remote bytes. Successful credential
records retain only a digest of method, object-key digest, and expiry. Read records retain only byte
length and SHA-256 result material.

Existing UX-007N checks remain authoritative after journaling: each call still checks the exact
current head immediately before the provider, ephemeral credentials are revalidated, all remote
bytes are rehashed, and only the complete matching tree can enter managed staging.

## Restart reconciliation

`RecoverableObjectStorageProviderRuntime.reconcile_pending()` discovers durable open attempts
before new work. It claims a higher recovery fence and invokes the provider-owned
`reconcile_upload()` operation. The only accepted typed observations are:

- `absent`: close the attempt without cleanup;
- `upload-open`: perform fenced idempotent prefix cleanup;
- `completed`: clean the completed remote prefix rather than assuming it is an Artifact; or
- `unknown`: leave the attempt open and block new work.

Cleanup must return typed `cleaned` or `already-absent`. An exception, invalid scalar, or `unknown`
keeps the attempt open. Provider exception text is removed from the raised recovery error. Recovery
does not resume finalization from provider completion because completion still proves neither the
canonical bytes nor the existing Replay lineage.

An original process that resumes after a recovery claim cannot append with its old fence. The
activated provider is separately required to reject the old fenced operation even if it reaches
the remote API after the newer recovery operation.

## Successor activation and failure windows

`activate_successor()` checks that no attempt is open before it writes a UX-007M authority
successor. It then appends the corresponding provider activation for the new checkpoint. A process
exit between those two durable stores leaves the provider runtime inactive for the new head; an
operator must explicitly append the exact provider activation. It cannot silently continue under
the previous checkpoint.

Direct calls to the lower-level authority store remain available for non-provider administration.
Once a concrete provider is activated, deployment orchestration must use the guarded transition or
accept that a bypassed head rotation will fail provider-runtime construction until the provider
activation is repaired. There is no cross-database or cross-host transaction in this slice.

## Compatibility, migration, and rollback

The change is additive. It adds one internal module, one explicit SQLite store, tests, this
contract, and ADR-0191. Existing inline transport, local multipart transport, UX-007N direct-call
runtime, public routes, Worker messages, and Replay finalization wires are unchanged.

There is no automatic migration because no prior provider-attempt store existed. First use
requires explicit bootstrap after the concrete provider profile has been reviewed. Rollback stops
new provider sessions but must retain the journal and reconcile every open attempt. Deleting the
journal or treating an unknown attempt as absent is not a rollback.

## Validation

- Durable, content-addressed concrete activation and exact restart identity.
- Explicit bootstrap/open behavior and refusal of an unactivated provider profile.
- Intent visibility inside the provider callback before every remote call.
- Credential URL and signature query absence from SQLite bytes.
- Binding-window enforcement before a new attempt.
- Successful completion/read/revalidation followed by terminal staged state.
- Unknown completion discovery after restart, provider-owned classification, fenced cleanup, and
  a higher fence for the next attempt.
- A real child-process hard exit after durable attempt creation followed by restart reconciliation.
- Unknown reconciliation blocking both new work and successor activation.
- Old-session journal rejection after a recovery fence is claimed.
- Secret-free reconciliation exceptions that leave the attempt pending.
- Successor head and provider activation rotation only when no attempt is open.

## Remaining boundaries

- No cloud-specific adapter, signer, credential loader, or live Object Storage conformance suite.
- No automatic expiry scheduler, historical garbage collector, multi-process service lock, or
  cross-host fence coordinator.
- No backup/restore bundle for the provider journal and authority head as one atomic unit.
- No KMS/HSM integration, tenant credential isolation, off-host retention, or provider SDK logging
  audit.
- No public request route or Distributed Worker transport.

## Related documents

- [ADR-0191](../adr/0191-journal-and-reconcile-object-storage-provider-attempts.md)
- [UX-007N provider revalidation](UX-007N-object-storage-provider-revalidation.md)
- [UX-007M durable head](UX-007M-object-storage-durable-authority-head.md)
- [ADR-0190 provider revalidation](../adr/0190-revalidate-remote-object-storage-before-managed-admission.md)
