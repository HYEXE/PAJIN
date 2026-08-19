# ADR-0191: Journal and Reconcile Object Storage Provider Attempts

## Status

Accepted

## Context

ADR-0190 introduces a provider-neutral runtime that checks the durable authority head and
revalidates all remote bytes. It intentionally treats uncertain mutations as unresolved, but it
has no durable memory of an operation after process exit. A restarted process could otherwise
start new work, repeat a provider mutation, or activate an authority successor while remote state
from the previous binding remains unknown.

The repository still has no selected cloud SDK, signer, credential inventory, or provider-specific
test environment. Selecting a vendor would be an unsupported deployment decision. The recovery
boundary therefore has to activate the exact provider supplied by trusted deployment code without
turning its profile, URL, or response into Artifact authority.

## Decision

### Activate one exact deployment-supplied provider

Introduce a secret-free deployment profile containing the required credential custody,
operation-ID fence, signature coverage, redirect, encryption, consistency, prefix cleanup, and
local conformance guarantees. Bind that profile, the UX-007N adapter definition, and the exact
UX-007M checkpoint into a content-addressed append-only concrete-provider activation.

Provision its SQLite store only through an explicit `bootstrap()` call. `open()` never creates or
repairs missing state and validates the complete logical contents. A provider whose adapter or
deployment profile differs from the latest activation cannot construct the recoverable runtime.

This activates only transport use. Artifact admission and finalization eligibility remain fixed
false. Provider choice and credentials remain deployment responsibilities.

### Journal intent before every provider call

Allow at most one open attempt per host-local journal. Bind the attempt to the concrete activation,
authority checkpoint, exact upload binding, active time window, and a transactional fence. Derive a
content-addressed operation for credential issuance, completion, every read, cleanup, and
reconciliation.

Write an append-only `intent` record before the provider call and exactly one typed outcome after
it. The record chain stores no credential URL, exception text, or remote bytes. Operation IDs carry
the fixed-width monotonic fence; the concrete provider must reject a lower fence observed after a
higher fence for the same binding.

The journal does not replace ADR-0190. Current-head checks, credential verification, canonical
manifest reconstruction, and the managed staging bridge still run for the exact call.

### Reconcile before admitting new work

On restart, discover every open attempt before beginning another one. Claim a newer fence and ask
the provider to classify the binding as `absent`, `upload-open`, `completed`, or `unknown`.

`absent` closes the attempt. `upload-open` and `completed` both require idempotent prefix cleanup;
provider completion cannot be resumed as Artifact authority. Cleanup must return `cleaned` or
`already-absent`. Unknown or invalid observations and provider exceptions leave the attempt open,
raise a secret-free error, and fence all new work.

### Block successor activation while cleanup is unresolved

Guard provider-aware authority succession with the same no-pending invariant. Write the authority
successor first and then append the concrete-provider activation for its exact checkpoint. A crash
between stores is fail-closed: provider runtime construction fails until an operator explicitly
completes the provider activation.

This is not a distributed transaction. Direct lower-level head administration can bypass the
guard, but doing so leaves the concrete provider inactive for the new checkpoint rather than
silently authorizing it.

## Consequences

- Process exit after a durable intent is discoverable on restart.
- Unknown remote state cannot be interpreted as absence or retried as a new attempt.
- A recovery claim fences the stale journal writer, while the activated provider contract fences
  a late remote call.
- Credentials and remote bytes remain outside durable provider records.
- Completed provider state is cleaned, not promoted into Replay finalization.
- One host-local journal serializes provider attempts conservatively.
- Provider truthfulness and native fence enforcement remain deployment TCB.

## Rejected alternatives

### Retry the same mutating call after restart

Rejected because response loss does not prove whether the remote mutation happened. Native
idempotency alone also does not resolve stale processes that resume after a newer recovery owner.

### Treat provider completion as a recoverable Artifact receipt

Rejected because completion does not prove the canonical remote bytes, sealed Run, executor
attestation, Replay gate, or database admission.

### Persist signed URLs or provider-native upload IDs

Rejected because those values are credential-like provider implementation details and would widen
the durable secret and authority boundary.

### Select a cloud provider in the core package

Rejected because deployment inventory, signer configuration, credentials, encryption policy, and
live conformance evidence are absent. The activation accepts a reviewed concrete implementation
without guessing its vendor.

### Atomically update the authority and provider SQLite stores

Rejected for this slice because it would introduce a new cross-store transaction coordinator. The
ordered fail-closed transition makes partial completion visible and requires explicit repair.

## Compatibility and rollback

The new runtime is additive. Existing provider-neutral direct calls and all public transport and
finalization wires remain unchanged. There is no migration from prior attempt state. A deployment
must explicitly provision the journal and activation.

Rollback stops new sessions and retains both durable stores until all attempts are reconciled.
Removing the database, lowering a fence, or classifying an unknown attempt as absent is prohibited.

## Follow-up work

- Implement and live-test a selected provider adapter and credential loader.
- Add automatic expiry and old-revision garbage collection.
- Define multi-process and cross-host provider fencing.
- Create a coordinated backup/restore and anti-rollback contract for both durable stores.
- Audit provider SDK and HTTP logging for credential leakage.
- Keep public routes, Distributed Workers, KMS/HSM, and tenant isolation in separate boundaries.

## Related documents

- [UX-007O contract](../orchestration/UX-007O-durable-object-storage-provider-recovery.md)
- [ADR-0190 provider revalidation](0190-revalidate-remote-object-storage-before-managed-admission.md)
- [ADR-0189 durable authority head](0189-activate-object-storage-authority-head-before-provider-use.md)
- [ADR-0188 transport/admission separation](0188-separate-object-storage-transport-from-artifact-admission.md)
