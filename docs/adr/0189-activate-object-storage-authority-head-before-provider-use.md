# ADR-0189: Activate Object Storage Authority Head before Provider Use

## Status

Accepted

## Context

ADR-0188 defines a content-addressed Object Storage deployment authority and rejects rollback,
gaps, equivocation, and tenant substitution relative to a supplied current head. That pure
transition verifier cannot distinguish first bootstrap from a restart that lost its remembered
head. Replaying revision one with `current=None` would therefore defeat operational anti-rollback.

Provider integration must also define when a new head becomes usable, what happens if a process
exits around the write, and how a lost local database is restored without accepting an older valid
backup. These decisions must exist before temporary upload credentials or remote side effects are
introduced.

## Decision

### Separate first provisioning from restart

Add `ObjectStorageAuthorityHeadStore` as a deployment-owned, single-chain SQLite store. First
provisioning is the explicit `bootstrap()` API and requires both the database and an immutable
identity sidecar to be absent. The sidecar binds deployment, tenant, genesis authority digest, and
provisioning time. Normal `open()` never creates state and requires both files, so database-only,
marker-only, or interrupted-provisioning state fails closed instead of becoming a new bootstrap.

The sidecar is a host-local loss marker. An independently retained head checkpoint remains required
to reject stale backup restore and to detect rollback outside the intact local store. Complete loss
of local state, backups, and that checkpoint is not solved by a content digest.

### Commit the head before any use

Persist immutable `ObjectStorageAuthorityHeadActivation` rows in a guarded append-only schema.
Every read validates the schema inventory, metadata, triggers, SQLite integrity, canonical row
content, immutable identity, and the full UX-007L chain from revision one.

`activate()` requires a checkpoint already present in the same history. Under one `BEGIN IMMEDIATE`
transaction it selects only an exact current retry or contiguous successor. A successor is committed
with SQLite full synchronization and re-read before return. Exact retry returns the original row and
does not change its time. This yields a conservative crash boundary: pre-commit exit leaves no new
head; post-return exit leaves a recoverable committed head.

Historical checkpoints are accepted only as recovery lower bounds. `require_current()` requires
the exact latest checkpoint and exact latest authority. A future provider adapter must invoke that
gate immediately before URL issuance or any remote operation.

### Bind backup restore to an external checkpoint

Create an exclusive local SQLite backup and canonical manifest only after validating the complete
copy. The manifest binds schema, identity, latest checkpoint, time, byte length, and SHA-256.
Restore writes only to an absent database, verifies physical and logical state, requires the caller's
expected checkpoint to exist in the backup history, and accepts a pre-existing identity marker only
when exact. A backup behind the expected checkpoint is rejected.

This backup is not a signature, encryption envelope, immutable repository, or off-host transparency
anchor. Those remain independent deployment responsibilities.

### Keep provider and Artifact authority closed

Fix provider integration, Artifact admission, and finalization eligibility to false in activation
and checkpoint wires. Do not add a provider client, URL issuer, remote byte reader, cleanup worker,
public route, configuration key, Distributed Worker, KMS/HSM, or Artifact finalization change.

## Consequences

- Restart cannot silently initialize missing durable state.
- A committed successor survives response loss and process exit; an uncommitted successor does not.
- Exact retries are idempotent without rewriting activation time or history.
- A separately retained checkpoint blocks stale restore and cross-store replay.
- Database-only loss can be recovered while preserving the immutable provisioning identity.
- The provider adapter remains a later trust boundary and cannot infer execution authority from this
  activation alone.
- Operators must retain the database, identity sidecar, latest checkpoint, and verified backups as
  one recovery set.

## Rejected alternatives

### Call the pure selector with `None` at every startup

Rejected because any old revision-one document would become an apparently valid bootstrap.

### Automatically recreate the database when it is missing

Rejected because normal restart would erase the distinction between first provisioning and state
loss.

### Write the head after issuing a URL or contacting the provider

Rejected because a crash would leave remote side effects under an authority the server never
remembered.

### Treat a local backup digest as an independent anti-rollback anchor

Rejected because an attacker or operator who can replace the backup and manifest can restore an
older self-consistent pair unless a separately retained checkpoint is required.

### Add provider execution in the same change

Rejected because credential handling, remote byte verification, expiration cleanup, and Artifact
admission are separate side-effect and integrity boundaries.

## Compatibility and rollback

The change is additive and internal. Existing transport and finalization wires are unchanged.
There is no migration from a previous Object Storage activation store. Product rollback must stop
future provider use while preserving the durable chain, identity marker, latest checkpoint, and
backups; it must not re-bootstrap or downgrade the remembered head.

## Related documents

- [UX-007M contract](../orchestration/UX-007M-object-storage-durable-authority-head.md)
- [ADR-0188 transport/admission separation](0188-separate-object-storage-transport-from-artifact-admission.md)
- [UX-007L deployment authority](../orchestration/UX-007L-object-storage-deployment-authority.md)
- [ADR-0049 durable SQLite backup](0049-durable-single-campaign-sqlite-graph-store.md)
