# ADR 0287: Retain a recovery head outside restored application state

Status: Accepted

## Context

OPS-003 authenticates an exact encrypted cold checkpoint and verifies a distinct,
quarantined PostgreSQL/local-store restoration. An older valid archive and its old
pin remain valid together. Authentication alone cannot determine whether they are
the latest checkpoint selected by the operator.

A separate physical Linux host is not available for the current exercise. The
selected next boundary is an independently retained volume, with separate
publisher and recovery processes, in an owned Linux rehearsal.

## Decision

Enroll one optional recovery authority in independently pinned source and target
deployment inventories. Its genesis commitment includes a random identity and
Ed25519 public key. Keep its create-only genesis and signed append-only checkpoint
chain outside all application state and archive restores. Unenrolled OPS-003
inventories retain their existing serialized representation and behavior.

Only a separately held publisher key advances the head. Every publication binds
the exact archive digest, source deployment digest, sequence and previous record.
It requires an expected sequence, rejects duplicate archives, synchronizes the
append, and rechecks the full chain. A partial write, missing file, invalid
signature or uncertain publication never triggers automatic repair or retry.
The source remains stopped after archive publication failures.

Enrolled restore, verification and resume must acquire the independent store and
match its current head before touching the target or contacting the resume API.
Shared advisory locks span the operation; cooperating publishers require an
exclusive lock. The head is checked again before releasing the lock. Resume also
binds the head in its separately signed verification receipt. Existing source
fencing, domain validation, conservative budgets, approval and Permit boundaries
remain mandatory. Recovery does not authorize a Worker or a Finding.

## Limits and alternatives

The independent volume, its pathname and lock ownership are trusted operator
infrastructure. Disjoint paths alone do not prove independent storage. Replacing
or rolling back that volume together with application state is outside this
boundary; a valid truncated signed prefix cannot prove its own freshness.
Operators must retain it separately and pin enrollment outside restored backups.
The current protocol is bounded to 4,096 publications and has no automatic
rotation, migration, distributed lock, remote witness or failover protocol.

A network witness with challenge-bound signed freshness would add authentication,
availability and distributed fencing contracts. It is deferred until an actual
separate-host target is available. The isolated rehearsal must demonstrate the
selected volume and process separation without claiming physical-host recovery.
