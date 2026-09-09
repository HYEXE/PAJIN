# ADR-0269: Retain Closed Recovery Sets under a Live Host Gate

- Status: Accepted
- Scope: OPS-001 declared local SQLite recovery sets
- Builds on: ADR-0263, ADR-0264, ADR-0267 and ADR-0268

## Context

An idle diagnostic cannot protect a multi-store copy after it releases exclusion. Independently
readable files do not establish a complete recovery set, intact budget history, or the intended
restore point. Copying databases over live state can mix authorities and reset consumed state.

## Decision

Provide a bounded recovery-set API using a live exclusive host-gate lease. An externally pinned
plan binds that exact gate and a sorted, closed partition below the host's `state/` directory:
one CP SQLite database, Graph databases with Campaign IDs, Run-bound Supervisor budget journals,
and opaque artifacts with expected digests. Missing, unlisted, linked, overlapping or oversized
files and hot SQLite journals fail closed. SQLite backup incorporates WAL state rather than
copying sidecars as independent authorities.

Capture CP and journal databases using SQLite backup. Reuse signed/encrypted Graph retention and
independent restore, including complete Graph history verification. Check source file identities
and SQLite `data_version` across collection while retaining exclusion. Verify copied CP schema,
checkpoint keys/signatures, journal Run bindings, complete budget histories, invocation chains and
CP Run membership without migration, repair or writes. Every previously attempted CP Run needs a
budget journal. Active/uncertain execution blocks this slice; Graphs with reversible-write cleanup
reservations need their separate reconciliation contract.

Pack exact objects into one bounded AES-256-GCM envelope. A separate-domain Ed25519 signature covers
the plan, ordered object digests/sizes, time, key ID, nonce and ciphertext identity. Reuse existing
backup signer/public-key types. Publish one new private fsynced file. Retain its manifest digest
independently: signatures alone cannot reject an older valid backup.

Restore verifies external checkpoint/plan digests, signature, key ID, ciphertext and all objects in
a private workspace. Repeat domain checks before reserving a new destination. Publish a completion
manifest last. Interrupted publication can leave an incomplete destination without that marker or
a runtime gate. Never overwrite, repair, delete or activate source/live state during restore.

## Consequences and remaining boundary

This verifies a declared closed recovery set, not automatic complete-host enrollment. The trusted
owner must include all participating stores and required evidence. Complete first-work enrollment,
exact Supervisor/urgent input/source/Run composition, and comparison with independently retained
prior per-store heads remain separate work. The gate cannot exclude unenrolled writers or prove
external cleanup.

Restore is passive and preserves historical paths and authority references. It creates no gate,
Permit, approval, refreshed budget or verifier. New deployment paths/configuration require separate
review and enrollment. Keys remain private caller inputs. POSIX local SQLite is the supported
boundary; PostgreSQL, network filesystems, remote retention enforcement and whole-host rollback
without independent expected state remain outside this slice.
