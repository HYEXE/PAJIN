# OPS-004: Independently retained checkpoint head

Status: Implemented; isolated Linux verification passed. New remote conformance is pending.

This extends [OPS-003](OPS-003-managed-hybrid-recovery.md) with an optional enrolled
recovery head. It rejects a previously valid archive and old archive pin after an
operator publishes a newer checkpoint to separately retained storage. It does
not detect rollback of that independent store itself.

## Enrollment and commands

Provision a private operator-owned directory on independently retained storage.
Application writers must not mount it. Keep the Ed25519 publisher key separately
from application state and recovery readers. Initialize it once:

```sh
python -m pajin.operations.checkpoint_anchor init \
  --directory "$ANCHOR_DIRECTORY" --binding "$NEW_BINDING_FILE" \
  --authority-id "$RECOVERY_AUTHORITY" --public-key "$PUBLISHER_PUBLIC_KEY_HEX"
```

The returned `AnchorBinding` becomes `recovery_anchor` in both independently
pinned deployment inventories. It contains the version, authority ID, public key
and genesis SHA-256. Its directory is supplied separately at execution time.
Removing enrollment or selecting another binding is an explicit trust change;
an archive cannot supply that authority. Existing unenrolled inventories serialize
exactly as before. Enrollment requires a new cold checkpoint; old unenrolled
archives cannot be silently upgraded.

Use existing OPS-003 checkpoint arguments plus:

```sh
--anchor-directory "$ANCHOR_DIRECTORY" \
--anchor-key "$PUBLISHER_PRIVATE_KEY_FILE" --expected-anchor-sequence 0
```

The key file contains 32 raw Ed25519 private-key bytes. Sequence zero means no
checkpoint has yet been published. Later publication requires the observed
current sequence. Archive authentication and source stop complete before the
signed head is published. A failed or uncertain publication keeps the source
stopped and any archive as evidence; it is not automatically retried or selected
for recovery. An operator must inspect the retained head and reconcile the
failure. Do not delete or reset the store to force publication.

Restore, verify and resume add `--anchor-directory` and do not need the publisher
key. The directory may be mounted read-only by recovery processes. Missing
enrollment material, an empty head, stale archive, wrong source, damaged chain,
conflicting publisher or unavailable store fails closed before target activity.
Verification includes `independent_checkpoint` in its receipt; the separate
resume signature binds that exact receipt and current head.

```sh
python -m pajin.operations.checkpoint_anchor inspect \
  --directory "$ANCHOR_DIRECTORY" --binding "$BINDING_FILE"
```

Inspection has no recovery, publication or execution side effects. It reports
the current signed entry, or `null` for a valid newly initialized empty store.
There is no implicit initialization, repair, truncation or history rotation.

## Durability and concurrency boundary

The store is a private genesis, empty lock file and bounded canonical JSON-lines
chain. Publication checks all signatures, contiguous sequence, previous digest
and unique archive digest. It appends under an exclusive nonblocking `flock`,
calls `fsync` and rereads the chain. Recovery holds a shared nonblocking lock and
checks the head before and after the operation. Conflicts require a new explicit
operator action; there is no automatic retry of an uncertain resume request.

The store permits 4,096 entries. Capacity is checked before stopping the source;
exhaustion requires a separately designed enrollment migration. A crash that leaves a partial last record fails
closed. It is not counted as a successful publication.

## Verification and limits

Focused tests cover old archive plus old pin rollback, publication compare and
swap, duplicate archive rejection, wrong signer/genesis/source, missing files,
symbolic links, malformed or reordered chain, concurrent publication and
pre-side-effect restore/verify/resume rejection. Existing OPS-003 serialization
and tests remain applicable.

The actual Linux arm64 exercise passed all 15 checks using fresh source and target
PostgreSQL containers, distinct application volumes, a separately retained anchor
volume, read-only recovery access and fresh CLI processes. Two durable checkpoints
were published. The old archive together with its old pin was rejected before
target materialization; the latest archive restored and verified in a fresh process.
Application writers had no anchor mount, and recovery could not write the anchor.
Expired, unapproved and wrong-role resume attempts failed. Separately approved
continuation succeeded once and preserved the unacknowledged-call charge.

The unchanged OPS-003 exercise also passed its 11 checks against the same product
code digest. Independent Docker observations found no owned resources remaining.
These local measurements preceded publication of the code checkpoint.

The first attempt of [OPS conformance 34669911248](https://github.com/HYEXE/PAJIN/actions/runs/34669911248)
then passed the original 11 and additional 15 checks on Ubuntu 24.04, Linux/amd64,
Python 3.12.14 at clean commit `1fd37d16d05887f9ff7956ccea4986b77cd4fe6c`.
The combined outer runner took 248.66 seconds. Both probe processes exited zero,
and the independently recomputed tracked-source commitment matched
`6326d2448a5a40dbe415e553aca8e2386dd2c15edc6e7635f0c59c8c18f84e4f`.
Cleanup and a separate read-only audit found zero owned containers, networks and
volumes without fallback removal. Only three bounded public summary files were
retained as workflow artifacts. The dedicated runner remains an isolated exercise;
it does not establish the physical or production guarantees excluded below.

The first OPS-004 attempt failed before checkpoint creation: its volume initializer
changed ownership before changing permissions under restricted capabilities. A
bounded Linux reproduction confirmed that failure and the corrected order. The
fixture now sets permissions before ownership and retains initialization stderr;
no extra capability or product permission was added. The first attempt and the
successful second attempt remain separate private evidence.

Path separation is checked by code; physical storage independence and retention
policy remain deployment responsibilities. Whole-anchor rollback, deletion of a
valid signed suffix by the trusted storage operator, hostile lock-file
replacement, distributed concurrent hosts, physical-host loss, power failure and
production failover are not established. The existing source Docker fencing
still operates in one selected daemon context. No new execution or Finding
authority is created.

Decision: [ADR 0287](../adr/0287-retain-a-recovery-head-outside-restored-application-state.md).
