# OPS-005: Separately Retained Recovery Witness

## Boundary and implementation

`pajin.operations.checkpoint_witness` adds witness v1 records and explicit
`pajin-recovery-anchor-v2` bindings. Distinct Ed25519 keys, domain-separated signatures,
canonical bytes, complete sequence/hash chains and exact anchor enrollment are
checked. Both logs are bounded to 4,096 records; paths must be private, owned,
regular, singly linked and disjoint from application state and each other.

Publication requires the expected sequence and both private publisher keys before
stopping any owned source. Under nonblocking exclusive locks in anchor-to-witness
order, a witness intent is fsynced before the anchor append. Reopening both logs
must agree. This is recoverable ordered publication, not a distributed atomic commit.

`restore`, `verify` and `resume` require the v2 witness even for an independently
pinned old archive. One-sided rollback, valid suffix removal, partial append, missing
store, signature failure and a conflicting publication fail closed before restore
materialization. Existing execution approval, one-use recovery authorization and
uncertain usage charges remain in force.

## Operator commands

Initialize an empty OPS-004 anchor first. Enroll its witness before pinning source and
target deployment documents. Command arguments below are operator-selected paths;
keys are files containing 32 private bytes and must never enter source control.

```sh
python -m pajin.operations.checkpoint_witness init \
  --directory "$WITNESS_DIRECTORY" --anchor-directory "$ANCHOR_DIRECTORY" \
  --anchor-binding "$V1_BINDING" --output-binding "$V2_BINDING" \
  --authority-id recovery-witness --public-key "$WITNESS_PUBLIC_KEY_HEX"

python -m pajin.operations.checkpoint_anchor inspect \
  --directory "$ANCHOR_DIRECTORY" --binding "$V2_BINDING" \
  --witness-directory "$WITNESS_DIRECTORY"

python -m pajin.operations.checkpoint_witness restore-anchor \
  --directory "$WITNESS_DIRECTORY" --anchor-binding "$V2_BINDING" \
  --target-directory "$NEW_EMPTY_ANCHOR_DIRECTORY" --output-binding "$NEW_BINDING_FILE"
```

Use `--witness-directory` for checkpoint/restore/verify/resume and `--witness-key`
only for checkpoint publication. A recreated anchor has the same enrollment but a
new operator-chosen path. Inspect it from a fresh process before manually selecting
that path for normal recovery. Restoration does not start application writers.

## Compatibility and rollback

V1 anchor bytes and CLI behavior are preserved. V2 cannot omit its witness or be
relabeled v1. Empty-anchor enrollment does not protect older unobserved checkpoints.
After adopting v2, retain compatible readers and both latest stores; do not remove
the witness or rewrite deployment pins to downgrade protection. A missing or rolled
back witness requires independent recovery evidence, not automatic local repair.

## Verification and limits

`tests/test_checkpoint_witness.py` covers authentication, rollback, malformed chains,
file aliases, concurrent CAS, early refusal and create-only CLI reconstruction.
`tests/checkpoint_witness_process_probe.py` injects actual SIGKILL after witness fsync
and verifies refusal and explicit restoration in fresh processes, followed by 32
publication/read cycles. `scripts/witness_checkpoint_rehearsal.py` connects this to
owned Linux PostgreSQL, SQLite, RunStore, mTLS CP/Worker and approved continuation.
The dedicated OPS workflow requires all 21 checks and independent residue absence.
The crash probe retains a 30-second limit for each of its 35 child processes and
a 1,200-second total controller budget. The earlier generic 180-second command budget
expired when this cumulative probe overlapped the full regression run. That incomplete
attempt and its observed cleanup are retained separately; no checks or per-child
timeouts were weakened. The final rehearsal ran without that overlap and completed
all checks in 184.27 seconds. The existing OPS-003 recovery rehearsal also passed
its eleven checks in 73.15 seconds on the same final runtime image.

The current owned Linux rehearsal passed all 21 checks, including a fresh PostgreSQL restore,
old archive/pin and anchor-suffix rollback refusal before materialization, independent process
verification, read-only recovery mounts, approved continuation and one-use resume. Actual
SIGKILL after witness fsync was followed by refusal, explicit reconstruction with the original
retained, and 32 fresh-process publication/read cycles. A separate read-only Docker observation
found no remaining containers, networks or volumes in the fixture's three ownership families.
Source and immutable runtime image evidence are retained with the private result.

No physical separate host, actual power loss, production deployment, automatic failover or
long-duration availability guarantee follows from these bounded checks. Simultaneous
rollback of anchor and witness remains indistinguishable from the old valid state.

The independent crash fixture runs after the approved application continuation so its 32 fresh
processes cannot consume the application's existing approval-intent window. It uses separate
temporary state and signing keys; approval expiry and per-process limits are unchanged. All
21 checks and independent cleanup remain necessary, including when the final stress phase fails.
The first remote attempt at `dd039ef` reached `target-resume` with 15 witness checks before
failing; its exact private-command cause is not available in the public report. Independent
cleanup succeeded. A deterministic regression separately reproduced the scheduling risk; the
corrected local Linux run passed all 21 checks and 32 fresh-process cycles in 187.20 seconds.
Nine independent resource queries found no owned containers, networks or volumes. The corrected
commit still requires fresh measured conformance.
