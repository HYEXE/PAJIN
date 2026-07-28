# GRAPH-005: Durable Single-Campaign SQLite Graph Store

- Status: Durable adapter, signed/encrypted retention, immutable-repository contract, pinned inventory restore, and hard-exit recovery locally verified; Linux CI pending
- Date: 2026-07-28
- Decision: [ADR-0049](../adr/0049-durable-single-campaign-sqlite-graph-store.md)
- Implementation: `pajin.graph.sqlite_store`, `pajin.graph.backup_retention`, and `pajin.graph.backup_repository`
- Tests: `tests/test_graph_sqlite_store.py`, `tests/test_graph_backup_repository.py`

## Outcome

GRAPH-005 selects a separate Graph Store instead of embedding Campaign-wide state in `RunStore`.
`RunStore` remains the sealed, one-Run artifact and audit boundary. The new
`SQLiteGraphStore` owns one Campaign's Canonical Event Log, append-only Projection history,
immutable Snapshot chain, and consumed ActionPermit authority in one local SQLite database. It can
also create and verify a bounded backup plus content-addressed manifest and restore it to a new
database path.

The public facade exposes four protocol-compatible adapters:

- `SQLiteGraphEventLog`;
- `SQLiteGraphProjectionStore`; and
- `SQLiteGraphSnapshotStore`; and
- `SQLiteGraphActionPermitStore`.

Existing in-memory implementations remain the reference semantics and require no migration.

## Durable schema

One database is pinned to one exact Campaign ID and schema fingerprint.

| Table | Authority | Mutation rule |
| --- | --- | --- |
| `graph_store_metadata` | schema version/digest and Campaign ID | immutable |
| `graph_store_writers` | Event and Snapshot writer identities | insert once, immutable |
| `graph_events` | ordered admission/rejection Event Log | append-only |
| `graph_nodes` | exact admitted-node lookup index | transactionally appended with Event |
| `graph_projections` | deterministic revision history including genesis | append-only |
| `graph_snapshots` | content-addressed Snapshot chain | append-only |
| `graph_action_permit_writers` | one compiler identity | insert once, immutable |
| `graph_action_permits` | consumed one-time dispatch authority | append-only |

Update, delete, and replacement triggers protect every managed table. Initialization fingerprints
the exact tables, index, triggers, schema version, application ID, and metadata. Reopen fails
closed on a different Campaign, missing trigger, unexpected table, foreign-key violation, or
failed SQLite integrity check.

## Event transaction

An Event append runs under `BEGIN IMMEDIATE` and verifies:

1. the process-local writer token and durable pinned authority ID/digest;
2. exact Campaign, canonical Event bytes, sequence, and previous digest;
3. unique Event identity and semantic attempt;
4. every Edge against nodes in the Event or the durable admitted-node index; and
5. equal material when a canonical node ID already exists.

The Event row and newly admitted node index rows commit together. An Event can commit before a
Projection refresh; this is an explicit recoverable state rather than a partial Event.

Two processes may reopen the database with the same pinned authority identity. SQLite serializes
their write transactions. If both construct the same next sequence, one append wins and the other
fails stale without changing the log. The caller must reload and resubmit through the authority;
the adapter does not pretend to provide a multi-host leader lease.

## Projection transaction

Projection rows are immutable revision history rather than a mutable head row. `current()` reads
the largest revision. `compare_and_advance()`:

1. revalidates the supplied Events;
2. requires them to be an exact prefix of this database's durable Event Log;
3. locks with `BEGIN IMMEDIATE`;
4. compares expected revision and Event Log head;
5. rejects rollback or a divergent current prefix; and
6. appends one deterministic candidate revision.

Concurrent store instances therefore produce one CAS winner. A process crash after Event commit
but before Projection publication leaves the Projection behind; `GraphProjectionReconciler`
replays the exact durable prefix after reopen. It never overwrites divergence.

## Snapshot transaction

The Snapshot writer identity is independently pinned. Snapshot append exact-validates the creator,
predecessor, and embedded Projection, then requires that Projection revision/digest to already
exist in the same database. Snapshot identity and predecessor form an immutable chain. Exact
`GraphSnapshotRef` resolution preserves the GRAPH-003 and GRAPH-004 decision contract after
restart.

## SQLite and filesystem boundary

The adapter uses:

- SQLite DELETE journal mode and `synchronous=FULL`;
- `BEGIN IMMEDIATE` for writes;
- foreign keys on, `trusted_schema` off, and read-only/query-only readers;
- a bounded busy timeout;
- canonical UTF-8 JSON BLOBs with model and index cross-checks;
- owner-only parent/file modes on POSIX;
- rejection of symlink path components, symlink/hard-linked database leaves, and unsafe
  journal/WAL sidecars; and
- file and direct-parent identity checks when connections open.

These controls establish a host-local durable adapter. They do not claim protection from a
privileged attacker replacing arbitrary ancestors concurrently or disk/controller failure beyond
SQLite's guarantees.

## Verified backup and restore

`SQLiteGraphStore.create_backup()` uses SQLite's online backup API to capture one consistent source
transaction into a private temporary file. Before publication, it checks the exact schema and
SQLite integrity and then revalidates:

- the complete Event hash chain and admitted-node index;
- every stored Projection against its exact Event prefix;
- the Snapshot predecessor chain and embedded published Projection; and
- every consumed ActionPermit against its Snapshot and pinned compiler writer.

The database is bounded to 256 MiB. A canonical
`pajin.dev/sqlite-graph-backup-manifest/v1alpha1` sidecar binds its SHA-256, byte length, Campaign,
schema, Event head, current Projection, Snapshot head, and Permit head. Both files use private
temporary files, file `fsync`, exclusive hard-link publication that cannot replace an existing
leaf, and parent-directory `fsync` on POSIX. A crash can leave at most one half of the pair; restore
requires both and therefore treats such output as incomplete.

`SQLiteGraphStore.restore_backup()` strictly parses and content-address verifies the manifest,
checks the exact database digest, repeats the complete logical-state verification, compares that
state to the manifest, and publishes only to a previously absent destination. It never overwrites
a live or previously restored database. This is a self-consistency and local disaster-recovery
boundary, not an external authenticity claim.

## Signed and encrypted retention

`SQLiteGraphStore.create_retained_backup()` creates the verified plaintext pair only in a private
temporary workspace. It encrypts the bounded database with AES-256-GCM and a fresh 96-bit nonce,
then signs a domain-separated canonical statement with an externally supplied Ed25519 signer. The
statement binds the complete plaintext backup manifest, encryption-key ID, nonce, ciphertext
digest, and ciphertext length. The published pair contains ciphertext and a signed manifest;
neither the 32-byte encryption key nor the Ed25519 private key is serialized.

`restore_retained_backup()` requires the expected external encryption key and ID plus an
out-of-band trusted Ed25519 public-key set. Signature verification precedes ciphertext read and
decryption. Restore then verifies the ciphertext digest, AEAD authentication, plaintext digest,
and the complete ADR-0049 logical state before exclusively publishing a new database.

The conformance drill copies the pair to a detached directory and restores it in a fresh process
without the source database. This proves transport independence inside the test host.

## Immutable repository and signed inventory

`SQLiteGraphBackupRetentionBackend` defines a provider-neutral `put_if_absent()` and
version-pinned `read_exact()` boundary. Each request binds exact content, object key, Campaign,
retention deadline, and object-lock mode. Publication accepts only a receipt that preserves every
requested field, includes a fixed object version, and retains at least through the requested
deadline. Ciphertext and signed manifest become one content-addressed publication only after both
receipts pass.

`append_sqlite_graph_backup_inventory()` signs cumulative, single-entry extensions. Verification
requires a contiguous signature-valid prefix chain and can pin any already observed revision with
an externally stored `SQLiteGraphBackupInventoryAnchor`. Restore requires that anchor, rejects
rollback, forks, reordering, duplicates, foreign Campaigns, and repository substitution, reads the
exact receipt versions, and then runs the complete signed/encrypted restore verification.

The locked in-memory backend in tests demonstrates no-overwrite and retention failure behavior. It
is not a production object-store adapter and its receipts are not provider attestations. Actual
off-host scheduling, authoritative cloud object-lock evidence, independently persisted anchors,
KMS/HSM integration, and restore drills on another host remain deployment work.

## Verified conformance

The focused Graph suite passes 78 tests locally.
Two POSIX link tests are correctly skipped on Windows and remain Linux CI obligations.

The durable tests cover:

- reopen of Events, Projection, Snapshot, and exact reference resolution;
- idempotent Proposal retry after restart;
- Event-committed/Projection-lag recovery and idempotent reconciliation;
- one winner for cross-instance Event append and Projection CAS;
- rejection of a Projection built from another Event Log;
- Campaign and writer-identity pinning;
- Snapshot predecessor and durably-published Projection checks;
- append-only trigger and schema-fingerprint tamper rejection; and
- stale Decision rejection when the durable Event Log is ahead;
- exact backup/restore of Events, Projection, Snapshot, and consumed Permit state;
- manifest and database tamper rejection plus no-overwrite restore; and
- encrypted retained-object publication without serialized secret material;
- external signing-key trust, wrong-key, signature-tamper, and ciphertext-tamper rejection;
- detached fresh-process restore with exact Event, Projection, and Snapshot state; and
- put-if-absent retry, object-lock deletion denial, shortened-retention receipt rejection, and
  partial-publication failure;
- signed cumulative inventory verification plus external-anchor rollback, fork, and reorder
  rejection;
- exact-version backend restore and tamper rejection before destination publication; and
- real subprocess `os._exit` immediately after Projection commit, before transaction commit, and
  after backup publication.

The adjacent GRAPH-006 Worker bridge now also exercises real subprocess termination after Permit
commit, after the RunStore claimed append, and after a durable external Gateway side-effect
marker. Reopen reconciliation preserves the consumed Permit and never redispatches.

## Compatibility, migration, and rollback

This adapter is opt-in and has no legacy Mode, CLI, API, or `RunStore` format change. There is no
existing production Canonical Graph database to migrate. The trusted legacy-to-Proposal adapters
defined by ARCH-001 remain future work and do not auto-admit converted material.

Before runtime wiring, rollback is to stop constructing `SQLiteGraphStore` and retain the database
as audit evidence. Once a Campaign uses this Event Log as canonical authority, rollback must export
and verify its exact Event chain; deleting or rewriting admitted history is not an allowed rollback.

## Remaining boundary

GRAPH-006 now combines the latest-revision comparison with a consumed-on-issuance ActionPermit
dispatch claim in one SQLite transaction. The following remain after GRAPH-005/006:

- multi-host leader election, leases, or PostgreSQL/HA storage;
- exhaustive process-kill and power-loss injection at every remaining SQLite/filesystem
  synchronization boundary;
- actual provider-backed remote retention transport and scheduling, restore drills on another
  host, authoritative object-lock evidence, compaction, KMS/HSM integration, or independently
  persisted anti-rollback anchors;
- admission queue/runtime service wiring; or
- B2.9 collaboration projections and Supervisor execution.

GRAPH-006 does not treat `GraphDecisionPreflight` as executable authority. External Worker side
effects and the SQLite commit are not physically atomic; the boundary remains at-most-once and
never automatically redispatches after the consumed claim.
