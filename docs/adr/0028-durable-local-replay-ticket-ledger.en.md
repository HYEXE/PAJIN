> Languages: [English](0028-durable-local-replay-ticket-ledger.en.md) | [한국어](0028-durable-local-replay-ticket-ledger.ko.md)

# ADR 0028: Durable local Replay Ticket ledger and restart verification

- Status: Accepted
- Date: 2026-07-16
- Implementation: M6-06 local vertical slice
- Amends: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)
- Related: [ADR 0011](0011-durable-control-plane.en.md), [ADR 0024](0024-cooperative-execution-cancellation.en.md)

## Context

The Restricted Reproducer in ADR 0027 binds compiled execution authority to an opaque single-use
ticket. The current process-local `ReplayExecutionAuthority` enforces the issued, claimed, and
finalized state transitions and final receipt verification within one process, but the ledger
disappears when the process exits. A restarted Gate therefore cannot re-verify the issued
compilation, Candidate source root, replay Run, artifact set, and final seal root against the
originally issued authority.

The two integrity seals in a Replay Run alone cannot close this gap. A seal verifies that stored
artifacts have not changed, but it does not prove that the Run actually claimed a pre-issued
single-use ticket or that the same ticket was not reused for another replay Run. Conversely,
passing a mutable runtime object to the Gate eliminates the meaning of independent verification by
the Gate after a restart.

Integrating replay orchestration into the entire PostgreSQL Control Plane at this stage would also
require designing Job leases, fencing, migrations, and role separation. Portable third-party
verification proof would additionally require public-key signatures and a key lifecycle. M6-06
does not broaden the scope that far. It first establishes the minimum durability boundary that
allows one host's KISA positive confirmation and baseline-bound negative retest to survive process
restarts.

## Decision

### Canonical local ledger

PAJIN adds an SQLite Replay Ticket ledger implemented with the Python standard library `sqlite3`
as the canonical durable backend for local execution. The DB resides in
`replay-tickets.sqlite3` under a stable state path derived from the output root and explicitly
injected, rather than inside an individual sealed replay Run directory. Every replay Run created
by one positive or negative KISA execution uses the same ledger path. Cleaning up a Run or
creating a new replay Run does not implicitly change existing ticket authority.

The DB has the following logical structure.

| Structure | Role | Core invariant |
| --- | --- | --- |
| schema metadata | Identifies and versions the ledger schema | Opens only the exact version expected by the implementation |
| tickets | Stores issued compilations and current state | Ticket IDs and replay Run IDs are unique |
| ticket events | Audits state transitions | Appended in the state-transition transaction and never updated or deleted |

PAJIN does not guess that a new schema or existing row is compatible. The writer creates the
current schema only in a new file that has no expected schema, and the verifier checks that the
schema version, required tables, indexes, constraints, and append-only protections are exact.
Version mismatches and partial migrations are not repaired automatically and fail closed. Future
schema changes require an explicit forward migration and a separate compatibility decision.

### Issuance data and binding

A ticket row preserves at least the following authority-bearing values:

- opaque ticket ID, state, issued/claimed/finalized timestamps, and expiry;
- canonical compiled replay specification bytes and their SHA-256 digest;
- Candidate source integrity root;
- context binding the Campaign, Tool specification, and Scenario, together with their respective
  digests;
- exact replay Run ID assigned to the ticket; and
- finalized artifact set digest and final receipt seal root.

The ledger does not trust canonical compilation bytes as a mere blob. On every read, it recomputes
the digest, parses the bytes as a typed contract, canonicalizes them again, and verifies that the
result is byte-for-byte identical to the stored value. A ticket cannot be used if the identity in
the compilation, separate index columns, context digest, source root, and replay Run do not agree.
Neither the compilation nor context is granted authority to store plaintext secrets; ADR 0027's
rejection of secret-bearing fields remains in force.

### Atomic single-use state machine

The only allowed state transitions are:

```text
issued -> claimed -> finalized
```

Issuance, claim, and finalize each run in a short `BEGIN IMMEDIATE` transaction with a
compare-and-set condition. The ticket-row mutation and corresponding append-only event are
committed in the same transaction. Foreign-key checks are enabled, and durability is kept at
`synchronous=FULL` or stronger. When multiple processes or threads concurrently claim the same
ticket, exactly one must succeed.

State-transition timestamps come from a UTC-aware trusted clock owned by the authority. Production
uses the system clock, while tests may inject a clock. The ledger does not trust timestamps
submitted by a facade caller or evidence when deciding expiry or state-transition authority, and
it stores the canonical UTC ISO representation. An issued ticket cannot be claimed after
`expires_at`.

If a claiming process crashes, the ticket is not returned to issued or reassigned to another
replay Run. It remains consumed, and the finalization verifier continues to reject it. A retry must
recheck current policy, budget, cancellation, and source bindings and issue a new compilation,
ticket, and replay Run. This local ledger does not pretend to provide a lease timeout or crash
recovery queue.

Finalize changes the state of a claimed ticket only once. A repeated request for an already
finalized ticket may succeed idempotently as a transport retry only when it contains the same
compilation digest, source root, replay Run ID, artifact set digest, and final seal root. A finalize
retry with any different value, a re-claim of a finalized ticket, a skipped state, or a reverse
transition is a hard failure.

### Read-only verification after restart

The execution Gate and retest Gate receive only a `ReplayTicketFinalizationVerifier` capability,
not an entire mutable authority object. Independently of the writer, the SQLite implementation
provides a read-only verifier that can open a new connection. The verifier uses `mode=ro` in the
SQLite URI and query-only behavior. It does not create a missing file, initialize or migrate a
schema, or modify rows.

After a process restart, the verifier rechecks all of the following conditions:

1. the DB and schema open with the expected version and structure, and exactly one ticket row
   exists;
2. the ticket state is `finalized`, and issued, claimed, and finalized ordering is valid;
3. the stored compilation bytes, compilation digest, and context bindings are self-consistent;
4. the requested Candidate source root, replay Run ID, and canonical compilation digest exactly
   match the issued row;
5. the artifact set digest and final receipt seal root validated by the replay Run loader exactly
   match the finalize row; and
6. the Candidate, original Run/request, replay request, Mode, scenario, threat, Tool, and target
   identities in the replay receipt and compilation pass the existing ADR 0027 Gate checks.

An `issued` ticket or a ticket left `claimed` by a crash is not verified even when sealed artifacts
exist. DB open errors, unknown tickets, duplicate rows, schema corruption, canonicalization
failures, digest mismatches, context/source/replay/final-seal/artifact substitution, and DB errors
observed during verification all fail closed. In this document, `offline verification` means that
a new read-only process, separated from execution authority, rereads the same host's DB. It does
not mean verification from a receipt file alone without the DB.

### Files and trust boundary

The writer creates a new dedicated state directory as owner-only `0700`, and creates the DB file
and DELETE journal sidecar as owner-only `0600`. OS ACLs and operational access controls for the
existing parent output directory, backups, and replicas are the deployer's responsibility. The
read-only verifier likewise does not bypass an unauthorized path or fall back to another file.

The SQLite ledger is the trust anchor for this local boundary. Digest, canonical-byte, schema, and
event checks detect partial writes, accidental corruption, and inconsistent row tampering. They do
not cryptographically prove tampering by a privileged attacker who can write the DB file and
consistently rewrite rows, digests, schemas, and safeguards. Such an OS account or storage
compromise is outside this ADR's trust boundary. Therefore, a copy of the SQLite DB is not portable
cryptographic proof for a remote auditor, and file permissions must not be mistaken for an
integrity seal or signature.

### KISA vertical slice and compatibility

M6-06 injects the same backend interface into both KISA paths:

- positive `kisa-run` claims and finalizes an issued ticket, then reopens the canonical receipt
  through a new read-only verifier and passes it to the reproduction-backed confirmation Gate.
- negative `kisa-retest` verifies every attack replay ticket in the same way while preserving the
  sealed Confirmed baseline and remediation binding. The normal-function parent regression is
  still not negative proof, and the ticket ledger does not change that meaning.

The coordinator result and common Gate expose only the minimum read-only verifier capability, not
the issuer or claimer. Positive and negative Oracles, every expected repetition, raw-transcript
recomputation, and baseline-binding rules remain exactly as defined by ADR 0027. A durable ticket
does not replace those rules; it only additionally binds the fact that the receipt consumed by the
Gate came from one pre-issued compilation.

The existing process-local `ReplayExecutionAuthority` and facade remain for unit tests, embedded
execution, and compatibility with earlier callers. They implement the common Protocol, but the
process-local backend does not claim restart durability and is not the canonical backend for
production-style KISA confirmation or retest.

## Explicit exclusions

- A PostgreSQL Replay Ticket repository, Control Plane API, distributed replay queue, Worker lease,
  retry ownership, and fencing are not included in this ADR. They are designed separately under
  the ADR 0011 repository/migration boundary and in M6-07/M10.
- SQLite is not used as a replacement for a PostgreSQL `SKIP LOCKED` queue or multi-host consensus.
- A crashed claimed ticket is not automatically reissued after a timeout or presumed finalized.
- Public-key signatures such as Ed25519, key rotation/revocation, an external transparency log, and
  third-party or off-host portable proof are in scope for M12 and a new ADR.
- A durable ticket does not replace Campaign Scope, a Capability Grant, the Tool Gateway, Worker
  isolation, budgets, rate limits, cancellation, evidence seals, or a Mode Oracle.

## Consequences

- KISA confirmation and retest Gates can re-verify ticket finalization without mutable memory from
  the executing process.
- Atomic claim and burn-on-crash rules prevent concurrent reuse or post-crash reuse of the same
  execution authority.
- A stable DB and append-only events preserve authority history outside replay Runs, but retention,
  backup, and access control for output state become new operational responsibilities.
- SQLite corruption or a schema mismatch prioritizes fail-closed integrity over availability and
  therefore requires manual recovery or issuance of a new ticket.
- The explicit local OS ACL trust distinguishes process-restart durability from portable
  cryptographic attestation.

## Acceptance and validation

The implementation is complete when automated tests prove that:

- a new ledger is created with the exact schema/version and owner-only permissions, while the
  existing process-local backend remains compatible;
- issuance succeeds, as do claiming after reopening the ledger in a new process, finalizing after
  reopening it in another process, and validation by a `mode=ro` verifier; the verifier neither
  creates nor modifies the DB;
- when separate processes and concurrent connections claim the same issued ticket, exactly one
  succeeds;
- a ticket whose process exits after claim does not return to issued, the verifier does not accept
  it as finalized, and a new replay requires a new ticket and replay Run;
- only an exact finalize retry is idempotent, while retries with a different root, artifact,
  source, compilation, or replay Run and every reverse state transition are rejected;
- expired, unknown, issued-only, and claimed-only tickets and substitution of the Candidate source
  root, replay Run, compilation, Campaign/Tool/Scenario context, final seal root, or artifact set
  fail closed;
- corruption of the schema version/table/index/append-only protection, tampering with rows or
  canonical compilation bytes, and digest/typed-parse/recanonicalization mismatches fail closed;
- the KISA positive and negative coordinators use the injected SQLite authority, and a new
  read-only verifier created after discarding execution authority re-verifies every canonical
  receipt;
- only a positive receipt enters reproduction-backed confirmation, and only a baseline-bound
  negative receipt enters a `fixed` decision; a normal regression, semantic-only result, or Worker
  verdict is not promoted merely because a ticket exists; and
- at the CLI level, normal restart verification succeeds, while a missing or wrong ledger, an
  unfinished ticket, a changed replay Run, or a tampered receipt cannot pass the success Exit Gate.

## References

- [ADR 0011: PostgreSQL durable Control Plane](0011-durable-control-plane.en.md)
- [ADR 0016: Tamper-evident Run integrity chain](0016-tamper-evident-run-integrity.en.md)
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.en.md)
- [ADR 0025: Candidate validation ledger and replay boundary](0025-candidate-validation-ledger-and-replay-boundary.en.md)
- [ADR 0027: Independent restricted reproduction confirmation boundary](0027-independent-reproduction-confirmation-boundary.en.md)
