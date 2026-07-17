> Languages: [English](0029-control-plane-replay-orchestration.en.md) | [한국어](0029-control-plane-replay-orchestration.ko.md)

# ADR 0029: Control Plane Replay orchestration and burn-on-claim delivery

- Status: Accepted
- Date: 2026-07-17
- Scope: M6-07B Control Plane vertical slice
- Extends: [ADR 0011](0011-durable-control-plane.en.md), [ADR 0012](0012-lease-aware-worker-daemon.en.md)
- Depends on: [ADR 0024](0024-cooperative-execution-cancellation.en.md), [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md), [ADR 0028](0028-durable-local-replay-ticket-ledger.en.md)
- Separate local scope: M6-07A Local Replay orchestration

## Status note

This ADR was Accepted on 2026-07-17 and fixes the distributed trust boundary and delivery semantics
for M6-07B. The first authority-state slice now includes a versioned Replay aggregate schema, a
repository-managed v1-to-v2 migration with strict startup validation, an internal-only strict Job
payload, and atomic batch creation, burn-on-claim, heartbeat, lease-expiry, and cancellation state
transitions. This does not complete M6-07B. The Artifact repository and server-owned source
admission, new-identity retry issuance, durable budget/rate permits, Replay executor wiring, typed
server-side artifact finalization and result-digest verification, the Gate, and live PostgreSQL
migration/locking acceptance remain outstanding. Until those boundaries are complete, the Control
Plane cannot claim to provide full durable Replay orchestration.

## Context

M6-07A and M6-07B use the same KISA Replay contract but have different authorities. M6-07A is an
explicit Local path in which one process directly owns local sealed Runs, the same live
budget/rate-limit state, and the ADR 0028 SQLite ticket ledger. In M6-07B, by contrast, process and
failure boundaries exist among the Operator, Control Plane API, PostgreSQL, Worker daemon, and
artifact storage. Pathnames, mutable runtime objects, or SQLite files from the local path must not
be extended into remote Worker trust.

At the time this decision was written, the implementation had the following concrete gaps:

- [`JobKind` and `CompleteJobRequest`](../../src/pajin/control_plane/models.py) defined only the
  public `campaign`/`tool-loop` kinds and an arbitrary `dict` result. They had no Replay-specific
  typed finalization, ticket fence, or result digest.
- [`ControlPlaneRepository.initialize`](../../src/pajin/control_plane/database.py) used
  `create_all` and created only Run, Job, checkpoint, approval, and event tables. It had no Replay
  schema or deployable forward-migration path.
- [`ControlPlaneService.claim_job`, `complete_job`, and `_expire_leases`](../../src/pajin/control_plane/service.py)
  leased a normal Job, stored result JSON as-is to complete the entire Run, and returned the same
  Job row to queued when its lease expired. Those requeue semantics were inappropriate for a
  burn-on-claim Replay ticket.
- [`WorkerDaemon._finalize`](../../src/pajin/control_plane/worker.py) retried the same completion
  call after a transport failure, but the server did not reopen Replay artifacts and verify the
  exact result digest.
- [`CampaignJobExecutor` and `ToolLoopJobExecutor`](../../src/pajin/control_plane/executors.py)
  used a trusted registry, but their result `runPath` was an absolute path on the Worker host. The
  API process could not guarantee that path's object identity, immutability, or seal.
- [`GatewayRestrictedReproducerRuntime._finish`](../../src/pajin/replay/runtime.py) seals artifacts
  twice in one process, finalizes the ticket, and then reopens the verified result. Moving this
  sequence so that a Worker also owns PostgreSQL authority would trust the Worker's self-verification.
- [`KISAReplayCoordinator`](../../src/pajin/modes/ai_redteam/replay.py) is the existing reference
  point for rereading sealed sources and exact KISA contracts, while
  [`SQLiteReplayExecutionAuthority`](../../src/pajin/replay/sqlite_tickets.py) is the reference
  point for local restart verification. Neither replaces a distributed queue and artifact handoff.

The first implementation slice after acceptance closes part of that baseline without weakening the
decision: public Job kinds remain `campaign` and `tool-loop`, while a separately typed internal
Replay payload is persisted with batch/item/ticket/event authority state and burn-on-claim fencing.
Repository startup now performs a versioned v1-to-v2 migration or rejects incompatible schema
state. Generic Job completion and failure paths remain unavailable to Replay Jobs. The remaining
Artifact, retry issuance, permit, executor, typed finalization, Gate, and live PostgreSQL acceptance
work listed in the status note is intentionally still outside the completed slice.

M6-07B therefore cannot be implemented merely by adding a public `JobKind.REPLAY`, or by storing a
Worker-submitted Candidate, Capability Grant, contract, `runPath`, and verdict. The at-least-once
lease recovery of a normal Job must also be explicitly reconciled with the burn-on-claim rule of a
single-use Replay ticket.

## Decision

M6-07B adopts the following boundaries.

### Separation of Local M6-07A and Control Plane M6-07B

- M6-07A retains a single-host Local runner and SQLite ticket ledger. Local filesystem paths and
  process-local objects are valid only within that boundary.
- Authority for M6-07B belongs to the Control Plane service and PostgreSQL. The SQLite ledger is not
  replicated, and Local authority held by a Worker is not treated as a proxy for PostgreSQL.
- Both paths share the typed Candidate, exact Mode contract, compilation, Outcome, Oracle, and
  common Gate semantics from ADR 0027. Each boundary separately implements storage identity,
  ticket lifecycle, leases, and finalization.
- The first Control Plane Mode is restricted to the existing explicitly registered exact contracts
  for KISA M03, M06, and A04. A generic predicate based on structural similarity of a Candidate
  does not admit a new scenario or Tool to automatic execution.

### Server-owned source admission and immutable `ArtifactRef`

The Control Plane exchanges only versioned `ArtifactRef` values, never raw paths. The minimum
contract contains an opaque `artifact_id`, repository version, media/schema kind, byte length,
content digest, Run ID, integrity-root digest, and creation identity. The storage key is internal
to the repository; neither an Operator nor a Worker may choose an arbitrary path, URL, symlink, or
object key.

The first single-host implementation may use an owner-controlled filesystem repository. The API
takes an artifact from a staging directory, checks its canonical path and size bound, computes its
content digest, and registers it as an immutable object. The bytes of an `ArtifactRef` cannot
change after registration; new bytes produce a new version and reference. Both source and replay
output pass through the same import rules. A Worker's absolute `runPath` is not part of the Control
Plane contract.

When creating a Replay batch, the server admits the source in this order:

1. the server resolves the `ArtifactRef` through the repository and directly verifies the entire
   Run integrity chain and every sealed artifact;
2. the server rereads the sealed Campaign, Plan, Capability ledger, budget/rate-limit snapshot,
   Candidate, and validation projection with typed loaders;
3. the server derives eligible Candidates and Mode contracts from the exact KISA registry and runs
   the Replay Compiler; and
4. the server stores the original source root, canonical Candidate/contract/compilation digests,
   and new Replay Capability in PostgreSQL.

A Worker-submitted Candidate, contract, comparison rule, Capability Grant, target, Tool arguments,
source root, or eligibility flag is not an authority input. The Worker claim envelope carries only
the exact compilation already derived and stored by the server and a short-lived, non-delegable
Capability.

### PostgreSQL Replay aggregate and forward migration

The new schema has at least the following aggregates.

| Aggregate | Role | Core invariant |
| --- | --- | --- |
| `cp_replay_batches` | Source snapshot and entire Gate lifecycle | Bound to one immutable source `ArtifactRef`/root, Mode, purpose, policy version, and CAS version |
| `cp_replay_items` | Progress for each eligible Candidate | Candidate/contract/compilation digest and required repetition count are unique within the batch |
| `cp_replay_tickets` | Authority for one execution attempt | Bound to the item attempt, Job, Replay Run ID, Grant, source root, claim principal/fence, and exact finalization |
| `cp_replay_events` | Replay authority audit history | Appended in the state-transition transaction and never updated or deleted |

Separate tables may store Artifact metadata, durable budget reservations, and rate-limit
buckets/permits. The database enforces every authority-bearing foreign key and uniqueness/check
constraint. A Replay event and corresponding `cp_events` summary, when needed, are written in the
same transaction.

The state machines distinguish at least the following meanings:

```text
batch:  planned -> running -> gating -> completed
                    |           |
                    +----------> failed / cancelled

item:   pending -> queued -> running -> verified -> gated
                               |
                               +-> retry-pending / failed / cancelled

ticket: issued -> claimed -> finalized
           |          |
           +----------+-> abandoned
```

`abandoned` is not an Oracle determination that execution failed. It is a terminal authority state
meaning the ticket's authority and result cannot be used by the Gate. An Item may proceed with a
new attempt when policy and remaining budget permit, but an abandoned ticket is never revived.

As anticipated by ADR 0011, this schema does not depend on `create_all` at production startup. A
versioned, forward-only migration adds tables, enum/check constraints, indexes, triggers, and links
to existing Jobs and records the migration version. The server refuses to start against an older
or unknown schema rather than guessing compatibility. SQLite may serve as a repository unit-test
adapter, but it does not replace verification of PostgreSQL row locks, constraints, and migrations.

### Internal-only Replay Job and burn-on-claim lease

A Replay Job is an internal kind that is not exposed through the Operator submission API. Public
`SubmitRunRequest` cannot select `replay`; only the trusted Control Plane batch service creates a
Job from a validated `cp_replay_item` and ticket. The exact Replay executor must also be explicitly
installed in the Worker startup registry. The Job payload contains only opaque
batch/item/ticket/artifact references and a server-generated compilation identity. It contains no
executable path, arbitrary URL, callable, or Worker-selected Grant.

The normal Control Plane queue retains at-least-once delivery, but Replay binds it to tickets as
follows:

- the transaction leasing a queued Replay Job changes exactly one `issued` ticket to `claimed` and
  stores the authenticated Worker principal, lease identity, attempt number, and fencing value.
  The ticket is burned from the moment of claim.
- each internal Replay Job represents only one ticket attempt and may not requeue execution of the
  same Job row. The Item owns the Replay retry count separately from reuse of a normal Job's
  `max_attempts`.
- when the lease ends after a heartbeat failure or explicit retryable failure, the existing Job is
  made terminal and the claimed ticket becomes `abandoned`. `_expire_leases` must not return that
  Job/ticket to queued/issued.
- if retry is allowed, the server rechecks source root, cancellation, policy, budget, and rate
  state, then creates a new attempt number, ticket ID, Replay Run ID, and Job ID.
- even when a claim response is lost and the Worker cannot execute, the claimed ticket is not
  revived. Preventing duplicate use of the same execution authority takes priority over the loss
  of availability.

Thus multiple delivery attempts are possible at the Item level, but each ticket and Job attempt is
single-use. This exception does not discard the general Job lease recovery in ADR 0012; it applies
a stronger rule only to the internal Replay kind.

### Authenticated Worker principal and fencing

The `worker_id` string in the current request body alone does not grant Replay authority.
Authentication middleware binds the established Worker principal subject to a registered Worker
identity, and the actor for claim, heartbeat, permit, and finalize is derived only from that
principal.

Every Replay mutation requires an exact match of:

- Worker principal subject and permitted Replay executor profile;
- Job ID and lease-token digest;
- batch, item, and ticket IDs and attempt number;
- the ticket's monotonically increasing fencing value;
- source root and compilation digest; and
- active Run/batch/item/ticket state and cancellation fence.

When a new attempt is created or a ticket is abandoned, cancelled, or finalized, its previous
fence is immediately invalid. A stale Worker cannot perform a heartbeat, Tool-call permit,
artifact-import completion, or finalization. Theft of Worker credentials or compromise of a Worker
host is a separate operational threat, but even such a Worker must not be able to finalize a
server-unissued contract/Capability or stale attempt as a PAJIN result.

### Durable budget reservation and request-rate authority

Replay batch admission calculates the worst-case Tool calls across every eligible item and
repetition and atomically reserves the Campaign budget in PostgreSQL before creating the first
Job. A reservation is bound to its batch/item/ticket and cannot exceed the same Campaign limit
shared by other Local or Control Plane executions. Worker-reported `usedCalls` or a local snapshot
is not a basis for settlement.

Before every actual Tool call, the Worker's trusted Replay runtime calls an internal permit
endpoint. The server rechecks the active principal/lease/ticket fence, issues a one-use permit for
the canonical target/Tool/call ordinal while consuming reserved budget, and updates a durable
rate-limit bucket or append-only entry. The permit cannot be reused for another ticket, target,
Tool, or ordinal. Even when multiple Workers request permits concurrently, database locks and
unique constraints must prevent issuance beyond the budget and rate limit.

An issued permit is considered consumed and is not automatically refunded even when execution is
uncertain. No new permit is issued after abandonment or cancellation; only clearly unissued
reservations may be released with an audit event. A new attempt must pass the remaining durable
budget and rate window again.

### Separating Worker execute/seal from authority finalize phases

The distributed path splits the current process-local `_finish` into two phases:

1. **Worker execute/seal:** the Worker uses only the server-issued compilation and permits and
   executes through the ordinary Tool Gateway/Worker boundary. It writes the canonical artifact
   set, Outcome, and execution receipt to a separate Replay Run, completes both seals, and imports
   them into the managed repository. This receipt indicates which bytes the Worker created and
   sealed; it is not ticket-finalization authority.
2. **Control Plane authority finalize:** the server reopens the immutable Replay `ArtifactRef` and
   directly verifies the content digest, both seals, artifact set, fresh request/evidence lineage,
   Mode Oracle result, source root, Candidate, compilation, ticket, and Replay Run identity. It
   creates typed finalization only from verified values and finalizes the ticket, Job, item, and
   event in one PostgreSQL transaction.

Replay completion does not use the generic `CompleteJobRequest.result: dict`. A dedicated typed
command binds at least the exact Job/ticket/fence, immutable `ArtifactRef`,
compilation/source/replay-Run identity, artifact-set digest, both seal roots, Outcome digest, and
canonical `result_digest`. The server recomputes authority-bearing values from artifact bytes and
does not trust a Worker-submitted verdict or digest as-is.

If the finalization transaction succeeds but its HTTP response is lost, an exact retry by the same
authenticated principal with the same canonical `result_digest` and ArtifactRef idempotently
returns the stored success. A retry differing in any value is a conflict. If the lease/fence ends
before the transaction commits, the attempt is abandoned and late finalization is rejected. The
Gate subsequently re-verifies the finalized ticket and sealed artifact through a new read-only
repository/session and therefore does not trust a mutable validation object from the API process.

### Source-root CAS confirmation Gate

The Worker neither runs the confirmation Gate nor submits `confirmed`. Control Plane authority
runs the Gate after every required item has an exact finalized receipt.

1. the server snapshots the batch's immutable source `ArtifactRef`, admitted source root, CAS
   version, and sorted set of item/finalization digests;
2. outside a database transaction, it reopens source and replay artifacts through new handles and
   applies the ADR 0027 common Gate and exact KISA Oracle/coverage rules;
3. it creates Gate output as a new immutable versioned validation-projection artifact whose parent
   is the source reference/root, without overwriting the imported source object; and
4. in a short transaction, it changes batch/items to gated/completed and records the projection
   reference only when `batch_id`, state=`gating`, CAS version, source ArtifactRef/root, and item
   digest set all still match the snapshot.

If the source has been substituted with another object/version/root, or the item set, ticket
finalization, cancellation, or policy state has changed, compare-and-set fails and does not publish
the confirmation projection. A Gate retry performs the entire verification again from a new
snapshot. Only a Gate retry for the exact `result_digest` of an already completed result is
idempotent; it neither reinterprets nor modifies the existing sealed source.

### Cancellation, abandonment, and lock ordering

ADR 0024 typed cooperative cancellation is used unchanged. Cancellation of a Run or Replay batch
immediately fences new Job claims and Tool-call permits and makes queued Jobs and issued/claimed
tickets terminal. A running Worker may observe cancellation through a heartbeat conflict and
attempt bounded cleanup and a sealed local receipt. That receipt remains only process-local
cleanup evidence; it does not prove Control Plane physical quiescence or rollback of external
effects.

A claimed ticket becomes `abandoned` after lease expiry, a stale fence, Worker crash, forced
cancellation, conflicting finalization, or retryable execution failure. Abandoned artifacts and
tickets are not included in Gate coverage. Cancellation preserves already finalized history and
events but stops new Gate publication. Operational `abandoned` is not mixed with validation
dispositions such as ADR 0027 `inconclusive`, `needs-review`, or `confirmed`.

PostgreSQL mutations extend the dependent-to-Run ordering from ADR 0023/0024 and observe the
following order:

```text
cp_jobs (stable Job ID order)
  -> cp_replay_tickets (stable attempt/ticket order)
  -> cp_replay_items (stable item order)
  -> cp_replay_batches
  -> budget reservations / rate-limit buckets (canonical key order)
  -> cp_runs
```

If a path has no row for an earlier stage, it skips that stage but never locks in reverse order.
Cancellation locks active Jobs in stable order, then Replay dependents, and the Run last. Issuance,
claim, lease expiry, permits, finalization, and Gate publication use the same order. Artifact
hashing, seal verification, and Oracle execution occur without database locks; immutable
references and CAS commit the result.

## First vertical slice and non-goals

The first implementation is a KISA positive-confirmation vertical slice using PostgreSQL, the
Control Plane API, a managed filesystem artifact repository, and one or more Worker processes on a
single host. It verifies concurrent Worker claims, API/Worker restarts, and response loss even on
one host. The `ArtifactRef` abstraction is used from the beginning to avoid raw-path dependencies.

The following are outside the first vertical slice of this ADR:

- multi-host artifact transfer, shared network filesystems, an S3-compatible object store,
  cross-region replication, and object-store credential delegation;
- using SQLite as a PostgreSQL queue or distributed ticket authority;
- public Operator-authored Replay Jobs, automatic registration of arbitrary Modes/Tools, and T3/T4
  or non-idempotent replay;
- portable third-party attestation, public-key receipt signatures, a transparency log, and key
  lifecycle;
- rollback of external side effects caused by Worker-host compromise or destination-level
  exactly-once semantics; and
- a cancellation-acknowledgement protocol through which the Control Plane proves physical fleet
  quiescence.

Multi-host/object-store support is added only after a separate ADR designs an immutable
`ArtifactRef` resolver, upload authorization, retention, encryption, tenant isolation, and
cross-service authentication.

## Consequences

- A Worker is an execution principal, not the authority for Candidate selection, Replay authority
  issuance, finalization, or confirmation.
- Normal queue at-least-once recovery is retained, while single-use tickets and Job attempts are
  not reused, reducing duplicate execution of Replay authority. In exchange, a lost claim response
  or crash incurs the cost and latency of a new ticket.
- Immutable artifact import and server-side seal verification remove Worker-local absolute paths
  and mutable runtime objects from result authority.
- PostgreSQL migrations, artifact retention, orphan-artifact cleanup, reservation reconciliation,
  and rate-limit operations become new responsibilities.
- Conservative budget/permit consumption may reduce available budget after an ambiguous crash.
  This loss takes priority over increasing duplicate-execution risk through automatic refunds.
- Local M6-07A remains a lightweight single-host path and does not pretend that M6-07B is implemented.

## Acceptance and validation

Implementation of this ADR is complete when automated tests prove at least that:

- a forward migration upgrades both an empty PostgreSQL database and the immediately preceding
  supported version to the new Replay schema, and the server fails closed on an unknown, partial,
  or constraint/trigger-corrupted schema;
- public submission rejects injection of the internal Replay kind, a raw path/URL, Candidate,
  contract, Capability, or Worker verdict, and only server-side sealed-source admission creates an
  exact KISA Job;
- substitution of the content, Run ID, seal root, artifact set, or repository version in source or
  replay `ArtifactRef`, as well as symlink/path traversal, is rejected by server-side verification;
- when two Workers concurrently claim the same queued Replay Job/ticket, exactly one succeeds and
  the principal, lease token, ticket, and fence are bound in the same transaction;
- when a claiming Worker crashes or its lease expires, the old ticket and Job are not requeued and
  become abandoned, while retry uses a new attempt/ticket/Replay Run/Job ID;
- a stale Worker attempting heartbeat, permit, artifact-import completion, or finalization is
  rejected and cannot alter the new attempt's budget, rate state, or result;
- concurrent permit requests from multiple Workers do not exceed reserved Tool-call budgets or the
  durable rate window, a duplicate ordinal is consumed only once, and an abandoned/cancelled ticket
  receives no new permit;
- an exact retry simulating response loss after the finalization commit returns the same result,
  while a retry with a different ArtifactRef, root, Outcome, or `result_digest` is rejected;
- when response/connection loss before finalization overlaps lease expiry, the old attempt does not
  enter the Gate and only a new ticket may execute;
- a race that changes the source reference/root, item set, or ticket finalization during Gate
  verification fails source-root CAS and does not publish a confirmed projection;
- Run/batch cancellation and Worker shutdown propagate ADR 0024 cancellation, leave claimed tickets
  abandoned, and do not finalize or confirm from a sealed cleanup receipt alone;
- after separately restarting the API, Worker, and Gate processes, PostgreSQL tickets/events,
  immutable artifacts, reservation/rate state, and exact finalized receipts can be reopened to
  verify the same result;
- PostgreSQL concurrency tests race claim against claim, lease expiry against late finalize,
  cancellation against permit/finalize, and Gate against source drift, satisfying the lock ordering
  and fencing above without deadlock; and
- a single-host KISA end-to-end test succeeds from sealed-source admission through internal
  Candidate -> Replay -> Gate to a versioned Confirmed projection, while semantic-only results,
  missing coverage, unsupported scenarios, and tampered artifacts do not confirm.

## Relationship to prior decisions

- [ADR 0011](0011-durable-control-plane.en.md) is extended with PostgreSQL
  orchestration/authorization boundaries and requires the managed forward migration that was
  previously future work, beginning with the Replay schema. The existing Run/Job/checkpoint/
  approval/event semantics are insufficient without Replay-specific aggregates and typed completion.
- [ADR 0012](0012-lease-aware-worker-daemon.en.md) authenticated leases, trusted executor registry,
  heartbeat, and at-least-once delivery are reused, with the stronger exception that after a Replay
  claim, the same Job is not requeued and a new ticket/Job attempt is created instead.
- [ADR 0024](0024-cooperative-execution-cancellation.en.md) first-write-wins cancellation and the
  limits of a local cleanup receipt are retained. This ADR's `abandoned` is a durable
  execution-authority fence, not physical-quiescence attestation.
- [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md) Candidate/Compiler/
  Restricted Reproducer/Mode Oracle/common Gate and the `confirmed` invariant are unchanged. The
  Control Plane only adds orchestration authority that derives those inputs from a sealed source
  and re-verifies finalized receipts.
- [ADR 0028](0028-durable-local-replay-ticket-ledger.en.md) canonical compilation binding,
  burn-on-claim, exact idempotent finalization, and read-only restart-verification principles are
  extended to the PostgreSQL failure model. Neither an SQLite file nor a Local writer is promoted
  to distributed authority.

## References

- [Control Plane typed contracts](../../src/pajin/control_plane/models.py)
- [Control Plane database schema](../../src/pajin/control_plane/database.py)
- [Control Plane transactional service](../../src/pajin/control_plane/service.py)
- [Lease-aware Worker daemon](../../src/pajin/control_plane/worker.py)
- [Trusted executor registry](../../src/pajin/control_plane/executors.py)
- [Run integrity store and verifier](../../src/pajin/runtime/store.py)
- [Restricted Replay runtime and verified loader](../../src/pajin/replay/runtime.py)
- [SQLite durable Replay ticket authority](../../src/pajin/replay/sqlite_tickets.py)
- [KISA sealed-source Replay coordinator](../../src/pajin/modes/ai_redteam/replay.py)
