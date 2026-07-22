> Languages: [English](0029-control-plane-replay-orchestration.en.md) | [한국어](0029-control-plane-replay-orchestration.ko.md)

# ADR 0029: Control Plane Replay orchestration and burn-on-claim delivery

- Status: Accepted
- Date: 2026-07-17
- Implementation update: 2026-07-22 (schema-v11 multi-item versioned-projection publication)
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
admission are now implemented as the bounded M6-07B-2A foundation: an owner-controlled staging and
managed filesystem repository, immutable `cp_artifacts` metadata, schema v3, and exact opaque
`(artifact_id, repository_version)` resolution with content and seal re-verification. Admission
preserves the producer Control Plane Run ID separately from the sealed Run ID. The forward migration
path is v1→v2→v3; v2→v3 fails closed if legacy Replay data exists rather than synthesizing an
Artifact binding. M6-07B-2B was implemented on 2026-07-18. Its batch command accepts only the exact
Artifact locator and an idempotency key. The Control Plane rereads the managed sealed AI Red Team
source, derives eligible exact M03, M06, and A04 confirmation Candidates and contracts, runs the
trusted Replay Compiler, and stores canonical `ReplayCompilation` and `ReplayCapabilityGrant` as an
append-only, non-dispatchable derivation record and proof in PostgreSQL with the batch in `planned`
and each item in `pending`. Caller-authored Candidate, contract, policy, digest, target, and arguments
are not authority inputs. Schema v4 extends the forward path to v1→v2→v3→v4 with canonical,
non-dispatchable compilation derivation records. `compilation_id` is the row identity; `item_id` is
non-unique, the Candidate/contract fields form the plan-identity foreign key, and every row owns its
Replay Run identity, compilation digest, and Grant digest. This permits append-only attempt/version
rows for one item. The planned Grant lasts at most five minutes and may expire while pending, so it
MUST NOT be reused as later execution authority. M6-07B-2C durable issuance was implemented on
2026-07-18. Schema v5 adds `cp_replay_budget_accounts`, `cp_replay_budget_reservations`,
`cp_replay_rate_accounts`, and `cp_replay_rate_reservations`, plus exact compilation and reservation
foreign keys on `cp_replay_tickets`. The budget account binds the sealed source Run/root, Campaign,
budget digest, baseline/max counts, mutable reserved/consumed/released counters, and CAS. The rate
account conservatively binds the sealed ledger ID/digest and observed units, the managed Artifact
admission time as `observed_at`, a nullable per-minute limit, a fixed 60-second window, and CAS;
each first-attempt rate reservation expires after that window. The internal idempotent
`ControlPlaneService.issue_replay_batch(batch_id, actor=...)` path
re-resolves and re-verifies the managed source before locking authority. It reserves the whole
batch's first-attempt Tool-call and request-unit requirements, recompiles every pending item with a
fresh Replay Run identity and Grant, appends the canonical compilation, and creates its active
budget/rate reservations, one-shot internal Job, and `issued` ticket in one transaction. The strict
payload and ticket bind the exact `compilation_id`, `budget_reservation_id`, `rate_reservation_id`,
attempt, Replay Run, compilation digest, and Grant digest. The batch becomes `running` and its items
become `queued`. Only a response-loss retry against the current active exact authority graph
reconstructs that issuance: the ticket/Job pair must still be `issued`/`queued` immediately after
issuance or `claimed`/`running` after claim; a terminal or otherwise changed graph must fail closed. The transaction
records `run.submitted`, item-level `replay.compilation.derived` and `replay.ticket.issued`, and the
final `replay.batch.issued` event. The initial planned row remains non-dispatchable and is never
promoted or reused. M6-07B-2D internal service-only per-call permit ledger/issuance was also
implemented on 2026-07-18. Schema v6 extends the forward
path to v1→v2→v3→v4→v5→v6 and adds append-only `cp_replay_tool_permits`. Strict
`ReplayToolPermitRequest` accepts only the executor profile, lease token, ticket ID, fencing value,
and 1-based call ordinal. Idempotent
`ControlPlaneService.issue_replay_tool_permit(job_id, request, actor=...)` rechecks the authenticated
principal and registered profile, exact Job/ticket lease token and fence, active Run/batch/item/ticket,
canonical compilation/Grant, exact reservation counters, and rolling request-rate admission. With a
configured cap, admission counts the current sealed baseline, post-admission unconsumed units in still-live
reservations, active permit units in their 60-second windows, and the new trusted request cost. With
no cap, rate rejection is skipped but exact reservation counters are still consumed. The canonical
permit binds the exact
ticket/compilation/reservation graph, source/original request, Tool/version/target/method, ordinal, one
Tool-call unit, and trusted request units. Permit TTL is at most 30 seconds and is capped by the
Job/ticket lease and compiled-spec/Grant deadlines, not rate-reservation expiry. The unique
`(ticket, ordinal)` plus persisted permit digest/request ID returns the same row for an exact response-loss duplicate without consuming
counters or appending an event twice. The first issuance atomically moves reserved budget/rate units to
consumed and appends the audit event. Issued units remain consumed when execution is uncertain;
cancel/abandon releases only the definitely unissued remainder. Stale, wrong, cancelled, expired,
finalized, ordinal-gap, and over-limit requests fail closed. M6-07B-2E adds the strict JSON
`PAJIN_CP_REPLAY_EXECUTOR_PROFILES` subject-to-profile-array allowlist and dedicated WORKER-role HTTP
endpoints plus async client methods. The allowlist is empty and fail closed when unset; for example,
`{"replay-worker-service":["kisa-exact-v1"]}` grants that one profile only to the separately
authenticated Replay Worker subject. `PAJIN_CP_REPLAY_WORKER_TOKEN` must differ from the Operator,
Approver, and generic Worker credentials. Claim, heartbeat,
and Tool-permit issuance are exposed only through the internal Worker transport, and claim/heartbeat
envelopes contain the canonical `ReplayCompilation` after the server revalidates its exact digest and
identity bindings. A permit remains a non-bearer proof already consumed on issuance; there is no
separate redeem mutation. M6-07B-2F adds schema v7 and append-only
`cp_replay_execution_contexts`. First-attempt issuance now stores exactly one canonical context for
each fresh compilation. It contains the exact typed Campaign, exact KISA Scenario, canonical
`AIChatProbeTool.spec`, their component digests and the complete context digest, the source and policy
identities, fixed `kisa-exact-v1` executor profile, forbidden-secret policy with no Secret Lease IDs,
and an opaque output-staging slot. The strict Job payload repeats the context ID and digest;
claim/heartbeat returns the context after exact graph verification, profile admission verifies its
fixed profile, and Tool-permit issuance transitively rechecks the same compilation/context authority.
The staging slot is an identity only, not a path, store, upload authorization, or result claim. The
v6→v7 migration fails closed when any dispatchable v6 Replay authority exists because the exact
issuance-time bytes cannot be reconstructed; a database containing only non-dispatchable planned
proof may advance with an empty context table. The 2026-07-19 slice completes the first one-item
exact-KISA execution boundary. Schema v8 completes append-only guards; schema v9 adds append-only
server-derived Replay finalizations. A dedicated `kisa-exact-v1` daemon claims and heartbeats the
fenced ticket, obtains a durable permit immediately before every Tool dispatch, writes only into the
server-reserved opaque staging slot, and submits no path, ArtifactRef, result, digest, or verdict.
The server imports and reopens the sealed output, verifies the exact source/compilation/ticket/permit
lineage, derives the ADR 0027 common Gate decision, and atomically commits finalization and terminal
authority state. Compose now wires that daemon and its owner-only staging handoff. Opaque public
source/batch admission, role-scoped state reads, and automatic fresh-identity retry issuance are also
implemented. The 2026-07-22 schema-v11 slice adds append-only `cp_replay_projections`, server-owned
copy-on-project materialization, aggregate receipt re-verification outside database locks, a final
source-root/batch-CAS/sorted-finalization-set commit, and a role-scoped projection read. Negative
Control Plane retest is implemented by schema v12. An append-only `cp_replay_retest_sources` row
binds one batch to its exact parent Retest Artifact; the baseline and parent seals are both reopened,
capacity is charged to the parent Retest snapshot, and a v2 dual-source projection authority binds
all negative receipts before `KISARetestService` writes and seals `kisa-retest.json` on a copy of the
parent Retest Run. This does not elevate target-authored defensive responses to `fixed` without an
independent remediation attestation. Multi-host/object-store handoff remains outstanding.

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

The first implementation slice after acceptance closed part of that baseline without weakening the
decision: public Job kinds remain `campaign` and `tool-loop`, while a separately typed internal
Replay payload is persisted with batch/item/ticket/event authority state and burn-on-claim fencing.
Repository startup now performs a versioned v1-to-v2 migration or rejects incompatible schema
state. M6-07B-2A then added the private managed repository and immutable Artifact metadata. Its
trusted admission service accepts only a strict staging identity for a completed producer Job,
imports and verifies the sealed source outside database locks, rechecks producer state, and records
the canonical metadata and internal storage key. Replay-batch consumers use only the exact opaque
Artifact locator, which the service resolves and re-verifies before batch creation. M6-07B-2B then
made the remaining command input idempotency-only and added trusted source rereading, exact
M03/M06/A04 confirmation Candidate and contract derivation, canonical compilation, and append-only
planned/pending non-dispatchable PostgreSQL derivation records. The stored compilation and Grant
prove what was derived; they do not authorize dispatch and may not be reused at issuance.
M6-07B-2C then added schema-v5 durable budget/sealed-rate reservation and the internal idempotent
first-attempt issuance transaction. The service re-verifies the source, appends fresh Replay
Run/Grant compilation authority, and creates the exact reservation-bound Job/ticket set for the
entire batch atomically. Generic Job completion and failure paths remain unavailable to Replay Jobs.
M6-07B-2D adds the schema-v6 append-only per-call permit ledger and internal service issuance with
exact active-authority rechecks, canonical-operation binding, ticket/ordinal idempotency, the
reserved-to-consumed transition, and burn on uncertainty. M6-07B-2E adds the fail-closed
subject/profile allowlist, WORKER-only claim, heartbeat, and Tool-permit HTTP endpoints, async client,
and server-validated canonical compilation claim envelope. M6-07B-2F adds schema-v7 append-only
execution contexts that bind every fresh issuance compilation to the exact typed Campaign, KISA
Scenario, canonical ToolSpec, component and context digests, fixed executor profile, forbidden
secrets, and opaque output-staging identity. The Job payload, claim envelope, profile admission, and
permit issuance now preserve or transitively revalidate that authority graph. The v6→v7 migration
refuses dispatchable legacy authority rather than inventing missing issuance-time bytes. The
2026-07-19 implementation adds the dedicated executor, pre-dispatch permit seam, opaque staging
handoff, server-side import/finalization, and one-item common Gate described below. The 2026-07-21
implementation adds opaque public source/batch admission, role-scoped state reads, and automatic
fresh-identity retry issuance for zero-permit terminal attempts. Negative Control Plane retest
remains outside the completed slice.

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
content digest, producer Control Plane Run ID, sealed Run ID, integrity-root digest, and creation
identity. The storage key is internal to the repository; neither an Operator nor a Worker may
choose an arbitrary path, URL, symlink, or object key.

The first single-host implementation may use an owner-controlled filesystem repository. A trusted
Control Plane service imports an artifact from a staging directory, checks its canonical path and
size bound, computes its content digest, and registers it as an immutable object. The bytes of an
`ArtifactRef` cannot change after registration; new bytes produce a new immutable identity and
reference. The current filesystem repository emits repository version 1 for each such identity.
Both source and replay
output pass through the same import rules. A Worker's absolute `runPath` is not part of the Control
Plane contract.

When creating a Replay batch, the server admits the source in this order:

1. the server resolves the `ArtifactRef` through the repository and directly verifies the entire
   Run integrity chain and every sealed artifact;
2. the server rereads the sealed Campaign, Plan, Capability ledger, budget/rate-limit snapshot,
   Candidate, and validation projection with typed loaders;
3. the server derives eligible Candidates and Mode contracts from the exact KISA registry and runs
   the Replay Compiler; and
4. the server stores the original source root, canonical Candidate/contract identity, and initial
   Replay compilation/Capability as a `compilation_id`-keyed, non-dispatchable derivation record and
   proof. That row owns its Replay Run ID, compilation digest, and Grant digest; and
5. the separate internal issuance call resolves and re-verifies the managed source again, binds the
   sealed budget/rate snapshots to durable accounts, reserves the complete first attempt, and
   appends fresh Replay Run/Grant compilation authority before atomically creating its Jobs and
   tickets.

The Candidate itself is not semantic authority. The source snapshot must contain
`validator-output.json` with the exact Validator Agent/Task identity, Findings, and per-Candidate
assessments. The server reads that artifact from the same pinned snapshot, verifies every canonical
claim digest, complete evidence list, and one-to-one binding between a positive assessment and an
exact validated Validator Finding, then replays the deterministic Gate. A missing artifact,
identity/claim/evidence/Finding substitution, or disagreement with the stored Decision fails
admission closed; support is never synthesized from the Candidate or lifecycle state. This
verification proves only preservation of the original Validator output and adds no independent
execution attestation, product confirmation, or remediation evidence.

A Worker-submitted Candidate, contract, comparison rule, Capability Grant, target, Tool arguments,
source root, or eligibility flag is not an authority input. The planned record's five-minute Grant
can expire before issuance and is never Worker execution authority. A Worker claim envelope carries
only the fresh compilation and short-lived, non-delegable Capability that the server bound during
the implemented durable issuance transaction.

### Public Replay admission and reads

Only an Operator may call `POST /v1/replay/source-artifacts` and `POST /v1/replay/batches`. Source
admission accepts only an opaque staging ID, completed producer Run/Job IDs, and an idempotency key;
batch admission accepts only the exact `(artifact_id, repository_version)` locator and an
idempotency key. The server derives and verifies the sealed source, Candidate, contract,
compilation, and all digests. Raw paths or URLs, caller-authored Candidates, contracts,
Capabilities, Tool requests, verdicts, and the internal Replay Job kind do not exist in the public
contract. A trusted producer must have completed the server-controlled staging handoff before source
admission; the endpoint neither uploads bytes nor imports a caller-selected path.

Operators, Approvers, and Auditors may read batches, items, tickets, and finalizations by exact ID.
Responses contain opaque Artifact identities and server-derived authority, but no staging ID,
repository storage key, or lease token. Public batch admission creates only the `planned` proof and
does not dispatch a Tool. First-attempt Job/ticket issuance remains a trusted internal service
operation that re-verifies the source.

### PostgreSQL Replay aggregate and forward migration

The new schema has at least the following aggregates.

| Aggregate | Role | Core invariant |
| --- | --- | --- |
| `cp_replay_batches` | Source snapshot and entire Gate lifecycle | Bound to one immutable source `ArtifactRef`/root, Mode, purpose, policy version, and CAS version |
| `cp_replay_items` | Progress and plan identity for each eligible Candidate | Candidate/contract plan identity and required repetition count are unique within the batch; one item may have multiple compilation rows |
| `cp_replay_compilations` | Non-dispatchable derivation/attempt record | `compilation_id` is the PK; non-unique `item_id` plus Candidate/contract fields bind the plan identity, while each append-only row owns the Replay Run ID, canonical bytes, compilation digest, and Grant digest |
| `cp_replay_budget_accounts` | Source-Campaign Tool-call authority | Binds source Run/root, Campaign, sealed budget digest and baseline/max counts; reserved/consumed/released counters advance under CAS |
| `cp_replay_budget_reservations` | Tool-call authority for one item attempt | Binds account, batch/item/attempt and compilation; active/partially-consumed/consumed/released lifecycle never exceeds its total calls |
| `cp_replay_rate_accounts` | Conservative sealed request-rate authority | Binds source Run/root, Campaign, sealed ledger ID/digest and observed units, managed Artifact admission time as `observed_at`, nullable per-minute cap, 60-second window, and CAS |
| `cp_replay_rate_reservations` | Request-unit authority for one item attempt | Binds account, batch/item/attempt and compilation; has an exact 60-second expiry and the same bounded lifecycle |
| `cp_replay_execution_contexts` | Exact executor inputs and opaque staging capability | One append-only canonical context per dispatchable compilation, fixed to `kisa-exact-v1` and forbidden secrets |
| `cp_replay_tool_permits` | One pre-dispatch Tool-call decision | Append-only ticket/ordinal identity burns exact budget/rate units and binds the server-minted request ID |
| `cp_replay_tickets` | Authority for one execution attempt | Bound by exact foreign keys to the compilation and both reservations, plus item attempt, Job, Replay Run, source root, claim principal/fence, and finalization |
| `cp_replay_finalizations` | Server-derived immutable result | One append-only row per ticket binds the imported Artifact, both seal roots, artifact set, common Gate decision, and result digest |
| `cp_replay_events` | Replay authority audit history | Appended in the state-transition transaction and never updated or deleted |

Artifact metadata remains separate in `cp_artifacts`. Compilation, execution-context, permit,
finalization, and event rows are append-only; accounts and reservations are deliberately mutable
only through their bounded accounting lifecycle.
The database enforces every authority-bearing foreign key and uniqueness/check constraint. A Replay
event and corresponding `cp_events` summary, when needed, are written in the same transaction.

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
Job from a validated `cp_replay_item`, fresh compilation, active reservations, and ticket. The exact
Replay executor must also be explicitly installed in the Worker startup registry. The Job payload contains only opaque
batch/item/ticket/artifact references and server-generated `compilation_id`,
`execution_context_id`, `execution_context_digest`, `budget_reservation_id`, and
`rate_reservation_id` authority. It contains no executable path, arbitrary URL, callable, or
Worker-selected Grant. The context's `output_staging_id` is likewise an opaque identity and does not
authorize a filesystem location, storage operation, upload, import, or finalization.

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
- if retry is allowed, claim polling rereads the immutable source and rechecks the complete stable
  item plan, source root, cancellation, policy, maximum attempt count, zero-permit history, fully
  released budget/rate reservations, and an existing empty prior staging capability. It preserves
  the abandoned graph, removes the empty capability, and appends a fresh attempt number, fence,
  Replay Run, compilation, execution context, reservations, staging capability, ticket, and Job.
  Concurrent PostgreSQL and SQLite issuers converge on one committed authority graph.
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

The implemented internal issuance service calculates the exact first-attempt Tool calls and network
request units across every eligible item and repetition before creating any Job. Under PostgreSQL
locks it bootstraps or checks one budget account for the source Campaign, binds the sealed source
Run/root, Campaign, budget digest, baseline use, and maximum, and reserves the entire batch without
letting baseline + reserved + consumed exceed that maximum. Worker-reported `usedCalls` is not a
basis for settlement.

The rate account similarly binds the sealed `ledger_id`, rate snapshot digest and observed Campaign
request units, the managed Artifact admission time as `observed_at`, nullable
`max_requests_per_minute`, and a fixed 60-second window. The service conservatively counts the
sealed observation for 60 seconds from that admission time, locks all
unexpired reservations, and fails closed if adding the full first attempt would exceed the cap.
Each item receives a 60-second active request-unit reservation. An absent per-minute cap does not
remove the exact source/account/reservation binding.

The same transaction does not promote the initial planned derivation record into execution
authority. It recompiles each item with a fresh Replay Run identity and fresh Grant, appends a new
`cp_replay_compilations` row, and creates one active budget reservation, active rate reservation,
one-shot Job, and `issued` ticket. Schema-v5 foreign keys bind the ticket to the exact compilation
and both reservations; the strict Job payload repeats the same `compilation_id`,
`budget_reservation_id`, and `rate_reservation_id`. Only a response-loss retry whose current active
exact authority graph remains ticket/Job `issued`/`queued` immediately after issuance or
`claimed`/`running` after claim reconstructs the already persisted exact item/ticket set. Expired,
terminal, binding-drifted, or otherwise changed graphs must fail closed.

M6-07B-2D implements the server ledger/issuance half of this per-call boundary. Strict input does not
accept a Worker-authored target, Tool, method, argument, or unit as authority; it accepts only the
executor profile, lease token, ticket ID, fencing value, and 1-based call ordinal. The internal,
idempotent service rechecks the active principal/profile/lease/ticket fence, Run/batch/item/ticket
lifecycle, canonical compilation/Grant, exact reservation counters, and rolling request-rate state.
For a configured cap, re-admission sums the current sealed baseline, the post-admission unconsumed remainder of
reservations whose 60-second expiry is still live, permits whose issuance window is still active, and
the new trusted request cost. An expired reservation contributes no remaining capacity but does not
itself forbid issuance; with no cap, the rate comparison is skipped while exact counters are still
consumed. Only the next ordinal is allowed; compiled-call-count and reservation limits fail closed.
Each schema-v6 append-only row binds the
exact ticket/compilation/reservation graph, source/original request, canonical
target/Tool/version/method/compiled-argument digest, ordinal, one Tool-call unit, and trusted request
units. Its TTL is `min(now + 30 seconds, lease deadline, compiled-spec expiry, Grant expiry)` and does
not use rate-reservation expiry as a cap. The `(ticket_id, call_ordinal)` unique constraint and
persisted permit digest/request ID ensure
that concurrent requests and response-loss duplicates issue the same permit only once.

Only the first issuance transaction moves budget/rate units from reserved to consumed and appends an
audit event. An issued permit is considered consumed and is not automatically refunded even when
execution is uncertain. No new permit is issued after abandonment or cancellation; only clearly
unissued reservations may be released with an audit event. A new attempt must pass the remaining
durable budget and rate window again. M6-07B-2E exposes
`POST /v1/worker/replay/jobs/claim`,
`POST /v1/worker/replay/jobs/{job_id}/heartbeat`, and
`POST /v1/worker/replay/jobs/{job_id}/tool-permits` only to the WORKER role, with matching async
client methods. `PAJIN_CP_REPLAY_EXECUTOR_PROFILES` is a strict JSON subject-to-profile-array allowlist
that is empty and fail closed when unset. Claim and heartbeat return a `ReplayExecutionClaimView`
containing the canonical `ReplayCompilation`, after the server revalidates the exact compilation,
Candidate, contract, Grant, Campaign, Mode, Candidate Run, and Replay Run bindings. The permit remains
a non-bearer proof already consumed at issuance, so no separate redeem mutation is added. The
dedicated `kisa-exact-v1` executor now calls this endpoint at the last durable seam before every
Gateway dispatch and rejects any permit that differs from the canonical claim or call ordinal. A
bounded transport response-loss retry resends only the identical ordinal-bound permit request; the
server returns the same row/accounting and the executor dispatches the Tool only once after it has
received and revalidated that response.

### Exact KISA execution-context authority

M6-07B-2F makes the issuance-time executor inputs durable without turning the Worker into an
authority source. Schema v7 adds append-only `cp_replay_execution_contexts`; its row is bound
one-to-one to the fresh `cp_replay_compilations` row through compilation, item, batch, Replay Run,
compilation-digest, and Grant-digest foreign-key identity. The canonical context bytes and digest,
required executor profile, and output-staging identity are immutable, and the context digest and
staging identity are unique.

The server creates the context in the same first-attempt issuance transaction as the fresh
compilation, reservations, one-shot Job, and ticket. It contains the server-derived typed
`CampaignManifest`, exact `KISAScenarioDefinition`, canonical `AIChatProbeTool.spec`, their separate
canonical component digests, and the full-context digest. Source Artifact identity/root, policy
version, batch/item/compilation/Replay Run identities, fixed `kisa-exact-v1` profile,
`secret_policy="forbidden"`, empty Secret Lease IDs, and a generated opaque `output_staging_id` are
part of the same canonical bytes. A Worker cannot supply or broaden any of these values.

The strict Replay Job payload repeats the `execution_context_id` and `execution_context_digest`.
Claim and heartbeat return the typed context only after the server verifies its canonical bytes,
digest, row metadata, compilation, payload, Campaign, Scenario, ToolSpec, policy, source, and Replay
Run bindings. Executor-profile admission requires the context's fixed profile, and permit issuance
calls the shared active-authority verifier, so a context or payload substitution also prevents a
permit. The permit row need not duplicate the context identity: its exact ticket/compilation graph
transitively binds it to the one-to-one context.

The opaque output-staging slot is still not a path, mutable storage handle, ArtifactRef, upload
capability, imported artifact, or result claim. Issuance reserves its private empty directory in an
owner-controlled staging root. The dedicated executor can resolve only that exact ID beneath its
configured root and writes the twice-sealed Replay Run there. The server, not the Worker, turns the
verified staged tree into an immutable Artifact during finalization. Secrets are likewise not
deferred: this exact KISA profile forbids them and accepts no Secret Lease ID.

The v6→v7 migration cannot safely backfill execution contexts from old rows because the exact
issuance-time Campaign, Scenario, ToolSpec, and staging identity were never persisted as this
authority. Migration therefore locks writers and fails closed if any dispatchable v6 Replay state
exists, including issued or claimed tickets, permits, internal Replay Jobs, active authority
accounts/reservations, or batches/items beyond planned/pending proof. Only non-dispatchable planned
proof may migrate, and it receives no fabricated context row. This migration rule preserves the
meaning of every schema-v7 context instead of guessing compatibility.

### Separating Worker execute/seal from authority finalize phases

The distributed path splits the current process-local `_finish` into two phases:

1. **Worker execute/seal:** the Worker uses only the server-issued compilation and permits and
   executes through the ordinary Tool Gateway/Worker boundary. It writes the canonical artifact
   set, Outcome, and execution receipt to a separate Replay Run in the reserved opaque staging slot
   and completes both seals. It never imports into the repository. This receipt indicates which
   bytes the Worker created and sealed; it is not ticket-finalization authority.
2. **Control Plane authority finalize:** the Worker sends only executor profile, lease token,
   ticket ID, fence, and the issued opaque staging ID. The server imports the staged tree, reopens
   the resulting immutable Replay `ArtifactRef`, and directly verifies the content digest, both
   seals, artifact set, fresh request/evidence lineage, Mode Oracle result, source root, Candidate,
   compilation, ticket, Replay Run identity, and the exact ordinal permit/request sequence. It
   creates typed finalization only from verified values, revalidates the authority whose accounting
   units were already consumed at permit issuance, and atomically finalizes the Artifact, ticket,
   Job, item, batch, Run, and events.

Replay completion does not use the generic `CompleteJobRequest.result: dict`. The strict
`ReplayFinalizeRequest` intentionally has no Worker-authored `ArtifactRef`, path, result, verdict,
Outcome, seal, or digest field. Its lease/ticket/fence/profile and opaque staging ID select already
issued authority; the server recomputes the ArtifactRef, artifact-set digest, both seal roots, Gate
decision, and canonical `result_digest` from the imported bytes.

If the finalization transaction succeeds but its HTTP response is lost, an exact retry by the same
authenticated principal with the same lease/ticket/fence/profile/staging identity idempotently
returns the stored server-derived result. A retry differing in any value is a conflict. If the
lease/fence ends before the transaction commits, the attempt is abandoned and late finalization is
rejected. Once any permit has been issued, execution failure is terminal and automatic retry cannot
redispatch the same Job/ticket. The implemented fresh-identity issuer also refuses that item because
external side effects are uncertain; it creates a new attempt only when the abandoned attempt has no
permit and its capacity was fully released.

### Source-root CAS confirmation Gate

Each finalization invokes the pure ADR 0027 common Gate over the freshly reloaded source and output
and stores its server-derived decision in `cp_replay_finalizations`. The item remains `verified`.
When every item is verified, the batch enters `gating` and the schema-v11 publisher implements the
multi-item versioned-projection flow below. One-item batches use the same aggregate path.

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
Control Plane authority for the projection. A Gate retry performs the entire verification again
from a new snapshot. An exact retry of an already published input set reopens the existing immutable
projection and returns it idempotently; it neither reinterprets nor modifies the sealed source.

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

PostgreSQL mutations extend the dependent-to-Run ordering from ADR 0023/0024 with Replay
accounting/permit authority and observe the following order:

```text
cp_jobs (stable Job ID order)
  -> cp_replay_tickets (stable attempt/ticket order)
  -> cp_replay_items (stable item order)
  -> cp_replay_batches
  -> cp_runs
  -> cp_replay_budget_accounts (canonical account order)
  -> cp_replay_rate_accounts (canonical account/window order)
  -> cp_replay_budget_reservations (stable reservation order)
  -> cp_replay_rate_reservations (stable reservation order)
  -> cp_replay_tool_permits (ticket, call ordinal order)
```

If a path has no row for an earlier stage, it skips that stage but never locks in reverse order.
Cancellation locks active Jobs in stable order, then Replay dependents and the Run, followed by any
required accounting rows. Issuance,
claim, lease expiry, permits, finalization, and Gate publication use the same order. Artifact
hashing, seal verification, and Oracle execution occur without database locks; immutable
references and CAS commit the result.

### Compose deployment boundary

The single-host Compose lab uses two named volumes initialized and verified as mode `0700` under
UID/GID `10001`. The Control Plane owns staging and repository; the dedicated Replay Worker shares
only staging under the same identity and never mounts repository storage. Fresh Docker volume roots
are root-owned, so a networkless one-shot initializer runs as root with only `CHOWN`. It performs a
no-follow ownership handoff on each fixed mount path, opens and verifies the same inode, then applies
mode and final ownership through that descriptor before fsyncing and exiting. All long-running PAJIN
services remain UID/GID `10001`. A symlink or
non-private root fails startup/import rather than widening access. The daemon image alone contains a
digest-pinned Docker CLI and mounts `/var/run/docker.sock`; the API image does not contain that CLI.
The host socket group must be supplied as `PAJIN_DOCKER_SOCKET_GID` when it is not group 0.
A networkless one-shot preflight uses the same UID, socket mount, and supplemental group to inspect
the Docker server, both fixed execution images, and the configured proxy uplink. Failure prevents
the Replay daemon from starting; the check does not reduce socket authority.

Possession of the Docker socket is effectively host-root authority and dominates container-local
UID, capability, read-only-root, and `no-new-privileges` controls. This Compose wiring is therefore a
trusted single-host lab, not tenant isolation. Production deployment requires a dedicated Docker
host or a separately designed restricted execution broker. Bundled Compose creates the dedicated
`pajin-replay-uplink-lab` external-uplink network; a configured override must already exist. Only the
allowlist egress proxy attaches to that uplink, while each execution Worker remains on its fresh
internal network.

The host-facing API/database networks are ordinary Docker bridges needed to preserve published
loopback ports. They segment service attachment but are not an outbound-deny boundary, so production
deployment also requires a host firewall or equivalent egress control.

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

The currently implemented slice includes the dedicated exact-KISA Worker, per-dispatch durable
permit seam, twice-sealed opaque staging handoff, schema-v9 server-derived Artifact finalization,
schema-v11 multi-item versioned-projection publication, opaque public admission/read APIs, and
automatic zero-permit fresh-identity retry issuance. Schema v12 dual-source negative-retest
projection is also implemented. Because a permit is not a bearer credential, a separate redeem
mutation is not added.

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
- Local M6-07A remains a lightweight single-host path and does not imply the Control Plane's
  PostgreSQL, managed-Artifact, lease, permit, or finalization authority.

## Acceptance and validation

As of 2026-07-22, source admission/derivation, public admission/read APIs, durable reservation and permit authority, exact
execution contexts, dedicated Worker transport/execution, opaque staging, schema-v9 server-derived
finalization, exact response-loss idempotency, automatic zero-permit fresh-identity retry, and the
schema-v11 multi-item versioned-projection publisher cover the positive-confirmation execution path.
Schema v12 covers the negative Control Plane retest path with exact baseline/parent-Retest authority,
parent capacity accounting, aggregate receipt verification, and server-owned Retest projection.

Implementation of this ADR is complete when automated tests prove at least that:

- a forward migration upgrades both an empty PostgreSQL database and the immediately preceding
  supported version to the new Replay schema, and the server fails closed on an unknown, partial,
  or constraint/trigger-corrupted schema; specifically, v6→v7 refuses any dispatchable v6 authority
  rather than backfilling guessed context bytes, while non-dispatchable planned proof advances with
  no fabricated context row; v8 completes append-only guards and v9 adds an append-only, no-replace
  server-derived finalization table;
- v11-to-v12 adds exactly one append-only parent Retest source authority per negative batch and
  rejects missing, duplicate, same-as-baseline, or foreign Campaign/Run/root bindings;
- public submission rejects injection of the internal Replay kind, a raw path/URL, Candidate,
  contract, Capability, or Worker verdict; only server-side sealed-source derivation creates exact
  KISA planned/pending non-dispatchable compilation proof; internal issuance re-verifies the source,
  never reuses an expired planned Grant, appends a fresh compilation row for the same item, reserves
  budget/rate authority, and atomically binds each first-attempt Job/ticket to that row's
  `compilation_id`, Replay Run identity, compilation/Grant digests, `budget_reservation_id`, and
  `rate_reservation_id`; a response-loss retry reconstructs the same exact authority set only while
  the current active exact authority graph remains ticket/Job `issued`/`queued` or
  `claimed`/`running`, and a terminal or changed graph must fail closed;
- first-attempt issuance appends exactly one schema-v7 `cp_replay_execution_contexts` row for every
  fresh compilation and canonically binds the exact typed Campaign, KISA Scenario,
  `AIChatProbeTool.spec`, their component digests, the full context digest, source/policy identities,
  fixed `kisa-exact-v1` profile, forbidden secrets with no Secret Lease IDs, and an opaque unique
  output-staging identity; Job payload, claim/heartbeat, profile admission, and permit issuance reject
  any context, digest, component, or transitive authority substitution, while the staging identity
  alone cannot authorize storage, execution, import, or finalization;
- strict permit input accepts only the executor profile, lease token, ticket ID, fencing value, and
  1-based ordinal and rejects target/Tool/method/argument/unit injection; the server derives the exact
  active authority and canonical operation, performs rolling-window rate re-admission from current
  baseline/post-admission live-reservation remainder/active permits/new cost, and only an exact
  response-loss duplicate with the
  persisted permit digest/request ID returns the same row without duplicate counters/events;
- substitution of the content, Run ID, seal root, artifact set, or repository version in source or
  replay `ArtifactRef`, as well as symlink/path traversal, is rejected by server-side verification;
- when two Workers concurrently claim the same queued Replay Job/ticket, exactly one succeeds and
  the principal, lease token, ticket, and fence are bound in the same transaction;
- when a claiming Worker crashes or its lease expires, the old ticket and Job are not requeued and
  become abandoned; only a zero-permit, fully released attempt with an empty prior staging capability
  and remaining attempt count may retry, and it uses fresh Run/compilation/context/reservation/
  staging/Job/ticket identities plus an incremented attempt and fence; any permit, staged output,
  missing capability, authority drift, or exhausted count fails closed, and concurrent issuers append
  only one new authority graph;
- a stale Worker attempting heartbeat, permit, artifact-import completion, or finalization is
  rejected and cannot alter the new attempt's budget, rate state, or result;
- concurrent permit requests from multiple Workers do not exceed reserved Tool-call budgets or the
  durable rate window, a duplicate ordinal is consumed only once, and ordinal-gap, over-limit,
  expired/finalized/abandoned/cancelled tickets receive no new permit;
- an exact retry simulating response loss after the finalization commit returns the same
  server-derived result, while a different authenticated principal, lease, ticket, fence, profile,
  or opaque staging identity is rejected; no Worker-authored ArtifactRef, path, Outcome, verdict,
  seal, or `result_digest` is accepted by the finalize request;
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
