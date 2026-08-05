# PERMIT-004B1: Pre-reserved One-shot CleanupPermit Authority

- Status: Implemented
- Runtime APIs: `pajin.graph.GraphReversibleActionPermitAuthority`,
  `pajin.graph.GraphCleanupPermitAuthority`
- Record APIs: `pajin.dev/action-cleanup-reservation-request/v1alpha1`,
  `pajin.dev/action-cleanup-reservation/v1alpha1`, `pajin.dev/cleanup-request/v1alpha1`, and
  `pajin.dev/cleanup-permit/v1alpha1`
- Decision: [ADR-0132](../adr/0132-pre-reserve-cleanup-capacity-before-reversible-write.md)

## Scope

PERMIT-004B1 adds the durable GRAPH substrate required before a reversible write may dispatch. It
does not relax the PERMIT-004A no-write gate. Instead, a separate reversible-action authority must
atomically consume the ordinary `ActionPermit` and hold one exact cleanup Tool-call, request-unit,
and fixed-point cost reservation before the write callback can run. A later externally verified
`CleanupRequest` can consume that hold exactly once through a separately domain-separated
`CleanupPermit`.

The current CAP-005 inventory still contains no production `reversible-write` Capability. The
positive path is therefore an isolated authority fixture, not a claim that a production cleanup
workflow is active. PERMIT-004B2 must connect PERMIT-004A-equivalent sealed write-result
authentication, the current Cleanup Handler plan, a distinct cleanup Capability, and Gateway
dispatch to these GRAPH contracts.

## Pre-dispatch cleanup capacity

`ActionCleanupReservationRequest` is non-executable planner input. It binds:

- Campaign, Run, `MissionEnvelope`, and source `ActionProposal` identity;
- one distinct, exact registered cleanup Capability and the unchanged source target;
- code identity for the expected Cleanup Handler and cleanup Executor Adapter;
- one reused `ActionBudgetReservation` value; and
- creation and bounded claim-expiry times no later than the Envelope expiry.

The request grants no dispatch. `GraphReversibleActionPermitAuthority` resolves both registered
Capabilities, then requires a mandatory `ReversibleActionPermitInputAuthority` to exact-rebuild the
current signed Definition and code-owned source-to-cleanup mapping and prove
`reversible-write + cleanupRequired=true` before any durable claim. There is no built-in permissive
implementation. The authority delegates one `BEGIN IMMEDIATE` transaction to the existing
`SQLiteGraphActionPermitStore`. The transaction validates the ordinary Action algebra and latest
Graph Snapshot, validates the cleanup reservation algebra, aggregates the new Action plus cleanup
capacity with all stored ordinary ActionPermits and cleanup holds, then inserts both the consumed
ActionPermit and `ActionCleanupReservation` before one commit.

One-sided state is invalid. A deterministic exact retry must find both records and exact-match the
complete request; otherwise it fails closed. The reversible dispatcher calls the Action callback
only when the returned Action authorization has `newlyConsumed=true`. A callback exception or
unknown start leaves both authority records durable and never automatically redispatches the
write.

## CleanupRequest boundary

`CleanupRequest` is non-executable and content-addressed. It binds:

- exact Envelope, cleanup reservation, source ActionPermit, and source action dispatch;
- declared outcome ID/digest, Run root, terminal event, Gateway outcome, and Worker execution
  coordinates that the required higher-level input authority must exact-rebuild;
- one Graph decision and exact latest Snapshot whose payload digest names that outcome;
- exact pre-reserved Handler, Executor, cleanup Capability, target, and budget identities;
- one cleanup-plan digest; and
- a fresh Tool request, request digest, and normalized-parameter digest.

This GRAPH slice verifies the request's canonical identity and every durable predecessor it owns.
It also requires a caller-supplied `CleanupPermitInputAuthority` before and after the durable claim;
there is no default implementation. That authority must exact-rebuild sealed source evidence and
the current Handler, Executor, Capability, Tool request, target, price, and hold bindings. B1 does
not provide that production adapter and cannot independently prove that caller-supplied outcome
coordinates or the Handler plan came from sealed PERMIT-004A-equivalent evidence. Those fields
remain explicit input-authority TCB until PERMIT-004B2 supplies the managed-Run and current-role
adapter. A self-consistent `CleanupRequest` must not be treated as authenticated write-result
authority by itself.

## One-shot CleanupPermit

`CleanupPermit` has separate kind, API version, ID, dispatch ID, and digest domains from
`ActionPermit`. It directly repeats the source ActionPermit and hold identities, outcome and audit
digests, decision and Snapshot, Handler and Executor digests, plan, Capability, target, Tool
request, parameter, reservation, and time bindings. The complete source Worker execution and
Handler/Executor ID and version bindings remain transitively committed through the exact
`cleanupRequestDigest`; they are not direct Permit fields. The original ActionPermit is immutable
lineage only and is never reinterpreted as cleanup execution authority.

`GraphCleanupPermitAuthority` uses the same Campaign-pinned compiler identity and in-process writer
token as the Action authority. Its final transaction:

1. resolves a deterministic exact retry;
2. rejects any second request, plan, Tool request, source Action, or hold under an already consumed
   identity;
3. loads and exact-validates the stored ActionPermit and cleanup reservation;
4. rechecks the registered Capability, target, pre-reserved Handler and Executor equality, budget,
   decision, and latest Graph Snapshot, while the mandatory input authority owns current-role
   verification;
5. appends one consumed CleanupPermit without charging the already held capacity again; and
6. commits before any cleanup callback starts.

The dispatcher invokes cleanup only for `newlyConsumed=true`. A crash, exception, or uncertain
response after the claim is terminal and manual-review-only; an exact retry returns the stored
Permit with `newlyConsumed=false`.

## Aggregate budget and rolling rate

The authoritative total is:

```text
all ordinary ActionPermit reservations
+ all durable ActionCleanupReservation holds
```

CleanupPermit rows are not added again. Total Tool-call, request-unit, and fixed-point cost limits
remain permanently consumed under the immutable Envelope. For rolling request units, ordinary
Actions use their consumption time. An unclaimed cleanup hold continues to occupy rolling capacity
even after its reservation time leaves the window, preventing cleanup starvation. Once claimed,
that hold moves to the CleanupPermit consumption time and is still counted exactly once.

There is deliberately no automatic hold release. Expiry prevents late automatic cleanup but does
not manufacture capacity or restored state. Abandonment, manual recovery, or a later release
authority requires a separate contract.

## SQLite schema v3, migration, and backup

Schema v3 adds two fingerprinted append-only tables to the same single-Campaign database:

| Table | Authority |
| --- | --- |
| `graph_action_cleanup_reservations` | cleanup capacity committed with one source ActionPermit |
| `graph_cleanup_permits` | consumed one-shot cleanup dispatch claims |

Both tables use strict columns, uniqueness and foreign keys, canonical JSON payload/index equality,
immutable update/delete/replace triggers, and Envelope indexes. They reuse
`graph_action_permit_writers`; no cleanup writer or disconnected budget ledger is introduced.

Initialization recognizes and fingerprints exact schema v1 and v2 stores before transactionally
migrating them to v3. Migration adds empty cleanup tables and never fabricates a reservation or
Permit. Existing Events, Projections, Snapshots, compiler identity, and ActionPermits are preserved.

New backups use `pajin.dev/sqlite-graph-backup-manifest/v1alpha2`, schema version 3, and bind cleanup
reservation and CleanupPermit count/head digests in addition to the existing state. The strict
legacy v1alpha1/schema-v2 reader remains available for restore: it verifies the original bytes,
schema fingerprint, and logical state first, migrates only the private destination copy, verifies
that no cleanup authority appeared, and then publishes the absent destination. New signed retained
statements and detached manifests use explicit v1alpha2 outer APIs and embed only the v1alpha2
low-level manifest. A strict historical v1alpha1 outer reader accepts only its original v1alpha1
schema-v2 low-level manifest, signature domain, and AEAD domain; the same outer version is never
reinterpreted with a new payload shape.

Direct code rollback after a v3 store is created is not supported because v2 code rejects the v3
fingerprint. Rollback requires retaining v3-aware restore/export code and must never delete or
reinterpret consumed authority rows.

## Fail-closed conditions

- cleanup capacity was not committed atomically before the reversible Action claim;
- one half of an Action-plus-hold exact retry is missing or differs;
- Campaign, Run, Envelope, compiler, Proposal, ActionPermit, decision, Snapshot, Capability,
  target, Handler, Executor, Tool request, parameter, plan, or reservation substitution;
- cleanup Capability reuse of the source Action Capability;
- inactive or expired reservation/Envelope authority;
- total Tool-call, request-unit, cost, or rolling-unit exhaustion;
- stale Projection or Snapshot, writer drift, cross-request collision, duplicate claim, or
  cross-action replay;
- schema, trigger, canonical payload, index, foreign-key, backup, or manifest divergence; and
- callback failure or uncertain dispatch followed by an attempted automatic retry.

## Verification

Tests exercise canonical contracts, exact retry, atomic rollback after an injected hold-insert
failure, aggregate call/unit/cost/rolling budgets, outstanding-hold starvation prevention,
cross-instance Action-plus-hold and CleanupPermit races, plan/source equivocation, callback
uncertainty, append-only and schema fingerprint tampering, v1-to-v3 and populated v2-to-v3
migration, v3 backup/restore, canonical cross-ledger substitution rejection during backup and
restore, and strict legacy v2 plus retained-v1alpha1 restore with destination-only migration.

## Remaining boundary

PERMIT-004B2 must reuse the PERMIT-004A sealed result authentication core for
`reversible-write + cleanupRequired=true`, exact-rebuild a single current Handler plan, compile a
distinct cleanup Capability request, prove that the pre-action hold exactly covers it, dispatch it
through the existing Grant/Gateway lifecycle, and authenticate cleanup outcome and restored target
state. `irreversible-write`, incomplete or uncertain source outcomes, stale role activation, and
unverified cleanup completion remain closed.

## Related documents

- [PERMIT-004A contract](PERMIT-004A-authenticated-action-outcome-gate.md)
- [PERMIT-003 contract](PERMIT-003-exact-single-use-action-permit.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [GRAPH-005 contract](../graph/GRAPH-005-durable-sqlite-graph-store.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
