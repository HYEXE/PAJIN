# GRAPH-006: Atomic ActionPermit Authority

- Status: locally implemented with hard-exit crash-window verification
- Date: 2026-07-28
- Prerequisites: GRAPH-003, GRAPH-004, GRAPH-005, ADR-0047, ADR-0049

## Purpose

Close the race in which the Graph changes after `GraphDecisionPreflight`. The preflight record is
never promoted into execution authority. Instead, the final write transaction in the same
single-Campaign SQLite Graph Store:

1. validates the exact `MissionEnvelope`, `ActionProposal`, `GraphDecision`, and registered
   Capability;
2. reprojects the complete durable Event Log and compares it to the stored current Projection;
3. requires the decision's immutable Snapshot to be that exact latest Projection;
4. rechecks Scope, target, risk, Campaign/Run, compiler, and Tool/version/digest bindings;
5. computes cumulative call/unit/cost budgets and the rolling-window unit rate; and
6. appends a deterministic `ActionPermit` as a consumed dispatch claim.

## Authority contracts

`RegisteredActionCapability` canonically pins a Capability ID/version, CAP-001
`definitionDigest`, Tool ID/version/digest, and risk tier into a separate Graph registration
digest. `ActionCapabilityRegistry` resolves only an exact version, definition digest, and
registration digest. The registry is currently an immutable process-local contract; durable
registry distribution remains follow-up work.

`MissionEnvelope` is the execution ceiling for one Campaign/Run. It binds profile/compiler/source
Campaign identity, exact allowed Capability references, target digests, maximum risk, autonomy,
call/unit/fixed-point micro-USD budgets, an optional rolling rate, and an authorization window.

`ActionProposal` is non-executable intent bound to an exact Envelope, Graph decision, Snapshot,
Capability, target, request, normalized parameter digest, and budget reservation.

`ActionPermit` is a consumed-on-issuance non-bearer audit proof. It binds every authority input,
compiler identity, canonical permit and dispatch IDs, and a short authority window no longer than
the Envelope. Its ID excludes clock values, so an exact response-loss retry resolves the stored row
but returns `newlyConsumed=false` and cannot redispatch.

## SQLite schema v2

GRAPH-005 schema v1 gains two append-only tables:

| Table | Meaning |
| --- | --- |
| `graph_action_permit_writers` | Campaign-pinned compiler identity |
| `graph_action_permits` | consumed-on-issuance Permit and dispatch-claim ledger |

Permit rows reference the durable Snapshot and Projection revision. Proposal and request IDs are
independently unique. Update/delete/replace triggers and the schema fingerprint protect all Permit
material.

Migration first verifies the exact v1 schema and fingerprint. It preserves every Event, Projection,
and Snapshot and never fabricates Permit authority.

## Final authority transaction

```text
BEGIN IMMEDIATE
  verify pinned compiler
  resolve deterministic exact retry
  reject request/proposal equivocation
  validate Envelope + Proposal + Capability algebra
  reproject durable Event Log
  compare stored Projection + Snapshot exactly
  calculate durable budget/rate use
  append consumed ActionPermit
COMMIT  # authoritative dispatch-claim point
```

Graph Event append and Projection publication use the same database writer lock, so Graph mutation
and a dispatch claim have one serial order. A Graph Event committed afterward is later than the
already-authorized dispatch.

`GraphActionPermitDispatcher.dispatch_once()` calls the Worker callback only when
`newlyConsumed=true`. A callback failure or uncertain response leaves the Permit consumed; an exact
retry does not dispatch again. This is safety-first at-most-once behavior.

## Opt-in Capability and Gateway bridge

The CAP-005 compatibility layer can now build a content-addressed activation subset from one
CAP-004-verified release set. It adapts only those exact definitions into
`ActionCapabilityRegistry`, compiles a prepared request through CAP-002, and revalidates release,
Capability, Tool, request, normalized-parameter, and request-unit identities on both sides of the
Permit claim. `ExistingModeCapabilityGatewayDispatcher` calls the existing Tool Gateway only from
the first-consumption callback.

The callback requires a RunStore matching the Permit Run. It appends a content-addressed
`CapabilityDispatchAuditEvent` at `claimed` before Gateway entry and then one observed terminal
stage: `completed`, `failed`, `cancelled`, or `expired`. All stages bind the exact Permit,
dispatch, Proposal, request, activation set, and signed release. Completion also binds the exact
Gateway outcome digest, execution identity when available, policy/execution/result flags, and
evidence references. Result bodies and exception details are not copied into the lifecycle event.

An unavailable or mismatched audit store prevents Gateway entry. An expired Permit records
`claimed` and `expired` without calling Gateway. Failure and cancellation retain the consumed
Permit and record only an audit-safe exception type. The outer RunStore `AuditEvent` supplies
sequence, previous-hash linkage, and seal coverage.

The bridge is explicit construction, not default runtime wiring. Existing Mode execution is
unchanged, and local signed fixtures are not organization-issued activation authority.

## Fail-closed conditions

- durable Event Log and stored Projection mismatch;
- Snapshot differs from latest revision/head/projection;
- Campaign, Run, Envelope, decision, or compiler lineage mismatch;
- unknown Capability or version/digest/Tool/risk drift;
- out-of-Scope target or excessive risk;
- inactive or expired Envelope;
- cumulative budget or rolling-rate exhaustion;
- different material under an existing proposal or request identity; and
- compiler writer drift.

## Verification

Tests cover canonical identities, registry drift, reopen recovery, exact response-loss retry,
projection lag and stale decisions, cross-instance one-winner races, terminal callback failure,
durable budgets and rolling rates, Scope/expiry rejection, request equivocation, append-only and
fingerprint tampering, honest v1-to-v2 migration, signed Web + AI subset activation, inactive
Capability rejection, exact prepared-request Gateway dispatch binding, outcome-digest tamper
rejection, success/failure/expiry/cancellation lifecycle events, and pre-execution audit failure.
The Worker bridge additionally covers deterministic crash injection immediately after the SQLite
Permit claim and immediately after a Gateway side effect. It seals a pre-claim deployment/Run
anchor, records content-addressed `consumed-without-claim` or `claimed-outcome-unknown`
reconciliation, and proves repeated retries do not invoke Gateway or duplicate the record.
GRAPH-005 additionally backs up and restores consumed Permits with their exact Snapshot/compiler
bindings. A real subprocess hard exit preserves a committed Projection, rolls back an uncommitted
writer mutation, and leaves a published backup restorable after immediate process termination.
The Worker bridge now also terminates a real child process at three non-atomic boundaries:
immediately after Permit commit but before the claimed event, immediately after the claimed
RunStore append but before Gateway entry, and after a durable external Gateway side-effect marker
but before the completed event. Reopen and two retries preserve one Permit, record one immutable
reconciliation, and execute the retry Worker zero times.

The concentrated Capability/Graph regression suite on Windows is `158 passed, 2 skipped`;
the skips are the existing POSIX symlink/hard-link semantics checks.

## Remaining boundaries

- durable Capability Registry and compiler rotation policy;
- exhaustive process-kill and power-loss testing at every remaining SQLite, RunStore, and
  filesystem synchronization boundary;
- actual off-host backup transport/scheduling, independent-host restore drills, managed key
  service integration, object lock, and external anti-rollback inventory;
- multi-host leader/lease and PostgreSQL/HA adapters; and
- B2.9 Handoff projections and Supervisor shadow mode.

An external Worker side effect is not physically part of the SQLite commit. This slice defines the
commit as the one-time dispatch claim and prevents duplicate side effects on retry. A process crash
after commit may leave the action unexecuted but consumed; it is never automatically redispatched.
The Graph claim, RunStore lifecycle event, and Worker side effect are not one transaction. The
Worker bridge now durably distinguishes a consumed Permit with no `claimed` event from a
`claimed`-only outcome-unknown state. Neither classification manufactures completion or permits
automatic redispatch.
