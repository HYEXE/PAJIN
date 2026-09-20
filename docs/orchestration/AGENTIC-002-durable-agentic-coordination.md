# AGENTIC-002: Durable Agentic Coordination

## Status

Implemented in the local working tree. Linux descriptor, persistence, recovery, adversarial,
cross-platform fail-closed, Ruff, and strict mypy gates passed on 2026-09-18. No model, target,
Gateway, Worker, Finding, Graph-write, report-delivery, or PoC execution was performed by this
slice.

## Version

- Coordination API: `pajin.dev/agentic-durable-coordination/v1alpha1`
- Decision: [ADR-0306](../adr/0306-publish-durable-agentic-coordination-without-execution-authority.md)
- Compatibility: additive; AGENTIC-001 objects remain byte- and behavior-compatible

## Objective

AGENTIC-002 moves the AGENTIC-001 planning loop from process-local audit state to a bounded,
single-host durable coordination boundary. It provides:

1. independent resolution of the current canonical Graph head;
2. a durable no-automatic-redispatch model invocation claim;
3. exact checkpoint compare-and-set;
4. transactional logical-command outbox publication;
5. verified restart recovery; and
6. deterministic target-neutral context compaction.

It does not translate a logical assignment into Scope, Capability, Permit, Tool, Worker, Finding,
Graph write, report, SARIF, delivery, or executable PoC authority.

## Durable flow

```text
deployment-fixed Graph DB + Campaign + expected Snapshot ref
        |
        | read-only complete current-head verification
        v
opaque VerifiedCurrentGraphHead
        |
        +--> model invocation intent -> dispatch-started/outcome-unknown -> sealed terminal
        |
        +--> deterministic AGENTIC-001 cycle
                |
                | exact source-head CAS in one SQLite transaction
                v
        durable checkpoint publication + complete logical-command outbox
                |
                | current Graph revalidation and durable claim
                v
        lifecycle delivery only; no target execution authority
```

## Current Graph head

The resolver is configured with one exact regular Graph database path and Campaign. `resolve()`
accepts only an expected Snapshot reference and calls the existing complete verified-current Graph
reader. The issued handle binds:

- resolver and database identity;
- Campaign;
- Snapshot ID and digest;
- revision and event-log head;
- Projection ID, digest, node digest, and edge digest; and
- the canonical `GraphSnapshot` value.

Only the issuing resolver can consume or revalidate the handle. A raw Snapshot, copied handle,
cross-resolver handle, changed file identity, missing current Snapshot, stale head, or any differing
canonical field is rejected.

## Coordination storage authority

The authoritative coordination store is Linux-only. It fails before creating or changing the
coordination path unless POSIX descriptors and `/proc/self/fd` are available. The store pins
owner-only descriptors for the parent directory and main database for the lifetime of the store,
opens SQLite only through the descriptor-relative `/proc/self/fd/<parent-fd>/<leaf>` path, and proves
that the main database descriptor actually opened by SQLite has the same inode identity as the
pinned database. There is no pathname fallback on unsupported hosts.

SQLite must remain in `DELETE` journal mode. WAL, SHM, and any idle sidecar fail closed. A valid hot
rollback journal may be recovered once while first reopening an existing store; any later idle
journal fails closed. Reopening also requires an independently retained exact expected store ID.
That ID prevents substitution with another valid store, but it is not an independent head witness
and therefore cannot detect rollback of the same complete database.

The integrity of the hosting process is part of this boundary's trusted computing base. Arbitrary
in-process file-descriptor-table manipulation, memory mutation, or monkeypatching is process
compromise and is not isolated by this store. A deployment that loads hostile extension code must
move coordination behind a dedicated broker or a descriptor-aware SQLite VFS before treating it as
authoritative. This residual is distinct from the external same-UID path and namespace replacement
attacks that the pinned descriptors and actual SQLite-FD attestation reject.

## Invocation journal

One immutable intent binds the exact source head and all Provider-visible and private compilation
inputs without granting authority. Its stable slot cannot be rebound to a different Context,
Projection, request, runtime, model, schema, budget, or output Run.

State transitions are closed and durable:

| State | Dispatch permitted | Automatic retry | Recovery |
| --- | --- | --- | --- |
| `intent-recorded` | exactly one atomic start | no separate duplicate | exact intent may start |
| `dispatch-started-outcome-unknown` | no | never | exact sealed receipt or manual decision |
| `terminal-success` | no | no | strict reload only |
| `sealed-terminal-failure` | no | no | strict reload only |

The started transition is committed before entering the Provider boundary. A crash after it cannot
return to `intent-recorded`.

## Checkpoint CAS and outbox

The coordination deployment is pinned to one Campaign, Supervisor, Graph source, Exploit Group,
Supervisor policy, scoring policy, and allowed-target set. Initialization accepts only the exact
deterministic revision-zero checkpoint for those pins.

Publishing a Cycle requires all of the following:

- the Cycle strictly reloads and deterministically replays under AGENTIC-001;
- its source checkpoint is the exact durable head;
- its result revision increments by one;
- its source Graph equals a freshly revalidated current Graph handle;
- every prior session, command, Candidate, semantic digest, and event binding is preserved; and
- every Cycle command appears exactly once in the same transaction's outbox rows.

The atomic transaction appends the transition, inserts canonical command wires, and advances the
head. A stale writer, partial command set, duplicate sequence, different successor, or hidden
Pydantic mutation fails without advancing the head.

The durable publication wrapper records the store binding and current head. The embedded
AGENTIC-001 checkpoint retains `restartResumeSupported=false` and `durableHeadPublished=false`;
those fields describe the v1 object itself and are never rewritten to true.

## Recovery

The store opens existing state without silently recreating missing metadata, tables, indexes, or
triggers. It verifies the expected store identity, SQLite application/schema versions, schema
objects, canonical stored wire, hash chains, head uniqueness, checkpoint transition continuity,
event-to-acknowledged-inbox binding, outbox coverage, and closed states.

Restart restoration requires:

- a current verified coordination-head handle issued by the store;
- a current verified Graph handle issued by the configured resolver; and
- exact current Exploit Group and policy pins.

The restore path reconstructs AGENTIC-001 state from the verified durable checkpoint. It does not
accept a caller-provided checkpoint. A whole-database rollback is outside this local store's proof
unless an independent expected head or recovery witness is supplied.

## Context compaction

The compactor accepts an exact verified checkpoint and exact artifact-reference input. Its output
contains only:

- source checkpoint and Snapshot digests;
- deterministic item counts and ordered manifest digests;
- digest-only retained artifact projections;
- omitted count and omitted-manifest digest; and
- policy, byte, item, node, and ancestry-depth bounds.

It excludes Campaign and agent names, artifact IDs, Run IDs, media types, target locators, raw
content, free-form summaries, credentials, request bodies, DOM, and executable data. The output is
untrusted advisory context with instruction, Evidence, Scope, Capability, Permit, execution,
Finding, and Graph authority all literally false.

The compactor never replaces or truncates the authoritative checkpoint, command/event ledger,
budgets, Graph material, approvals, or Permits. It may be discarded and rebuilt from verified
inputs.

## Required negative behavior

The implementation rejects, before Provider or target dispatch where applicable:

- raw, forged, stale, cross-database, or cross-resolver Graph heads;
- a Graph file that changes identity during verification;
- a non-Linux host, unavailable `/proc/self/fd`, pathname fallback, or unsupported-platform path
  mutation;
- parent, leaf, pinned database, or SQLite-opened main-database descriptor identity drift;
- reopen without the independent expected store ID, or with a different store ID;
- WAL/SHM, idle sidecars, or any hot journal after the one first-reopen recovery opportunity;
- a duplicate or equivocal model invocation slot;
- automatic redispatch from any outcome-unknown state;
- an arbitrary self-consistent or historical checkpoint offered for resume;
- stale, skipped, forked, or foreign checkpoint CAS;
- a checkpoint advance with missing, extra, reordered, or rewritten outbox commands;
- lifecycle command rows containing Capability, Permit, Tool, payload, Finding, or Graph authority;
- out-of-order per-session delivery and stale claim acknowledgement;
- database schema, trigger, canonical wire, digest-chain, or head tampering;
- nested `model_copy`, `model_construct`, non-wire container, primitive-subclass, alias collision,
  duplicate-key, cycle, depth, node-count, and byte-budget smuggling; and
- compact context containing target, content, identity, instruction, or authority material.

## Verification matrix

Focused tests must cover normal initialization, cycle publication, event publication, reopen,
restart restore, stable invocation claim, terminal receipt recovery, context compaction, Linux
descriptor binding, A/B namespace replacement, one-time hot-journal recovery, sidecar rejection,
fork/close behavior, unsupported-platform zero mutation, and the negative cases above.
Crash-boundary tests distinguish:

1. before and after invocation intent;
2. before and after dispatch start;
3. after Provider result but before journal terminal;
4. after terminal invocation but before checkpoint CAS;
5. after checkpoint/outbox commit but before delivery; and
6. after receiver admission but before sender acknowledgement.

No test may weaken assertions, use a success stub in place of durable behavior, or contact a model
or target.

## Migration and rollback

No existing database or wire is migrated. A new coordination store is explicitly initialized for
one deployment binding. Rolling back AGENTIC-002 leaves AGENTIC-001 process-local behavior intact;
the new database is retained as read-only audit material and is not opened by the older runtime.

## Next boundary

AGENTIC-003 may consume an outbox assignment only after revalidating the current Graph and durable
head and compiling the Candidate through an exact code-owned specialist route. It must issue fresh,
task-scoped authority through the existing approval, Permit, Gateway, Worker, Evidence, and
independent replay chain. The AGENTIC-002 command itself is never that authority.
