# ADR-0306: Publish Durable Agentic Coordination without Execution Authority

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-002 durable coordination
- Implementation status: Implemented in the local working tree

## Context

AGENTIC-001 introduced deterministic hypothesis expansion, path scoring, and logical specialist
commands, but deliberately accepted a caller-supplied `GraphSnapshot`, kept checkpoints in process,
and made every model runtime single-use only in memory. Those controls prevent accidental reuse in
one process but do not prove that a Snapshot is the deployment's current durable head, prevent a
second process from dispatching the same model request, or recover a Supervisor after a crash.

Publishing a self-consistent checkpoint file is insufficient. A valid historical checkpoint can be
replayed, two writers can publish different successors, and a checkpoint can be persisted without
the commands that it claims to have issued. Similarly, marking a Provider attempt complete after a
network error can silently turn an unknown outcome into an authorized retry.

## Decision

### Resolve the Graph head through the existing verified store reader

Agentic durable entry points accept an opaque verified-current handle issued by a resolver bound to
one deployment-fixed Graph database and Campaign. The resolver uses the existing read-only current
Snapshot verifier and binds the exact Snapshot ID, digest, revision, event-log head, projection, and
database identity. A raw `GraphSnapshot`, a handle from another resolver, or a handle that has become
stale is not a durable authority.

Verification is repeated before an invocation claim, before checkpoint compare-and-set, and before
future command release. This is a fail-closed freshness gate, not a cross-database transaction. A
Graph Decision audit store, the Graph store, and the agentic coordination store remain independent
authorities, so no distributed atomicity claim is made.

### Pin the coordination database through Linux descriptors

The authoritative coordination backend is restricted to Linux hosts with working POSIX descriptors
and `/proc/self/fd`. It pins owner-only parent-directory and database descriptors for the store
lifetime, opens SQLite only through a descriptor-relative `/proc/self/fd/<parent-fd>/<leaf>` URI, and
attests the inode identity of the main database descriptor actually opened by SQLite. Unsupported
platforms, missing descriptor support, namespace replacement, or descriptor drift fail before
coordination state is created or trusted; there is no absolute-path fallback.

The database uses `DELETE` journal mode and rejects WAL, SHM, and idle sidecars. The first reopen of
an existing store may recover one valid hot rollback journal; later idle journals fail closed.
Reopen requires an independently retained expected store ID and compares it during schema
validation. The store ID prevents replacement by a different valid database, but detecting rollback
of the same whole database still requires a separately retained head or recovery witness.

The hosting process is trusted. Code that can arbitrarily close or reuse process descriptors,
mutate memory, or monkeypatch the runtime has already crossed the coordination trust boundary. A
deployment with hostile in-process extensions requires an isolated coordination broker or a
descriptor-aware SQLite VFS; the current implementation does not claim to contain such code. This
does not weaken its defense against external same-UID pathname, leaf, parent, or sidecar
replacement.

### Journal model invocation before dispatch

Every durable hypothesis-expansion attempt receives a content-addressed immutable intent before a
Provider call. The intent binds the Campaign, Supervisor, source checkpoint and current Graph head,
private Context and target-neutral Projection identities, exact request identity, schema and token
limits, Provider/runtime pins, budget pins, Exploit Group, and expected sealed receipt location.

The closed lifecycle is:

```text
intent-recorded
  -> dispatch-started-outcome-unknown
  -> terminal-success | sealed-terminal-failure
```

`dispatch-started-outcome-unknown` is committed before the Provider call. It is never automatically
redispatched. Recovery may finalize only from the exact preplanned Run and a fully verified sealed
receipt. An unstarted exact intent can be resumed; an equivocal intent for the same slot is rejected.

### Publish checkpoint and command outbox with exact CAS

The coordination store has one current head per exact Campaign and Supervisor deployment binding.
Initialization publishes the deterministic revision-zero checkpoint. A later cycle is accepted only
when its complete deterministic replay consumes the exact current head. The store atomically writes:

- the next checkpoint and its source-head binding;
- the complete cycle or accepted event transition;
- every newly issued logical command as canonical outbox wire; and
- the new `(revision, checkpoint ID, checkpoint digest)` head.

The compare-and-set rejects stale writers, skipped revisions, rewritten command history, partial
command sets, foreign configuration, and a different successor for the same source head. The
AGENTIC-001 checkpoint keeps its original `restartResumeSupported=false` and
`durableHeadPublished=false` meanings. A separate durable publication wrapper records that an exact
checkpoint was published by this store; it does not reinterpret the v1 object.

### Recover through verified heads, not caller checkpoints

Restart construction accepts only a verified current-head handle returned by the coordination store
and a freshly verified current Graph handle. The store reloads canonical checkpoint and command
wire, checks schema and event-chain integrity, and restores the deterministic in-memory state. A
caller cannot pass an arbitrary content-addressed checkpoint to a resume constructor.

Outbox delivery is not described as distributed exactly-once. Commands have stable IDs and durable
claim state. A delivery that may have crossed the receiver boundary remains outcome-unknown until
reconciled; any future retry requires receiver-side durable deduplication and a monotonic fence.
Logical commands still grant no Capability, Permit, Tool, Finding, or Graph authority.

### Compact context without summarizing authority

Context compaction is deterministic and model-free. It consumes one verified checkpoint plus exact
artifact references, emits only target-neutral digests, counts, and closed metadata, and binds the
full retained and omitted manifests. It never summarizes or discards command/event ledgers, budgets,
Graph bindings, approvals, Permits, or other authority-critical state. Free-form agent text, target
locators, credentials, raw bodies, and DOM content are excluded.

## Consequences

### Positive

- A caller-authored or stale Graph Snapshot cannot enter the durable agentic path.
- Cross-process model invocation and checkpoint races have an auditable fail-closed state.
- Checkpoint and logical command publication cannot diverge inside one coordination transaction.
- Restart recovery is bound to the current durable head rather than a supplied historical file.
- Context growth is bounded without letting summaries become instructions or Evidence.

### Tradeoffs and residual risks

- Local SQLite coordination is a single-host boundary, not a distributed consensus system.
- The authoritative backend currently requires Linux `/proc/self/fd`; other platforms are an
  availability follow-up and do not use a weaker pathname fallback.
- Hosting-process integrity is trusted; hostile in-process extensions require a dedicated broker or
  descriptor-aware SQLite VFS.
- A valid rollback of the entire coordination database cannot be detected without a separately
  retained expected head or recovery witness.
- The Graph and coordination stores are not one atomic database. A Graph advance can make an
  otherwise valid cycle stale and unreleasable.
- Provider outcome-unknown attempts require manual or sealed-receipt reconciliation and may reduce
  availability.
- AGENTIC-002 still does not create Scope, activate a Capability, issue or consume a Permit, execute
  a Tool, admit a Finding, mutate the Graph, generate a report, or contact a target.

## Compatibility, migration, and rollback

The change is additive. AGENTIC-001 wire objects and existing Web, Provider, Graph, Capability,
Permit, Finding, report, and PoC formats remain unchanged. Existing in-process callers can continue
to use AGENTIC-001 but cannot claim durable restart or current-head authority.

Rollback removes the durable resolver, coordination store, context compactor, tests, and this
contract. Because AGENTIC-002 grants no target or execution authority, no target-side rollback is
required. A retained coordination database becomes audit material only and must not be reopened by
an older implementation.

## Rejected alternatives

### Trust any self-consistent Graph Snapshot or checkpoint

Rejected because content addressing does not prove current deployment state or prevent rollback.

### Retry any Provider call after a process crash

Rejected because a dispatch may have completed outside the process even when its local outcome is
unknown.

### Mark an outbox row delivered before receiver admission

Rejected because a crash between those operations can permanently lose a logical command.

### Let an LLM summarize Supervisor history for restart

Rejected because lossy, target-influenced text cannot replace authority-critical ledgers or become
trusted instructions.

## Related documents

- [ADR-0305: Add a Bounded Agentic Hypothesis Frontier and Exploit Group](0305-add-a-bounded-agentic-hypothesis-frontier-and-exploit-group.md)
- [ADR-0123: Durably Claim and Seal Supervisor Invocations](0123-durably-claim-and-seal-supervisor-invocations.md)
- [ADR-0049: Durable Single-Campaign SQLite Graph Store](0049-durable-single-campaign-sqlite-graph-store.md)
