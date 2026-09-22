# ADR-0320: Durably Claim Prepared Compact Web Analysis and Recover Cleanup

- Status: Accepted
- Date: 2026-09-22
- Scope: WEB-007 prepared compact live-call Gate B
- Implementation status: the adjacent dual-identity journal, winner-only transition handles,
  durable dispatch marker, conservative recovery projection, and deterministic live-resource owner
  binding are implemented in the working tree. Gate C authorization verification, Gate D runtime and
  receipt integration, and every actual model, Provider, or target dispatch remain pending.

## Context

[ADR-0319](0319-separate-prepared-compact-admission-from-live-call-authority.md) requires one durable
claim before a prepared compact request may cross the live boundary. The preparation identity and
authorization identity must each be independently single-use, rather than merely unique as a pair.
The claim must distinguish reservation, live start, pending cleanup, and terminal outcomes, prevent
concurrent winners, preserve uncertainty after a crash, and never authorize automatic redispatch.

Two existing journals provide useful durability patterns but do not have this contract.

`SupervisorInvocationJournal` is bound to Supervisor checkpoints, stable Provider request IDs,
preplanned Runs, and Supervisor budget state. Its exact unstarted retry returns the existing entry,
and its lifecycle has no pending-cleanup phase. Extending that table would either reinterpret an
existing Supervisor retry contract or add an unrelated Web trust boundary to the Supervisor store.

`AgenticCoordinationStore` is bound to an Agentic deployment, current Graph head, checkpoint,
target-neutral hypothesis projection, and Provider Run. Its hypothesis claim also returns an exact
existing entry and has no cleanup phase. Extending it would make WEB-007 depend on Agentic Graph and
deployment authority that the prepared compact admission neither owns nor needs.

The existing Gate A live materializer initially selected a random process-local resource owner.
That is safe for ordinary in-process cleanup, but it cannot let a restarted process identify the
exact container, seed container, volume, and network that belong to an uncertain durable claim. The
cleanup identity must therefore be fixed by the claim before any live resource side effect.

## Decision

### 1. Add an adjacent Web-specific journal without reusing another domain's claim

Add `WebAnalysisLiveClaimJournal` beside the WEB-007 preparation and admission code. It has its own
SQLite application ID, schema version, schema digest, and random store ID. It reuses the established
Supervisor journal's narrow filesystem, sidecar, canonical-schema, read-only connection, and
`BEGIN IMMEDIATE` transaction helpers. It does not reuse the Supervisor intent, state, receipt,
budget, or retry contract, and it does not add WEB-007 rows to the Agentic coordination database.

The journal uses:

- owner-only path and database modes;
- `DELETE` journal mode, `synchronous=FULL`, foreign keys, and `trusted_schema=OFF`;
- an exact table, index, and trigger fingerprint plus `quick_check` on every trusted connection;
- immutable metadata and claim identity columns;
- append-only, hash-chained transition events; and
- state-digest compare-and-set updates whose affected row count must be exactly one.

Every write fixes the parent/file identity before opening the transaction and, after commit,
rechecks that identity, the exact schema and store ID, and the final path identity before returning a
winner handle or successful transition result. A valid-database path substitution during commit is
therefore an uncertain failure, never returned live authority.

Creation is a deployment-initialization operation that must retain the resulting store ID outside
the open call. Production and recovery reopen the configured authoritative path with creation
disabled and that expected store ID. Silently creating another valid database would create a second
uniqueness domain and invalidate the single-use claim. This is a single-host SQLite authority, not
distributed consensus or an independent anti-rollback service.

### 2. Consume preparation and authorization identities independently

`WebAnalysisLiveClaimBinding` canonically binds fields from the supplied exact admission envelope,
the future authorization coordinate, exact request and response-schema digests, Capacity and
transport pins, Provider registration and chat-request digests, compact projection, and
owned-resource locator. The builder revalidates those typed objects but does not strict-reload their
sealed files. Gate D must perform ADR-0319's independent strict reload before building or reserving
this binding.

The claim table enforces separate SQL `UNIQUE` constraints for:

- `preparation_identity`, equal to the admitted preparation digest; and
- `authorization_identity`, derived with domain separation from authorization issuer, key ID, and
  nonce.

The immutable binding separately retains the preparation Run ID and root, preparation Index digest,
authorization-envelope digest, authorization-coordinate digest, admission identity, and selected
request anchors. The admission digest commits the remaining exact admission envelope without
duplicating all of its fields. The claim ID and digest, admission digest, deterministic resource
owner, and canonical binding are also unique or immutable as appropriate.

Reservation is one plain insert inside one immediate write transaction. It does not perform a
pre-check followed by insert, use replace or upsert, or return an existing row. Therefore all of the
following lose with a replay error:

- the same preparation with a different authorization;
- the same authorization with a different preparation; and
- the exact same preparation and authorization pair.

An uncertain reservation error returns no transition handle. Read-only lookup by claim,
preparation, or authorization identity exists only to classify durable state after uncertainty; it
does not turn an existing row into renewed authority.

### 3. Fix cleanup ownership before the live boundary

The canonical claim core deterministically derives a 32-hex-character resource owner. That owner
fixes the exact runtime-container, seed-container, model-volume, and internal-network names in the
immutable claim. The Gate A live materializer accepts this precomputed owner and derives the same
names before creating a resource.

This binding does not itself create, inspect, or remove Docker resources. It gives the later Gate D
runtime and cleanup recovery path exact coordinates that can be checked against Gate A ownership
labels. A caller-supplied arbitrary owner, an unbound random owner, a resource-name variation, or a
broad label scan cannot substitute for the locator in the durable claim.

### 4. Preserve four durable phases and a separate one-dispatch marker

The closed phase model is:

```text
reservation
  -> live-start
      -> live-start with dispatchCount = 1
      -> pending-cleanup
  -> pending-cleanup
      -> terminal
```

`reservation` commits both independent identities. `live-start` is committed before the first owned
live-resource side effect. A reservation may move directly to `pending-cleanup` when work fails or is
abandoned before live start.

The `dispatch-started` event is a state-digest CAS within `live-start`, from `dispatchCount=0` to
`dispatchCount=1`. It must be committed immediately before the later Gate D runtime invokes the
model. The journal method only consumes and records the slot; it contains no model client and does
not dispatch anything. A live-start row alone is not evidence that a dispatch happened.

`pending-cleanup` carries one conservative outcome:

- `not-dispatched`;
- `success-observed`;
- `failure-observed`; or
- `outcome-unknown`.

The terminal disposition is separately `success`, `failure`, or `abandoned`. Terminal success
requires exactly one consumed dispatch slot and `success-observed`. Every terminal disposition,
including failure and abandonment, requires a prior pending-cleanup phase plus the exact cleanup
result, resource-absence, and terminal-receipt digests. Gate D remains responsible for verifying the
actual cleanup evidence and strict receipt before supplying those digests; Gate B only binds them.

### 5. Return live progression only to the transaction winner

A successful reservation returns a store-local `ReservedWebAnalysisLiveClaim`. Successful live-start
and dispatch-marker transitions replace it with correspondingly narrowed one-use handles. These
handles:

- are issued only after the winning transaction commits and reloads the exact row;
- are bound to one in-process journal authority object;
- reject foreign journal authority instances, including another instance over the same file, as well
  as wrong concrete types, wrong phases, and reuse;
- are consumed immediately before the next durable transition attempt, so rollback and ambiguous
  commit outcomes cannot return retry authority; and
- cannot be copied, deep-copied, or serialized.

`WebAnalysisLiveClaimJournalEntry` is an audit projection with every model, Provider, target, general
execution, reuse, and automatic-redispatch marker fixed to false. Inspection and restart return only
this projection, never a reservation, live-start, or dispatch-started handle.

### 6. Recover only toward cleanup and terminalization

On restart, `recover_pending_cleanup()` atomically moves every unfinished `reservation` or
`live-start` row to `pending-cleanup` with `outcome-unknown`. Rows already pending remain pending.
This operation does not infer whether model dispatch occurred, recreate a consumed handle, or permit
another dispatch. The persisted dispatch marker remains the only durable dispatch-count fact.

Recovery is explicit and must run under quiescent, single-coordinator operational ownership. The
journal has no lease or process-liveness detector and cannot decide whether another process holding
an in-memory handle is alive. It is not an automatic startup sweeper.

Pending entries expose the immutable resource locator only for a future cleanup-only consumer.
Cleanup failure appends a content-addressed failure event and leaves the row pending and unusable.
Repeated cleanup attempts may continue from that state because cleanup removes exact owned resources;
they never restore model-call authority. Only verified cleanup, absence, and receipt evidence may let
Gate D request the final pending-to-terminal CAS.

If a database commit may have succeeded but the caller did not receive a result, the caller must
inspect the durable identities and proceed only toward cleanup. It must not repeat reservation,
recreate a live handle, assume that the dispatch slot is free, or issue another model request.

### 7. Keep Gate C's coordinate explicitly non-authoritative

Gate B defines `WebAnalysisOneCallAuthorizationCoordinate` only so an issuer, key ID, nonce, and exact
future authorization-envelope digest have a stable identity that can be consumed independently. Its
status is `unverified-identity-coordinate-no-authority`; authorization verification and every
execution marker are literal false.

This coordinate does not verify a signature, validity interval, admitted request digest, model,
transport, or replay policy. It cannot reinterpret a locally generated Campaign approval as external
authorization. Gate C must verify the external authorization against those exact values outside the
execution path. Gate D must require that verified result before reserving the Gate B claim and must
revalidate it immediately before the durable dispatch marker and model call.

## Consequences

### Positive

- Within one exact journal database, either preparation identity or authorization identity can win
  at most one reservation, including under concurrent processes.
- Exact-pair replay is rejected instead of being mistaken for an idempotent live retry.
- The durable dispatch marker closes the race between a general live-start state and the single
  actual completion slot.
- Cleanup coordinates survive process death without making serialized database values into bearer
  authority.
- Supervisor and Agentic journal schemas and historical retry meanings remain unchanged.
- Gate B performs no model, Provider, target, Tool, Finding, Graph, report, or delivery operation.

### Cost and remaining work

- The dedicated database adds one more single-host durable authority that must be retained, backed
  up, and reopened with its expected store identity.
- Whole-database rollback of the same valid store is not independently detected without an external
  retained head or recovery witness.
- Explicit recovery requires a quiescent deployment or one trusted recovery coordinator; it does
  not fence an independently running process through a lease or liveness protocol.
- Gate B can durably consume an unverified authorization coordinate, but doing so grants no call
  authority. Gate C must add the real external verifier and bind its result without widening this
  journal wire.
- Recovery currently projects exact cleanup work; Gate D must perform owner-checked removal, prove
  absence, seal the compact terminal receipt, and then request terminalization.
- Successful structured model output, Provider behavior, latency, memory, stability, proposal
  quality, and all target-side effects remain unverified.

## Rejected alternatives

- Extend `SupervisorInvocationJournal` and reinterpret its idempotent unstarted retry as a rejected
  Web authorization replay.
- Add WEB-007 claims to `AgenticCoordinationStore` and require unrelated Graph, checkpoint, or
  deployment authority.
- Protect only the composite preparation-and-authorization pair instead of two independent unique
  identities.
- Return an existing row or reconstruct a process-local handle after replay, restart, or uncertain
  commit.
- Create a replacement journal on restart and thereby establish another uniqueness domain for the
  same preparation or authorization identities.
- Treat live start as the dispatch marker or keep the dispatch count only in memory.
- Generate resource ownership after materialization starts or discover cleanup scope with a broad
  resource scan.
- Recycle a claim after timeout, cleanup, terminal failure, or abandonment.
- Seal terminal success before cleanup and exact absence are independently verified.
- Treat the Gate B authorization coordinate or a code-generated Campaign approval as Gate C
  authorization.

## Compatibility and rollback

This decision is additive. Existing Supervisor, Agentic, Capacity, preparation, admission, legacy
analysis request, receipt, loader, and runtime contracts retain their historical meanings. No
existing journal schema is migrated or reinterpreted.

Rollback disables the prepared compact live successor while retaining the Gate B journal for audit
and future cleanup. Deleting or replacing that journal to regain consumed identities, returning to a
legacy runtime, reconstructing a progression handle from an audit row, or automatically
redispatching is prohibited.

## Related documents

- [ADR-0319: Separate Prepared Compact Admission from Live-call Authority](0319-separate-prepared-compact-admission-from-live-call-authority.md)
- [ADR-0318: Attest Descriptor-bound Model Materialization before Live Web Analysis](0318-attest-descriptor-bound-model-materialization-before-live-web-analysis.md)
- [ADR-0306: Publish Durable Agentic Coordination without Execution Authority](0306-publish-durable-agentic-coordination-without-execution-authority.md)
- [ADR-0123: Durably Claim and Seal Supervisor Invocations](0123-durably-claim-and-seal-supervisor-invocations.md)
- [WEB-007 contract](../orchestration/WEB-007-llm-assisted-web-analysis-proposal.md)
