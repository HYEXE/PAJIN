# ADR-0316: Persist Specialist Job Attempts and Typed Verification without Recovering Dispatch Authority

- Status: Adopted
- Date: 2026-09-20
- Scope: AGENTIC-003C3C-live durable job-attempt classification, typed verification records,
  schema migration, and the recovery authority boundary
- Implementation status: additive SQL-injection v2 complete seven-role Capability bundle, signed
  current Range activation, exact action registry and deterministic `PreparedCapabilityAction`,
  distinct v2 Plan/runtime generation, same-Task Grant/approval/Permit callback, private capsule
  transfer and Store-owned one-shot runtime claim,
  schema-v6 JobAttempt and terminal-receipt records, detached typed-verification builders, explicit
  offline v5-to-v6 migration, audit-only recovery, and a source-byte-addressed structured zero-
  Target-I/O v2 fake backend with Ed25519 result verification implemented; public C3C-to-JobAttempt
  admission, governed Gateway/Worker execution, and signed terminal finalization pending

## Context

[ADR-0315](0315-separate-c3c-conformance-contracts-from-executable-specialist-dispatch.md)
separates the serializable C3C audit binding and Target-I/O-zero conformance contract from future
executable specialist dispatch. It requires a new v2 authorization chain, a Store/DB/Task-bound
opaque live capsule, current-state revalidation at the Gateway and backend boundaries, one durable
dispatch linearization point, terminal classification, and restart behavior that never reconstructs
execution authority.

Coordination schema version 5 records the C3B2 Permit and Grant-consumption crash fence but cannot
represent one exact backend job attempt, the typed inputs to its claim and dispatch checks, or its
terminal classification. A future scheduler also needs a durable way to distinguish a claim made
before backend handoff from a handoff that may already have started and therefore cannot be retried
safely.

The repository now contains an additive SQL-injection v2 complete seven-role code-backed Capability
bundle, an externally signed current Range release activation, an exact action registry, a
deterministic `PreparedCapabilityAction`, a distinct v2 Plan/runtime generation, same-scheduler-Task
Grant/approval/Permit callback and private one-shot runtime claim, schema-v6 JobAttempt and
terminal-receipt models, and typed
`AgenticSpecialistClaimVerification` and
`AgenticSpecialistDispatchVerification` records. These records are canonical detached audit
evidence. The private claim freshly revalidates the current Graph, durable history, deployment,
preparation/action, approval, terminal Permit, and Grant lineage, consumes its Store-owned capsule
even on terminal failure, and performs no Target I/O. It does not mint a public C3C or JobAttempt
handle. The detached record builders derive records from supplied canonical material; they do not
observe a live scheduler Task, catalog, ledger, deployment, Gateway, backend, or Target. The
repository also contains a structured one-call fake backend whose signed result proves its own
zero-Target-I/O conformance only. Neither the serialized records, pure builders, nor fake-backend
result can substitute for the missing live authority boundary.

## Decision

### 1. Preserve the inert v1 boundary and keep v2 planning additive

The existing v1 specialist Capability, Tool, releases, activations, requests, plans, Grants,
approvals, Permits, and started executions retain their existing inert meaning. None can be upgraded
to executable v2 authority.

The current live-path identity is limited to SQL injection and uses the same logical Capability ID
at version `2.0.0` plus the distinct Tool `web.specialist.sql-login.v2@2.0.0`. Its exact Definition is
bound to a complete seven-role code-backed authority set. A lifecycle registry admits one externally
signed current experimental release for Range use, creates one content-addressed activation set and
exact `ActionCapabilityRegistry`, and deterministically compiles one `PreparedCapabilityAction` from
sealed preparation and account-receipt references. Only the materializer and action compiler can
perform this preparation. Direct Tool dispatch and the executor, normalizer, oracle, replay, and
cleanup roles remain fail-closed before I/O. No v2 Plan, Grant, approval, Permit, Gateway binding, or
backend authority is admitted by the activation or prepared action alone.

The exact Store and creating scheduler Task separately own one distinct
`pajin.dev/agentic-sql-specialist-dispatch-plan/v2alpha1` plan, its one-call Grant, signed approval,
Permit callback, started handle, transferred private capsule, and one-shot runtime claim. The claim
retires the capsule after success or terminal failure. It yields no bearer object, does not create a
JobAttempt, and performs no Gateway, Worker, backend, browser, network, or Target I/O.

### 2. Advance the coordination Store to schema version 6

Schema version 6 adds two append-only authority-classification families:

- `agentic_specialist_job_attempts`; and
- `agentic_specialist_terminal_receipts`.

Their versioned wire contracts are:

- `pajin.dev/agentic-specialist-job-attempt/v1alpha1`;
- `pajin.dev/agentic-specialist-terminal-receipt/v1alpha1`;
- `pajin.dev/agentic-specialist-claim-verification/v1alpha1`; and
- `pajin.dev/agentic-specialist-dispatch-verification/v1alpha1`.

One JobAttempt is uniquely bound to one dispatch plan, reservation, command, dispatch binding,
request, Grant-consumption receipt, ActionPermit, approval-consumption receipt, action dispatch, and
Worker job. It also pins the exact Store and coordination binding, database identity, deployment,
control-plane Run, Campaign, Graph Snapshot, target agent and Task, specialization, prepared action,
release and activation set, Capability definition and runtime Capability digest, complete Capability
authority-set ID and digest, Tool, Target, Gateway, backend, immutable Worker image, and Worker
verifier.

The record additionally pins both scheduler ownership and capsule lineage through
`schedulerTaskName`, `schedulerTaskTokenDigest`, and `runtimeCapsuleTokenDigest`. These are digest
references in a detached record. Their presence does not prove that the referenced Task or capsule
is still live, owned by the caller, or eligible to dispatch.

The table stores the complete canonical JobAttempt bytes and denormalizes the security-relevant IDs
and digests into strict columns. Claim- and dispatch-verification IDs are unique, their digests are
stored separately, and row reload checks require the indexed columns to equal the embedded canonical
record. SQL constraints, triggers, canonical reload, and structural-history validation reject
identity collision, parent substitution, state rewind, mutation, deletion, terminal-state advance,
and a receipt attached to a different attempt.

The schema is specialization-generic, but the current internal Store insertion path accepts only the
exact SQL-injection v2 Capability and Tool identity. This restriction is not a live execution path.

### 3. Persist typed canonical verification preimages without treating them as authority

The verification digest graph is deliberately acyclic:

```text
canonical claim subject
        -> claim verification
        -> immutable JobAttempt identity and claimed-state digest
        -> dispatch verification
        -> dispatch event and started-state digest
```

The claim subject is the complete alias-keyed JobAttempt identity material before attempt, state,
claim-verification, or dispatch-verification identities exist. Its digest becomes
`subjectDigest` in the embedded claim verification. The claim verification also binds the Store,
database, deployment, control-plane Run, plan, Graph Snapshot, scheduler Task token, runtime capsule
token, dispatch binding, complete authorization-lineage digest, exact runtime-inventory digest, and
claim timestamp. Its Target-I/O state is `not-started`, and all execution, Finding, Graph, report,
and PoC authority markers are literal false.

The JobAttempt identity includes the claim-verification digest while excluding the embedded
verification object itself, avoiding a digest cycle. The canonical JobAttempt nevertheless embeds
the full claim-verification preimage, and the durable row separately records its content-addressed ID
and digest.

Dispatch verification is permitted only for one exact claimed JobAttempt. It embeds the prior
claim-verification ID and digest, attempt ID and digest, claimed-state digest, Graph Snapshot,
scheduler Task and capsule tokens, dispatch binding, authorization-lineage digest, runtime-inventory
digest, a derived backend idempotency key, a fresh backend-handoff deadline, and the verification
timestamp. The started JobAttempt embeds this complete verification record and separately stores its
ID and digest. The attempt identity remains stable; its state digest adds the dispatch-verification
digest, derived dispatch-event digest, and dispatch-start timestamp.

The functions that currently build these records are pure detached builders. Canonical agreement,
digest agreement, and embedded-preimage agreement prove only internal structural consistency. They
do not prove fresh observation of current catalogs, Capability ledger state, deployment inventory,
Task ownership, capsule liveness, Gateway admission, backend state, or Target I/O.

### 4. Use a one-way JobAttempt state machine around backend handoff

A JobAttempt begins as `claimed-before-backend`. The only allowed state transition is:

```text
claimed-before-backend -> dispatch-started-outcome-unknown
```

The dispatch transition requires the embedded typed dispatch verification, its separately stored
digest, a derived dispatch-event digest, and a dispatch timestamp. The Store commits that marker
synchronously before a future backend await. A terminal receipt fences any later attempt-state
transition.

The current private Store methods can persist a detached claim and derive the dispatch-verification
record from that claim. They are not a public scheduler authority and do not establish that the
required live capsule, catalogs, ledger, deployment, Gateway, or backend were re-observed.

### 5. Use one closed terminal-receipt grammar

Every terminal receipt is content-addressed, immutable, one-per-attempt, and bound to the exact
attempt state digest, plan, request, and Worker job. The allowed classifications are:

- `abandoned-before-backend`: the claimed state ended with Target I/O not started;
- `failed-before-target-io`: backend dispatch was marked, a terminal backend result is proven, and
  Target I/O is proven not started;
- `completed-verified`: backend dispatch was marked, Target I/O is proven performed, success is
  true, and both the Worker result and terminal backend proof are present;
- `failed-after-dispatch-proven-terminal`: backend dispatch was marked, Target I/O is proven
  performed, success is false, and both result and terminal proof are present; or
- `started-outcome-unknown`: backend dispatch was marked, Target I/O remains unknown, success is
  null, and no result, terminal proof, or backend-finish time is claimed.

Every receipt keeps automatic redispatch, execution, Finding, Graph, report, and PoC authority
literal false. The receipt grammar prevents contradictory classification, but a structurally valid
receipt is not trusted backend provenance until a deployment-owned terminal-proof verifier and
authorized receipt producer exist.

A zero-I/O fake backend result is not `completed-verified`. It may exercise serialization, state
fencing, and denial behavior as conformance evidence, but it cannot claim Target I/O was performed
or that a vulnerability-oriented specialist action completed. Until the trusted terminal producer
exists, such a result remains a test artifact rather than a production terminal receipt. A future
trusted producer may classify an exact proven terminal zero-I/O failure as
`failed-before-target-io`; it may not relabel it as successful execution.

### 6. Treat the structured v2 fake backend as source-byte-addressed conformance only

The structured fake backend uses versioned job-template, execution-inventory, launch-envelope,
result, signed-result, and verification-key contracts. Its execution inventory binds:

- the exact contract implementation digest derived from the bytes of
  `specialist_backend_v2.py`;
- the Gateway identity and digest;
- the compiler identity and digest;
- the network-disabled fake image reference and digest;
- the exact backend job-template identity and digest;
- the fake-backend identity and digest;
- the output-verifier identity and digest; and
- the deployment-owned Ed25519 verification-key identity and public key.

The launch envelope binds one exact JobAttempt, typed dispatch verification, job template,
execution inventory, backend idempotency key, and deadline. The fake backend consumes that envelope
at most once, including rejection paths. A successful invocation signs a canonical result whose
terminal classification is `conformance-completed-no-target-io`. When the separately pinned output
verifier accepts the result, it proves only that this fake backend signed its terminal conformance
statement under the deployment key. Network mode remains none, Target I/O and secret requests remain
false, and production, Gateway, execution, independent-validation, Finding, Graph, report, SARIF,
and PoC authorities remain false.

This result is not a production Gateway/Worker success, independent Evidence, or a durable terminal
receipt. It cannot satisfy `completed-verified`, and the schema-v6 terminal grammar intentionally has
no conformance-success classification. No model, browser, network, or Target I/O occurs in this
path. The exact bytes of `specialist_backend_v2.py` now participate in the v2 identity graph and are
therefore frozen for this version. Any source change, including a semantic-neutral formatting
change, requires a successor version and regenerated pins rather than an in-place edit.

### 7. Require explicit offline migration from schema version 5

Normal Store opening rejects schema version 5 and never migrates implicitly. The only migration path
is the explicit `migrate_agentic_coordination_schema_v5_to_v6()` operation against an offline Store.
It requires:

- the Linux descriptor-bound database backend;
- the expected Store ID and exact coordination binding;
- the frozen complete v5 schema object set and schema digest;
- the expected SQLite application ID, `user_version`, metadata, and DELETE journal mode; and
- a successful database integrity check inside an exclusive transaction.

Migration preserves all legacy rows, creates the v6 JobAttempt and terminal-receipt schema objects,
updates only the schema version and digest metadata, and proves that both new tables remain empty.
It validates the complete v6 schema before commit and rolls the transaction back on any failure.
Running the operation against an already exact v6 Store is idempotent. Migration never manufactures
a JobAttempt, verification, receipt, capsule, or execution authority.

### 8. Keep restart recovery audit-only

Recovery validates complete structural history and separates:

- unreceipted `claimed-before-backend` attempts;
- unreceipted `dispatch-started-outcome-unknown` attempts; and
- immutable terminal receipts.

Attempts that already have a terminal receipt do not reappear in the claimed or unknown sets. Both
the specialist-only recovery snapshot and the general coordination recovery snapshot explicitly
deny automatic redispatch and execution authority. Recovery never recreates a scheduler Task,
runtime capsule, catalog snapshot, ledger lock, Grant, approval, Permit, Gateway handle, backend
handle, Worker verifier, or terminal-proof authority.

### 9. Keep live activation blocked until the missing authority boundary exists

Schema-v6 records, typed verification models, and the private runtime claim are necessary
foundations, not executable dispatch. Live Gateway/Worker activation remains blocked until all of
the following are implemented and verified:

- Store-owned minting of a non-copyable, non-serializable live JobAttempt handle from the exact
  scheduler-owned Task and runtime capsule, with their opaque token digests derived internally;
- fresh re-observation immediately before irreversible handoff of the current authority already
  checked by the private claim plus the immutable Worker image, job, backend, and verifier;
- a specialist-specific Gateway owned by the same scheduler Task and holding the exact backend and
  verifier objects, rather than accepting only caller-supplied IDs or digests;
- verification of the signed result followed by a deployment-authorized terminal-receipt producer
  that owns the result/proof/classification boundary;
- task close, cancellation, expiry, revocation, Store close, Gateway close, deployment close, and
  backend uncertainty linearization without automatic authority recovery or redispatch;
- actual governed SQL-injection execution against the approved local Juice Shop target; and
- separate AGENTIC-003D validation before any Finding, Graph, report, SARIF, or PoC promotion.

Detached builders, JobAttempt models, verification records, database rows, terminal receipts,
recovery snapshots, conformance outputs, and zero-I/O fake backend results cannot substitute for any
of these live objects or observations.

### 10. Keep independent validation and promotion outside this decision

This decision ends at durable execution-attempt classification. Independent Replay or validation,
controls, semantic oracle decisions, Finding promotion, Graph admission, attack-path expansion,
report generation, SARIF, and redacted PoC production remain AGENTIC-003D responsibilities under
separate authority and provenance.

## Consequences

### Positive

- The durable Store can distinguish a pre-backend claim from a handoff that may already have begun.
- Typed verification preimages are embedded and content-addressed instead of represented only by an
  opaque caller-supplied digest.
- Capability authority-set, scheduler Task, runtime capsule, Gateway, backend, image, and verifier
  identities are explicit in the canonical attempt.
- Indexed IDs and digests can be checked against canonical bytes and exact parent history.
- Restart classification does not recreate execution authority or permit unsafe redispatch.
- Existing v1 identities retain their inert meaning.
- The SQL-injection v2 signed release, complete authority set, exact action registry, and prepared
  action remain non-bearer inputs; an explicit Store-owned v2 Plan/Permit path ends at a private
  one-shot runtime claim without JobAttempt, Gateway, or execution authority.
- An exact v5 Store can be migrated without inventing v6 execution history.
- The structured fake backend exercises compiler, image, job, backend, verifier, key, one-call, and
  Ed25519 result bindings without model, browser, network, or Target I/O.

### Tradeoffs and residual risks

- The typed records remain detached until the live scheduler owns their minting.
- Detached JobAttempt builders cannot prove that mutable catalogs, ledger state, deployment
  inventory, or Task ownership were freshly re-observed.
- The coordination database and external backend cannot share one atomic transaction.
- Outcome-unknown attempts remain consumed and require explicit reconciliation.
- A valid terminal-receipt shape is not independently verified backend provenance.
- The fake backend proves only its own zero-I/O conformance and has no durable successful terminal
  classification.
- Schema migration is an explicit operational step, and schema-v6 Stores cannot be downgraded to
  v5 safely.
- The identity-bearing `specialist_backend_v2.py` source bytes are frozen; even formatting changes
  require a successor version and regenerated pins.
- Additional deployment-owned state and runtime checks are required before live Gateway/Worker
  activation.

## Security considerations

- Serialized JobAttempts, typed verifications, receipts, migration metadata, and recovery snapshots
  are evidence, never bearer credentials.
- Verification names describe the structure and intended observation boundary; current detached
  builders do not provide the missing live observation authority.
- Matching an ID or digest alone is insufficient. The embedded canonical preimage, indexed fields,
  exact parent history, live handle, and current deployment observations must all agree.
- `capabilityAuthoritySetId` and `capabilityAuthoritySetDigest` identify the approved code authority
  family but do not prove that its live implementations remain installed or current.
- Task and capsule token digests cannot be used to reconstruct or impersonate their process-local
  objects.
- The current signed v2 activation and `PreparedCapabilityAction` are non-bearer planning inputs;
  they cannot mint their own Grant, approval, Permit, plan, JobAttempt handle, or Gateway access.
- An outcome-unknown attempt cannot be retried, refunded, reissued, rewritten as abandoned, or
  silently converted into a terminal success.
- A zero-I/O backend or conformance result cannot satisfy `completed-verified`; its valid Ed25519
  signature authenticates the pinned fake deployment statement, not Target execution.
- Serialized backend/verifier IDs and digests do not pin the future live objects. The same-task
  Gateway must hold those exact objects at irreversible handoff.
- Editing the source-byte-addressed backend module in place would silently change every dependent
  identity and is prohibited for this version.
- Caller-authored or model-authored route, payload, policy, transport, backend, image, verifier,
  observation, result, or proof material must not cross into the future live authority path.

## Compatibility and migration

The change is additive to all v1 wires and artifacts. Existing v1 records remain readable and inert.
The distinct v2 Plan API, `AgenticSQLSpecialistDispatchPlanV2` kind, `sql-specialist-v2` durable
runtime generation, and schema-v6 attempt and verification wires use new identities and do not
reinterpret a v1 plan or Permit.

Schema v5 is accepted only by the explicit offline migration after exact validation. Normal Store
opening fails closed. Schema version 4 and older drafts remain unsupported. The migration creates no
new authority rows and does not convert an existing v1 authorization chain into v2.

## Rollback

Rollback disables v2 planning admission, structured-backend registration, and every future live
scheduler, Gateway, and backend path. It preserves schema-v6 JobAttempts, embedded verifications,
terminal receipts, and terminal tombstones. It does not downgrade the database, delete or rewrite
outcome-unknown history, synthesize terminal proof, refund or reissue a Grant or Permit, reconstruct
a Task or capsule, or automatically retry a dispatch. The current
`specialist_backend_v2.py` bytes remain frozen for their published identity; replacement uses a new
version rather than modifying or reinterpreting the old identity.

## Rejected alternatives

- **Rewrite ADR-0315.** Accepted ADRs are append-only; this decision extends its pending durability
  details without changing its authority boundary.
- **Store only a caller-supplied verification digest.** A digest without its canonical typed
  preimage cannot establish which exact identities and timestamps were claimed.
- **Treat typed-record construction as live verification.** Pure canonical builders do not observe
  current catalogs, ledger state, deployment inventory, Task ownership, or backend state.
- **Use a serialized JobAttempt or recovery row as a bearer credential.** This would recreate
  process-local authority from audit evidence.
- **Open and silently migrate schema v5.** Migration must be an explicit offline operation against
  the exact frozen v5 schema and Store identity.
- **Synthesize terminal receipts during recovery.** Recovery can classify missing receipts but
  cannot invent backend proof.
- **Report zero-I/O fake-backend success as `completed-verified`.** That classification requires
  proven performed Target I/O and trusted terminal result evidence.
- **Treat a valid fake-backend signature as Gateway/Worker success.** It authenticates a pinned
  conformance statement whose execution and promotion authorities remain false.
- **Edit the source-byte-addressed v2 backend in place.** Its exact bytes are identity-bearing;
  changes require a successor contract and regenerated compiler/image/job/backend/verifier pins.
- **Retry or refund an outcome-unknown attempt.** Backend dispatch may already have occurred.
- **Upgrade v1 authorization artifacts to v2.** Planning must begin with the current signed v2
  activation and exact v2 action, and every later Grant, approval, Permit, plan, and JobAttempt must
  bind that lineage. The implemented v2 Plan/Permit path does so; the live JobAttempt boundary must
  continue it without substituting v1 artifacts.

## Related documents

- [ADR-0315: Separate C3C Conformance Contracts from Executable Specialist
  Dispatch](0315-separate-c3c-conformance-contracts-from-executable-specialist-dispatch.md)
- [ADR-0314: Pin Specialist Permit Dispatch to One Deployment and Record Grant
  Consumption](0314-pin-specialist-permit-dispatch-to-one-deployment-and-record-grant-consumption.md)
- [ADR-0313: Enter the Specialist Dispatch Crash Fence Inside the Approved Permit
  Callback](0313-enter-specialist-dispatch-crash-fence-inside-approved-permit-callback.md)
- [AGENTIC-003: Governed Specialist Execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)

## 2026-09-20 implementation clarification

The v2 private-runtime authority is zeroized only when the trusted owner invokes the exact unbound
Store close implementation captured during trusted composition. That captured path retires the
exact Plan and capsule implementations, removes their captured owner-Task callbacks, abandons the
binding registries, and closes the pinned database descriptor through frozen implementations.

Ordinary `store.close()`, context-manager exit, and finalizer cleanup remain convenience or
best-effort paths. They do not independently prove zeroization when arbitrary same-process code can
replace Python class, instance, or module attributes before the call. Any production C3C owner must
retain and invoke the trusted captured close rather than dynamically re-resolve a public shutdown
entry point.

## 2026-09-20 live pre-backend admission clarification

References above to public admission being pending and to detached builders not minting a live
JobAttempt describe the preceding checkpoint. The Store now admits one exact SQL-injection v2
pre-backend attempt from the scheduler-owned Task and private runtime capsule. It rechecks current
Graph and durable history, authorization lineage, deployment inventory, and factory-pinned runtime
components before persisting `claimed-before-backend` and issuing one non-copyable,
non-serializable `VerifiedSQLSpecialistJobAttemptClaimV2`. The embedded typed ClaimVerification is
audit data; it is not a separate bearer handle.

The public deployment token and live claim expose no raw backend, verifier, verification key, job
template, execution inventory, Store, runtime context, or deployment lease. Exact runtime objects
remain in a private owner vault whose current view is compared by identity with separate
factory-time anchors. That vault is part of the trusted control-plane interpreter. It is an
encapsulation and drift-detection boundary, not a sandbox against arbitrary same-interpreter
reflection. Untrusted LLM, Skill, plugin, target, and payload code must remain out-of-process or
sandboxed and must never execute in that interpreter.

The Store now owns a trusted pre-backend abandonment producer. Owner-Task completion, trusted Store
close, explicit discard, and post-insert mint failure may append `abandoned-before-backend` with no
Target I/O and no backend terminal proof, then retire the claim, deployment lease, and private owner.
These receipts do not establish backend provenance. If the receipt writer fails, or the process
fails after JobAttempt commit and before receipt commit, recovery may observe an unreceipted claimed
attempt. Recovery must not synthesize a receipt, recreate live authority, or automatically
redispatch it.

Opaque-claim consumption, immediate pre-handoff re-observation, durable dispatch-start fencing,
specialist Gateway and private Worker invocation, signed backend-result verification and
deployment-authorized finalization, the approved Juice Shop SQL-injection execution, and independent
003D promotion remain pending.

## 2026-09-20 governed zero-I/O execution clarification

The final paragraph of the preceding clarification described the pre-execution checkpoint. The
structured zero-I/O path now consumes the exact live claim on its creating scheduler Task, repeats
the current Graph, authorization-lineage, and deployment-inventory observations immediately before
handoff, and commits `dispatch-started-outcome-unknown` before the backend await. It then invokes
the factory-pinned private Worker exactly once and verifies the signed result against the exact
launch envelope, verifier, deployment key, image, job template, and execution inventory.

The verified raw result is not returned to the scheduler or accepted by the Store receipt builder.
The Gateway instead issues a non-copyable, non-serializable, same-Task one-shot opaque completion
that binds the deployment lease, Store, owner Task and token, attempt, dispatch verification,
launch envelope, signed result, and result digest. The Store consumes that provenance before it
constructs the terminal receipt. The generic receipt writer separately rejects a proven terminal
receipt unless the exact private proven-insertion authority accompanies it.

A verified `conformance-completed-no-target-io` result terminates as
`failed-before-target-io`, never `completed-verified`. A backend failure or propagated
`CancelledError` after the dispatch marker is recorded as `started-outcome-unknown`; a terminal
receipt commit failure leaves the started attempt unreceipted and unknown. These paths retire the
claim, deployment lease, and private owner, prohibit automatic redispatch, and keep the Store close
fenced while backend dispatch is active. The current cancellation regression injects
`CancelledError` inside the pinned zero-I/O backend path; an actual scheduler `Task.cancel()` race
at a suspending target-I/O backend remains a successor-version obligation.

The SQLite marker COMMIT-success/return-failure split is covered by fault injection. The committed
started row prevents a false pre-backend abandonment receipt, the backend remains uninvoked, and
recovery exposes only an unreceipted unknown attempt with no automatic redispatch authority.

This clarification does not authorize or claim browser, network, or Target I/O. The identity-bearing
`specialist_backend_v2.py` remains unchanged. An additive target-I/O-capable Worker/Gateway
successor, the approved local Juice Shop SQL-injection execution, and independently permitted 003D
Evidence, Finding, Graph, report, SARIF, and redacted-PoC promotion remain pending.
