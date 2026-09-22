# ADR-0322: Enforce a Cleanup-bound Compact Web-analysis Live Runtime

- Status: Accepted
- Date: 2026-09-22
- Scope: WEB-007 prepared compact live-call Gate D
- Implementation status: the additive compact runtime, terminal receipt and strict loader, transport
  cleanup evidence, and Docker pre-cleanup durability barrier pass focused and static acceptance
  verification and are preserved in this local commit. No model completion, Provider
  dispatch, or target request is authorized or performed by this decision; the first fresh
  completion remains behind a separate explicit user approval.

## Context

[ADR-0319](0319-separate-prepared-compact-admission-from-live-call-authority.md) separates proof of
an exact compact request from authority to execute it. Its first three live gates are now available:

- Gate A copies the model from a held `O_NOFOLLOW` descriptor into a fresh owned volume and attests
  the live server's final read-only view;
- [ADR-0320](0320-durably-claim-prepared-compact-web-analysis-and-recover-cleanup.md) gives the
  preparation and authorization identities independent durable uniqueness, a one-dispatch marker,
  and cleanup-only recovery; and
- [ADR-0321](0321-verify-external-one-call-web-analysis-authorization.md) verifies an externally
  signed, short-lived grant for the exact admission, request, model, and transport.

Those components do not by themselves compose a safe live call. The existing Skill-bound analysis
runtime and receipt use the historical `developer` plus `user` wire. The existing local model
runtime binds a host path. The general Docker Worker also historically removed its transient
container, proxy, and internal network before a caller could durably record the attempt outcome.
Reusing any of those behaviors would either change a historical wire's meaning, break the
descriptor-to-live-view lineage, or leave a crash window in which cleanup can begin before the
single-use claim becomes cleanup-only.

The terminal evidence also has an ordering problem. A terminal receipt must name the durable claim,
while the durable terminal row must name the receipt digest. Building either object from the other
after both are final would create a digest cycle. The runtime therefore needs an explicit durable
publication-intent-to-terminal commit protocol rather than an opportunistic receipt written after
the call.

## Decision

### 1. Add a compact-only runtime and receipt family

Gate D uses additive compact live modules with a new wire identity. The runtime consumes the exact
`system` plus `user` projection produced by the compact preparation. It does not import, accept,
translate to, or fall back to the historical `developer` plus `user` invocation envelope, receipt,
loader, runtime, or host-bind `LocalModelRuntime`.

The compact terminal receipt binds at least:

- the strict-reloaded preparation and non-executing admission;
- the Capacity v2 and Skill anchors;
- the signed authorization, both its initial and immediate pre-dispatch verifications, and the
  exact authorization expiry bound used by the dispatch-marker transaction;
- the Gate B journal store, exact claim, Gate D context digest, pending outcome, and consumed
  dispatch count;
- the Gate A live materialization attestation and, when pre-dispatch context committed, the exact
  Provider-route attestation digest covering the `host.docker.internal` alias, sole-member network
  topology, and exact `http://host.docker.internal:8080/v1/chat/completions` endpoint;
- the exact Provider registration, compact chat request, transport Pin, synchronous Worker v6
  context, job metadata, execution identity, and secret-free lease identities;
- the observed dispatch outcome and, only for success, the strict draft and deterministic compiled
  advisory;
- the exact model and transport cleanup results plus independently derived absence evidence; and
- the intended terminal disposition, failure stage and digest when applicable, and literal false
  target, Tool, Capability, Permit, Finding, Graph, report, delivery, retry, and automatic-redispatch
  authorities.

Pre-dispatch failures after a claim may not have a live materialization attestation or a second
authorization verification. Those fields are therefore absent only when the bound failure stage
precedes them. Success and a normal in-process terminal receipt with a consumed dispatch slot
require both. A quiescent restart may know from the durable marker that the slot was consumed while
the in-memory attestation or verification object was lost. Only an `ABANDONED`
`quiescent-recovery` or `post-observation-recovery` receipt may explicitly record that lost evidence;
it can never become success. Failure artifacts use the same fixed inventory with JSON `null` in
place of a draft or proposal; they do not silently shorten or widen the sealed layout.

A transient second verification is not receipt evidence by itself. The receipt may include it only
when the journal's all-or-none pre-dispatch context contains the exact matching verification digest,
evaluation time, and expiry. If that context CAS did not commit, the receipt omits the transient
object and cannot terminalize as success.

### 2. Enforce the nine live steps as one closed state machine

The runtime performs the ADR-0319 sequence without reordering:

1. strict-reload and independently anchor the immutable source, Skill, Capacity, preparation, and
   admission inputs;
2. verify the external one-call authorization against the exact admitted compact request;
3. reserve both independently unique identities in one Gate B transaction and enter live start
   before creating an owned live resource;
4. materialize from the held descriptor and attest the exact live read-only model view;
5. strict-replan the admission, reverify the still-current authorization, re-attest the model view,
   inspect the current claim, verify that the runtime is the sole exact member exposing
   `http://host.docker.internal:8080/v1/chat/completions` under the exact network alias, reconstruct
   the Worker context and job metadata, and durably record the authorization expiry and Provider-
   route attestation digests;
6. in the dispatch-marker transaction, sample the dispatch-start time, require it to be strictly
   earlier than that durable expiry bound, and only then consume the one slot immediately before at
   most one Provider dispatch;
7. classify the observed result or uncertainty and move the claim to `pending-cleanup` before any
   owned Worker, proxy, network, model container, seed container, or volume cleanup starts;
8. revoke any exact claim-bound credential leases, remove only resources named by the claim, and
   independently verify their absence; and
9. record the sole publication intent while the claim is pending, seal its deterministic Run,
   strict-load the complete unanchored candidate, consume that store-local proof in a one-use root
   CAS, terminalize the journal, and strict-reload the sealed Run and terminal cross-link.

No fallible authorization, request, topology, or claim check may be deferred until after the
dispatch marker. Once that marker is durably consumed, the next external operation is the single
dispatch. The runtime never calls the Provider twice, even when a response, cleanup, receipt write,
journal commit, process, or caller outcome is uncertain.

The Gate B journal receives an additive, immutable Gate D context beside the claim rather than a
second execution authority. Its initial authorization verification digest, evaluation time, and
`initialAuthorizationExpiresAt` are inserted atomically with the dual-identity reservation, which
also rejects a reservation at or after that bound. Before the dispatch marker, one all-or-none
transition records the second verification digest, evaluation time, and
`preDispatchAuthorizationExpiresAt` together with the Provider-route attestation, transport
execution ID, secret-free lease IDs, Worker-context, job-metadata, and transport-binding digests.
The route-attestation digest covers the Provider registration digest, exact endpoint,
`host.docker.internal` network alias, port `8080`, claim-owned runtime/network identities, and
sole-member topology. The
two expiry fields must equal the same signed authorization bound. The context remains audit- and
recovery-only with every invocation, dispatch, target, execution, and redispatch authority false.

The expiry comparison belongs inside the same journal transaction that consumes the dispatch slot.
A receipt loader can later detect that a recorded dispatch began after expiry, but such a
post-dispatch rejection cannot prevent the external call. The marker CAS therefore fails before
slot consumption unless `dispatchStartedAt < preDispatchAuthorizationExpiresAt`; no runtime-only
comparison or subsequent receipt check substitutes for that atomic guard. The transaction's Python
guard and the SQLite claim-transition trigger both enforce the bound. At exact expiry the consumed
in-memory handle does not produce a durable dispatch event or increment, the Provider remains
uncalled, and only cleanup/abandoned recovery may follow. Historical no-context callers retain their
existing semantics and cannot be reinterpreted as Gate D calls.

This addition advances the Web live-claim journal to schema v2. A v1 store is not rewritten or
implicitly migrated: v2 open fails closed on its version metadata and exact schema fingerprint.
Gate B v1 was never used for an authorized live dispatch, so there is no production live-call store
whose immutable audit state needs an in-place migration. Any retained v1 store remains a separate
cleanup/audit artifact and cannot be opened as Gate D authority, converted to make identities
reusable, or silently replaced by a new uniqueness domain. The schema tests keep application ID,
version, store identity, table/index/trigger inventory, and immutable version metadata under exact
verification.

Success is not the receipt writer returning. A proposal may leave the runtime only after the strict
loader has reconstructed every independent anchor and proved that the terminal journal row points
back to the exact sealed receipt.

### 3. Put a host-owned durability barrier before Docker cleanup

The Docker Worker gains an optional pre-cleanup barrier without changing historical callers that do
not supply it. Its canonical secret-free mapping binds only `claimDigest`, `executionId`, and
`pendingCleanupRequired=true`. The surrounding `pajin.docker-worker/v6` context and compact receipt
bind that mapping to the exact request and transport; the barrier does not duplicate those fields.

For a Gate D dispatch, the barrier runs exactly once after a Worker result is available or the
attempt becomes uncertain, and before the first Worker-container, proxy-container, or internal-
network cleanup action. It must expose the exact host-held Worker result to the Gate D owner when a
result is observed, not merely a status summary, so the owner can perform Provider interpretation,
strict proposal parsing, deterministic compilation, and outcome classification before committing
`pending-cleanup`. An exception, timeout, or cancellation without a verified result is recorded as
`outcome-unknown`.

Gate D uses the v6 synchronous callback under a code-owned hard POSIX real-time deadline; it cannot
yield or outlive cleanup indefinitely. Deadline, `CancelledError`, `SystemExit`, and
`KeyboardInterrupt` identities are never converted to ordinary response failure or swallowed.
Docker cleanup still runs, and the barrier/control-flow exception retains priority if cleanup also
fails, with bounded cleanup diagnostics attached. Once safe cleanup evidence is available, the
runtime seals only an abandoned recovery and then re-propagates the original interruption; without
that evidence the claim remains pending and non-reusable. No path redispatches.

### 4. Bind transport and model cleanup into one absence proof

Gate A cleanup removes the exact claim-owned model server, seed container, model volume, and model
network and then produces a separate absence proof. Transport cleanup removes only the exact
execution-labeled Worker, proxy, and internal-network resources and verifies that no matching
resource remains. Neither path uses a broad name or label sweep as authority to delete resources.

The terminal cleanup object binds both results and derives a distinct aggregate absence digest.
Cleanup is idempotent only as cleanup: a restart may repeat exact owner-checked removal and absence
verification, but it cannot recreate a dispatch handle, reopen the authorization, or synthesize a
successful result. Any cleanup or absence-check failure is durably recorded against the pending
claim and forbids terminal success and proposal return.

The existing OpenAI-compatible transport always creates one `provider-api-key` Worker secret
request even for the fixed loopback local Provider, and this decision does not reinterpret or remove
that binding. Gate D permits at most one exact lease, derives its identity deterministically from
the claim-bound call, records only that secret-free identity, and requires the same broker to
positively inspect and revoke it before sealing a receipt. A crash may occur after deterministic
issuance but before `issue_exact` returns or before the optional pre-dispatch context commits.
The adapter therefore retains the deterministic ID before issuance; neither an exception nor absent
context proves a zero-lease call. Cleanup-only recovery derives the same possible ID from the exact
claim and fixed Worker request, without issuing or materializing it, and asks the same broker for
positive revocation evidence. If process loss discards broker state or that
exact proof cannot be obtained, recovery leaves the claim in `pending-cleanup`; it does not
synthesize absence or revocation, reissue a credential, or create a terminal receipt. An
unauthenticated or zero-lease local transport is not part of Gate D and would require a separate
contract before use.

### 5. Resolve the receipt and journal cross-link without a digest cycle

After positive cleanup and absence verification, the runtime builds a receipt from the immutable
`pending-cleanup` entry. Before any Run exists, it CAS-records the sole publication intent, binding
the pending state, trusted output root, full-claim-digest parent, deterministic Run ID/path, receipt,
cleanup and absence digests, disposition, and optional live attestation. A Run without that prior
intent is never recoverable authority.

After sealing, the candidate loader performs the complete receipt and lineage verification while
the publication row is still unanchored, reading that row both before and after artifact I/O and
requiring it to be unchanged. Only the loader can mint the unconstructible, store-local, one-use
candidate accepted by the root-anchor CAS. The anchored row then gates pending-publication reload,
terminal CAS, and final terminal reload; a self-consistent seal alone is insufficient.

The strict loader accepts the Run only when the terminal journal entry retains the exact pending
history, has exactly one additional terminal event, agrees with the intended disposition and
cleanup evidence, and points back to the receipt digest. It compares the index hashes to the raw
artifact bytes and binds the cleanup absence digest to the store, claim, pending state, dispatch
observation, stage-appropriate live and Provider-route attestations, and exact lease set. Every
trusted-path component, including the output root and its ancestors, campaign parent, and Run, must
be canonical and non-symlink; relocation through any symlink is rejected. A publication failure leaves
no accepted terminal result. An uncertain terminal CAS is resolved by inspecting the exact claim:
an already matching terminal row is accepted, an unchanged pending row may retry only the same
terminal CAS against the same sealed receipt, and every other state fails closed. A restart that finds the
deterministic Run already sealed uses the durable intent, full unanchored-candidate reload, and
one-use root CAS before the same terminal CAS. It cannot build a second receipt, expose the proposal
while pending, accept a caller-supplied bare root, or redispatch.

Historical authorization is reverified at the recorded evaluation timestamps so strict reload
proves the original decision rather than attempting to create fresh call authority from an expired
artifact. Current-time authorization verification is required only before the live dispatch.

### 6. Preserve conservative failure semantics and zero target authority

A failure before the first Gate B reservation creates no claim and no live authority. Any failure
or uncertainty after reservation makes both identities permanently non-reusable:

- known pre-dispatch failures become `not-dispatched`;
- a validated and compiled one-response result becomes `success-observed`;
- an observed rejected or invalid response becomes `failure-observed`; and
- a timeout, transport-reported cancellation, lost commit acknowledgement, or otherwise ambiguous
  attempt becomes `outcome-unknown`; a raised `CancelledError` remains process control as specified
  below.

`not-dispatched` is impossible after the dispatch marker. Terminal success requires one consumed
dispatch slot, `success-observed`, verified cleanup and absence, a sealed proposal, a matching
terminal CAS, and strict reload. Explicit failure terminalizes as failure; a known non-dispatch or
uncertain attempt terminalizes as abandoned. If terminal evidence cannot be completed safely, the
claim remains pending cleanup and unusable rather than being reported as success.

`CancelledError`, `SystemExit`, `KeyboardInterrupt`, and
`DockerPreCleanupBarrierDeadlineExceeded` are control flow, not model outcomes, across the complete
nine-step runtime boundary. The strict reload, authorization, claim, materialization,
pre-dispatch, marker/dispatch, result settlement, cleanup, and publication/terminal paths must not
wrap, normalize, or absorb those identities as an ordinary failure. Before a durable claim they
escape without creating live authority. After a claim, the runtime performs only the conservative
cleanup/failure settlement that the durable phase permits. With provable cleanup it records at most
an abandoned recovery and re-raises the original identity; if cleanup or publication cannot be
proven, the claim remains pending and the original identity still escapes. A cleanup exception may
add only bounded diagnostics and never replace the process-control exception or produce a proposal.

The compact advisory grants no target request or downstream assessment authority. A future action
still needs its own Scope, Capability, approval, Permit, Gateway, Worker, replay, Finding, Graph,
report, and delivery boundaries. Gate D tests use injected transport seams and must keep actual
model completion, Provider dispatch, and target-request counts at zero. The first real Qwen3 4B Q8
completion requires a separate explicit user approval after all four gates and their acceptance
verification are complete.

## Consequences

### Positive

- The exact compact request reaches a live-capable boundary without changing the meaning of any
  legacy wire or receipt.
- Durable single-use state crosses the cleanup boundary before ephemeral Docker resources disappear.
- Model and transport resources share one claim-owned cleanup and absence story without broad
  deletion authority.
- The durable intent, strict candidate loader, one-use root CAS, and terminal cross-link close both
  publication crash windows without a recursive digest.
- A successful proposal is observable only after cleanup, publication anchoring, terminal CAS, and
  independent strict reload.

### Cost and remaining work

- Gate D adds a compact-only runtime, another sealed Run family, a Docker Worker barrier version,
  and explicit recovery handling.
- The single-host SQLite journal still relies on an externally retained store identity and
  operator-driven quiescent cleanup recovery; it is not distributed consensus or an anti-rollback
  witness.
- A sealed receipt can exist while its claim remains pending. Recovery must follow the same durable
  publication intent through root anchoring and terminal CAS rather than dispatch again.
- The production issuer, real signed authorization, successful structured output, quality,
  latency, peak memory, and stability remain outside this implementation checkpoint and require the
  separately approved first call.

## Rejected alternatives

- Translate the compact request to the legacy `developer` plus `user` wire or adapt the legacy
  receipt with optional fields.
- Reuse the host-bind `LocalModelRuntime` or the benchmark host-path bind mount.
- Treat a code-generated Campaign approval, preparation, admission, or serialized Gate C result as
  sufficient call authority.
- Let the Docker Worker clean up before the durable claim records the attempt outcome.
- Pass only a success/failure summary to the durability barrier when strict response validation is
  still required to classify the pending outcome.
- Seal terminal success before model and transport absence are verified.
- Create a sealed Run before recording its publication intent, trust a self-consistent seal without
  full lineage reload, or let a caller submit a bare root digest to the anchor CAS.
- Finalize the claim first and fill in a receipt digest later.
- Retry automatically after timeout, cancellation, cleanup failure, receipt failure, or uncertain
  commit.

## Compatibility and rollback

This decision is additive. Historical WEB-007 request, runtime, receipt, loader, Provider Run,
Capacity, preparation, admission, Campaign, and target-side contracts remain readable with their
original meanings. Gate B v1 journal stores remain audit/cleanup artifacts but are intentionally
not readable as Gate D live authority. The optional Docker barrier preserves the exact historical
backend context and behavior when absent.

Rollback disables the compact live runtime while retaining its journal and sealed Runs for audit
and cleanup. It may continue exact owner-bound cleanup, but it may not delete or replace the
journal to regain consumed identities, unseal or rewrite a receipt, reconstruct a progression
handle, fall back to a legacy runtime, or redispatch.
