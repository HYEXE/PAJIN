# ADR-0319: Separate Prepared Compact Admission from Live-call Authority

- Status: Accepted
- Date: 2026-09-21
- Scope: WEB-007 prepared compact admission and the future one-call live-analysis boundary
- Implementation status: non-executing admission implemented and test-verified; external
  authorization, durable single-use claiming, descriptor-bound live model materialization, and the
  additive compact live runtime and receipts remain P0 pending. Model runtime starts, model
  invocations, Provider dispatches, and target requests remain zero.

## Context

[ADR-0317](0317-prove-compact-skill-bound-web-analysis-capacity-before-model-dispatch.md) proved
that the exact compact `system` plus `user` request fits the pinned tokenizer context without model
inference. [ADR-0318](0318-attest-descriptor-bound-model-materialization-before-live-web-analysis.md)
then bound Capacity v2 to model bytes materialized from a held `O_NOFOLLOW` descriptor and sealed a
proof-bound preparation without granting dispatch authority.

That preparation is sufficient evidence for a non-executing admission decision. It is not
sufficient authority for a live model call. Treating it as an authority bearer would collapse the
distinction between proving an exact request and obtaining permission to execute that request. It
would also leave four independent gaps:

- no externally supplied authorization for one narrowly identified call;
- no durable atomic claim preventing concurrent or later reuse of that authorization;
- no proof that the live runtime consumes the descriptor-bound bytes admitted by Capacity v2; and
- no wire format that preserves the exact compact `system` plus `user` request through live
  execution and terminal receipt validation.

The existing analysis-skill runtime does not close these gaps. Its request and receipt contract is
the historical `developer` plus `user` wire, and its local model runtime bind-mounts a host path.
Likewise, a Campaign approval generated locally by the same code path is not external authorization
for a model call.

## Decision

### 1. Admit the sealed preparation without executing it

The prepared-compact admission path is additive and non-executing. It strict-reloads the sealed
preparation and independently checks the exact Capacity, Skill, and preparation anchors supplied to
the admission. It reconstructs the exact compact `system` plus `user` request and binds that request
to those anchors in the admitted result.

Admission establishes only that the reviewed compact request is the request represented by the
sealed prerequisites. It does not start a model runtime, invoke a model, dispatch a Provider, make a
target request, create a Tool request, activate a Capability, mint an ActionPermit, or grant any
future execution authority. Missing, mismatched, unsealed, non-canonical, or ambiguously resolved
inputs fail closed.

The implemented admission and its tests are the current checkpoint. At that checkpoint, model
runtime starts, model invocations, Provider dispatches, and target requests are all literally zero.

### 2. Never treat preparation or admission as an authority bearer

Neither the sealed preparation nor its admission result is a Capability, permit, approval token,
or replayable call credential. Possession of either object cannot authorize a live call, select a
broader model or transport, extend an expiry, authorize a retry, or create target-side authority.

The future live path must receive a separate, externally supplied authorization narrowed to one
call. A Campaign approval synthesized by local code, including one generated from the preparation
or admission, cannot satisfy this requirement.

### 3. Require all four P0 gates before any live call

A future live successor may make at most one model call only after all of the following gates have
passed. The gates are cumulative; none substitutes for another.

#### 3.1 Externally supplied narrow one-call authorization

The authorization must come from outside the execution code path and identify exactly one admitted
compact call. It must be bound to the immutable preparation and admission identities, the exact live
request digest, the selected model and Provider transport, and a bounded validity and nonce or
equivalent replay-resistant identity. It grants no target, Tool, Finding, Graph, report, delivery,
or retry authority.

#### 3.2 Durable preparation-and-authorization single-use claim

Before starting any model runtime, the successor must atomically claim a durable journal entry that
binds the preparation identity and authorization identity. Each identity has its own independent
unique constraint and compare-and-set transition: the same preparation with a new authorization and
the same authorization with a new preparation are both rejected, as is replay of the same pair. The
journal must distinguish reservation, live start, pending cleanup, and terminal or abandoned
outcomes, record uncertainty conservatively, and prevent concurrent processes from both proceeding.

An in-memory flag, process-local lock, sealed preparation, or terminal analysis receipt is not a
substitute for this durable claim. Once a claim reaches the live boundary, failure or uncertainty
does not make it reusable and does not authorize an automatic redispatch.

#### 3.3 Descriptor-bound live model materialization attestation

The live successor must open the registered model with `O_NOFOLLOW`, hold that descriptor through
copying into a fresh owned Docker volume, and attest the live runtime's final read-only view of the
materialized bytes. Descriptor identity before and after the copy, model digest and size, normalized
runtime ownership and mode, runtime-user readability, pinned image identity, final mount topology,
and cleanup ownership must match the admitted Capacity v2 anchors.

The existing host-bind `LocalModelRuntime` is not eligible for this path. A preflight hash followed
by a host-path bind mount cannot satisfy the descriptor-to-live-runtime identity requirement.

#### 3.4 Additive compact runtime, receipt, and strict loader

The live successor must have a new additive runtime and wire identity that preserves the exact
compact `system` plus `user` request. Its receipt and strict loader must bind the preparation,
admission, authorization, durable claim, Capacity and Skill anchors, live materialization
attestation, request, selected transport, dispatch count, terminal outcome, and cleanup result.

The historical `developer` plus `user` request, receipt, loader, and runtime remain readable for
their original contract but are not live-eligible for a prepared compact call. Converting the
compact request to that legacy wire, filling new fields opportunistically, or falling back to the
legacy runtime is prohibited.

### 4. Preserve fail-closed ordering and zero target authority

The live successor must enforce this order:

1. strict-reload the immutable preparation, admission, Capacity, and Skill anchors;
2. verify the external one-call authorization against the exact admitted request;
3. atomically claim both independently unique identities in one journal transaction;
4. materialize and attest the model from the held descriptor into the owned volume;
5. revalidate the admission, authorization, and current claim before dispatch;
6. perform at most one model dispatch;
7. move the durable claim to a non-success `pending-cleanup` outcome;
8. remove and verify absence of owned live resources; and
9. only then seal the cleanup-bound terminal receipt and finalize the durable claim.

Any failure before the atomic claim produces no live authority. Any failure or uncertainty after the
claim must leave a durable non-reusable outcome and, where the live contract requires it, a strict
terminal receipt. Cleanup or absence-check failure cannot produce or return a successful proposal.
No failure path may fall back to a legacy runtime or redispatch automatically.
Target requests remain zero regardless of model outcome; a later target action requires its own
Capability, permit, Gateway, worker, and independent verification boundaries.

## Consequences

### Positive

- Reviewable preparation evidence cannot silently become execution permission.
- Exact compact request semantics survive admission and the future live wire without translation to
  the legacy `developer` plus `user` contract.
- Durable compare-and-set claiming closes concurrent and cross-process replay, including uncertain
  failures.
- The bytes measured by Capacity v2 can be connected to the bytes read by the future live runtime
  without trusting a mutable host pathname.
- Existing analysis-skill artifacts retain their meanings without becoming an unintended bypass.

### Cost and remaining work

- The external authorization verifier and its narrow one-call contract remain P0 work.
- The durable preparation-and-authorization CAS journal and crash-recovery rules remain P0 work.
- Descriptor-bound materialization must be connected to the actual live model server and attested at
  its final read-only mount; the current host-bind runtime is intentionally ineligible.
- The additive compact request, receipt, strict loader, and one-shot runtime remain P0 work.
- Successful model output, Provider behavior, structured proposal quality, and every target-side
  effect remain unverified. The current observed counts are zero model, zero Provider, and zero
  target operations.

## Rejected alternatives

- Treat the sealed preparation or admission as a bearer credential for a later completion.
- Reuse a code-generated local Campaign approval as external live-call authorization.
- Use an in-memory consumed flag or process-local lock instead of a durable atomic claim.
- Make a failed or uncertain claim reusable, or permit an automatic retry under the same
  authorization.
- Feed the compact request into the legacy `developer` plus `user` runtime and adapt its receipt with
  optional fields.
- Reuse the host-bind `LocalModelRuntime` after hashing the model path.
- Make any of the four P0 gates optional when another gate has passed.

## Compatibility and rollback

This decision is additive. Existing Capacity v1 and v2, Skill, preparation, legacy analysis request,
receipt, loader, and runtime artifacts retain their historical meanings and remain readable under
their original contracts. None is upgraded into prepared-compact live authority.

Rollback disables the prepared-compact admission or leaves the future successor inactive. It does
not permit fallback to the legacy runtime, reopen a consumed or uncertain claim, reinterpret a local
Campaign approval as external authorization, bind-mount the host model path, or grant model,
Provider, target, Tool, Finding, Graph, report, or delivery authority.
