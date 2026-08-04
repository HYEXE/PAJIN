# ADR-0122: Bind Stable Provider Requests to Secret-Free Outcomes

- Status: Accepted
- Date: 2026-08-04

## Context

SUP-004A fixes the exact future Shadow Supervisor request, and SUP-004B1 can atomically charge its
Campaign and dedicated model budgets. The existing `PolicyBoundProviderPort.chat()` still creates
a random `ToolRequest` ID and returns only a raw `ProviderChatResult`. A caller therefore cannot
name the exact Gateway dispatch in advance or bind the request, Gateway, Worker, response, and
charged usage into one safe receipt. Persisting the raw Gateway outcome would copy tainted prompt,
response, Tool arguments, Worker transcripts, endpoint, and potentially sensitive references into
another artifact.

## Decision

1. Preserve `chat()` and `complete()` and add `chat_bound()` for callers that supply one exact
   portable Tool request ID.
2. Inject that ID unchanged into the actual Provider `ToolRequest` before reservation and
   Capability consumption. Reuse the Gateway's existing Run-local create-only reservation.
3. Expose one public canonical Tool request digest helper. Gateway reservation, Capability
   activation, and Provider outcome construction use that same implementation.
4. Return the raw Provider result only as an ephemeral companion to a frozen, versioned
   `ProviderBoundChatOutcome`.
5. Bind all exact raw sources through domain-separated digests and bounded metadata, including the
   complete Provider registration without exposing its secret reference, grant, chat, Tool
   request, Policy decision, Tool result, successful Worker result, Gateway outcome, Provider
   result, response and target,
   optional text, normalized tool calls, exact evidence reference, reported usage, and the exact
   conservative SUP-004B1 charge and budget scope. Independently recompute the conservative token
   and cost bound during verification; require Campaign versus dual scope as a separate
   caller-expected input until the Supervisor-specific B3 consumer requires dual scope.
6. Require one successful zero-exit Worker result and exactly one
   `evidence/{requestId}.json` reference. Rebuild every source in the public verifier and require
   exact outcome equality.
7. Keep raw prompt, response, refusal, Tool arguments, endpoint, secret reference, Worker
   transcript, and complete raw results out of the serializable outcome. Store only the outcome ID
   and digest in the existing completion event.
8. Keep conservative lifecycle semantics: proven non-execution releases the reservation; dispatch
   or uncertainty commits it. Bound-outcome construction failure after dispatch records failure
   and retains the charge.
9. Reject ambiguous boolean/integer coercion in Policy, Tool, Gateway, Worker, Provider, usage, and
   bound-outcome success fields.
10. Fix automatic redispatch and all Task, Plan, Scope, Capability, Permit, execution, and
    activation authority to false.
11. Do not claim durable at-most-once dispatch. A separate SUP-004B3 SQLite journal must claim the
    intent before dispatch and seal a consumer-verified Supervisor receipt.

## Consequences

- A future Supervisor scheduler can deterministically name the exact request before dispatch and
  compare the returned successful outcome with the exact planned sources.
- Secret-free audit metadata can detect source or result substitution without copying raw model or
  Worker content into an additional artifact.
- Existing Provider callers retain their current signatures and raw return behavior.
- A valid outcome binds one caller-supplied, revalidated successful source tuple. It does not by
  itself prove Run membership, a durable cross-Run claim, evidence-artifact authenticity, live
  budget-ledger state, trusted Provider token accounting, or draft admission.
- Provider-reported usage remains explicitly untrusted; budget authority is the conservative
  charged bound.
- A digest binds source bytes but is not encryption and does not conceal a guessable low-entropy
  secret-reference name.

## Compatibility and rollback

The bound-call method, outcome models, verifier, and digest helper are additive. Valid existing
Provider wires remain valid, while ambiguous scalar coercions fail closed. No artifact migration
is required because this checkpoint returns but does not seal the outcome. Rollback removes the
new API and schema; canonical digest reuse and strict scalar hardening may remain independently.

## Related documents

- [SUP-004B2 contract](../orchestration/SUP-004B2-stable-provider-bound-outcome.md)
- [SUP-004B1 contract](../orchestration/SUP-004B1-atomic-dual-model-budget.md)
- [SUP-004A contract](../orchestration/SUP-004A-checkpoint-invocation-plan.md)
- [ADR-0121: Atomic Dual Budgets](0121-atomically-charge-campaign-and-dedicated-model-budgets.md)
- [ADR-0120: Plan Supervisor Checkpoints](0120-plan-supervisor-checkpoints-before-invocation.md)
- [ADR-0009: Policy-bound Provider Runtime](0009-provider-backed-agent-runtime.md)
