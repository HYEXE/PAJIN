# SUP-004A: Sealed Checkpoint Invocation Plan

- Status: Implemented
- Request authority: `pajin.dev/supervisor-invocation-request/v1alpha1`
- Schedule authority: `pajin.dev/supervisor-checkpoint-schedule/v1alpha1`
- Dedicated budget authority: `pajin.dev/supervisor-dedicated-budget/v1alpha1`
- Decision: [ADR-0120](../adr/0120-plan-supervisor-checkpoints-before-invocation.md)

## Scope

SUP-004A defines the first exact Shadow Supervisor checkpoint and Provider request wire. It
re-verifies one current SUP-002 `SupervisorSnapshotInput` that fits the current 65,536-character
single-Provider-message limit, resolves its exact current Canonical Graph Snapshot, builds one
deterministic structured-output `ProviderChatRequest`, checks a Supervisor-dedicated
Campaign-attenuated affordability ceiling, and publishes one digest-only schedule in a separate
sealed Run.

This slice deliberately does not call a Provider. It does not reserve or consume a Campaign or
Supervisor budget, issue or consume a Capability, create a ToolRequest, dispatch a Worker, receive
a model response, compile a SUP-003 proposal, create or mutate a Task or Plan, expand Scope, apply a
Stop, grant a Permit, or enable activation. SUP-004B owns the atomic dual-budget Provider dispatch
and receipt boundary.

## Exact invocation request

The request contains exactly two messages:

1. a code-owned `developer` contract that treats every user field as untrusted Snapshot data and
   forbids Tool requests, Scope expansion, Capability, Permit, and execution claims; and
2. the complete SUP-002 input encoded as canonical UTF-8 JSON in one `user` message.

The canonical user message must fit the existing `ProviderMessage` 65,536-character limit.
Otherwise planning fails before publication. This slice does not silently widen the shared
Provider wire and does not claim to support every otherwise-valid SUP-002 input up to its larger
projection-size ceiling.

The request fixes streaming and parallel Tool calls to false, exposes no functions, chooses no
Tool, and copies the exact SUP-001 maximum completion tokens, zero temperature, top-p one, and
seed. The response format is the strict SUP-001 `SupervisorShadowProposalDraft` schema. The
request binding stores only ordered role/source metadata, content SHA-256 and byte counts, request
and schema digests, source authority identities, and a conservative usage bound. It does not store
developer text, target-tainted Fact text, the canonical user payload, or the Provider secret
reference.

`ProviderChatRequest` and `ProviderChatResult` now reject boolean/integer coercion for invocation,
usage, streaming, and chunk-count fields. A raw `true` can no longer become one token or one chunk.

## Dedicated affordability boundary

`SupervisorDedicatedBudgetPolicy` bounds model calls, model tokens, wall-clock seconds, and cost.
Every bound must be no greater than the Campaign's model-call, Tool-call, token, duration, and cost
limits. The exact conservative Provider prompt framing calculation is a shared pure helper used by
both the schedule planner and `PolicyBoundProviderPort`.

SUP-004A performs affordability checking only. Its `reservationState` and request usage bound say
`not-reserved`, and no `BudgetController` is mutated. This avoids claiming usage without a model
dispatch and avoids bypassing the Campaign-wide budget with a second independent ledger. SUP-004B
must atomically pass and charge both the remaining Campaign budget and the dedicated Supervisor
ceiling.

## Checkpoint, idempotency, and audit

The checkpoint key binds Campaign digest, exact current Graph Snapshot ID and digest, and the
existing `checkpoint|handoff|replan|recovery` reason. One scheduler instance:

- publishes one schedule for a new key;
- returns the same publication for an exact retry;
- rejects another request, binding, configuration, or budget for the same key as equivocation;
- admits at most the dedicated policy's model-call count; and
- rejects stale Graph or cross-Campaign state before publication.

The process-local lock provides single-flight scheduling within the authority instance. The plan
is written create-only to a new Supervisor Run, audited by one digest-only event, and sealed. It is
never appended to a predecessor source Run. The external verifier reopens the exact registered
path in a Run containing exactly one seal, one artifact, and one exact event, verifies the
caller-expected dedicated budget policy plus the Run root/SHA and current Graph and SUP-002
sources, rebuilds the request binding, and requires exact equality.

Cross-process claiming, crash-after-dispatch classification, and Provider-call single-flight are
not claimed. They belong to SUP-004B because the current Provider port does not expose a stable
request ID, reservation, and Gateway receipt as one public result.

## Negative boundaries

Planning or verification fails closed for:

- stale or foreign Campaign, Graph, Collaboration Snapshot, SUP-002 input, SUP-001 binding,
  Provider, model revision, or configuration;
- message role/order/source, developer content, canonical user JSON, request, request schema, or
  response schema substitution;
- undefined Graph checkpoint reasons, request Tool/stream/parallel-call widening, or mutable model
  configuration;
- a dedicated call/token/time/cost ceiling wider than the Campaign or a request that does not fit;
- a valid SUP-002 projection whose canonical user JSON exceeds the current 65,536-character
  Provider message limit;
- exact-checkpoint request equivocation, model validation bypass objects, digest forgery, Run/root/
  artifact/event substitution, or unsealed/tampered audit data;
- boolean-number coercion in request/result/usage fields; and
- any attempt to turn the schedule into Task, Plan, Scope, Capability, Permit, execution, Stop, or
  activation authority.

## Compatibility and rollback

The invocation and schedule schemas, scheduler, public usage-bound helper, sealed audit Run, and
exports are additive. SUP-001 through SUP-003, Provider transport, TaskGraph, Campaign execution,
Capability, Permit, and existing readers are unchanged. The Provider validators preserve valid
JSON wires and reject only ambiguous coerced values. Rollback removes the SUP-004A modules and
contract; the Provider strictness hardening and shared pure estimate may remain independently.
