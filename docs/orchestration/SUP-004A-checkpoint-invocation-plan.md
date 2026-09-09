# SUP-004A: Sealed Checkpoint Invocation Plan

- Status: Implemented
- Request authority: `pajin.dev/supervisor-invocation-request/v1alpha1` or `v1alpha2`
- Schedule authority: `pajin.dev/supervisor-checkpoint-schedule/v1alpha1`
- Dedicated budget authority: `pajin.dev/supervisor-dedicated-budget/v1alpha1`
- Decision: [ADR-0120](../adr/0120-plan-supervisor-checkpoints-before-invocation.md)

## Scope

SUP-004A defines the first exact Shadow Supervisor checkpoint and Provider request wire. It
re-verifies one current SUP-002 `SupervisorSnapshotInput` up to its existing 4 MiB ceiling,
resolves its exact current Canonical Graph Snapshot, builds one
deterministic structured-output `ProviderChatRequest`, checks a Supervisor-dedicated
Campaign-attenuated affordability ceiling, and publishes one digest-only schedule in a separate
sealed Run.

This slice deliberately does not call a Provider. It does not reserve or consume a Campaign or
Supervisor budget, issue or consume a Capability, create a ToolRequest, dispatch a Worker, receive
a model response, compile a SUP-003 proposal, create or mutate a Task or Plan, expand Scope, apply a
Stop, grant a Permit, or enable activation. SUP-004B owns the atomic dual-budget Provider dispatch
and receipt boundary.

## Exact invocation request

The legacy request contains exactly two messages:

1. a code-owned `developer` contract that treats every user field as untrusted Snapshot data and
   forbids Tool requests, Scope expansion, Capability, Permit, and execution claims; and
2. the complete SUP-002 input encoded as canonical UTF-8 JSON in one `user` message.

The original chat and `v1alpha1` binding remain unchanged when the canonical input fits the existing
`ProviderMessage` 65,536-character limit. Larger inputs use the additive `v1alpha2` binding described
below. Input is never truncated or sent as independent partial model calls.

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

SUP-004A alone does not claim cross-process dispatch, crash-after-dispatch classification, or
Provider-call single-flight. SUP-004B owns their stable request ID, reservation, journal, and
Gateway receipt boundary.

## Negative boundaries

Planning or verification fails closed for:

- stale or foreign Campaign, Graph, Collaboration Snapshot, SUP-002 input, SUP-001 binding,
  Provider, model revision, or configuration;
- message role/order/source, developer content, canonical user JSON, request, request schema, or
  response schema substitution;
- undefined Graph checkpoint reasons, request Tool/stream/parallel-call widening, or mutable model
  configuration;
- a dedicated call/token/time/cost ceiling wider than the Campaign or a request that does not fit;
- input above the existing 4 MiB ceiling or incomplete/mixed input transport;
- exact-checkpoint request equivocation, model validation bypass objects, digest forgery, Run/root/
  artifact/event substitution, or unsealed/tampered audit data;
- boolean-number coercion in request/result/usage fields; and
- any attempt to turn the schedule into Task, Plan, Scope, Capability, Permit, execution, Stop, or
  activation authority.

## Compatibility and rollback

The original invocation and schedule schemas, scheduler, public usage-bound helper, sealed audit
Run, and exports are additive. Existing small requests and their readers remain compatible.
SUP-001 through SUP-003, TaskGraph, Campaign execution, Capability, and Permit authority do not
change. The versioned large-transport deployment and rollback requirements follow below.

## Complete input transport extension

[ADR-0272](../adr/0272-bind-complete-supervisor-input-chunks-and-version-large-provider-transport.md)
adds `pajin.dev/supervisor-input-chunks/v1`. `inputTransport` binds `inputId`, `inputDigest`,
`contentSha256`, UTF-8 `contentBytes`, Unicode `contentCharacters`, and `chunkCount`. Each user
message starts with a canonical JSON header containing the same values plus `chunkIndex` and
`offsetCharacters`, then a newline and up to 60,000 characters of the original canonical input.
Splitting is by Unicode character, not encoded byte; concatenating the text after the first newline
of each message recovers the exact original bytes. All chunks remain untrusted user data.

The planner reconstructs and validates the complete input before binding the request. Existing
schedule and receipt consumers rebuild that exact request from the current registered sources.
Role/source/content digests and counts cover every message in order. Missing, duplicated, reordered,
mixed, edited, incorrectly framed, noncanonical, oversized, or downgraded inputs fail closed.
The shared Provider message limit and 100-message ceiling remain unchanged, with one developer
message. The input ceiling remains 4 MiB; conservative usage includes all framing and must fit both
the Campaign and Supervisor budgets. Model context limits remain Provider-specific.

The Provider adapter selects `openai-chat-completion-v2` when the legacy serialized job exceeds
1,000,000 bytes. Its UTF-8 stdin ceiling is 16 MiB, with an additional 100,000-byte envelope allowance.
Other actions retain their original limits. The Gateway derives `max_request_bytes` for this action
and the receipt consumer reconstructs it; an unrelated Worker action cannot carry that wider
policy. Plain HTTP enforces the request ceiling and hashes the complete JSON body. HTTPS CONNECT
allows bounded request framing overhead (256 KiB) while retaining its original response ceiling;
its receipt explicitly remains opaque. Response parsing limits and all execution authority remain.

Ship matching host, Worker, and proxy versions before using large requests. Old images reject the
new command or field. Existing small requests have identical wire/binding values, with optional
transport fields omitted. A rollback must preserve matching readers/inventory for retained new
receipts and stop new chunk schedules; silently rewriting them as legacy requests is forbidden.

Validation includes the Supervisor input/Checkpoint suites, Provider/Gateway/Worker/proxy suites,
and this opt-in owned-host transport test (use an IPv4 address actually assigned to the test host):

```sh
PAJIN_LIVE_SUPERVISOR_INPUT=1 PAJIN_SUPERVISOR_TEST_BIND_IP=<owned-private-ipv4> \
  python -m pytest -q tests/test_supervisor_input_transport_live.py
```

The shared HTTPS handler passes the verified SSL context through the supported Python 3.12 API;
it does not use the removed private hostname option. The test binds an ephemeral HTTPS target
with an ephemeral certificate and credential, runs the
real Worker process through a loopback proxy, verifies complete received input and a CONNECT
receipt, and closes the servers/process. It does not bypass the proxy's loopback prohibition or TLS
verification, and checks that an untrusted test certificate prevents delivery. It does not establish
Docker isolation or real-model effectiveness.
