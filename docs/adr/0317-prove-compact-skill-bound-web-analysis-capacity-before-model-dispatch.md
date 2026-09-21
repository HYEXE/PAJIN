# ADR-0317: Prove Compact Skill-bound Web Analysis Capacity before Model Dispatch

- Status: Accepted
- Date: 2026-09-21
- Scope: WEB-007 compact Skill-bound request projection and offline context-capacity proof
- Implementation status: additive compact wire and sealed offline capacity proof implemented and
  strict-reloaded; no model completion, Provider dispatch, or target request authorized or performed

## Context

[ADR-0304](0304-pin-and-seal-one-shot-skill-bound-web-analysis-invocation.md) preserves reviewed
SKILL-002 instructions and tainted Evidence in separate `developer` and `user` messages. Its first
authorized operational attempt stopped before Provider dispatch because conservative Campaign
accounting exceeded the available model-token budget. The resulting preflight correctly prevents a
known oversized request from starting the runtime, but conservative accounting is not tokenizer
evidence.

An exact measurement with the pinned Qwen tokenizer and embedded chat template now gives the legacy
full two-message request a 4,208-token prompt. With its fixed 1,024-token completion ceiling, the
5,232-token total exceeds the frozen 4,096-token runtime context. The legacy request is therefore not
dispatchable under that RuntimePin. Raising only the Campaign budget cannot make it fit.

The embedded Qwen chat template also does not natively render a `developer` role. Silently relying on
an unsupported role, combining reviewed instructions with tainted Evidence, changing the historical
request in place, or running a model to infer whether the request fits would weaken either the trust
boundary or the immutable Run history.

A compact `system` plus `user` prototype first measured a 1,505-token prompt. Together with the same
1,024-token completion ceiling, its preliminary total was 2,529 tokens. Those values remain useful
only as historical design evidence and are not admission values. The implemented compact wire and
sealed proof independently recomputed a 1,460-token prompt and a 2,484-token total, leaving 1,612
tokens in the frozen 4,096-token context. The same request also passes conservative Campaign
accounting at `50,144 + 1,024 = 51,168 <= 65,536`.

## Decision

### 1. Freeze the legacy request as non-dispatchable under the current RuntimePin

Keep the existing full `[developer, user]` request and its historical Runs readable and immutable.
Record the exact observed legacy measurement as:

```text
prompt tokens:       4,208
completion ceiling: 1,024
total:               5,232
runtime context:     4,096
admission:           denied
```

No caller may reinterpret the legacy request as fitting, lower the completion ceiling implicitly,
drop template overhead, or raise only a bookkeeping budget to admit it. A historical terminal Run is
never reopened or retried.

### 2. Introduce compact role handling only through an additive successor

The compact successor must use exactly two messages supported by the embedded template:

1. one `system` message containing only the bounded, code-owned compact Skill instruction
   projection; and
2. one `user` message containing only the bounded, tainted Evidence projection.

It must have a new versioned request/projection identity and must not mutate the legacy request,
SKILL-002 preparation Run, or historical digest spine. Compaction may remove redundant
model-visible representation, but it must not add target material, merge instruction and Evidence
trust domains, relax required-Evidence status, introduce a Tool, or grant execution, Finding, Graph,
reporting, PoC, or delivery authority.

The proof input must embed two distinct, code-owned message sentinels, one in each message. The
rendered chat must contain both sentinels. Their presence proves that the template did not silently
drop either role payload; it does not prove model quality or authorize dispatch.

### 3. Make context admission an offline sealed proof

The proof process may call only the pinned runtime's metadata `/props` endpoint and its
`/apply-template` and `/tokenize` processing endpoints. It must not invoke inference, completion
generation, a Provider, a Worker, a browser, or a target. It must bind enough immutable input and
output material to strict-reload at least:

- the exact compact request/projection version and digest;
- the pinned model, tokenizer, chat-template, and 4,096-token runtime context identities;
- the exact 1,024-token completion ceiling;
- the two input message sentinels and evidence that both occur in the rendered template;
- the rendered prompt digest and exact token count returned by `/tokenize`;
- the checked `promptTokens + completionCeiling <= runtimeContext` relation; and
- literal false markers for inference, completion, Provider, target, execution, Finding, Graph,
  report, SARIF, PoC, and external-delivery authority.

The successful proof is sealed as Run `run_20260921T021716Z_b3939e0c` with root
`7991465747157b7ef4a75f79905955a4bc47bcb24915cf22438eab8150294383`. Its independently
recomputed admission evidence is:

```text
prompt tokens:                         1,460
completion ceiling:                    1,024
total:                                 2,484
runtime context:                       4,096
remaining context:                     1,612
conservative Campaign prompt:         50,144
conservative Campaign total / limit:  51,168 / 65,536
admission:                             proved offline
```

The capacity Pin digest is
`998f7c8340d42715ddf462b0f7ce5e35c577cd5e2f12335c51e1c56641338677`, the proof digest is
`bf30a56e691a0ebd3e41a6a75570fc655aa4dc1d0d327c6160c161bae8b0e95f`, the evidence digest is
`1a2ecb50f3d0b69fafcbf6d61c4bddf27eb6685e27df0b411ef372b353803b18`, the Index digest is
`047c80c5fb56e0cf42c0b8bdec4259917cf4b715501effec7365c53cace66283`, the compact projection
digest is `8ba7a786ca994ee7792a2f858c39a35470b1aa65e2e085961c8d66adee070b8b`, and the exact chat
request digest is `aae9d347ec353e911bf1d4ceb4535af485ae3e3556a13f414f75bb6665554244`. The proof also binds
chat-template digest `61be32c41fcad4c4ed2a4b656577feef0d09c4bf37142ead33246e218945c4a6` and tokenizer-runtime
digest `d32d223f88d4723b0a281df699f0c1df96e992d9c372c4664c893c33e6745326`.

The fifth evidence artifact seals the 5,593-byte formatted prompt, 2,630-byte chat template, and
all 1,460 token IDs. Strict reload independently recomputes their byte counts, digests, token count,
sentinel membership, and system-before-user order. It succeeded, the temporary tokenizer container
was removed, and completion generation, Provider dispatch, and target request counts remained zero.
The historical prototype values `1,505 + 1,024 = 2,529` remain labelled preliminary and are not
copied into this admission decision.

### 4. Keep model completion behind a second authorization boundary

Generating and strict-reloading a passing sealed capacity proof does not authorize a model call.
The proof now exists, but it is not itself wired into the live successor invocation boundary. The
next implementation step is a proof-bound live successor integration that strict-reloads the exact
capacity Run and rejects projection, request, runtime, or accounting drift. Only after that
integration exists may an operator separately approve exactly one fresh WEB-007 successor
completion. That completion must use a new Run, preserve all existing Provider, budget, one-shot,
cleanup, parser, compiler, and terminal-receipt checks, and remain incapable of target execution or
downstream promotion.

No model completion, Provider dispatch, or target request is part of this proof checkpoint.

## Consequences

### Positive

- The known legacy overflow is explicit and cannot be hidden by changing accounting policy.
- Role handling matches the embedded template while preserving instruction/Evidence separation.
- Template rendering and token counting are verified without invoking the model or target.
- A passing capacity proof remains distinct from human authorization for a fresh completion.

### Cost and remaining work

- The live successor must be updated to consume and strict-reload the exact sealed capacity proof
  before it can become eligible for separately authorized dispatch.
- Model usefulness, structured-output success, latency, memory, stability, and the WEB-008 execution
  topology remain unverified.

## Rejected alternatives

- Dispatch the legacy request because conservative Campaign accounting can be changed.
- Treat the unsupported `developer` role as equivalent to `system` without a new wire version.
- Merge reviewed instructions and tainted Evidence into one message.
- Accept byte counts, estimates, or the preliminary prototype total as a sealed tokenizer proof.
- Use an inference or completion endpoint to test capacity.
- Let a passing proof automatically start or authorize a model completion.

## Compatibility and rollback

This decision is additive. Existing WEB-007 and SKILL-002 artifacts, Runs, readers, and historical
receipts retain their meanings. The compact successor and sealed proof do not make the legacy full
request dispatchable and do not by themselves admit a live replacement request. Rollback means
leaving the proof-bound live integration inactive; it never makes a terminal Run reusable or grants
any target or execution authority.

## Additive follow-up

[ADR-0318](0318-attest-descriptor-bound-model-materialization-before-live-web-analysis.md) adds the
descriptor-bound Capacity v2 gate and a separately sealed zero-dispatch preparation. The current
successor must consume that preparation rather than integrating directly from this historical v1
proof. This follow-up does not alter the decision or artifacts recorded above.
