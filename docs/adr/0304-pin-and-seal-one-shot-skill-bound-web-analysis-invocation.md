# ADR-0304: Pin and Seal One-shot Skill-bound Web Analysis Invocation

- Status: Accepted
- Date: 2026-09-16
- Scope: SKILL-002 consumption and the WEB-007 proposal-only successor invocation
- Implementation status: implemented, locally test-verified, and provisioned with independently
  pinned immutable images; live Provider dispatch pending separate authorization

## Context

WEB-007/v1alpha1 proved the terminal no-redispatch path of one local model call, but its first live
Qwen3 4B Q8 attempt reached a Worker/proxy I/O ceiling of 30 seconds while the verified model runtime
reserved 180 seconds. SKILL-002 subsequently sealed reviewed target-neutral Skill instructions and
tainted opaque Evidence in separate projections, with no Provider or target dispatch.

Reusing the old action or silently changing its timeout would make historical Provider Runs
ambiguous. Putting both projections into one user message would erase the instruction/evidence trust
boundary. Reusing the failed Run or automatically retrying it would violate its terminal receipt.
The action-oriented WEB-007/v1alpha2 name is already reserved for a later governed diagnostic flow,
so the proposal-only Skill consumer also needs its own additive wire identity.

## Decision

### Add an independent transport/runtime Pin

Introduce `WebAnalysisTransportRuntimePin/v1alpha1`. It binds:

- the digest of the already verified model `RuntimePin`;
- newly built immutable Worker and proxy image IDs that must differ from each other and from the
  base images;
- Provider transport `pajin.web-analysis.provider-transport/v2`;
- Worker action `openai-chat-completion-v3`;
- exact integer 180-second Worker open, proxy exchange, and job ceilings;
- a single-dispatch-only marker; and
- literal denial of external egress authority.

The Pin is accepted only with an independently supplied expected digest. The v3 Worker requires the
exact transport version and timeout fields before opening the local Provider request. Existing v1
and v2 Worker actions retain their prior 30-second behavior. The proxy accepts a policy ceiling up
to 3,600 seconds so a separately pinned 180-second exchange is representable; the invocation still
uses the exact lower Pin and job deadline.

Source changes do not constitute an immutable image build. A live successor Run must use newly built
Worker and proxy digests and reverify the complete Pin before dispatch. The operational path now
strict-loads a separate bounded Pin artifact against a separately supplied digest, verifies both
image identities and platforms, and completes all source, plan, Skill, model, Pin, and output-root
checks before starting the model runtime.

### Preserve the base Provider authority and layer the successor context

Reuse the existing local Provider assembly, reservation, budget, Gateway, finalizer, cleanup, and
Provider Run ownership. Do not copy or replace that authority. A
`SkillBoundWebAnalysisProviderExecutionContext/v1alpha1` nests the exact base execution context and
adds only the transport Pin and proposal-only invocation Pin.

The Provider Run verifier is parameterized by expected role, attempt, response-schema name, and
execution context, while its v1 defaults remain unchanged. The successor uses role
`skill-bound-web-analysis-proposal`, attempt `1`, and the
`skill_bound_web_analysis_proposal_draft` response schema.

Keep the exact raw `DockerWorkerBackend` in the Gateway so host-observed network-log provenance is
not weakened by a wrapper. A separate non-executing attestor binds that exact object to the Pin and
rechecks its allowed image, proxy image, external network, and action route before Tool preparation,
after preparation but before Secret Lease opening, and immediately before the backend run.

### Keep reviewed instructions and tainted Evidence in separate messages

Strict-reload the exact SKILL-002 preparation Run and reconstruct its registered selection policy.
Construct exactly two messages:

1. a developer message containing only the code-owned selected instruction projection; and
2. a user message containing only the unchanged tainted opaque Evidence projection.

The request uses temperature `0.0`, top-p `1.0`, seed `0`, a 1,024-token completion ceiling,
streaming disabled, parallel tool calls disabled, an empty tool list, and tool choice `none`.
Planning, compilation, and strict readers require independently supplied source Run/root, SKILL-002
Run/root, registry, policy, and transport-Pin anchors.

### Seal one terminal successor Run per attempt

One runtime object can dispatch at most once. Success seals exactly seven artifacts: the bound
Snapshot, request, successor execution context, Provider outcome, raw draft, compiled inert
proposal, and invocation receipt. Failure seals the first three plus a terminal failure receipt,
and conditionally the Provider outcome and a bounded rejected draft. Both shapes have exactly a
start and a completed-or-failed event and are immediately strict-reloaded.

The only failure states are:

- `provider-invocation-failed-uncertain`, which claims no Provider response; and
- `provider-response-rejected`, which binds the Provider outcome but produces no proposal.

A rejected response at or below 256 KiB may be retained and hash-bound. A larger rejected response
is not retained in the analysis Run; its digest and byte count remain bound by the independently
verified Provider outcome. Cancellation terminalizes both Runs before propagating a typed
cancellation. No failure authorizes an in-Run retry or fallback.

Success and failure receipts fix one dispatch, zero target requests, and literal false authority for
automatic redispatch, execution, Scope expansion, Tool or Permit issuance, Finding promotion, Graph
admission, report publication, and external delivery. The compiled result remains an inert advisory.

## Consequences

### Positive

- WEB-007/v1alpha1 request, artifact, event, and loader grammars remain unchanged.
- The 180-second budget is represented at the base runtime, job, Worker open, and proxy policy
  layers without weakening the old transport.
- Reviewed Skill instructions cannot be confused with target-influenced Evidence.
- Provider ownership and cleanup remain in the existing assembly instead of a duplicated runtime.
- Every dispatched attempt has a terminal, sealed, strict-reloadable audit outcome and no automatic
  redispatch path.

### Tradeoffs and residual risks

- The local immutable Worker/proxy images and separate Pin have been built and preflight-verified,
  but remain host-local provisioning evidence rather than a live Provider outcome.
- The successor has not made a real model call, so structured-output success, latency, memory,
  usefulness, and output stability remain unverified.
- The proposal still cannot select or execute a Recipe, issue a Permit, create a Finding, mutate the
  Graph, publish a report, or deliver externally.
- A local Provider and single-host finalizer remain within one operational trust domain.

## Compatibility, migration, and rollback

This change is additive. Existing Worker actions and WEB-007/v1alpha1 models, Provider Calls, Runs,
receipts, and strict loaders retain their identities and defaults. Consumers opt into the successor
only through the exact transport Pin and Skill-bound wire types.

Rollback disables the successor binder and invocation entry point. Historical v1alpha1 Runs and
SKILL-002 preparation Runs remain readable and inert. A failed successor Run is never reopened or
retried; a later attempt requires a fresh Run and a separately authorized dispatch.

## Rejected alternatives

- Increase the old Worker/proxy timeout in place.
- Reuse the already failed WEB-007 Run or retry it automatically.
- Call the proposal-only successor WEB-007/v1alpha2.
- Place Skill instructions and tainted Evidence in one message.
- Rebuild Provider reservation, budget, cleanup, or finalization authority in a parallel runtime.
- Retain arbitrarily large rejected model output in the analysis Run.
- Treat a successful compiled proposal as Recipe, execution, Finding, Graph, reporting, or delivery
  authority.

## 2026-09-16 operational evidence update

The first separately authorized successor attempt exposed a capacity-preflight omission rather than
making a model dispatch. Its exact conservative accounting bound was 87,472 prompt tokens plus a
1,024-token completion ceiling, above the local Campaign limit of 65,536. The Provider and analysis
Runs sealed and strictly reloaded with dispatch count zero, no execution ID, no target request, no
external delivery, and verified cleanup.

The operational entry point now reconstructs the same code-owned local Provider registration and
the exact Skill-bound chat during preflight and applies the shared Campaign accounting check before
starting the model runtime. This closes the omitted validation-to-use boundary without changing the
historical transport Pin or raising the budget. The accounting bound is intentionally not treated as
a tokenizer/context measurement. The entry point now also fails closed before model construction
unless that conservative prompt-plus-completion bound fits the frozen 4,096-token RuntimePin. This
prevents an accounting-valid but context-oversized request from starting the runtime; it does not
replace pinned Qwen tokenizer and exact chat-template evidence. A later attempt still requires that
offline proof. If the useful request does not fit, the correction must be additive: compact the
model-visible successor wire or introduce a new Web-specific runtime Pin. Historical Runs remain
immutable and no terminal Run is retried.
