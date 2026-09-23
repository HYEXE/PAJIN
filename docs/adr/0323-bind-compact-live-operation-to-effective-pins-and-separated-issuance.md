# ADR-0323: Bind Compact Live Operation to Effective Pins and Separated Issuance

- Status: Accepted
- Date: 2026-09-23
- Scope: WEB-007 effective compact runtime identity and operator-only one-call composition
- Implementation status: implemented and locally verified without provisioning an operational key,
  signed authorization, or durable live store. No model completion, Provider dispatch, or target
  request is authorized by this status. The first fresh completion remains behind separate explicit
  user approval.

## Context

[ADR-0322](0322-enforce-cleanup-bound-compact-web-analysis-live-runtime.md) defines the closed
nine-step live state machine, cleanup-bound receipt, and no-redispatch semantics for one compact
WEB-007 completion. Its integration initially carried the historical benchmark `RuntimePin` and the
predecessor transport Pin as live receipt anchors.

Those historical Pins cannot be reinterpreted as the exact effective compact runtime. The immutable
benchmark `RuntimePin` fixes `max_completion_tokens=128`, while the admitted compact request and
Capacity v2 proof fix a 4,096-token context and a 1,024-token completion ceiling. The benchmark Pin
also belongs to source-byte-addressed effectiveness lineage. Editing it or changing its meaning
would invalidate historical identities and would make an audit artifact appear to authorize a
different request.

The predecessor transport Pin remains valuable lineage: it identifies the independently built
Worker and proxy images and the historical Provider transport contract. It does not by itself bind
the effective compact runtime, the Capacity v2 request, or a successor transport namespace.

There is also an operational separation gap. The verification-only Gate C module correctly omits a
private key, but a real external authorization requires a provisioning and issuance utility outside
the execution process. Conversely, the live process needs one bounded composition entry point that
can prove all inputs before side effects and invoke the Gate D runtime once without gaining signing,
retry, or state-creation authority.

## Decision

### 1. Preserve historical Pins and add an effective compact runtime Pin

The benchmark `RuntimePin`, including its exact 128-token completion ceiling, remains immutable and
readable only with its historical meaning. It is not accepted as the effective live runtime Pin and
is not edited, copied, translated, or widened for WEB-007.

Add a `CompactWebAnalysisRuntimePin` under a distinct API and digest domain. It binds:

- the exact Capacity v2 Pin and materialization-policy digest;
- the exact admitted compact live request, compact projection, chat request, and Provider
  registration digests;
- the exact Skill Run, root, and Snapshot lineage;
- context `4096` and completion ceiling `1024`;
- model CPU `4`, memory `6144 MiB`, PID limit `128`, parallelism `1`, and RAM cache `0`;
- the exact model ID, repository, revision, filename, byte size, SHA-256, model Pin, image,
  platform, and platform-manifest identity; and
- the predecessor transport Pin digest as lineage rather than as effective live authority.

The Pin is authority-free. It does not authorize materialization, Provider dispatch, target access,
or retry.

### 2. Add a compact transport successor bound to that runtime

Add a `CompactWebAnalysisTransportPin` with its own API and the transport identity
`pajin.web-analysis.compact-provider-transport/v1`. It binds the effective compact runtime Pin, the
predecessor transport lineage digest, the exact Worker action and immutable Worker/proxy images,
all three 180-second ceilings, literal single-dispatch-only behavior, and the separately named
pinned Worker wire protocol `pajin.web-analysis.provider-transport/v2`. The compact identity is the
successor Pin namespace; it is not substituted into the existing `openai-chat-completion-v3`
payload's `transportVersion` field. The Worker payload uses only the bound compatible wire protocol.

The compact live runtime, receipt, strict loader, Worker context, job metadata, cleanup proof, and
Provider-route attestation use the compact runtime and transport Pins as their effective anchors.
They may retain predecessor digests as lineage, but they do not accept the predecessor transport or
benchmark `RuntimePin` alone as sufficient live identity. ADR-0322's order, durable claim, cleanup,
publication, and terminal cross-link requirements remain unchanged.

### 3. Bind authorization v2 to both effective Pins

Add an authorization-request, statement, and detached-signature bundle v2. The exact request binds
the existing preparation and admission, compact chat request, model and Capacity anchors,
predecessor transport lineage, and both effective compact Pin digests. It also repeats the exact
4,096/1,024 profile, Worker action and images, compact Pin identity, pinned Worker wire protocol,
and literal denial of Provider, target, Tool, Finding, Graph, report, and retry authority before
external authorization.

The signed statement retains Gate C's bounded validity, nonce, exact-one-completion count, and all
downstream-authority denials. Verification remains necessary but not dispatch-ready: Gate B must
still durably consume the preparation and authorization identities before materialization.

Historical authorization v1 requests, statements, bundles, and verified results remain readable
with their original meaning. They are not live-authoritative for the compact successor, cannot be
upcast to v2, and cannot substitute either effective Pin digest.

### 4. Keep private-key provisioning and issuance outside the executor

Provide an offline provisioning and issuance utility as a physically separate package and operating
surface outside the main execution package, runtime images, and one-shot runner. It is the only
component allowed to read the raw Ed25519 private key. Provisioning creates the private seed, public
trust anchor, and independently retained trust-anchor digest. Issuance signs one canonical v2
authorization request into one bounded-lifetime bundle.

The private key is read only from an owner-controlled local file. It is not accepted as an argument
value, environment variable, standard input, or serialized executor input. The utility does not
import or call the live runtime, durable claim, materializer, Provider, Worker, target, or receipt
publisher. Its outputs grant no target or downstream assessment authority.

The offline package has no dependency on or import of the main `pajin` distribution. It implements
only the bounded canonical authorization-v2 and trust-anchor wire needed to provision and sign.
The main package remains the independent parser and verifier of its output. This small deliberate
wire duplication is preferred to loading execution-package initializers while a raw private key is
resident; cross-implementation conformance tests prevent silent schema or digest drift.

The execution package receives only the public trust anchor, independently retained anchor digest,
and signed bundle. It contains no signing function or private-key-loading path and does not import
the offline package.

### 5. Separate state provisioning, zero-side-effect preflight, and one-shot execution

The operator surface has three distinct phases:

1. state provisioning creates the private durable journal and terminal-output roots and returns an
   externally retained store identity without authorizing or attempting a call;
2. preflight strict-reloads the immutable source, Skill, Capacity, preparation, admission, effective
   Pins, public trust anchor, and signed authorization, then reconstructs and verifies the exact
   request without creating or mutating durable state, claiming an identity, issuing a credential,
   materializing a model, starting Docker resources, contacting a Provider, or contacting a target;
3. execution opens only a pre-existing durable store under the independently supplied store
   identity, repeats the strict checks, constructs the exact Gate D runtime, and invokes it exactly
   once.

The executor never creates a journal opportunistically, signs or refreshes authorization, loops
around `invoke`, falls back to a legacy runtime, or automatically redispatches. A failure or
uncertain result follows ADR-0322 into non-reusable durable cleanup or terminal state. Recovery may
complete cleanup and publication only; it cannot invoke the model again.

Provisioning, issuance, and preflight are not model dispatches. Even after all artifacts validate,
running the execution phase for the first Qwen3 4B Q8 completion requires a separate, explicit user
approval. This ADR does not provide or imply that approval.

## Consequences

### Positive

- The effective live identity agrees with the already admitted 4,096/1,024 compact request without
  rewriting source-addressed benchmark history.
- Authorization covers the exact runtime and transport that will be checked immediately before the
  durable dispatch marker.
- Compromise of the executor cannot use an embedded issuer path because the private key and signing
  utility are absent from that process and package.
- Operators can validate every immutable input with zero live side effects before deciding whether
  to grant separate execution approval.
- A supported one-shot composition path avoids ad hoc test-fixture assembly while retaining the
  Gate B and Gate D no-reuse guarantees.

### Cost and remaining work

- Two additional Pin schemas and an authorization v2 family must remain compatible with the
  Capacity, receipt, loader, journal, and cleanup contracts.
- The independent issuer wire implementation and main verifier must be kept aligned by
  cross-implementation conformance and v1-injection rejection tests.
- Provisioning and execution require explicit filesystem ownership, retained store identity, and
  public-anchor custody procedures.
- Acceptance requires focused negative tests for Pin substitution, v1 artifact injection, signer
  import or key leakage, preflight side effects, new-store creation, duplicate invocation, and retry.
- Successful structured output, quality, latency, peak memory, and stability are not established by
  this decision and remain outside the first-call authorization boundary.

## Rejected alternatives

- Change the historical benchmark `RuntimePin` from 128 to 1,024 completion tokens.
- Treat Capacity v2's request fields as permission to ignore the contradictory runtime Pin.
- Use the predecessor transport Pin directly as the effective compact transport identity.
- Accept or translate authorization v1 for the compact successor.
- Place private-key provisioning or signing helpers in the execution package, runtime image, or
  one-shot runner.
- Let preflight create the journal, reserve identities, issue credentials, materialize the model,
  or probe the Provider.
- Create a fresh durable store during execution, invoke more than once, retry after uncertainty, or
  fall back to a legacy runtime.

## Compatibility and rollback

This decision is additive for historical benchmark, Capacity, transport, authorization,
preparation, admission, and journal artifacts, which remain readable under their original
contracts. No v1 artifact is rewritten, migrated in place, or made live-authoritative by lineage
alone. The unexecuted local Gate D v1alpha1 prototype produced no operational terminal artifact;
its successor receipt/loader is deliberately v1alpha2-only and does not claim to read or authorize
that pre-live prototype wire.

Rollback disables the effective compact successor and one-shot executor while retaining existing
artifacts and durable state for audit and cleanup. It may continue exact owner-bound cleanup and
publication recovery, but it may not delete or replace the store, regain consumed identities,
reissue an authorization, translate a v1 artifact, or dispatch through a historical runtime.
