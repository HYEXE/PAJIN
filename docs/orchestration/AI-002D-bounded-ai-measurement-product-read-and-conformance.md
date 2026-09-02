# AI-002D: Bounded AI Measurement Product Read and Conformance

## Purpose

AI-002D projects one exact, sealed AI-002C evaluation into an AI-only public product and permits one
deployment-selected Operator read. It adds no prompt materialization, measurement, execution, model
call, Observation confirmation, Finding, Graph, report, or delivery authority. Existing AI-001,
AI-002A through AI-002C, generic benchmark, Walking Observation, and Finding wires retain their
accepted identities and meanings.

The deterministic implementation and its manual workflow are repository contracts. Phase 25 is not
complete until an exact-clean Ubuntu real-Docker run of that workflow succeeds, including its
unconditional residue audit.

## Versioned product

The only product artifact is `ai-measured-product.json`, validated as
`pajin.dev/ai-measured-product/v1alpha1` / `AIMeasuredProduct`. Its content is limited to:

- a content-addressed product ID and digest;
- one exact AI-002C public evaluation reference;
- the single AI-002A M03 public case reference;
- the bounded `synthetic-known-positive-observed` case state;
- the exact DOMAIN-006 AI floor policy reference;
- fourteen canonically ordered public metric observations, including twelve required and two
  explicit not-applicable metrics;
- the satisfied independent fresh-session Replay and Control floor state;
- the synthetic-benchmark-only marker; and
- literal-false disclosure and authority markers.

The product excludes prompt text, sensitive checks, private Ground Truth and evaluation bindings,
source/Replay/Control lineage, image identities, runtime coordinates, sessions, requests, approvals,
Permits, Grants, target receipts, transcripts, Worker or Tool results, Graph content, Observation
confirmation, Finding content, and reports. The two negative Controls not observing the sensitive
marker mean only that the exact registered transformations behaved as expected. They do not confirm
general prompt secrecy or production model safety.

The projector first contextfully reopens the complete AI-002C source, two Replay repetitions, and
three Controls through the AI-002A public/private mapping and fixed Docker image inspector. It then
creates a ninth, distinct sealed product Run. The loader repeats the complete source reopen and
verifies the product artifact, event type and order, event payloads, all nine Run identities, strict
canonical JSON bytes, product digest, exact case, metric order, applicability, comparison, rational
values, and false ceiling. Any drift fails closed with the fixed AI-002D integrity error.

## Deployment-pinned read

`AIMeasuredProductReadRegistration` binds one deployment ID to the exact product Run, product
ID/digest, source evaluation ID/digest, product outcome, and complete private verifier context.
`AIMeasuredProductReadRegistry` is immutable and rejects duplicate deployment, product Run, or
product identities. It is deployment TCB, not caller input and not a public registration wire.

`AIMeasuredProductReader.read()` takes no arguments. Every call resolves the fixed deployment
registration and runs the full AI-002D loader. It accepts no caller-selected path, Run, provider,
image, profile, route, prompt, check, session, case, metric policy, or verifier context, and it does
not cache a prior product.

## Operator endpoint

The Control Plane may receive one exact deployment-composed reader and expose:

`GET /v1/products/ai-measured-system-prompt-disclosure`

The route:

- requires an authenticated Operator;
- rejects missing or invalid authentication with 401;
- rejects authenticated non-Operator roles with 403;
- rejects any query string or non-empty GET body with 400;
- rejects method substitution with 405;
- returns 503 when no exact reader is configured;
- returns a fixed, non-reflective 409 for any integrity failure; and
- returns the unchanged by-alias product object without a wrapper on success.

All responses retain the existing `no-store, max-age=0`, `Pragma: no-cache`, no-referrer, and
nosniff boundary and set no cookie, CORS permission, ETag, or Last-Modified validator. This
deployment endpoint does not make the product's `httpEntrypointAuthorized: false` marker true; the
product cannot authorize another endpoint.

## Closed authority boundary

Every product marker for the following remains literal false:

- Docker image build, Target or network creation, provider selection, and caller configuration;
- approval, ActionPermit, or Grant issuance;
- Replay, Control, Gateway, Worker, live measurement, model call, or additional execution;
- further product projection, AI Observation confirmation, Graph admission or mutation, Finding
  authority, reporting, and external delivery;
- credentials, external providers or targets, and production targets;
- arbitrary prompts or Tools, plugins, RAG, MCP, memory mutation, M06, A04, or general AI scanning;
  and
- any additional application-protocol write.

Possession of the product, a source reference, passing floor, or Operator endpoint grants no
source, Replay, Control, publication, or HTTP-entrypoint authority.

## Fresh-process read conformance

The local conformance starts a new Python interpreter using `spawn`. The child receives only the
sealed product outcome, exact measured-case mapping, a deployment-owned audit root, and a literal
test-owned choice between a fake image inspector and the production Docker inspector. It rebuilds a
fresh provider, reopen context, immutable registration, reader, and Control Plane app.

The child runs all denial cases and two successful Operator reads. Each successful read must invoke
the resolver and full AI-002C reload independently and reproduce the sealed canonical product bytes.
The whole-call filesystem snapshot must remain identical. Run creation, product projection, source
measurement, Replay/Control evaluation, Worker execution, and Target mutation methods are prohibited.

Docker access during reading is limited to the three fixed image-inspection commands and the managed
container/network list queries required to reverify immutable image identity and zero residue. Any
mutable Docker command fails conformance.

## Exact-commit real-Docker requirement

The manual `ai-002d-conformance.yml` workflow is the only Phase 25 Exit Gate evidence for this
real-Docker boundary. It requires explicit confirmation, pinned Actions, locked dependencies, an
exact clean `GITHUB_SHA`, Ubuntu 24.04, and the three repository-built fixed images.

The opt-in test must:

1. start with no managed AI fixture residue;
2. execute one exact M03 source, two independent fresh-session Replay repetitions, and the three
   registered Controls;
3. verify the eight-case policy-denial set and exact satisfied fourteen-metric AI floor;
4. publish one AI-002D product only after all six executions finish and cleanup succeeds;
5. read that product twice in a fresh process without another Target, Worker, operation, or product
   Run; and
6. finish with no managed, execution-labelled, or exact-name Target, proxy, or network residue.

An unrun, skipped, failed, non-exact-commit, non-Linux, fake-provider, or same-process result is not
real-Docker conformance evidence and cannot complete the Phase 25 Exit Gate.

## Compatibility and rollback

AI-002D is additive. It changes no AI-001A through AI-001D identity, AI-002A through AI-002C wire,
DOMAIN-006 metric registration, generic benchmark/Finding wire, Walking Observation meaning,
accepted ADR, approval, ActionPermit, Grant, Worker, Graph, report, or delivery contract.

Rollback removes the AI-002D product, reader, route, tests, workflow, and this document. It does not
rewrite accepted source, Replay, Control, or product Runs and does not weaken AI-002A through
AI-002C validators.

## Related documents

- [ADR-0259](../adr/0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)
- [AI-002A](../benchmark/AI-002A-exact-m03-measured-case-authority.md)
- [AI-002B](../benchmark/AI-002B-registry-governed-disposable-m03-source-measurement.md)
- [AI-002C](../benchmark/AI-002C-independent-fresh-session-replay-controls-ai-floor.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [AI-002D workflow](../../.github/workflows/ai-002d-conformance.yml)
