# AI-002A: Exact M03 Measured-Case Authority

Status: Implemented additive registration boundary

## Purpose

AI-002A registers the one AI measured case that later Phase 25 boundaries may materialize and
measure. It binds the unchanged AI-001D contract, the exact code-owned KISA M03
`kisa.model.system-prompt-disclosure` scenario and `ai.chat-probe` Tool, the deterministic
synthetic Target contract, and the exact DOMAIN-006 AI plan into new AI-specific,
content-addressed artifacts. It does not build an image, create a Target or network, choose a
runtime provider, materialize a prompt, dispatch a Tool or Worker, call a model, or admit a
measurement.

The implementation is `pajin.workflow.ai_measured_case_authority`. It is additive and does not
change AI-001A through AI-001D, KISA, VAL-004A, REDTEAM-002, DOMAIN-006, the generic Finding
benchmark catalog, or `WalkingBenchmarkRunObservation`.

## Exact membership and predecessor

The public registry contains exactly one case:

| Ordinal | Case ID | Scenario | Threat | Tool | Role |
| --- | --- | --- | --- | --- | --- |
| 1 | `ai-fixture:m03-system-prompt-disclosure` | `kisa.model.system-prompt-disclosure` | `M03` | `ai.chat-probe@1.0.0` | exact M03 measured case |

`AIM03PredecessorContract` fixes the exact
`pajin.dev/ai-analysis-replay-benchmark-binding/v1alpha1` predecessor semantics required by this
case: the M03 scenario and digest, `POST`, the AI assessment Profile, the DOMAIN-006
`fresh-session-independent-replay` strategy, two supporting Replay repetitions, and canonical
Baseline, Negative Control, Counterfactual order.

AI-001D is a dynamic binding over separately sealed source, Replay, and Control evidence, so
AI-002A does not fabricate a concrete AI-001D binding ID or digest. Instead it records
`concreteBindingRequiredForMeasurement=true` and `concreteBindingBound=false`. A future source or
floor evaluator must contextfully reopen and bind an actual eligible predecessor. The registered
contract preserves AI-001D's `groundTruthCaseBound=false`,
`benchmarkMeasurementObserved=false`, `aiObservationConfirmed=false`, and false Finding,
Replay, and execution authority.

## Public and private authority split

`AIMeasuredCaseRegistry` is the versioned public registration. Its case carries only public-safe
identity, scenario, threat, Tool and method coordinates, a predecessor
reference, a public case digest, and a content-addressed commitment to the private case.

`AIPrivateGroundTruthBinding` is a separate deployment-private artifact. It binds the known-positive
Ground Truth class and exact
catalog-owned single-turn prompt and sensitive response check, expected vulnerable outcome, fixed
`vulnerable` Target mode, KISA scenario digest, Control materializer and executor identities, and
the three private Control derivations. The public authority carries only the private binding
digest. A digest is an integrity coordinate, not a redaction mechanism; deployments must keep the
private binding, raw request material, sessions, responses, transcripts, receipts, and runtime
coordinates off public products, Graph prose, reports, and delivery wires.

The artifacts are returned separately by `registered_ai_measured_case_mapping()`.
`load_ai_measured_case_authority()` requires both objects, reparses their strict wires, rebuilds
every code-owned registration, and rejects membership, predecessor, prompt, check, Control,
profile, ordering, nested-model, or digest substitution.

## Fixed Target and image contracts

`AIM03MeasuredTargetProfile` registers one code-owned synthetic Target contract:

- only the registered M03 case is accepted;
- the fixed mode is `vulnerable`;
- the fixed internal route is `POST /v1/chat` on container port `8080`;
- the fixed deterministic model identity is `pajin-deterministic-lab-v1`;
- the container must run as `65532:65532` with a read-only root filesystem, all capabilities
  dropped, no-new-privileges, an internal network, and no published host port; and
- callers cannot supply prompt text, checks, markers, route, mode, model, command, environment,
  image, endpoint, or provider configuration.

AI-002A registers immutable content-addressed image contracts in canonical Target, Worker, proxy
order. The Target role binds the fixed M03 profile, the Worker role binds
`pajin-worker:dev`, `ai.chat-probe@1.0.0`, and the `ai-chat-probe` command, and the proxy role binds
one exact internal HTTP JSON POST bridge with a required Target receipt and proxy-only Worker
attachment. These are image-contract identities, not fabricated OCI image IDs. Every role requires
a deployment-observed immutable image ID later while image build, observed-ID binding, caller
image selection, and runtime use remain false in AI-002A.

## Measurement protocol and canonical order

`AIMeasurementProtocol` registers six future operations in one exact order:

1. one source M03 operation;
2. Replay repetition 1;
3. Replay repetition 2;
4. Baseline Control;
5. Negative Control; and
6. Counterfactual Control.

Each operation requires a fresh Target, fresh session, and fresh action authorization. Source,
Replay, and Control runtime identities must be disjoint, the Worker must remain proxy-only, the
Target has no published host port, and a Target execution receipt is required. Cleanup and zero
residue are mandatory for every future Target lifecycle.

The protocol defines one request unit as one authorized single-turn M03 POST. Six registered
operations therefore establish the required protocol denominator of six request units and six
Tool calls, but they are not observed values. `common.total-request-units`,
`common.total-tool-calls`, and `common.total-cost-usd` remain measurement-required. In particular,
the deterministic local lab's zero external model-provider cost must be demonstrated by admitted
measurement evidence; it is not inferred as a default and is not marked N/A.

The fixed POST is the only application-protocol write that a later boundary may request. AI-002A
keeps `applicationProtocolWriteAuthorized=false`; each future POST still requires the existing
Capability, Campaign Scope, approval, one-use ActionPermit or bounded Grant, Gateway, Worker, proxy,
and Target-receipt path.

## Validation-floor policy

`AIValidationFloorPolicy` preserves all 14 exact DOMAIN-006 AI requirements. Twelve are required.
Two retain their registered not-applicable meaning:

- `common.task-success-rate`: `detection-recall-is-primary-outcome`; and
- `common.cleanup-success-rate`: `read-only-no-cleanup-required`.

The cleanup N/A value does not waive disposable Target cleanup or zero residue. Those are mandatory
admission requirements rather than a fabricated numeric action metric.

The registered ratio floors require full Ground Truth coverage, M03 recall and precision, two
supporting independent Replay repetitions, evidence completeness, policy-denial correctness, and
AI threat-class coverage. False-positive rate must be zero across the Negative Control and
Counterfactual denominators. The future denial set has eight minimum cases for scenario, prompt,
check, mode, image, route, Scope, and authority substitution. Time, request units, Tool calls, and
model-provider cost require measurement. The policy is registered but not evaluated or satisfied.

## Authority ceiling

All AI-002A runtime, scope-expansion, and projection authority remains false, including:

- Docker image build and observed image binding;
- Target selection or creation, network creation, and provider selection;
- prompt or Control materialization;
- Capability activation, approval, ActionPermit or Grant issuance, Gateway, Tool, and Worker
  execution;
- the fixed M03 application-protocol write and any model call;
- live measurement, accounting observation, metric evaluation, and floor satisfaction;
- product projection, Graph mutation, Finding authority, reporting, and external delivery;
- credential access, external provider or target access, and production targets;
- arbitrary prompts, Tools, plugins, M06, A04, RAG, MCP, and memory mutation; and
- caller-selected configuration, general AI scanning, and execution.

Ground Truth, a DOMAIN-006 plan, an image-contract digest, a predecessor requirement, or a future
passing metric never grants action authority or confirms an AI Observation.

## Verification

`tests/test_ai_measured_case_authority.py` verifies exact membership, unchanged AI-001D
predecessor requirements, private M03 prompt/check binding, actual code-owned Control
materializer order and expected contrast, public/private leakage boundaries, membership and
private-data substitution, canonical wire and strict boolean rejection, digest and nested-model
drift, fixed Target route and isolation, foreign image/profile rejection, caller-selected
configuration rejection, exact six-operation ordering, DOMAIN-006 applicability, accounting and
floor denominators, and every false runtime and projection marker.

## Related contracts and decisions

- [AI-001D fresh-session Replay, Controls, and benchmark binding](AI-001D-fresh-session-replay-controls-benchmark.md)
- [VAL-004A KISA Profile validation evidence](../orchestration/VAL-004A-kisa-profile-validation-evidence.md)
- [REDTEAM-002 initial Profile benchmark](REDTEAM-002-initial-profile-benchmark.md)
- [DOMAIN-006 domain-aware benchmark registry](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0259 Phase 25 selection](../adr/0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)
