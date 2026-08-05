# SUP-005B1: Sealed Benchmark Campaign and Request Context

- Status: Implemented
- Plan contract: `pajin.dev/supervisor-benchmark-campaign-plan/v1alpha1`
- Request-context contract: `pajin.dev/supervisor-benchmark-request-context/v1alpha1`
- Context-bound B3 intent and receipt: `v1alpha2`
- Runtime boundary: `invoke_supervisor_benchmark_candidate()`
- Decision: [ADR-0125](../adr/0125-bind-benchmark-coordinates-into-supervisor-provider-requests.md)

## Scope

SUP-005B1 creates the first exact model-backed candidate coordinate boundary without inventing a
numeric measurement. It reopens the sealed SUP-005A predecessor source, uses only its original
single-arm structural Manifest, and derives a fresh two-arm Manifest. The baseline arm is exact;
the candidate arm configuration digest is a static implementation authority over the SUP-001
model binding, registered SUP-003 compiler, SUP-004 dedicated budget, and request/response schema
identities. Per-coordinate Snapshot, schedule, Plan, request, receipt, and proposal identities are
not part of that static arm configuration.

The Plan contains the complete baseline/candidate Cartesian coordinate set and exactly one current
SUP-004A schedule for every candidate seed/repetition. It copies no predecessor numeric Result or
Comparison. The predecessor's `maxModelCalls=0` protocol is replaced by a new measured protocol
whose per-coordinate ceiling is one model call; both arms must be measured again under this new
Manifest in SUP-005B2.

## Plan authority

`SupervisorBenchmarkCampaignPlan` binds:

- the complete `CampaignManifest` and its detached digest;
- the exact sealed BENCH-003B2 source Run, root, artifact SHA-256, authority, structural authority,
  and original one-arm Manifest;
- the static candidate implementation and its content digest;
- the derived two-arm Manifest and complete canonical arm/seed/repetition coordinate tuple;
- the coordinate-set digest; and
- a one-to-one ordered mapping from every candidate coordinate to one independently verified,
  sealed SUP-004A schedule publication.

Schedule Run, checkpoint, schedule, request-binding, and source-Snapshot identities must be unique.
All schedules must use the same exact model binding, Provider/model/configuration lineage, schema,
compiler, and dedicated budget. The candidate schedule count cannot exceed that budget's model-call
ceiling.

The Plan state is `sealed-complete-set-not-dispatch-authority`. It does not claim that no earlier
dispatch exists and fixes `preDispatchBindingProven=false`. A Plan may therefore be useful as a
non-executable mapping even when created later, but only the invocation boundary below can prove
that its exact publication preceded one Provider dispatch.

## Typed request context and actual ToolRequest binding

Before calling B3, `invoke_supervisor_benchmark_candidate()` reloads the exact Plan and all live
sources. It creates one `SupervisorBenchmarkRequestContext` containing the Plan API/kind/ID/digest,
sealed Plan Run/root/path/SHA-256, Manifest and coordinate-set digests, exact coordinate, and exact
schedule publication.

The B3 journal stores this complete typed object in a `v1alpha2` invocation intent before
`begin_dispatch()`. Its context digest is part of the domain-separated stable request ID. The same
ID reaches the actual Gateway `ToolRequest.request_id`, request reservation, Provider outcome,
evidence, and receipt. The `v1alpha2` receipt also stores the exact context object. There is no raw
64-hex context input: the generic invoker accepts only the registered typed benchmark context.

The context model is an explicit caller assertion, not a standalone sealed-Plan authority. A
generic B3 caller can record such an assertion, but that receipt is not a SUP-005B candidate. Only
the benchmark wrapper and public candidate verifier upgrade it by reloading the exact Plan
envelope, Campaign, BENCH-003B2 source, every SUP-004A schedule source, and then exact-matching the
reconstructed context.

After dispatch, the wrapper requires the exact `SupervisorCheckpointInvoker`, independently calls
the existing `consume_supervisor_invocation()` reader, reconstructs the context and stable request,
and requires the Plan seal time to precede dispatch. A directly constructed candidate wrapper or
duck-typed invoker cannot replace the journal, two-seal Run, receipt, or content-free SUP-003
proposal authority.

## Compatibility

Context-free B3 callers retain the exact `v1alpha1` intent, `v1alpha1` receipt, stable-request v1
preimage, and omitted `requestContext` field. Context-bound benchmark calls use explicit
`v1alpha2` intent and receipt versions. Existing SUP-004A schedule, database columns, Provider,
Gateway, ToolRequest, SUP-003 proposal, Benchmark Result/Comparison, Harness, and Target wires are
unchanged. The journal stores the new typed context inside its existing canonical-intent record, so
no SQLite migration is required.

## Negative boundaries

Creation, invocation, and re-consumption fail closed for:

- missing, duplicate, extra, or reordered coordinates or candidate schedules;
- foreign Manifest, Campaign, arm, implementation, model binding, Provider/model/configuration,
  compiler, schema, budget, Snapshot, schedule, or sealed publication;
- reused checkpoint, schedule, request binding, source Snapshot, or schedule Run across candidate
  coordinates;
- caller-supplied aggregates or reuse of the predecessor's baseline-only numeric Results;
- post-hoc invocation through a legacy context-free intent;
- cross-Plan, cross-coordinate, foreign-context, or exact-checkpoint context equivocation;
- a fake invoker, forged completion, non-terminal journal, unsealed receipt, proposal substitution,
  or Plan seal after dispatch; and
- boolean coercion or any attempt to claim comparison, causal proposal effect, threshold,
  execution, or activation authority.

## Completed successor boundary

SUP-005B1 proves request lineage, not benchmark effectiveness. The model-visible Snapshot is still
untrusted, and no Finding, Chain, Replay, Policy, Human, time, call-count, or cost value is inferred
from a proposal or rationale. SUP-005B2 now uses the existing registry-governed Target/Harness and
external measurement attestation to bind one exact in-window B3 completion per candidate
coordinate, remeasure both arms, and then call the existing BENCH-003B1 Result and Comparison
authority. Threshold evaluation and activation remain false. See the
[SUP-005B2 contract](SUP-005B2-registry-governed-model-backed-comparison.md).
