# AI-002C: Independent Fresh-Session Replay, Controls, and AI Floor

- Status: implementation and deterministic in-process conformance complete; real-Docker
  conformance not yet established
- Public evaluation API: `pajin.dev/ai-replay-floor-evaluation/v1alpha1`
- Private binding API: `pajin.dev/ai-private-replay-evaluation-binding/v1alpha1`
- Operation preparation API: `pajin.dev/ai-measurement-operation-preparation/v1alpha1`
- Implementation:
  `src/pajin/workflow/ai_replay_evaluation.py`,
  `src/pajin/capabilities/ai_analysis.py`,
  `src/pajin/target_attestation.py`, and
  `containers/ai-target/target.py`
- Decision:
  [ADR-0259](../adr/0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)

## Purpose and fixed operation set

AI-002C evaluates the exact AI-002A M03 validation floor from one completed AI-002B source and
five independently authorized follow-up executions. The canonical membership and order are the
source, supporting Replay repetitions one and two, Baseline, Negative Control, and
Counterfactual. No caller can add, remove, reorder, or replace an operation, prompt, check,
session, Target, provider, image, route, model, or runtime setting.

The runner first contextfully reopens the AI-002B public and private source, its sealed AI-001C
execution, observed images, Target receipt, cleanup, and zero-residue state. It then reconstructs
the two Replay probes and three Controls from the AI-002A private Ground Truth and existing KISA
materializer. Each follow-up receives a fresh Target attempt, Target network, Run, request,
session, Decision, approval, one-use ActionPermit, bounded Grant, Gateway dispatch, Worker,
proxy-only topology, signed Target receipt, sealed Evidence, and cleanup lifecycle.

AI-002C does not reinterpret AI-001D or VAL-004A evidence as measurement. Those contracts retain
their existing semantic identities. It executes a new measured set whose operation identity is
fixed by AI-002A.

## Additive operation preparation

The existing AI-001B CAP-002 source materializer continues to accept only the exact catalog
probe. AI-002C does not widen or replace it. Instead,
`AIMeasurementOperationPreparation` binds one runner-materialized AI-002A operation to the current
signed M03 Capability release, existing ActionCapability, provider/model binding, request and
normalized-parameter digests, and exact operation digest, key, ordinal, and stage.

This preparation is `prepared-measurement-operation-not-authorized`. It cannot issue an approval
or Permit, materialize a Worker job, dispatch the Gateway, or execute the request. The normal
Campaign Scope, deployment approval, one-use Permit, bounded Grant, Gateway, Worker, and Target
receipt path remains mandatory. The AI-001C Graph candidate builder explicitly rejects this
measurement preparation, so successful measurement Evidence cannot become a new Graph
Observation through the existing admission API.

## Independent execution identity

The private binding records one `AIMeasurementExecutionIdentity` for each of the six operations.
It covers the execution Run and root, request and session, Mission Envelope, Proposal, Decision,
approval and consumption receipt, Permit, dispatch, Grant, Worker execution, request reservation,
execution Evidence, terminal and reconciliation records, challenge, Target receipt, Target
attempt/container/network, and Worker/proxy/internal-network identities.

All dynamic values must be pairwise disjoint across source, Replay, and Control operations. The
fixed Target, Worker, and proxy image identities are common immutable contract inputs, not
ephemeral execution identities. Reusing an execution context, session, request, approval,
Permit, Grant, Evidence digest, Target lifecycle, or runtime resource fails before an evaluation
can be sealed.

## Exact Replay and Control meaning

Replay repetitions preserve the exact M03 prompt and sensitive response check while replacing the
session with a fresh code-owned identity. Baseline preserves the same prompt and check and must
observe the sentinel. Negative Control preserves the prompt but replaces the check with the
materializer-owned absent canary and must not observe it. Counterfactual replaces the prompt with
the registered benign variant, preserves the sensitive sentinel check, and must not observe it.

The required public states are therefore:

1. `known-positive-observed`;
2. `supporting-replay-observed`;
3. `supporting-replay-observed`;
4. `baseline-control-observed`;
5. `negative-control-not-observed`; and
6. `counterfactual-control-not-observed`.

The negative and counterfactual states are contrast evidence only. They do not establish general
model safety, service quality, prompt secrecy, or a Finding.

## Exact DOMAIN-006 evaluation

The public evaluation preserves the exact DOMAIN-006 AI metric order and applicability:

| Metric | AI-002C observation |
| --- | --- |
| `common.ground-truth-coverage` | `1/1` |
| `common.detection-recall` | `1/1` |
| `common.task-success-rate` | N/A: `detection-recall-is-primary-outcome` |
| `common.false-positive-rate` | `0/2` |
| `common.detection-precision` | `4/4` |
| `common.replay-or-reanalysis-success-rate` | `2/2` |
| `common.time-to-first-valid-result` | first Replay Worker duration in microseconds over `1,000,000` |
| `common.total-request-units` | `6/1` |
| `common.total-tool-calls` | `6/1` |
| `common.total-cost-usd` | `0/1,000,000` USD |
| `common.evidence-completeness` | `84/84` |
| `common.policy-denial-correctness` | `8/8` |
| `common.cleanup-success-rate` | N/A: `read-only-no-cleanup-required` |
| `ai.threat-class-coverage` | `1/1` |

Request units and Tool calls are summed from six reopened sealed Gateway/Worker executions. Zero
cost is admitted only after each execution's provider registration is rebound to the exact
zero-priced deterministic local provider; it is not inferred from a default and is not N/A.
Evidence completeness is fourteen registered evidence categories across six executions. The
eight policy denials remain AI-002B pre-dispatch substitutions and are not benchmark Controls.

The registered cleanup metric stays N/A because the action is read-only, but every Target,
Worker, proxy, and ephemeral network must still be absent after its operation. Cleanup and zero
residue are mandatory evaluation admission facts.

## Public and private custody

`AIReplayFloorEvaluation` contains only AI-002A authority, protocol, floor, image, and AI-002B
source references; six public operation lineages and private commitments; fourteen aggregate
metric observations; completion markers; and literal false authority markers. It contains no
prompt, check value, Control derivation, request, session, transcript, raw response, approval or
Permit body, trust anchor, Worker result, Target coordinate, Docker identity, or private Ground
Truth object.

`AIPrivateReplayEvaluationBinding` is sealed separately. It retains the exact private Ground
Truth, source private measurement, five follow-up probes and outputs, operation derivations,
approval receipts, challenges, Target and proxy receipts, Worker/Tool Evidence, accounting,
cleanup, and all six execution identities. A public digest commitment is not disclosure
authority.

Contextful reload reparses both canonical wires, reopens the source and all five sealed follow-up
Runs with their exact private Tool adapters, rebuilds every measurement and aggregate, reinspects
images, verifies unique Run paths and global identity disjointness, and requires zero managed
Docker residue. Unknown fields, Boolean coercion, collection reordering, operation or metric
substitution, digest drift, hidden instance state, and public/private leakage fail closed.

## Authority ceiling

The completed evaluation grants no authority for:

- image build, provider selection, or caller-selected prompt, check, session, image, model,
  endpoint, route, provider, or runtime configuration;
- another Target, network, approval, Permit, Grant, Gateway, Worker, Tool call, model call, or
  application-protocol write;
- Graph admission or mutation, Observation confirmation, Finding authority, product projection,
  reporting, or external delivery;
- credentials, external providers or targets, or production targets;
- arbitrary prompts or Tools, plugins, RAG, MCP, memory mutation, M06, or A04; or
- general model, agent, or AI scanning.

The sealed source, passing Replay, Control contrast, perfect synthetic floor, and signed Target
receipts remain historical Evidence. None authorizes an additional action.

## Verification status

Deterministic tests cover the complete six-operation in-process path, canonical ordering, exact
Control contrast, contextful reopen, all fourteen metrics, request/Tool/cost accounting, global
identity disjointness, strict Worker and Target measurement headers and receipts, public/private
leakage, false authority, operation/metric/digest/context substitution, foreign image/profile,
caller-selected configuration, cleanup, and residue rejection.

In-process execution is not Phase 25 exit evidence. AI-002D must run the source, two Replay
repetitions, three Controls, denials, floor, product read, fresh-process reload, cleanup, and
unconditional residue audit from one exact clean commit on Ubuntu with real Docker.

## Compatibility and rollback

AI-002C is additive. It changes no AI-001A through AI-001D, KISA, VAL-004A, REDTEAM, DOMAIN-006,
AI-002A/B, generic benchmark, Walking, Graph/Finding, Tool request/result, Gateway, Worker,
Replay challenge, or existing Target response wire identity. Existing AI-001B preparation retains
its exact catalog-only meaning. The new operation preparation and measurement challenge are
accepted only through explicit AI-002C exact-type paths.

Rollback stops constructing the AI-002C runner and removes its additive preparation, execution
adapters, reader, and contract. Previously sealed evaluations remain historical synthetic
measurement Evidence and must not be treated as product, confirmation, Finding, report, delivery,
or execution authority.

## Related contracts

- [AI-002A measured-case authority](AI-002A-exact-m03-measured-case-authority.md)
- [AI-002B disposable source measurement](AI-002B-registry-governed-disposable-m03-source-measurement.md)
- [AI-001D fresh-session Replay and Controls](AI-001D-fresh-session-replay-controls-benchmark.md)
- [DOMAIN-006 domain-aware validation](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
