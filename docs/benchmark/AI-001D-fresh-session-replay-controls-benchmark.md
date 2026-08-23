# AI-001D: Fresh-session Replay, Controls, and Benchmark Contract

- Status: Implemented, bounded composition
- Binding: `pajin.dev/ai-analysis-replay-benchmark-binding/v1alpha1`
- Decision: [ADR-0219](../adr/0219-bind-ai-replay-controls-and-benchmark-without-action-authority.md)
- Predecessors: [AI-001C](../graph/AI-001C-cross-surface-observation-evidence-admission.md),
  [VAL-004A](../orchestration/VAL-004A-kisa-profile-validation-evidence.md),
  [REDTEAM-002](REDTEAM-002-initial-profile-benchmark.md), and
  [DOMAIN-006](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)

## Purpose

AI-001D binds one exact AI-001C admitted M03, M06, or A04 Observation to independently sealed
KISA validation evidence and the matching REDTEAM-002 benchmark contract. It reuses the existing
KISA source, fresh-session Replay, three-Control evaluator, Profile-floor evaluator, REDTEAM
Capability denominator, and DOMAIN-006 AI plan. It does not introduce an AI executor, Replay
compiler, Control runner, benchmark recorder, or Graph writer.

The result is one content-addressed projection. It proves that an independently authorized KISA
validation lane evaluated the same provider target, Tool, scenario, threat class, turns, and checks
as the AI-001C source while using disjoint source, Replay, and Control sessions and requests. It
does not claim that the KISA Candidate is the AI Graph Observation or that either artifact confirms
the other.

## Sealed AI source revalidation

`bind_ai_analysis_replay_controls_and_benchmark` reopens the AI-001C source Run and requires:

- the exact AI-001B preparation, REDTEAM job, consumed ActionPermit, reservation, Tool/Worker
  evidence, terminal dispatch event, reconciliation, and Run root;
- the exact admitted Graph event already stored for the candidate proposal and digest; and
- equality of the admission's source Run, root, artifact paths and hashes, preparation, terminal
  event, and reconciliation with the reopened source.

AI-001C's ActionPermit remains consumed provenance. Its Graph membership does not approve or
dispatch the KISA lane.

## Fresh-session Replay and independent Controls

The binding invokes the existing VAL-004A evaluator over a separately sealed KISA source and
requires the registered `pajin.profile.ai-assessment@1.0.0` floor. That evaluator reopens:

- two successful confirmation-purpose Replay repetitions;
- the fresh-session KISA materializer, bounded Replay Capability, Oracle, receipts, and disjoint
  evidence lineage; and
- the canonical Baseline, Negative Control, and Counterfactual executions with three separate
  child Capabilities, requests, sessions, receipts, and observed contrast.

AI-001D additionally compares the AI-001C request with the KISA source semantics. Provider target,
method, Tool, scenario, threat class, turns, and checks must match exactly. Only the session is
allowed to differ. The admitted AI source session, KISA source session, every Replay session, and
every Control session must all be unique; all corresponding request identities must also be
disjoint.

The independent VAL-004A evidence satisfies its own Profile floor. The projection keeps
`aiObservationConfirmed=false`: semantic equivalence does not transfer Candidate, Claim,
confirmation, or Finding authority to the AI-001C Graph Observation.

## AI benchmark contract extension

The binding reconstructs the complete code-owned REDTEAM-002 profile set from the exact existing
Tool and CAP-002 inventory. It selects the profile and Capability already fixed by AI-001B and
requires:

- exact REDTEAM profile, Capability, CAP-003 benchmark mapping, request-unit cost, and CAP-006
  Replay support;
- `required` negative-control and Replay applicability for the selected M03, M06, or A04
  Capability;
- the KISA Replay contract ID to be one of the selected Capability's registered contracts; and
- the exact DOMAIN-006 AI `fresh-session-independent-replay` plan.

The projection binds the REDTEAM `known-positive` and `negative-control` vocabulary and coverage
requirements, not a concrete Ground Truth case. It fixes `groundTruthCaseBound=false` and
`benchmarkMeasurementObserved=false`. Producing a measured result still requires separately
sealed REDTEAM raw observations, policy-denial coverage, truthful cost and request accounting, and
the existing REDTEAM-002 aggregate runner.

## Required rejection behavior

The implementation fails closed for:

- altered, foreign, unsealed, unsuccessful, or mismatched AI source/admission artifacts;
- missing, altered, single-repetition, non-supporting, non-fresh, or cross-Candidate Replay;
- missing, reordered, altered, non-observed, or cross-Claim Controls;
- scenario, threat class, target, method, Tool, turn, check, Profile, Capability, benchmark mapping,
  Replay contract, Domain plan, or strategy substitution;
- reused source, Replay, or Control session and request identities;
- treating MCP metadata as KISA Replay support; and
- boolean coercion or attempts to enable benchmark measurement, confirmation, Finding, Scope,
  Capability activation, approval, Permit, Tool/Worker selection, network, credential, Replay, or
  execution authority.

## Compatibility and rollback

AI-001D is additive. It changes no AI-001A/B/C, KISA, VAL-004A, REDTEAM-002, DOMAIN-006, Profile,
Capability, ActionPermit, Graph, Worker, Replay, Control, benchmark, validation, Finding, or sealed
artifact wire identity. Rollback stops producing the projection and removes its module, tests,
contract, and ADR while preserving every source Run and Graph event.

## Remaining work

- MCP has no registered KISA Replay or three-Control path and is rejected by this binding.
- The projection is direct-call and does not schedule, execute, or expose Replay or Controls.
- No concrete AI Ground Truth case or numeric benchmark measurement is produced by AI-001D.
- No AI Observation is confirmed and no Finding, retest, report delivery, production score,
  arbitrary provider/agent support, or general AI discovery runtime is implemented.
