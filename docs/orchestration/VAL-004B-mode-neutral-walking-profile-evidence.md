# VAL-004B: Mode-neutral WALK Profile Validation Evidence

## Purpose

Evaluate a VAL-001 WALK MCP validity Claim against an exact VAL-003 Profile floor without mixing it
with KISA-specific Control evidence. VAL-004B adds a code-owned stateless Control materializer, a
sealed three-Control evidence authority, and a Profile-floor evaluator. It does not select a
Profile, mutate a Campaign, dispatch a Tool, confirm a Finding, or add impact or severity assurance.

## API and state

The Control API version is `pajin.dev/mode-neutral-claim-control/v1alpha1`. The Profile assessment
API version is `pajin.dev/mode-neutral-profile-validation-evidence/v1alpha1`. Both use the explicit
module API `pajin.workflow.mode_neutral_profile_evidence` to avoid eager package import cycles.

`compile_mode_neutral_claim_control_plan(...)` accepts one self-validating VAL-001 authority and
emits a content-addressed `ModeNeutralClaimControlPlan` in state `planned-not-authorized`.
`ModeNeutralClaimControlRunner` accepts only separately executed `WalkingExecutionEvidence`; it does
not own a dispatcher. `load_mode_neutral_claim_control_authority(...)` reopens the publication and
all three execution Runs before returning the authority.

`evaluate_mode_neutral_profile_validation_evidence(...)` re-verifies the exact VAL-001 Chain and
WALK-005B2 Replay predecessors, optionally reloads one Control authority, and emits
`ModeNeutralProfileValidationEvidenceAssessment` only when the derived registered depth reaches the
exact Profile floor. `verify_mode_neutral_profile_validation_evidence(...)` rebuilds and exact-matches
that assessment from the sealed predecessors.

## Stateless Control materialization

VAL-001 currently binds the registered WALK MCP text Tool, whose request schema contains exactly one
`text` argument and no session field. VAL-004B records `sessionPolicy=stateless`; it does not invent a
session identifier. The deterministic materializer derives these Controls from the exact source
request:

| Control | Request condition | Required observation |
| --- | --- | --- |
| Baseline | exact source text | vulnerable, authorization not enforced, internal data accessed |
| Negative Control | exact source text with a registered absent-content canary oracle | canary remains absent from the otherwise exact source observation |
| Counterfactual | registered benign text | not vulnerable, no internal data access, no hijacking pattern |

The Plan fixes the exact request ID, executor, Tool, target, method, arguments, request digest,
condition, observation oracle and expected output for each canonical Control. Baseline and Negative
Control content must equal the source observation, while the nonce-derived Negative canary must be
absent. The Counterfactual must contain no MCP content. Server, remote Tool and target identities
must equal the source observation. The Negative Control changes the observation oracle, not target
authorization state; VAL-004B does not claim authority over target configuration.

## Execution admission

Every Control must already have completed through the existing WALK execution boundary with:

- one exact independent operator approval;
- one non-delegable `maxCalls=1` Capability Grant for the Campaign, Tool and target;
- one consumed ActionPermit bound to the exact request and registered WALK Capability;
- one successful Policy, Gateway, dispatch-audit and Worker lifecycle; and
- one sealed Tool evidence artifact with `networkLogTrusted=false`.

In addition to the existing WALK approval receipt, the execution Run must contain exactly one
`walking.claim-control-plan.approved` receipt for the Plan and Control before the dispatch claim.
This prevents an unrelated completed execution from being relabelled as a planned Control after the
fact.

## Session and independence evidence

The Control authority enumerates source, Replay, Baseline, Negative Control and Counterfactual
coordinates. All five must have distinct:

- execution Run IDs and roots;
- execution digests;
- request IDs;
- Capability Grant IDs;
- Permit IDs;
- approval IDs;
- Worker execution IDs; and
- Run-qualified evidence references.

All five requests must retain the exact stateless text schema. The three copied Control evidence
artifacts are sealed again in the Control publication Run and must byte-match their source execution
artifacts. The publication Run must differ from all execution Runs.

## Depth evaluation

VAL-001 contains one fresh WALK-005B2 validity Replay. Therefore VAL-004B can derive only:

| Verified evidence | Achieved VAL-002 depth |
| --- | --- |
| VAL-001 without Controls | `single-validity-replay` |
| VAL-001 plus the exact observed three-Control contrast | `controlled-validity-replay` |

This lets the current WALK evidence satisfy the `ctf`, `bug-hunt` and `pentest` floors. It cannot
satisfy `ai-assessment`, which requires `repeated-controlled-validity-replay` and at least two fresh
Replay repetitions. VAL-004B rejects that floor instead of treating Control executions as Replay
repetitions.

## Authority ceiling

The Plan, Control authority and Profile assessment fix Profile selection, Campaign mutation,
additional execution, confirmation and Finding authority to false. The Control authority is
`informationalOnly=true`; the assessment records only that verified evidence reached one registered
floor. None of these artifacts is an approval, Grant, Permit, dispatch instruction, Validation
Decision, Finding, Report or confirmation basis by itself.

## Fail-closed boundaries

Compilation, execution admission, loading or evaluation rejects unsupported Chains, non-validity or
cross-Claim evidence, KISA Control substitution, changed materialization, session-shaped requests,
missing pre-dispatch Plan approval, Capability substitution, reused source/Replay/Control lineage,
unexpected output flags or content, changed copied artifacts, broken Run seals, forged digests,
non-boolean authority markers, unknown Profiles and insufficient floors.

## Current limitations

VAL-004B supports only VAL-001 CHAIN-002 and CHAIN-005 because they share the exact WALK-003 and
WALK-005B2 predecessor. It supports only the registered stateless MCP text schema. A second fresh
Replay authority does not exist yet, so mode-neutral repeated-controlled evidence remains a future
VAL-004C slice. All evidence remains PAJIN-local sealed-Run evidence, not off-host organizational or
public cryptographic attestation. The v1 Claim ceiling remains validity.

## Compatibility and rollback

The module, wires and documentation are additive. Existing VAL-001, KISA VAL-004A, Campaign,
Profile, Replay, Control, Validation Decision and Finding wires do not change. Rollback removes the
VAL-004B module, tests, contract and ADR-0151 without rewriting sealed predecessors.

## Related documents

- [VAL-004A contract](VAL-004A-kisa-profile-validation-evidence.md)
- [VAL-003 contract](VAL-003-profile-assurance-floor.md)
- [VAL-002 contract](VAL-002-validation-depth-policy.md)
- [VAL-001 contract](VAL-001-mode-neutral-claim-replay.md)
- [ADR-0151](../adr/0151-bind-stateless-walking-controls-to-val001.md)
- [ADR-0147](../adr/0147-bind-mode-neutral-claim-replay-to-sealed-walking-evidence.md)
- [ADR-0032](../adr/0032-fresh-capability-validation-controls.md)
