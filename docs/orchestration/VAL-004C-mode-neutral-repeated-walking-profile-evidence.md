# VAL-004C: Mode-neutral Repeated WALK Profile Validation Evidence

## Purpose

Bind two exact sealed WALK-005B2 validity Replays and the VAL-004B three-Control authority to the
registered VAL-002 `repeated-controlled-validity-replay` requirement. VAL-004C evaluates evidence;
it does not plan or dispatch another execution, select a Profile, mutate a Campaign, confirm a
Finding, or add impact or severity assurance.

## API and state

The repeated Claim Replay API version is
`pajin.dev/mode-neutral-repeated-claim-replay/v1alpha1`. The Profile assessment API version is
`pajin.dev/mode-neutral-repeated-profile-validation-evidence/v1alpha1`. Both are exposed through the
explicit module `pajin.workflow.mode_neutral_repeated_profile_evidence`.

`compile_mode_neutral_repeated_claim_replay(...)` verifies one existing VAL-001 authority against
its primary WALK-005B2 outcome, compiles a second VAL-001 authority from the same exact Chain and an
additional sealed WALK-005B2 outcome, and emits a content-addressed
`ModeNeutralRepeatedClaimReplayAuthority`.

`verify_mode_neutral_repeated_claim_replay(...)` rebuilds that authority from both sealed Replay
predecessors. `evaluate_mode_neutral_repeated_profile_validation_evidence(...)` additionally reloads
the exact VAL-004B Control authority and emits
`ModeNeutralRepeatedProfileValidationEvidenceAssessment` only when the complete evidence reaches
the registered Profile floor. The corresponding verifier rebuilds and exact-matches the assessment.

## Plan and Replay ownership

Both repetitions must retain one exact `WalkingMCPReplayPlan`. WALK-005B1 is deterministic and
`planned-not-authorized`; it fixes Claim and request semantics but contains no reusable approval,
Grant, Permit or dispatch authority. Each WALK-005B2 authority must therefore still prove its own:

- pre-dispatch Plan approval receipt;
- fresh request and independent operator approval;
- non-delegable single-call Capability Grant;
- consumed request-bound ActionPermit and dispatch;
- successful Gateway and Worker lifecycle;
- sealed execution evidence; and
- distinct WALK-005B2 publication Run.

VAL-004C never invokes these boundaries. It accepts only completed outcomes that the existing
WALK-005B2 loader and VAL-001 compiler can reopen and verify.

## Repeated Replay independence

The repeated authority fixes the first Replay as index `0`, the Control anchor used by VAL-004B.
The second Replay must retain the same Campaign, Chain, validity Claim, source execution, complete
WALK-005B1 Plan and exact stateless request arguments.

The source and two Replay executions must have pairwise-distinct:

- execution Run IDs and roots;
- execution digests;
- request IDs;
- Capability Grant IDs;
- Permit and dispatch IDs;
- approval IDs;
- Worker execution IDs; and
- Run-qualified evidence references.

The two Replay publications must also have distinct Run IDs, roots, artifact references and WALK
authority digests. Reusing the primary outcome as the second repetition fails closed.

## Stateless session boundary

The source and both Replays must use the exact one-field `text` schema, contain no session argument
and retain byte-equivalent argument values. VAL-004C records `sessionPolicy=stateless` and requires
that policy to appear in the registered VAL-002 allowlist. It never creates a synthetic session or
accepts `preserve-scenario-session`.

## Control composition and depth evaluation

VAL-004C accepts only the exact VAL-004B Control authority anchored to Replay index `0`. The Control
set must remain ordered Baseline, Negative Control and Counterfactual with one execution per kind and
`contrast-observed`.

The complete assessment enumerates six execution lineages in this order:

1. source execution;
2. primary Replay;
3. additional Replay;
4. Baseline;
5. Negative Control; and
6. Counterfactual.

Every Run/root, execution, request, Grant, Permit, dispatch, approval, Worker and evidence coordinate
must be unique across all six. This is the boundary that prevents a Control execution from being
counted as the additional Replay.

Exactly two Replays plus the exact observed three-Control contrast satisfy
`repeated-controlled-validity-replay`. The evaluator then compares that depth ordinal with the exact
VAL-003 Profile floor. The current evidence can satisfy `ai-assessment`; lower floors can also be
satisfied by the stronger registered depth.

## Authority ceiling

The repeated authority and Profile assessment fix Profile selection, Campaign mutation, additional
execution, additional Replay, confirmation and Finding authority to false. They are evidence
projections, not an approval, Grant, Permit, dispatch instruction, Validation Decision, Finding,
Report or remediation result.

## Fail-closed boundaries

Compilation or evaluation rejects a changed Chain, Campaign, Claim, source execution or Plan;
reused or reordered Replay predecessors; changed stateless arguments; a session-shaped request;
duplicate execution or publication lineage; a Control authority anchored to another VAL-001 Replay;
changed Control order or contrast; a forged requirement, digest or authority marker; an unknown
Profile; or a floor above the registered repeated-controlled depth.

## Current limitations

VAL-004C supports only the VAL-001 CHAIN-002 and CHAIN-005 WALK path and its registered stateless MCP
text schema. It proves repeated validity reproduction and the existing three-Control contrast only.
It does not prove impact, severity, full Finding confirmation, remediation, Profile selection or
Campaign mutation. All evidence remains PAJIN-local sealed-Run evidence, not off-host organizational
or public cryptographic attestation.

## Compatibility and rollback

The module, wires and documentation are additive. Existing VAL-001, VAL-004A, VAL-004B, Campaign,
Profile, Replay, Control, Validation Decision and Finding wires do not change. Rollback removes the
VAL-004C module, tests, contract and ADR-0152 without rewriting sealed predecessors.

## Related documents

- [VAL-004B contract](VAL-004B-mode-neutral-walking-profile-evidence.md)
- [VAL-003 contract](VAL-003-profile-assurance-floor.md)
- [VAL-002 contract](VAL-002-validation-depth-policy.md)
- [VAL-001 contract](VAL-001-mode-neutral-claim-replay.md)
- [WALK-005B2 contract](WALK-005B2-plan-bound-mcp-claim-replay.md)
- [ADR-0152](../adr/0152-bind-repeated-walking-replays-without-new-execution-authority.md)
- [ADR-0151](../adr/0151-bind-stateless-walking-controls-to-val001.md)
