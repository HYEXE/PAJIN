# VAL-004A: KISA Profile Validation Evidence

## Purpose

Evaluate whether already sealed KISA validity Replay and Validation Control evidence satisfies one
exact VAL-003 Profile assurance floor. The evaluator does not execute a Replay or Control, select a
Profile for a Campaign, mutate a Campaign, confirm a Finding, or add impact or severity assurance.

## API and state

The API version is `pajin.dev/profile-validation-evidence/v1alpha1`. The explicit module API is
`pajin.workflow.profile_evidence`.

`evaluate_kisa_profile_validation_evidence(...)` accepts:

- one exact Profile ID and version;
- one Candidate ID;
- the exact sealed KISA source Run path;
- one `KISAReplayBatchOutcome`; and
- an optional `KISAValidationControlBatchOutcome`.

It emits one content-addressed `ProfileValidationEvidenceAssessment` only when the verified evidence
reaches or exceeds the registered floor. The state is
`profile-floor-satisfied-not-confirmed`. `verify_kisa_profile_validation_evidence(...)` rebuilds the
assessment from all sealed predecessors and requires exact equality.
Content addressing normalizes typed set fields before canonical JSON encoding, so evidence identity
does not depend on process-specific set iteration order or a JSON round-trip.

## Replay evidence admission

The evaluator calls the existing KISA batch verifier and reloads the selected Claim result through
the existing replay ticket verifier. It accepts exactly one validity result for the requested
Candidate and requires:

- confirmation-purpose Replay with a successful `SUPPORTS` Oracle result;
- the exact Candidate, validity Claim, source Run and source root;
- the exact sealed Replay Run, final root, Artifact Set digest and receipt root;
- every compiled repetition to have succeeded;
- one distinct Replay request and fresh-session materialization per repetition;
- unique materialized session digests that differ from the source session;
- disjoint evidence references between repetitions; and
- the exact bounded Replay Capability Grant identity retained by the compiled specification.

The Replay executor owns one fresh, non-delegable bounded Grant for the Replay Run. Its one-to-twenty
attempts are the registered repetition units. VAL-004A does not mint or consume that Grant.

## Control evidence admission

For controlled floors, the evaluator reopens the exact sealed Control Run from its public record and
loads only these bounded artifacts:

- `run.json`;
- `control-plan.json`;
- `control-requests.json`;
- `control-attempts.json`;
- `control-receipts.json`;
- `control-reconciliation.json`; and
- `capabilities.json`.

The public Run/root/Plan/receipt/reconciliation identifiers, creation and completion events, and
artifact SHA-256 digests must exact-match. The Plan, attempts and receipts must retain canonical
Baseline, Negative Control and Counterfactual order. Every attempt must be successful, reproduce its
receipt exactly, and match its code-registered expected observation. Reconciliation must rebuild to
`contrast-observed`.

The evaluator also requires one revoked delegable root Capability and three distinct revoked,
non-delegable, consumed `maxCalls=1` child Capabilities. Each child must attenuate the root and bind
the exact request agent, Tool and target. The root must retain the exact source Campaign, Tool and
target, and its remaining-call accounting must reflect all three child executions.

## Replay and Control cross-binding

Replay and Control evidence must bind the same source Run/root, Candidate, validity Claim, scenario,
original request ID and original request digest. The existing registered KISA materializer is
resolved by exact ID, version, Mode, scenario, Tool and scenario digest, then rerun with the sealed
nonce. Its three generated argument sets, sessions and expected observations must equal the sealed
Plan and requests. Control IDs, request IDs, executor, Tool, target and method must also equal the
deterministic KISA compiler output and the original Replay semantics.

Replay and Control request IDs, Capability IDs, session digests and evidence references must be
disjoint. Source, Replay and Control sessions must also be distinct.

The evaluator exact-matches `ReplaySessionPolicy.FRESH_SESSION` against VAL-002's isolated Replay
session allowlist before reporting an achieved depth. A state-preserving Replay cannot satisfy a
Profile floor.

## Depth evaluation

| Verified evidence | Achieved VAL-002 depth |
| --- | --- |
| One or more supporting Replay repetitions, no Control set | `single-validity-replay` |
| One supporting Replay repetition and exact observed three-Control contrast | `controlled-validity-replay` |
| At least two supporting Replay repetitions and exact observed three-Control contrast | `repeated-controlled-validity-replay` |

The achieved registered requirement must have an ordinal greater than or equal to the exact Profile
floor. Higher evidence may satisfy a lower floor, but no caller-defined depth or floor is accepted.

## Authority ceiling

An emitted assessment fixes:

- `evidenceEvaluationPerformed=true`;
- `floorSatisfied=true`;
- `profileSelectionAttested=false`;
- `campaignMutationAuthorized=false`;
- `executionAuthorized=false`;
- `confirmationAuthorized=false`; and
- `findingConfirmed=false`.

The assessment is evidence-satisfaction authority only. It is not a Profile selection, Campaign
configuration, approval, Grant, Permit, dispatch instruction, Validation Decision, Finding, Report,
or confirmation basis by itself.

## Fail-closed boundaries

Evaluation or verification rejects unknown Profiles, missing or duplicate Candidates, non-validity
Claims, incomplete or non-supporting Replay outcomes, missing required Controls, insufficient
repetitions, stale or substituted source roots, cross-Claim Controls, materializer substitution,
request/session/Capability/evidence reuse, reordered Controls, non-observed contrast, forged
digests, non-boolean authority markers, changed artifacts and broken Run seals.

## Current limitations

VAL-004A supports only the existing KISA M03, M06 and A04 Claim Replay and Control materializers.
It does not combine VAL-001 WALK MCP Claim Replay with KISA Controls: those artifacts refer to
different Claims, requests and session semantics. A future VAL-004B adapter must provide an exact
Control materializer and explicit session/independence evidence for the WALK Claim before it can
satisfy the same floor.

All evidence remains PAJIN-local sealed-Run evidence. It is not off-host organizational or public
cryptographic attestation. The v1 Claim ceiling remains validity.

## Compatibility and rollback

The evaluator and explicit module API are additive. Existing Profile, Replay, Control, Campaign,
Validation Decision and Finding wires do not change. Rollback removes the VAL-004A module, tests,
contract and ADR-0150 without rewriting any sealed predecessor.

## Related documents

- [VAL-003 contract](VAL-003-profile-assurance-floor.md)
- [VAL-002 contract](VAL-002-validation-depth-policy.md)
- [ADR-0150](../adr/0150-evaluate-kisa-profile-floors-from-sealed-evidence.md)
- [ADR-0032](../adr/0032-fresh-capability-validation-controls.md)
- [ADR-0033](../adr/0033-registered-validation-control-materializers.md)
