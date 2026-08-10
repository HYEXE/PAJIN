# VAL-002: Validation Depth Policy

## Purpose

Define exact, mode-neutral minimum evidence requirements for Validation depth without evaluating
evidence, selecting a Campaign Profile floor, executing a Replay or Control, confirming a Finding,
or changing any predecessor artifact.

## API and policy identity

The API version is `pajin.dev/validation-depth-policy/v1alpha1`. The sole registered policy is
`val-002:validation-depth-policy` version `1.0.0`. Its digest covers the complete ordered requirement
set, Claim ceiling, repetition ceiling, mode constraint, and false authority markers.

`campaignModeConstraint=none`. No Campaign, source Mode, Profile, Claim Replay, Control receipt,
Validation Decision, or Finding is accepted as policy input.

## Registered depths

| Depth | Ordinal | Required Claims | Minimum Replay repetitions | Required Controls | Minimum executions per Control | Required contrast |
| --- | ---: | --- | ---: | --- | ---: | --- |
| `single-validity-replay` | 1 | `validity` | 1 | none | 0 | none |
| `controlled-validity-replay` | 2 | `validity` | 1 | Baseline, Negative Control, Counterfactual | 1 | `contrast-observed` |
| `repeated-controlled-validity-replay` | 3 | `validity` | 2 | Baseline, Negative Control, Counterfactual | 1 | `contrast-observed` |

All depths require `ClaimReplayStatus.REPRODUCED`, `fresh-execution-lineage`, an isolated Replay
session policy, a fresh Capability and distinct request per execution, and exact evidence lineage.
The exact `allowedReplaySessionPolicies` are `fresh-session` and `stateless`. A fresh-session Replay
must prove a distinct materialized session for each repetition; a stateless Replay must prove that
its registered request schema and every admitted request contain no session argument. The
state-preserving `preserve-scenario-session` policy cannot satisfy VAL-002. Replay repetitions remain
bounded by the existing maximum of twenty.

The v1 Claim ceiling is intentionally `validity`. Impact and severity remain information-only until
their own independent Replay and Control evidence requirements are implemented.

## Authority ceiling

Every requirement has:

- `policyOnly=true`;
- `evidenceEvaluationAuthorized=false`;
- `executionAuthorized=false`;
- `confirmationAuthorized=false`; and
- `findingConfirmed=false`.

The policy also fixes `profileAssuranceFloorBound=false`. A registered depth is a prerequisite
description, not evidence that a Campaign reached that depth. It is not a Replay Plan, ticket,
approval, Grant, Permit, dispatch, Control Plan, receipt, Validation Decision, Finding, or Report.

## Resolution and canonicalization

`registered_validation_depth_policy()` returns the complete exact catalog.
`resolve_validation_depth_requirement(depth)` accepts only one registered enum value or its exact
wire string. It does not accept aliases, `latest`, partial identifiers, caller-defined requirements,
or version fallback.

Each requirement digest covers its depth, ordinal, Claim and Replay prerequisites, exact allowed
session-isolation policies, Control set, minimum counts, independence scope, and authority markers.
The policy digest covers all requirements in canonical order. A standalone structurally valid
requirement cannot replace a code-owned catalog entry.

## Fail-closed boundaries

Parsing or resolution rejects:

- unknown, aliased, reordered, duplicated, or omitted depths;
- an ordinal or minimum repetition change;
- impact or severity Claim substitution;
- a partial, reordered, or extra Control set;
- a missing `contrast-observed` requirement on a controlled depth;
- a missing, reordered, widened, or state-preserving Replay session policy;
- a forged requirement or policy digest;
- string or integer coercion of security-relevant boolean markers; and
- any Profile-floor, evidence-evaluation, execution, confirmation, or Finding marker set true.

## Compatibility and rollback

The policy and resolver are additive public APIs. They do not alter existing VAL-001, KISA Replay,
Validation Control, PROF-001, Validation Decision, or Finding wires. Rollback removes the module,
exports, tests, this contract, and ADR-0148 without rewriting sealed evidence.

## Current limitations

VAL-002 does not bind a Profile to a floor and does not determine whether real evidence satisfies a
depth. It supports only validity requirements. The repeated controlled depth defines a minimum of
two Replay repetitions but does not schedule them or aggregate their outcomes. Fresh local lineage
is not off-host organizational attestation.

VAL-003 must bind exact PROF-001 Profiles to an assurance floor without granting Campaign or
execution authority. VAL-004 must separately verify actual Baseline, Negative Control,
Counterfactual, and repeated Replay evidence.

## Related documents

- [VAL-001 contract](VAL-001-mode-neutral-claim-replay.md)
- [PROF-001 contract](PROF-001-campaign-profile-authority.md)
- [ADR-0148](../adr/0148-register-validation-depth-requirements-without-evidence-authority.md)
- [ADR-0032](../adr/0032-fresh-capability-validation-controls.md)
