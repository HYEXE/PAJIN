# ADR-0148: Register Validation Depth Requirements without Evidence Authority

- Status: Accepted
- Date: 2026-08-10

## Context

VAL-001 can bind one exact validity Claim to a sealed fresh Replay, but it deliberately cannot
infer controls, repeated reproduction, confirmation, or a Profile-specific assurance level. PAJIN
also already has information-only Baseline, Negative Control, and Counterfactual contracts and a
KISA Replay repetition bound of one through twenty. A new Validation depth model must coordinate
those existing meanings without duplicating their execution or evidence-verification authority.

VAL-003 will assign Profile-specific assurance floors, and VAL-004 will bind actual Control and
repeated-Replay evidence. Performing either operation in VAL-002 would make a requirement catalog
look like proof that its requirements were satisfied.

## Decision

1. Register one immutable, mode-neutral `ValidationDepthPolicy` with three ordered requirements:
   `single-validity-replay`, `controlled-validity-replay`, and
   `repeated-controlled-validity-replay`.
2. Keep the v1 Claim ceiling at `validity`. Existing generic Control reconciliation is validity-only,
   so impact or severity requirements remain unsupported instead of being inferred.
3. Require `REPRODUCED`, fresh execution lineage, a fresh session per Replay, a fresh Capability and
   distinct request per execution, and exact evidence lineage at every depth.
4. The controlled depths additionally require the exact ordered Baseline, Negative Control, and
   Counterfactual set, at least one execution of each, and `contrast-observed`.
5. The repeated controlled depth requires at least two Replay repetitions. The policy retains the
   existing maximum of twenty but does not schedule or execute any repetition.
6. Content-address every requirement and the complete ordered policy. Exact resolution accepts no
   aliases, `latest` lookup, or caller-defined requirement.
7. Fix Profile-floor binding, evidence evaluation, execution, confirmation, and Finding authority
   to false. The policy states prerequisites only; it cannot attest that any prerequisite exists.

## Consequences

- VAL-003 can reference stable depth identities without rewriting Validation or Replay semantics.
- VAL-004 can build evidence satisfaction against explicit minimums while reusing existing Replay
  and Control authorities.
- Reordering, weakening, widening Claim types, omitting Controls, reducing repetitions, changing a
  digest, or escalating a boolean authority marker fails closed.
- A higher depth never upgrades VAL-001 evidence by declaration. Until a separate verifier binds
  actual evidence, every depth remains an unsatisfied policy requirement.
- Local fresh-execution lineage is not cryptographic proof of a separate off-host organization.

## Rejected alternatives

### Map Campaign Profiles in VAL-002

Rejected because Profile-specific assurance floors are the distinct VAL-003 authority and require
the exact PROF-001 catalog.

### Evaluate VAL-001 or Control artifacts in the policy resolver

Rejected because resolution would then mix a code-owned requirement lookup with mutable evidence
admission and could imply confirmation.

### Add impact and severity depths structurally

Rejected because current generic Controls reconcile one validity Claim only. Claim names cannot
substitute for independent impact or severity Replay evidence.

### Create a new Replay or Control executor

Rejected because existing WALK/KISA Replay and Validation Control boundaries already own fresh
execution, Capability, request, receipt, and evidence lineage.

## Compatibility and rollback

The change is additive. Existing Claim, Replay, Control, Validation Decision, Profile, and Finding
artifacts keep their meanings and wire formats. Rollback removes the policy module, public exports,
tests, contract, and this ADR without changing any sealed Run or Profile catalog.

## Related documents

- [VAL-002 contract](../orchestration/VAL-002-validation-depth-policy.md)
- [VAL-001 contract](../orchestration/VAL-001-mode-neutral-claim-replay.md)
- [PROF-001 contract](../orchestration/PROF-001-campaign-profile-authority.md)
- [ADR-0032](0032-fresh-capability-validation-controls.md)
- [ADR-0147](0147-bind-mode-neutral-claim-replay-to-sealed-walking-evidence.md)
