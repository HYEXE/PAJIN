# ADR-0149: Bind Profile Assurance Floors without Campaign Selection

- Status: Accepted
- Date: 2026-08-10

## Context

PROF-001 defines four exact operating Profiles but intentionally carries no Campaign selection or
execution authority. VAL-002 defines three ordered, validity-only evidence requirement depths but
intentionally maps no Profile. VAL-003 must connect these catalogs so a later evidence gate can
know the minimum requirement for one exact Profile without claiming that a Campaign selected the
Profile or that any evidence satisfies the requirement.

The floor is a product-policy choice, not a value inferred from labels at runtime. The four current
Profiles have distinct reporting and benchmark semantics: AI Assessment covers stochastic threat
classes, Bug Hunt prepares program submissions, CTF evaluates fixed-lab ground truth with a flag
validator, and Pentest produces an authorized technical assessment with remediation reporting.

## Decision

1. Register one immutable `ProfileAssuranceFloorPolicy` that embeds and exact-verifies the complete
   PROF-001 Profile catalog and VAL-002 Validation depth policy.
2. Register these minimum floors in canonical PROF-001 order:
   - AI Assessment: `repeated-controlled-validity-replay`;
   - Bug Hunt: `controlled-validity-replay`;
   - CTF: `single-validity-replay`; and
   - Pentest: `controlled-validity-replay`.
3. Bind each floor to the complete registered Profile, Profile digest, exact minimum depth,
   ordinal, full requirement, and requirement digest. Content-address each floor and the complete
   ordered policy.
4. Treat the mapping as minimums. A higher registered VAL-002 requirement is acceptable, but this
   ordinal comparison evaluates requirement identities only and never evidence.
5. Keep the policy mode-neutral and accept no Campaign, source Mode, Claim Replay, Control receipt,
   Validation Decision, Finding, or Report.
6. Fix Profile selection, Campaign mutation, evidence evaluation, execution, confirmation, and
   Finding authority to false.

## Rationale for current floors

- AI Assessment receives the repeated controlled floor because its `ai-threat-assessment` and
  `threat-class-coverage` semantics operate over stochastic model behavior and its registered
  controls already require Claim validation and independent Replay.
- Bug Hunt receives the controlled floor because a `program-submission-draft` and
  `program-scope-finding` should require the full contrast before external program review. The
  minimum does not prevent a later policy from requiring repetition.
- CTF receives the single floor because its registered fixed-lab and flag-validator controls define
  a deterministic objective. The Profile does not itself prove a flag validator or ground truth
  exists; the floor only states the minimum requirement when that Profile is selected elsewhere.
- Pentest receives the controlled floor because an authorized technical assessment and remediation
  report need Baseline, Negative Control, and Counterfactual contrast. Repetition remains optional
  above the minimum.

## Consequences

- VAL-004 can resolve an exact minimum without reinterpreting Profile labels or weakening depth
  requirements.
- Unknown Profile versions, standalone Profile substitution, cross-catalog substitution, floor
  reordering, weakened or widened floors, forged digests, and authority-marker escalation fail
  closed.
- Resolving a floor does not choose a Profile for a Campaign. Comparing two registered depth
  ordinals does not attest that either depth has evidence.
- The v1 floor catalog inherits VAL-002's validity-only ceiling. Impact and severity assurance are
  not implied by a Profile's reporting semantics.

## Rejected alternatives

### Derive floors dynamically from Profile strings

Rejected because labels such as `remediation-report` or `flag-validator` are semantic metadata, not
stable executable evidence policy.

### Bind a floor directly to Campaign Mode

Rejected because PROF-001 is deliberately separate from legacy Mode compatibility and Campaign
selection. PROF-002 remains the owner of legacy Mode projection.

### Evaluate evidence while resolving a floor

Rejected because VAL-004 is the separate evidence-admission boundary. A floor resolver must not
turn policy lookup into confirmation.

### Require the highest depth for every Profile

Rejected because a minimum floor should preserve the fixed-lab CTF distinction and allow higher
registered requirements without making them mandatory for every product workflow.

## Compatibility and rollback

The change is additive. Existing Profile, legacy compatibility, Validation depth, Replay, Control,
Campaign, and Finding wires remain unchanged. Rollback removes the VAL-003 policy, resolver,
comparison helper, exports, tests, contract, and this ADR without changing either predecessor
catalog.

## Related documents

- [VAL-003 contract](../orchestration/VAL-003-profile-assurance-floor.md)
- [VAL-002 contract](../orchestration/VAL-002-validation-depth-policy.md)
- [PROF-001 contract](../orchestration/PROF-001-campaign-profile-authority.md)
- [ADR-0102](0102-separate-profile-semantics-from-campaign-compilation.md)
- [ADR-0148](0148-register-validation-depth-requirements-without-evidence-authority.md)
