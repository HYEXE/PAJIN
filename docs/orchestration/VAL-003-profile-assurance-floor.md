# VAL-003: Profile Assurance Floor

## Purpose

Bind every exact PROF-001 Campaign Profile to a minimum registered VAL-002 Validation depth without
selecting the Profile for a Campaign, evaluating evidence, authorizing execution, or confirming a
Finding.

## API and policy identity

The floor API is `pajin.dev/profile-assurance-floor/v1alpha1`; the complete policy API is
`pajin.dev/profile-assurance-floor-policy/v1alpha1`. The sole policy identity is
`val-003:profile-assurance-floor` version `1.0.0`.

The policy embeds the complete `campaign-profile-catalog:common-engine-v1` authority and
`val-002:validation-depth-policy` authority with their exact digests. Either predecessor catalog
must equal its current code-owned registration. A standalone structurally valid Profile or depth
requirement cannot enter the mapping.

## Registered minimum floors

| Profile | Purpose and reporting basis | Minimum Validation depth |
| --- | --- | --- |
| `pajin.profile.ai-assessment` | AI threat assessment and threat-class coverage | `repeated-controlled-validity-replay` |
| `pajin.profile.bug-hunt` | program submission draft and program-scope Finding | `controlled-validity-replay` |
| `pajin.profile.ctf` | fixed-lab result and fixed-lab ground truth | `single-validity-replay` |
| `pajin.profile.pentest` | technical assessment and authorized-target assessment | `controlled-validity-replay` |

These are minimum requirement identities. A higher registered VAL-002 depth is acceptable. The
helper `validation_depth_requirement_meets_profile_floor()` compares only code-owned depth ordinals;
it does not inspect or accept evidence and cannot claim that a Campaign reached the offered depth.

## Floor binding

Each `ProfileAssuranceFloor` preserves:

- the exact Profile ID, version, digest, and complete `RegisteredCampaignProfile`;
- the exact minimum `ValidationDepth`, ordinal, requirement digest, and complete
  `ValidationDepthRequirement`;
- `floorRegistered=true` and `higherDepthRequirementAcceptable=true`; and
- a content-addressed floor ID and digest.

The policy preserves the complete four-floor set in canonical PROF-001 order and content-addresses
both predecessor catalogs, every floor, the order, mode constraint, and authority markers.

## Mode neutrality and authority ceiling

`campaignModeConstraint=none`. VAL-003 does not accept or retain a Campaign, source Mode, target,
Scope, risk, budget, Capability, Claim Replay, Control receipt, Validation Decision, Finding, or
Report.

Every floor and the policy fix these markers to false:

- `profileSelectionAuthorized`;
- `campaignMutationAuthorized`;
- `evidenceEvaluationAuthorized`;
- `executionAuthorized`;
- `confirmationAuthorized`; and
- `findingConfirmed`.

Resolving a floor is not Profile selection. A Profile remains a non-executable semantic record, and
its floor remains an unsatisfied minimum until a separate evidence authority proves otherwise.

## Resolution and fail-closed behavior

`registered_profile_assurance_floor_policy()` returns the complete exact mapping.
`resolve_profile_assurance_floor(profileId, profileVersion)` accepts only an exact PROF-001 Profile
version. There is no `latest`, alias, partial identifier, Mode fallback, or caller-defined floor.

Parsing and resolution reject:

- unknown Profile IDs or versions;
- changed Profile purpose, reporting, benchmark, operating controls, Profile digest, or catalog;
- a substituted or stale VAL-002 policy or requirement;
- reordered, duplicated, missing, weakened, or widened floors;
- mismatched floor Profile, depth, ordinal, requirement, or digest;
- forged floor or policy identity and digest;
- string or integer coercion of security-relevant boolean markers; and
- any Profile-selection, Campaign-mutation, evidence, execution, confirmation, or Finding marker
  set true.

## Compatibility and rollback

The policy, resolver, ordinal comparison, and workflow exports are additive. Existing PROF-001,
PROF-002, VAL-002, Campaign, Replay, Control, Validation Decision, and Finding artifacts keep their
wire meanings. Rollback removes the VAL-003 additions without rewriting predecessor catalogs.

## Current limitations

VAL-003 inherits the VAL-002 validity-only ceiling. It does not bind impact or severity assurance,
select a Profile for a Campaign, or prove that Replay and Control evidence satisfy the floor. The
CTF floor relies on registered fixed-lab/flag-validator semantics as policy rationale, not proof
that a live validator or ground truth exists. Higher-depth comparison is ordinal only.

VAL-004 must admit exact Baseline, Negative Control, Counterfactual, and N-run Replay evidence and
determine whether it satisfies one resolved floor without creating new execution authority.

## Related documents

- [VAL-002 contract](VAL-002-validation-depth-policy.md)
- [PROF-001 contract](PROF-001-campaign-profile-authority.md)
- [ADR-0149](../adr/0149-bind-profile-assurance-floors-without-campaign-selection.md)
- [ADR-0102](../adr/0102-separate-profile-semantics-from-campaign-compilation.md)
