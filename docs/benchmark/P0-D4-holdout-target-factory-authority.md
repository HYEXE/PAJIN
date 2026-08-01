# P0-D4 Holdout Target Factory Authority

## Status

Implemented as a non-runnable `v1alpha1` authority for the first Traditional Web/API holdout
profile. This contract does not provision a Holdout Target or admit benchmark measurements.

## Goal and trust boundary

P0-D4 separates the identity and private evaluation material of a Holdout Target Factory from the
registered active Target. A caller must prove the exact existing Traditional Web/API catalog,
Manifest, adapter, provider profile, and seeded Ground Truth before it can bind a Holdout profile.
The Holdout case, matcher identity, and evaluation seed remain inside a private suite and private
binding. Public-safe artifacts contain only domain-separated commitments.

The boundary protects against benchmark overfitting and accidental disclosure. It does not make
repository source code a secret store and does not authorize provider calls, measurements, or
publication of private suite contents.

## Versioned authorities

| Authority | API version | Visibility and purpose |
| --- | --- | --- |
| `HoldoutTargetFactoryProfile` | `pajin.dev/holdout-target-factory-profile/v1alpha1` | Public-safe identity of a separate non-runnable factory, bound to one active registration digest |
| `HoldoutTargetPrivateSuite` | `pajin.dev/holdout-target-private-suite/v1alpha1` | Private Holdout Ground Truth and evaluation seeds |
| `HoldoutTargetRegistration` | `pajin.dev/holdout-target-registration/v1alpha1` | Public commitment to the profile, private suite, and Ground Truth digests |
| `HoldoutTargetPrivateBinding` | `pajin.dev/holdout-target-private-binding/v1alpha1` | Private exact registration-to-suite binding |
| `HoldoutTargetSelectionAuthority` | `pajin.dev/holdout-target-selection/v1alpha1` | Public-safe active-to-holdout selection with all execution and disclosure flags false |

Every authority uses bounded canonical JSON and a distinct digest domain. Supplied IDs or digests
must exactly match recomputation.

## Invariants

1. The active side is reconstructed through `select_traditional_web_api_target_profile`; a
   caller-provided selection digest is never trusted by itself.
2. Active Ground Truth contains only `seeded` cases. The private suite contains only `holdout`
   cases and uses the separate Holdout Factory digest.
3. Active and Holdout Ground Truth IDs, Finding IDs, matcher IDs, and matcher digests are disjoint.
4. Holdout evaluation seeds are canonical and cannot overlap the public active protocol seeds.
5. The Holdout profile is bound to exactly one active registration. Cross-profile or cross-image
   replay changes the active registration digest and fails selection.
6. The public profile, registration, and selection do not contain Ground Truth cases, matcher IDs,
   matcher digests, Finding IDs, or evaluation seeds.
7. `providerExecutionAuthorized`, `measurementAdmissionEligible`, and
   `holdoutContentDisclosureAuthorized` are literal `false`.
8. The first registration contains exactly one code-owned private suite. Additional cases, matcher
   substitutions, seed substitutions, active catalog expansion, and private-binding substitution
   fail closed.

## Threat model and negative boundaries

- **Public artifact or log disclosure:** callers publish the registration or selection, not the
  private suite or binding. Public types do not have private-content fields.
- **Active/holdout replay:** separate Factory digests, visibility values, identities, and seed sets
  prevent either side from being reinterpreted as the other.
- **Catalog scope expansion:** active selection is re-run against the exact code-owned one-entry
  catalog before Holdout binding.
- **Commitment forgery:** every nested authority is structurally reconstructed and every supplied
  content digest is recomputed.
- **Execution escalation:** this slice provides no adapter, provider, runner, capability, or
  measurement admission path.

The commitment digests provide integrity and exact binding, not confidentiality against guessing.
A future external Holdout service must keep high-entropy private material outside the repository and
return only signed commitments and bounded adjudication results.

## Audit and benchmark impact

The audit artifact for this slice is `HoldoutTargetSelectionAuthority`. It binds the active
Manifest, catalog, active selection and registration, Holdout profile and registration, and private
binding digest. It deliberately cannot be used to reconstruct private content.

No benchmark metric changes in P0-D4. Measurement admission remains false until a later slice adds
an isolated provider, private evaluator, signed result projection, and leakage-safe audit policy.

## Compatibility, migration, and rollback

The implementation is additive. It does not change the BENCH-001 Manifest or Ground Truth wire
shape, the existing Target catalogs, provider adapters, or measurement readers. Existing public
imports keep their behavior; new imports are exported from `pajin.benchmark`.

Adoption is opt-in by constructing the new Holdout authorities. Rollback stops constructing them
and removes the module and exports. Historical active Target artifacts remain valid and cannot be
reinterpreted as Holdout artifacts because API versions and digest domains differ.

## Verification

Positive tests cover deterministic registration, private binding, public-safe serialization, and
non-runnable authority flags. Adversarial tests cover case and matcher substitution, seeded-case
replay, active-seed reuse, active catalog expansion, cross-profile replay, binding substitution,
forged flags, and forged content digests.

## Successor boundary

A runnable Holdout provider remains future work. It must introduce a private evaluator boundary,
signed adjudication projection, access-controlled storage and logging, isolated one-time seeds, and
cleanup/recovery evidence without exposing suite contents to either benchmark arm.
