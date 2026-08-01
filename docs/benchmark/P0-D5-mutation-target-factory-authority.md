# P0-D5 Mutation Target Factory Authority

## Status

Implemented as a non-runnable `v1alpha1` authority for one seeded Traditional Web/API mutation.
No provider materializer, reset receipt, execution authority, or measurement admission is added.

## Goal and trust boundary

The BENCH-001 Manifest already has `mutationProfileId`, and Target registrations already contain a
mutation allowlist. Those fields identify a choice but do not define mutation semantics, bind an
ordered state transition, or prove that the provider restored the base state before applying a
mutation.

P0-D5 keeps the existing P0-D1 registration and its empty mutation allowlist unchanged. It first
reconstructs the exact unmutated Traditional Web/API selection. A separate Mutation registration
then binds a code-owned profile, an exact derived Manifest, and a declared reset plan. The boundary
cannot call a provider or claim that any reset or mutation occurred.

## Versioned authorities

| Authority | API version | Role |
| --- | --- | --- |
| `MutationTargetOperation` | `pajin.dev/mutation-target-operation/v1alpha1` | One ordered, content-addressed base-state transition |
| `MutationTargetProfile` | `pajin.dev/mutation-target-profile/v1alpha1` | Mutation Factory identity, base registration, seed, states, and exact operation chain |
| `MutationTargetRegistration` | `pajin.dev/mutation-target-registration/v1alpha1` | Public registration above the unchanged base catalog |
| `MutationResetPlanAuthority` | `pajin.dev/mutation-reset-plan/v1alpha1` | Declared base reset and expected mutation provenance, explicitly without a receipt |
| `MutationTargetSelectionAuthority` | `pajin.dev/mutation-target-selection/v1alpha1` | Non-runnable binding of base selection, derived Manifest, registration, and reset plan |

Every authority uses bounded canonical JSON and a separate digest domain. Supplied digests and IDs
must match recomputation.

## Registered baseline

The first profile preserves the synthetic Boolean-SQLi Finding while changing only the seeded
account layout. It uses one public deterministic mutation seed and three exact operations:

1. restore the base snapshot;
2. apply the seeded account layout; and
3. verify the expected state.

Each operation binds its input and output state digests. Adjacent operations must form one state
chain. The complete profile is bound to the exact P0-D1 active registration digest.

## Invariants

1. The base Manifest has no mutation and must reconstruct through the existing P0-D1 catalog
   selector, adapter, Docker profile, and private Ground Truth.
2. The base registration remains the code-owned one with an empty `mutationProfileIds` tuple. P0-D5
   does not silently promote the existing provider catalog.
3. The derived Manifest differs from the base Manifest only at `mutationProfileId`, whose value is
   the registered profile ID.
4. The public Manifest derivation helper requires and revalidates the exact base registration; it
   cannot apply a profile to a foreign base Manifest.
5. Mutation seed, base state, expected state, operation IDs, order, and state chain must equal the
   code registration.
6. The reset plan binds both Manifest digests, base registration, mutation profile, benchmark seeds,
   mutation seed, state digests, and all ordered operation digests.
7. The reset plan remains `declared-not-applied` and `resetReceiptBound=false`.
8. Provider execution, measurement admission, and mutation materialization are literal `false`.

## Threat model and negative boundaries

- **Unregistered mutation:** unknown IDs and changed profile semantics fail exact derivation.
- **Base Target replay:** alternate image/profile registrations change the base registration digest
  and fail before mutation selection.
- **Scope expansion:** additional base catalog registrations and changes to Campaign, Ground Truth,
  profile, Factory, protocol, or any other Manifest field fail closed.
- **Order or seed substitution:** reordered operations, broken state chains, changed seeds, and state
  digest substitution cannot reconstruct the code-owned profile.
- **False reset provenance:** the authority contains no provider receipt and cannot set
  `resetReceiptBound` to true.
- **Execution escalation:** no adapter wrapper, materializer, capability, operation journal entry, or
  measurement authority is created.

## Audit and benchmark impact

The audit artifact is `MutationTargetSelectionAuthority`. It preserves the exact base selection and
both Manifest digests plus the mutation registration and complete declared reset plan.

No metric changes in P0-D5. A future runnable slice must add reset evidence that proves the observed
base state, mutation materialization evidence that proves the expected state, cleanup/recovery, and
registry-governed measurement admission.

## Compatibility, migration, and rollback

The implementation is additive. BENCH-001, P0-D1 catalogs, existing Manifest readers, provider
adapters, lifecycle receipts, and measurement artifacts retain their wire shape and meaning. The
new construction path is opt-in.

Rollback removes the new authorities and stops deriving mutation Manifests. The P0-D1 catalog
continues to reject every mutation because its allowlist remains empty. Historical mutation
authorities cannot be interpreted as provider receipts because their API versions, kinds, flags,
and digest domains are distinct.

## Verification

Positive tests cover exact Manifest derivation, unchanged base allowlist, ordered state chaining,
reset-plan binding, and fixed false authority flags. Adversarial tests cover seed and state changes,
operation reorder and chain break, unknown mutation IDs, Manifest scope expansion, cross-profile
replay, base catalog expansion, registration substitution, already-mutated base replay, forged
authority flags, false receipt claims, and forged digests.
