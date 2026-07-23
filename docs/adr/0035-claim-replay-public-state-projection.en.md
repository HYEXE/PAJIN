# ADR 0035: Claim Replay Lineage and Public Partial-Validation States

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement B2.4 first vertical slice
- Extends: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md),
  [ADR 0030](0030-candidate-aware-atomic-claim-validation.en.md)

## Context

Restricted Replay binds a Candidate, original request, Mode, Scenario, Tool, Target, Threat, and
fresh execution evidence, but the final Validation Decision has one Candidate-wide disposition.
Consumers therefore could not distinguish successful validity reproduction from failure of the
full Finding confirmation invariant. An explicit Mode Oracle contradiction also appeared under the
same internal disposition used for an objective-gate rejection.

Adding values directly to `FindingDisposition` would simultaneously change the confirmation Gate,
Control Plane canonical-decision validation, KISA retest baselines, and interpretation of historical
sealed Runs. Treating execution failure as non-reproduction would also misrepresent target
unavailability, timeouts, and cancellation as negative evidence.

## Decision

1. Project each existing Candidate-bound confirmation Replay onto the Candidate's exact `validity`
   Atomic Claim.
2. `ClaimReplayAssessment` binds Candidate and Claim IDs and digests, Replay Run, Outcome, Oracle,
   requests, evidence, assessment time, and independent-execution attestation into a canonical
   assessment ID.
3. Seal assessment sets in a separate `validation/v1alpha1/claim-replays.json` artifact.
4. New `VersionedValidationIndex` projections expose a fixed `claimReplaysPath` and a
   `publicStates` map that covers every Candidate exactly once. Historical v1alpha1 projections
   without both fields remain readable.
5. Keep public states separate from internal `FindingDisposition`.
   - `confirmed`: the existing independent-execution confirmation invariant passed.
   - `partially-confirmed`: a typed Oracle reproduced the validity Claim, but the full confirmation
     invariant did not pass.
   - `not-reproduced`: a successful typed Oracle explicitly contradicted the exact validity Claim.
   - `inconclusive`: execution failed, was cancelled, timed out, could not reach the target, or the
     Oracle could not decide.
   - Otherwise preserve existing `needs-review` and `rejected-objective` meaning.
6. Neither `partially-confirmed` nor `not-reproduced` enters `confirmed_findings` or canonical
   `findings.json`.
7. The loader revalidates the exact validity Claim, Decision replay lineage, attestation, Gate
   reason, public state, and seal inclusion, failing closed on substitution.
8. The Markdown projection shows internal disposition, public state, Claim ID, and Claim replay
   status, and states that `partially-confirmed` is not product confirmation.

## Authority Boundary

This change does not weaken existing `confirmed` authority. Claim support alone cannot create
`ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY`; internal Decisions and Control Plane canonical Gate
validation remain unchanged. `not-reproduced` also requires both a threshold-bound contradiction
from a successful ReplayOutcome and its corresponding Gate reason, never a terminal miss.

## Migration

Historical sealed `validation/v1alpha1` projections remain immutable. When an index has neither
`claimReplaysPath` nor `publicStates`, the loader treats it as a legacy replay-evidence projection
and uses internal dispositions for the legacy public view. New projections must create both fields
and `claim-replays.json` together. A partial artifact, seal, or lineage is rejected.

## Limitations and Follow-ups

- The first vertical slice supports validity Claims only. Separate impact and severity execution
  contracts and Oracles do not exist yet.
- This projects an existing Candidate replay onto its validity Claim. Fully Claim-by-Claim Replay
  with separate compiled execution authority per Claim remains follow-up work.
- Local seals and receipts prove lineage and content consistency, not portable off-host execution
  by a separately attested organization or infrastructure.
- Human overturn, Gold Datasets, calibration, and multi-Reviewer consensus remain follow-up scope.

## Verification Requirements

- Substituting Claim or Candidate digests, Replay Run or Outcome, requests, or evidence lineage must
  fail.
- Typed Oracle support must project to `partially-confirmed`; explicit contradiction must project
  to `not-reproduced`.
- Failed, cancelled, timed-out, target-unavailable, and Oracle-inconclusive results must be
  `inconclusive`, never `not-reproduced`.
- Public-state substitution and partial artifacts or seals must fail closed.
- Historical v1alpha1 projections must remain readable without the new artifact.
- The new public states alone must never create a confirmed Finding.
