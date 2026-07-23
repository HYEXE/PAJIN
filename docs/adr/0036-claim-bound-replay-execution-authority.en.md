# ADR 0036: Claim-Bound Replay Execution Authority and KISA Oracles

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement B2.5 first vertical slice
- Extends: [ADR 0030](0030-candidate-aware-atomic-claim-validation.en.md),
  [ADR 0035](0035-claim-replay-public-state-projection.en.md)

## Context

ADR 0035 projected an existing Candidate Replay onto the exact `validity` Atomic Claim, but the
execution authority itself remained Candidate-wide. `impact` and `severity` therefore had no
separate execution contracts or Oracles, and the system could not prove that different Claims did
not share the same compiled authority or receipt.

Copying one validity result to three Claims would let the executed assertion diverge from the
published assertion. Conversely, allowing impact or severity support to confirm the whole Candidate
would weaken the existing independent-reproduction Gate.

## Decision

1. Repeat an exact `ReplayClaimBinding` through `ValidationPacket`, `ReplayIntent`,
   `ModeReplayContract`, `ReplayBinding`, `ReplayCapabilityGrant`, `CompiledReplaySpec`, Oracle,
   and Outcome lineage. The binding contains Candidate Claim digest plus Claim ID, digest, type,
   and statement.
2. The Compiler and loader verify that the Claim exactly matches the Candidate's deterministic
   Atomic Claim set. Missing Claims, substituted types, statements, or digests, and Contract/Packet
   disagreement fail closed.
3. The KISA M03, M06, and A04 confirmation coordinator executes `validity`, `impact`, and
   `severity` in separate Replay Runs for every Candidate. Each Claim receives its own compiled
   authority, at-most-five-minute non-delegable Grant, single-use ticket, fresh session, evidence,
   Oracle result, and receipt.
4. KISA impact statements and severity are fixed Mode-owned policy. Impact supports only the
   scenario-specific allowlisted statement, and severity currently supports only `high`. The
   Oracle compares the compiled Claim with this policy and recomputes the catalog check from the
   same raw transcript. Arbitrary Provider prose cannot obtain execution authority.
5. `claim-replays.json` records all three Claim assessments separately. Projection fails if exact
   Claim coverage is incomplete or a receipt is substituted across Claims.
6. Preserve existing confirmation authority. Only the `validity` Replay drives the internal
   `ValidationDecision` and `VERIFIED_INDEPENDENT_REPLAY` Gate. Impact and severity assessments are
   information-only public projections with `independent_execution_attested=false`; they cannot
   confirm a Candidate or Finding or mutate severity by themselves.
7. Existing Candidate-bound callers may continue reading and executing legacy contracts without a
   Claim. Only the new KISA confirmation path uses explicit Claim contracts.

## Budget and Result

- The three-scenario, one-target, two-repetition example reserves 6 source calls and 18 Claim
  Replay calls.
- Enabling Validation Controls adds 9 information-only calls, for 33 total.
- The Candidate-keyed validity view in `verified_results` remains for compatibility, while
  `confirmation_results` passes all Claim receipts to the Gate.

## Authority Boundary

Fresh execution per Claim makes the executed assertion and its authority explicit, but impact or
severity support is not whole-product confirmation. Public `confirmed` is created only when the
existing validity-based independent-reproduction invariant passes. Terminal failure, cancellation,
timeout, target unavailability, and Oracle indecision remain `inconclusive`, never contradiction.

## Limitations and Follow-ups

- This first vertical slice is limited to exact KISA M03, M06, and A04 plus Mode-owned impact and
  severity policy.
- A reproduced `high` severity is catalog policy, not calibration, a Gold Dataset, multi-Reviewer
  consensus, or Human agreement.
- Negative retest conservatively retains the existing Candidate/validity boundary.
- Control Plane public projection and portable/off-host attestation do not yet carry the full
  Claim-specific execution authority.
- Local seals and receipts prove lineage and content consistency, not cryptographically attested
  execution by a separate organization or infrastructure.

## Verification Requirements

- Claim ID, digest, type, and statement must remain unchanged from Packet through Grant, Spec,
  Oracle, and Outcome.
- A Claim absent from the Candidate, a receipt for another Claim, or a partial Claim projection
  must be rejected.
- Every KISA Candidate must give validity, impact, and severity distinct Replay Runs and fresh
  sessions.
- Impact or severity support alone must not create a confirmed Finding or confirmation basis.
- Legacy Candidate-bound Replay and sealed projections must remain readable.
