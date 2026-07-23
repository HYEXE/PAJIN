# ADR 0032: Fresh-capability validation Control execution boundary

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement B2.2 first vertical slice

## Context

B2.1 separates the Candidate-aware Validator from the Blind Evidence Reviewer, but both roles only
review already collected evidence. Letting either role execute the Baseline, Negative Control, and
Counterfactual would add offensive Tool authority to a review role. Reusing a session or Capability
would also make state contamination and authority mixing difficult to distinguish. Treating Control
results as independent reproduction would bypass the existing `needs-review` to `confirmed`
boundary.

## Decision

1. The first vertical slice supports only the KISA M03 `validity` Atomic Claim.
2. `pajin kisa-run --validation-controls` re-verifies the sealed source Run and its existing
   Candidate and Decision, then creates a separate Control Run. The ordinary Validator and Blind
   Reviewer receive no Tool authority.
3. Baseline, Negative Control, and Counterfactual each use a unique request and fresh session. The
   Control Executor delegates a new non-delegable child Capability with `max_calls=1` for every
   execution and revokes it immediately afterwards.
4. Baseline preserves the catalog M03 attack input and sentinel check. Negative Control uses the
   same input with a per-execution absent canary. Counterfactual uses a benign `READY` input and
   checks that the original sentinel is absent.
5. Each execution records separate Gateway evidence, a `ValidationControlAttempt`, and a
   `ValidationControlReceipt`. The Receipt binds request and result digests, Capability grant, and
   evidence paths, and claims only the `pajin-local-sealed-run` attestation scope.
6. A deterministic `ClaimControlReconciliation` records the expected `true/false/false` pattern as
   `contrast-observed`, a different fully observed pattern as `contrast-not-observed`, and a missing
   valid observation as `inconclusive`.
7. Every Plan, Receipt, and Reconciliation has `informationalOnly=true` and
   `confirmationEligible=false`. Candidate disposition, severity, and confirmation basis do not
   change. Only the existing Restricted Reproducer and receipt-verifying Gate can confirm.
8. When Replay runs first after the source, Controls continue using the same in-memory Campaign
   budget and rate-limit ledger. A counter below the source state or a different ledger identity is
   rejected.

## Consequences

- Review-model judgment remains separate from new offensive execution authority.
- Each Control has independently auditable request, session, Capability, evidence, and Receipt
  lineage.
- Control results provide useful contrast signals without bypassing product confirmation.
- The flow is opt-in, so existing `kisa-run` calls do not add network requests.

## Limits and follow-up

- The slice decided by this ADR supports one M03 check and one attempt per Control. The M06/A04
  and registered-materializer extension was subsequently accepted in
  [ADR 0033](0033-registered-validation-control-materializers.en.md).
- It uses a local Run seal and Docker proxy receipts; it is not portable or off-host independent
  attestation.
- Independent severity derivation, Provider/model diversity, and public claim-level validation
  states remain follow-up work.
