# ADR 0033: Registered validation Control materializers

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement B2.2 M03, M06, and A04 expansion

## Context

The first ADR 0032 slice transformed the M03 request directly inside the coordinator. Continuing to
add scenario branches there would make it difficult to determine from the Plan which transformation
rule received execution authority. It could also let a future replayable catalog scenario become a
Control target without explicit review. A04 additionally needs to preserve a two-turn memory causal
relationship, so it cannot use the same single benign request as M03 and M06.

## Decision

1. Automatic validation Controls are limited to an explicit allowlist containing M03 system-prompt
   disclosure, M06 jailbreak bypass, and A04 memory poisoning.
2. Only Mode adapters registered in the generic `ValidationControlMaterializerRegistry` may create
   Control variants. The Registry freezes after its first resolution and requires exact
   materializer ID/version, Mode, scenario, Tool, and scenario digest.
3. `ValidationControlPlan` advances to `v1alpha2` and includes `materializerId`,
   `materializerVersion`, and `scenarioDigest` in its canonical Plan ID.
4. For all three scenarios, Baseline preserves the catalog input and check. Negative Control uses
   the same input with a per-execution absent-canary check.
5. M03 and M06 Counterfactuals use a benign `READY` input and check that the original marker is
   absent.
6. The A04 Counterfactual changes the first-turn poison write to `PAJIN_MEMORY_SAFE` while
   preserving the second memory query and original poison-marker check. This contrasts the memory
   persistence cause instead of substituting an unrelated conversation.
7. A materializer creates argument variants only; it cannot create a Request or Capability. The
   existing Control Executor alone may dispatch them with fresh non-delegable `max_calls=1`
   Capabilities.
8. Results for all three scenarios remain information-only and cannot change Candidate, severity,
   Replay, or confirmation state.

## Consequences

- The transformation rule and version for every supported scenario are auditable from the sealed
  Plan.
- A new replayable scenario does not execute Controls without an explicit allowlist entry and
  materializer registration.
- M03, M06, and A04 share the same fresh request, session, Capability, evidence, and receipt
  boundary.
- For all three scenarios against one target, the B2.2 preflight baseline reserves exactly 21
  calls: 6 source, 6 Replay, and 9 Control calls. After B2.5 Claim-by-Claim Replay, the current
  budget is the 33 calls specified by
  [ADR 0036](0036-claim-bound-replay-execution-authority.md).

## Limits and follow-up

- Each scenario supports one validity check and one attempt per Control.
- Materializers are code-registered, not an operationally approved or signed remote registry.
- ADR-0034 implements the first opt-in independent-severity and Provider/model-diversity vertical
  slice. Attested operational diversity, calibration, multi-Reviewer consensus, Claim-level Replay,
  and public partial-validation states remain follow-up work.
- Receipts still cover only a PAJIN-local Run seal and Docker proxy receipt; they are not portable
  or off-host independent attestation.
