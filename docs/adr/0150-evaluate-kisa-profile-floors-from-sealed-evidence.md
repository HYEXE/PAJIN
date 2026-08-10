# ADR-0150: Evaluate KISA Profile Floors from Sealed Evidence

- Status: Accepted
- Date: 2026-08-10

## Context

VAL-002 defines three validity-only evidence depths and VAL-003 maps exact Profiles to minimum
depths. Neither authority may inspect evidence. PAJIN already has a KISA Replay verifier that
reopens one-to-twenty fresh-session attempts and a separate Validation Control boundary that seals
Baseline, Negative Control and Counterfactual requests, receipts, reconciliation and fresh child
Capabilities.

The first VAL-004 slice must determine whether those real artifacts satisfy a Profile floor without
turning the result into execution or Finding confirmation authority. Repository inspection also
showed that VAL-001 WALK MCP Claims cannot be combined with current KISA Controls: the Claim,
original request, Tool and session semantics differ. Treating them as interchangeable would create
evidence that no existing executor produced.

## Decision

1. Add a KISA-specific VAL-004A adapter that accepts one exact Profile, Candidate, sealed KISA
   source Run, KISA Replay batch and optional KISA Control batch.
2. Reuse `KISAReplayBatchOutcome.verified_records()` and the existing ticket-bound sealed result
   loader. Admit only an exact validity Claim with a successful supporting confirmation Replay.
3. Count the sealed Replay attempts as repetitions only when every compiled attempt succeeded and
   request IDs, fresh-session materializations and evidence lineage are distinct. Retain the exact
   Replay Capability Grant ID but create or consume no authority.
4. Reopen the Control Run and exact-match its public record, final root, bounded artifacts, audit
   events, Plan, requests, attempts, receipts, reconciliation and Capability ledger.
5. Rerun the registered KISA Control materializer from its exact ID/version/scenario/Tool digest and
   require its variants and deterministic request identities to equal the sealed requests. Bind the
   Control executor, Tool, target and method to the original Replay semantics.
6. Require Replay and Controls to share one exact source root, Candidate, validity Claim, scenario
   and original request while keeping request, session, Capability and evidence lineage disjoint.
7. Derive the achieved VAL-002 depth only from verified evidence: Replay alone is single, one
   Replay plus observed Controls is controlled, and two or more Replays plus observed Controls is
   repeated controlled.
8. Emit an assessment only when the achieved registered requirement reaches the exact VAL-003
   floor. Content-address the complete floor, Claim, Replay evidence, Control evidence and achieved
   requirement.
9. Fix Profile selection attestation, Campaign mutation, execution, confirmation and Finding
   authority to false. Record only that evidence evaluation occurred and the floor was satisfied.
10. Keep VAL-004A explicitly KISA-scoped. A mode-neutral VAL-001 adapter requires a compatible
    Control materializer and explicit session/independence evidence and remains a later VAL-004B
    slice.

## Consequences

- AI Assessment can require two supporting fresh-session Replay attempts plus the exact observed
  three-Control contrast, while Bug Hunt and Pentest require at least the contrast and CTF may use a
  single supporting Replay.
- A stronger verified depth can satisfy a lower registered floor without weakening either catalog.
- Stale roots, cross-Claim Controls, missing repetitions, non-supporting outcomes, materializer
  substitution and request/session/Capability/evidence reuse fail closed.
- The assessment can be rebuilt from sealed predecessors and exact-matched before another boundary
  consumes it.
- The output does not select a Profile for any Campaign and cannot confirm a Finding.

## Rejected alternatives

### Combine VAL-001 WALK Replay with KISA Controls

Rejected because the current artifacts bind different Candidates, Claims, original requests, Tools
and session semantics. Matching only a threat label or Profile would be authority forgery.

### Trust public Replay or Control records without reopening Runs

Rejected because the records are summaries. They do not replace ticket finalization, Run integrity,
artifact, materializer, Capability and event verification.

### Let callers declare the achieved depth

Rejected because a caller-defined ordinal would turn policy metadata into evidence. VAL-004A derives
one exact registered requirement from verified counts and contrast.

### Confirm a Finding when the floor is satisfied

Rejected because Profile evidence satisfaction is not the existing confirmation Gate and the v1
policy covers only validity. Impact, severity and confirmation remain separate authorities.

## Compatibility and rollback

The change is additive and uses an explicit module API to avoid eager package import cycles. No
existing Profile, Replay, Control, Campaign, Validation Decision or Finding wire changes. Rollback
removes the evaluator, tests, contract and this ADR without modifying predecessor artifacts.

## Related documents

- [VAL-004A contract](../orchestration/VAL-004A-kisa-profile-validation-evidence.md)
- [VAL-003 contract](../orchestration/VAL-003-profile-assurance-floor.md)
- [VAL-002 contract](../orchestration/VAL-002-validation-depth-policy.md)
- [ADR-0149](0149-bind-profile-assurance-floors-without-campaign-selection.md)
- [ADR-0032](0032-fresh-capability-validation-controls.md)
- [ADR-0033](0033-registered-validation-control-materializers.md)
